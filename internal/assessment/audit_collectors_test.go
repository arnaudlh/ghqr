// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestFetchOrgAuditLogFullPaginationLocalClassificationAndDedup exercises the
// shared ent.audit_log/org.audit_log implementation: cursor-based (after=)
// pagination across 2 pages, an explicit since..until bounded phrase, local
// phrase-category classification from a single full pull (not a separate
// query per phrase), the official @timestamp field, and `_document_id`
// deduplication for an entry repeated across pages.
func TestFetchOrgAuditLogFullPaginationLocalClassificationAndDedup(t *testing.T) {
	earliest := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	until := earliest.AddDate(0, 0, 30)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		phrase := request.URL.Query().Get("phrase")
		wantPhrase := "created:" + earliest.Format("2006-01-02") + ".." + until.Format("2006-01-02")
		if phrase != wantPhrase || request.URL.Query().Get("include") != "all" {
			t.Errorf("expected a single full pull bounded by an explicit since..until range (%q), got %q", wantPhrase, phrase)
		}
		switch request.URL.Query().Get("after") {
		case "":
			next := *request.URL
			query := next.Query()
			query.Set("after", "cursor-2")
			next.RawQuery = query.Encode()
			writer.Header().Set("Link", "<"+server.URL+next.RequestURI()+">; rel=\"next\"")
			writeJSON(t, writer, []map[string]any{
				{"action": "repo.destroy", "_document_id": "doc-1", "@timestamp": earliest.UnixMilli()},
				{"action": "org.disable_two_factor_requirement", "_document_id": "doc-2", "@timestamp": earliest.Add(24 * time.Hour).UnixMilli()},
				{"action": "dependabot.alert_dismiss", "_document_id": "doc-3", "@timestamp": earliest.Add(48 * time.Hour).UnixMilli()},
			})
		case "cursor-2":
			writeJSON(t, writer, []map[string]any{
				// doc-1 repeated across the page boundary: must be deduplicated.
				{"action": "repo.destroy", "_document_id": "doc-1", "@timestamp": earliest.UnixMilli()},
				{"action": "repository_ruleset.create", "_document_id": "doc-4", "@timestamp": earliest.Add(72 * time.Hour).UnixMilli()},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcome, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", earliest, until)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || outcome.Pages != 2 {
		t.Fatalf("expected a complete, fully paginated (2-page) result: %+v / %+v", result, outcome)
	}
	// 4 distinct document IDs (doc-1..doc-4); doc-1's repeat must not inflate the count.
	if result.TotalEntries != 4 {
		t.Fatalf("expected exactly 4 deduplicated entries, got %d", result.TotalEntries)
	}
	if result.CategoryCounts["repo.destroy"] != 1 || result.CategoryCounts["org.disable_two_factor_requirement"] != 1 ||
		result.CategoryCounts["repository_ruleset"] != 1 {
		t.Fatalf("unexpected category classification: %+v", result.CategoryCounts)
	}
	if _, ok := result.CategoryCounts["dependabot.alert_dismiss"]; ok {
		t.Fatal("an action outside the documented phrase list must not be classified into any category")
	}
	if result.EarliestEntryAt == nil || !result.EarliestEntryAt.Equal(earliest) {
		t.Fatalf("expected the earliest observed entry timestamp (from @timestamp) to be tracked: %+v", result.EarliestEntryAt)
	}
	if !result.RequestedSince.Equal(earliest) || !result.RequestedUntil.Equal(until) {
		t.Fatalf("expected the exact requested since/until window to be disclosed: %+v", result)
	}
	if result.WebRetentionLimitedDays != auditLogWebRetentionDays || result.GitRetentionLimitedDays != auditLogGitRetentionDays {
		t.Fatalf("expected the documented retention limits to be disclosed: %+v", result)
	}
}

// TestFetchOrgAuditLogUsesOfficialMillisecondTimestampNotCreatedAt is a
// regression test: the official, authoritative event-time field is
// `@timestamp` (UTC epoch milliseconds), not `created_at`, which official
// documentation does not guarantee is always present. An entry carrying
// only `@timestamp` must still be tracked correctly.
func TestFetchOrgAuditLogUsesOfficialMillisecondTimestampNotCreatedAt(t *testing.T) {
	observed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"_document_id": "observed-1", "action": "repo.destroy", "@timestamp": observed.UnixMilli()},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", observed.Add(-24*time.Hour), observed)
	if err != nil {
		t.Fatal(err)
	}
	if result.EarliestEntryAt == nil || !result.EarliestEntryAt.Equal(observed) {
		t.Fatalf("official @timestamp must be used, not silently discarded: %+v", result)
	}
}

// TestFetchOrgAuditLogMissingRequiredFieldsCannotBeComplete confirms an
// entry missing its documented action or a usable timestamp cannot be
// classified with confidence, and must downgrade the whole result to
// Complete=false rather than silently looking like a clean, empty category
// inventory.
func TestFetchOrgAuditLogMissingRequiredFieldsCannotBeComplete(t *testing.T) {
	t.Run("missing_action", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeJSON(t, writer, []map[string]any{{"_document_id": "observed-1", "@timestamp": time.Now().UnixMilli()}})
		}))
		t.Cleanup(server.Close)
		client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
		result, outcome, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", time.Now().Add(-24*time.Hour), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if result.Complete {
			t.Fatalf("omitted action cannot imply a complete, clean category inventory: %+v", result)
		}
		if result.UnclassifiableEntries != 1 {
			t.Fatalf("expected the unclassifiable entry to be tracked, not silently dropped: %+v", result)
		}
		if outcome.Status != CollectionPartial || outcome.Complete || outcome.Reason == "" {
			t.Fatalf("the semantic failure must propagate into the reported outcome itself, not only the typed result: %+v", outcome)
		}
	})
	t.Run("missing_timestamp", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeJSON(t, writer, []map[string]any{{"_document_id": "observed-1", "action": "repo.destroy"}})
		}))
		t.Cleanup(server.Close)
		client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
		result, outcome, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", time.Now().Add(-24*time.Hour), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if result.Complete || result.CategoryCounts["repo.destroy"] != 0 {
			t.Fatalf("an entry with no usable timestamp must not be counted or make the result clean: %+v", result)
		}
		if outcome.Status != CollectionPartial || outcome.Reason == "" {
			t.Fatalf("expected the outcome itself to disclose the semantic failure: %+v", outcome)
		}
	})
}

// TestFetchOrgAuditLogRejectsZeroOrInvertedWindow confirms a zero or
// inverted (since after until) window is rejected before any request is
// attempted, rather than silently sent to the API.
func TestFetchOrgAuditLogRejectsZeroOrInvertedWindow(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, []map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	now := time.Now()

	if _, _, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", time.Time{}, now); err == nil {
		t.Fatal("a zero since must be rejected")
	}
	if _, _, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", now, time.Time{}); err == nil {
		t.Fatal("a zero until must be rejected")
	}
	if _, _, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", now, now.Add(-time.Hour)); err == nil {
		t.Fatal("an inverted window (since after until) must be rejected")
	}
	if requests != 0 {
		t.Fatalf("an invalid window must never reach the network, got %d requests", requests)
	}
}

// TestFetchOrgAuditLogExcludesEntriesOutsideExactWindow confirms the
// day-granular source query's over-fetched edges (up to 24h wider on EACH
// side of the requested instants, up to 48h combined) are trimmed back to
// the exact [since, until] range: an entry timestamped before since or
// after until must never be silently folded into the counted result.
func TestFetchOrgAuditLogExcludesEntriesOutsideExactWindow(t *testing.T) {
	since := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	until := since.AddDate(0, 0, 10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			// Before the exact since instant (but still on since's day, so
			// the day-granular source query would legitimately return it).
			{"action": "repo.destroy", "_document_id": "too-early", "@timestamp": since.Add(-6 * time.Hour).UnixMilli()},
			// Exactly within the window.
			{"action": "repo.destroy", "_document_id": "in-window", "@timestamp": since.Add(6 * time.Hour).UnixMilli()},
			// After the exact until instant (but still on until's day).
			{"action": "repo.destroy", "_document_id": "too-late", "@timestamp": until.Add(6 * time.Hour).UnixMilli()},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", since, until)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalEntries != 1 || result.CategoryCounts["repo.destroy"] != 1 {
		t.Fatalf("expected only the exactly-in-window entry to be counted, the day-granular-only matches excluded: %+v", result)
	}
	if result.EarliestEntryAt == nil || !result.EarliestEntryAt.Equal(since.Add(6*time.Hour)) {
		t.Fatalf("expected the earliest IN-WINDOW entry to be tracked, not the out-of-window one: %+v", result.EarliestEntryAt)
	}
}

// TestFetchOrgAuditLogMissingDocumentIDMarksIncomplete confirms an entry
// missing the documented `_document_id` field (always present per official
// schema) downgrades the result rather than being silently trusted for
// deduplication.
func TestFetchOrgAuditLogMissingDocumentIDMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{{"action": "repo.destroy", "@timestamp": time.Now().UnixMilli()}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	result, outcome, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("a missing _document_id must downgrade the result, not be silently trusted for dedup")
	}
	if outcome.Status != CollectionPartial || outcome.Reason == "" {
		t.Fatalf("expected the outcome itself to disclose the semantic failure: %+v", outcome)
	}
}

// TestFetchOrgAuditLogManyCursorPagesBeyondOneHundred proves full pagination
// across more than 100 cursor hops (not merely more than 100 entries on a
// couple of pages), confirming no silent page-count cap.
func TestFetchOrgAuditLogManyCursorPagesBeyondOneHundred(t *testing.T) {
	const totalPages = 120
	fixedTimestamp := time.Now()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page := 1
		if value := request.URL.Query().Get("after"); value != "" {
			parsed, convErr := strconv.Atoi(value)
			if convErr != nil {
				t.Fatal(convErr)
			}
			page = parsed + 1
		}
		if page < totalPages {
			next := *request.URL
			query := next.Query()
			query.Set("after", strconv.Itoa(page))
			next.RawQuery = query.Encode()
			writer.Header().Set("Link", "<"+server.URL+next.RequestURI()+">; rel=\"next\"")
		}
		// A fixed timestamp captured once before the server starts, not
		// time.Now() re-evaluated per page, so a slow full pagination run
		// (120 round trips) cannot drift an entry's timestamp outside the
		// since/until window captured once up front below.
		writeJSON(t, writer, []map[string]any{
			{"action": "repo.destroy", "_document_id": fmt.Sprintf("doc-%d", page), "@timestamp": fixedTimestamp.UnixMilli()},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcome, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org",
		fixedTimestamp.Add(-24*time.Hour), fixedTimestamp.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Pages != totalPages {
		t.Fatalf("expected all %d cursor pages to actually be fetched, got %d", totalPages, outcome.Pages)
	}
	if !result.Complete || result.TotalEntries != totalPages {
		t.Fatalf("expected %d fully collected entries across >100 pages, got %d (complete=%v)", totalPages, result.TotalEntries, result.Complete)
	}
}

// TestFetchOrgAuditLogLaterPageFailureRetainsKnownCountsIncomplete confirms
// a later-page failure (for example a mid-pagination permission change)
// preserves the already-collected pages' counts for audit while marking the
// whole result incomplete, rather than discarding them or reporting clean.
func TestFetchOrgAuditLogLaterPageFailureRetainsKnownCountsIncomplete(t *testing.T) {
	earliest := time.Now().Add(-48 * time.Hour)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("after") == "" {
			next := *request.URL
			query := next.Query()
			query.Set("after", "cursor-2")
			next.RawQuery = query.Encode()
			writer.Header().Set("Link", "<"+server.URL+next.RequestURI()+">; rel=\"next\"")
			writeJSON(t, writer, []map[string]any{
				{"action": "repo.destroy", "_document_id": "doc-1", "@timestamp": earliest.UnixMilli()},
			})
			return
		}
		writer.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgAuditLog(context.Background(), client, store, scope, "fixture-org", earliest.Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("a later-page failure must mark the result incomplete")
	}
	if result.TotalEntries != 1 || result.CategoryCounts["repo.destroy"] != 1 {
		t.Fatalf("the first page's known entry must still be preserved for audit, not discarded: %+v", result)
	}
}

// TestFetchEnterpriseAuditLogIncompletePageMarksResultIncomplete confirms an
// ent.audit_log collection failure marks the result incomplete rather than
// silently reporting the partially collected subset as clean.
func TestFetchEnterpriseAuditLogIncompletePageMarksResultIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	now := time.Now()
	result, _, err := FetchEnterpriseAuditLog(context.Background(), client, store, scope, "fixture-enterprise", now.AddDate(0, 0, -180), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("a forbidden audit-log probe must mark the result incomplete, not clean")
	}
}

// TestFetchEnterpriseAuditLogStreamsCountsEnabledAndPaused confirms
// ent.audit_log_streams reads the actual enabled/paused_at fields (not a
// guessed "paused" boolean).
func TestFetchEnterpriseAuditLogStreamsCountsEnabledAndPaused(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"id": 1, "stream_type": "datadog", "enabled": true, "paused_at": nil},
			{"id": 2, "stream_type": "splunk", "enabled": false, "paused_at": "2026-09-01T00:00:00Z"},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseAuditLogStreams(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.StreamsCount != 2 || result.EnabledCount != 1 || result.PausedCount != 1 {
		t.Fatalf("unexpected audit-log streams result: %+v", result)
	}
}

// TestFetchEnterpriseAuditLogStreamsMissingEnabledCannotMeanDisabled is a
// regression test: a stream missing its documented `enabled` field must not
// be silently counted as confirmed disabled.
func TestFetchEnterpriseAuditLogStreamsMissingEnabledCannotMeanDisabled(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{{"id": 1, "stream_type": "Datadog", "paused_at": nil}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcome, err := FetchEnterpriseAuditLogStreams(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("omitted enabled must not be counted as confirmed disabled")
	}
	if result.EnabledCount != 0 {
		t.Fatalf("an unknown stream must never contribute a false enabled count: %+v", result)
	}
	if outcome.Status != CollectionPartial || outcome.Complete || outcome.Reason == "" {
		t.Fatalf("the semantic failure must propagate into the reported outcome, not only the typed result: %+v", outcome)
	}
}

// TestFetchOrgSecretScanningSettingsExplicitOverridesOnly confirms
// org.secret_scanning_settings reports only the literal, explicitly
// configured "enabled" overrides, never an inherited ("not-set" +
// default_setting) effective value, and that "not-set" entries are neither
// counted as enabled nor as disabled.
func TestFetchOrgSecretScanningSettingsExplicitOverridesOnly(t *testing.T) {
	enterpriseNotSet := "not-set"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{
			"pattern_config_version": "fixture-version",
			"provider_pattern_overrides": []map[string]any{
				{"token_type": "GITHUB_PAT", "slug": "github-pat", "display_name": "GitHub PAT",
					"setting": "enabled", "default_setting": "disabled", "enterprise_setting": &enterpriseNotSet},
				{"token_type": "AWS_KEY", "slug": "aws-key", "display_name": "AWS Key",
					"setting": "not-set", "default_setting": "enabled", "enterprise_setting": nil},
			},
			"custom_pattern_overrides": []map[string]any{
				{"token_type": "cp_1", "slug": "custom-api-key", "display_name": "Custom API Key",
					"setting": "enabled", "default_setting": "disabled", "enterprise_setting": nil},
			},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgSecretScanningSettings(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ProviderPatternOverridesCount != 2 || result.ProviderPatternsExplicitlyEnabledCount != 1 ||
		result.CustomPatternOverridesCount != 1 || result.CustomPatternsExplicitlyEnabledCount != 1 {
		t.Fatalf("expected only the literal setting==\"enabled\" overrides counted (the \"not-set\"+default_setting=enabled "+
			"pattern must not inflate this explicit tally): %+v", result)
	}
}

// TestFetchOrgSecretScanningSettingsOmittedArraysCannotMeanEmpty is a
// regression test: an entirely empty `{}` response body (both override
// arrays absent, not merely empty) must not be treated as a confirmed empty
// configuration.
func TestFetchOrgSecretScanningSettingsOmittedArraysCannotMeanEmpty(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcome, err := FetchOrgSecretScanningSettings(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("omitted configuration arrays cannot be confirmed empty")
	}
	if outcome.Status != CollectionPartial || outcome.Complete || outcome.Reason == "" {
		t.Fatalf("the semantic failure must propagate into the reported outcome: %+v", outcome)
	}
}

// TestFetchOrgSecretScanningSettingsUnknownEnumValueMarksIncomplete confirms
// an override carrying a value outside the documented setting/
// default_setting/enterprise_setting enums downgrades the result.
func TestFetchOrgSecretScanningSettingsUnknownEnumValueMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{
			"provider_pattern_overrides": []map[string]any{
				{"token_type": "GITHUB_PAT", "slug": "github-pat", "display_name": "GitHub PAT",
					"setting": "unexpected-value", "default_setting": "disabled", "enterprise_setting": nil},
			},
			"custom_pattern_overrides": []map[string]any{},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcome, err := FetchOrgSecretScanningSettings(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("an unrecognized setting enum value must downgrade the result, not be silently ignored")
	}
	if outcome.Status != CollectionPartial || outcome.Reason == "" {
		t.Fatalf("the semantic failure must propagate into the reported outcome: %+v", outcome)
	}
}

// TestFetchOrgBypassRequestsCountsOpenAndPendingAcrossBothEndpoints confirms
// org.bypass_requests collects both the secret-scanning and push-rules
// bypass-request inventories, requests the documented time_period=month
// maximum window on BOTH endpoints (the default is day/24h if omitted), and
// tracks "pending" distinctly from "open".
func TestFetchOrgBypassRequestsCountsOpenAndPendingAcrossBothEndpoints(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("time_period") != "month" {
			t.Errorf("expected time_period=month on both bypass-request endpoints (default is day/24h only), got %q",
				request.URL.Query().Get("time_period"))
		}
		switch request.URL.Path {
		case "/orgs/fixture-org/bypass-requests/secret-scanning":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "status": "open"}, {"id": 2, "status": "approved"}, {"id": 3, "status": "open"}, {"id": 4, "status": "pending"},
			})
		case "/orgs/fixture-org/bypass-requests/push-rules":
			writeJSON(t, writer, []map[string]any{{"id": 10, "status": "denied"}, {"id": 11, "status": "pending"}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgBypassRequests(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.SecretScanningRequestsCount != 4 || result.SecretScanningOpenCount != 2 ||
		result.SecretScanningPendingCount != 1 || result.PushRulesRequestsCount != 2 || result.PushRulesOpenCount != 0 ||
		result.PushRulesPendingCount != 1 {
		t.Fatalf("unexpected bypass requests result: %+v", result)
	}
	if result.ObservedWindowDays != 30 || result.WindowLimitationReason == "" {
		t.Fatalf("expected an explicit, always-populated observed-window-days/limitation-reason field, not just a code "+
			"comment: %+v", result)
	}
}

// TestFetchOrgBypassRequestsMissingStatusCannotMeanClosed is a regression
// test: a request missing its documented status must not be silently
// excluded from only the open count while the result still claims complete.
func TestFetchOrgBypassRequestsMissingStatusCannotMeanClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{{"id": 1}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgBypassRequests(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("omitted request status cannot yield complete zero-open counts")
	}
	if outcomes[0].Status != CollectionPartial || outcomes[0].Reason == "" {
		t.Fatalf("the semantic failure must propagate into the reported secret-scanning outcome: %+v", outcomes[0])
	}
}

// TestFetchOrgCampaignsSumsOpenAndClosedSeparately confirms org.campaigns
// queries both states (the endpoint has no "all states" mode) and sums them.
func TestFetchOrgCampaignsSumsOpenAndClosedSeparately(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("state") {
		case "open":
			writeJSON(t, writer, []map[string]any{{"number": 1, "name": "Fix critical CodeQL alerts", "state": "open"}})
		case "closed":
			writeJSON(t, writer, []map[string]any{
				{"number": 2, "name": "Rotate leaked secrets", "state": "closed"},
				{"number": 3, "name": "Upgrade vulnerable dependencies", "state": "closed"},
			})
		default:
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgCampaigns(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.OpenCount != 1 || result.ClosedCount != 2 {
		t.Fatalf("unexpected campaigns result: %+v", result)
	}
}

// TestFetchOrgCampaignsMissingStateCannotBeComplete is a regression test: a
// campaign missing its documented number/state must not yield a complete
// inventory.
func TestFetchOrgCampaignsMissingStateCannotBeComplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") == "open" {
			writeJSON(t, writer, []map[string]any{{"number": 1, "name": "fixture-campaign"}})
			return
		}
		writeJSON(t, writer, []map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgCampaigns(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("omitted campaign state cannot yield a complete inventory")
	}
	if outcomes[0].Status != CollectionPartial || outcomes[0].Reason == "" {
		t.Fatalf("the semantic failure must propagate into the reported open-state outcome: %+v", outcomes[0])
	}
}
