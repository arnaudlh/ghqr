// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ===== org.api_insights =====

// TestFetchOrgAPIInsightsRejectsZeroOrInvertedWindow confirms a zero or
// inverted window is rejected before any request is attempted (the
// min_timestamp parameter is documented required, and max_timestamp's
// documented default "30 days ago" is never trusted implicitly).
func TestFetchOrgAPIInsightsRejectsZeroOrInvertedWindow(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	now := time.Now()

	if _, _, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Cloud, time.Time{}, now); err == nil {
		t.Fatal("a zero since must be rejected")
	}
	if _, _, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Cloud, now, now.Add(-time.Hour)); err == nil {
		t.Fatal("an inverted window must be rejected")
	}
	if requests != 0 {
		t.Fatalf("an invalid window must never reach the network, got %d requests", requests)
	}
}

// TestFetchOrgAPIInsightsSkippedOnServerDeployment confirms this GHEC-only
// REST surface is never attempted against a GitHub Enterprise Server
// deployment: no request is made, and the outcome explicitly discloses why.
func TestFetchOrgAPIInsightsSkippedOnServerDeployment(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	now := time.Now()

	result, outcomes, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Server, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("API Insights must never be attempted against a GitHub Enterprise Server deployment, got %d requests", requests)
	}
	if result.Complete {
		t.Fatal("a deliberately skipped Cloud-only collector must not report Complete=true")
	}
	if len(outcomes) != 1 || outcomes[0].Status != NotRun || outcomes[0].Reason == "" {
		t.Fatalf("expected a single explicit NotRun outcome disclosing the Cloud-only gate: %+v", outcomes)
	}
}

// TestFetchOrgAPIInsightsAggregatesSummaryTimeAndSubjects confirms the exact
// ISO 8601 min_timestamp/max_timestamp window is sent to every endpoint, the
// timestamp_increment parameter is set on time-stats, and all three
// endpoints' results are aggregated.
func TestFetchOrgAPIInsightsAggregatesSummaryTimeAndSubjects(t *testing.T) {
	since := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	until := since.AddDate(0, 0, 7)
	wantMin, wantMax := isoTimestamp(since), isoTimestamp(until)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("min_timestamp") != wantMin || request.URL.Query().Get("max_timestamp") != wantMax {
			t.Errorf("expected explicit min/max timestamp %q/%q, got %q/%q",
				wantMin, wantMax, request.URL.Query().Get("min_timestamp"), request.URL.Query().Get("max_timestamp"))
		}
		switch {
		case strings.Contains(request.URL.Path, "summary-stats"):
			writeJSON(t, writer, map[string]any{"total_request_count": 1000, "rate_limited_request_count": 4})
		case strings.Contains(request.URL.Path, "time-stats"):
			if request.URL.Query().Get("timestamp_increment") != "1d" {
				t.Errorf("expected timestamp_increment=1d, got %q", request.URL.Query().Get("timestamp_increment"))
			}
			writeJSON(t, writer, []map[string]any{
				{"timestamp": "2026-08-01T00:00:00Z", "total_request_count": 500, "rate_limited_request_count": 1},
				{"timestamp": "2026-08-02T00:00:00Z", "total_request_count": 500, "rate_limited_request_count": 3},
			})
		case strings.Contains(request.URL.Path, "subject-stats"):
			writeJSON(t, writer, []map[string]any{
				{"subject_type": "User", "subject_name": "octocat", "total_request_count": 600, "rate_limited_request_count": 2},
				{"subject_type": "Bot", "subject_name": "dependabot", "total_request_count": 400, "rate_limited_request_count": 2},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Cloud, since, until)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.TotalRequestCount == nil || *result.TotalRequestCount != 1000 ||
		result.RateLimitedRequestCount == nil || *result.RateLimitedRequestCount != 4 ||
		result.TimeStatsBucketsCount != 2 || result.SubjectsObservedCount != 2 {
		t.Fatalf("unexpected aggregated result: %+v", result)
	}
	if result.DataLagCaveat == "" {
		t.Fatal("expected the documented 4-6h data lag to be explicitly disclosed")
	}
}

// TestFetchOrgAPIInsightsMissingSummaryFieldsMarksIncomplete confirms an
// omitted total_request_count/rate_limited_request_count field is preserved
// as an unknown pointer, never silently coerced to a zero count.
func TestFetchOrgAPIInsightsMissingSummaryFieldsMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "summary-stats") {
			writeJSON(t, writer, map[string]any{})
			return
		}
		writeJSON(t, writer, []map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	now := time.Now()

	result, outcomes, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Cloud, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.TotalRequestCount != nil || result.RateLimitedRequestCount != nil {
		t.Fatalf("an omitted summary-stats field must stay an unknown pointer, never a false zero: %+v", result)
	}
	if outcomes[0].Status != CollectionPartial || outcomes[0].Reason == "" {
		t.Fatalf("expected the semantic failure to propagate into the outcome: %+v", outcomes[0])
	}
}

// TestFetchOrgAPIInsightsMalformedBucketsNotCompleteDespiteValidSummary
// confirms a fully valid summary-stats response never vouches for a
// separately malformed time-stats/subject-stats array: an array containing
// [{}] (an object with every documented field omitted) decodes without a
// JSON error and must not inflate the observed bucket/subject counts or be
// reported Complete=true.
func TestFetchOrgAPIInsightsMalformedBucketsNotCompleteDespiteValidSummary(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "summary-stats") {
			writeJSON(t, writer, map[string]any{"total_request_count": 10, "rate_limited_request_count": 0})
			return
		}
		writeJSON(t, writer, []map[string]any{{}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	now := time.Now()

	result, outcomes, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Cloud, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.TimeStatsBucketsCount != 0 || result.SubjectsObservedCount != 0 {
		t.Fatalf("a valid summary cannot vouch for omitted time/subject fields as complete or non-empty: %+v", result)
	}
	if outcomes[1].Status != CollectionPartial || outcomes[1].Reason == "" || outcomes[2].Status != CollectionPartial || outcomes[2].Reason == "" {
		t.Fatalf("expected both the time-stats and subject-stats outcomes to disclose the semantic failure independently: %+v / %+v",
			outcomes[1], outcomes[2])
	}
}

// TestFetchOrgAPIInsightsNegativeCountMarksIncomplete confirms a negative
// request count (a sanity-failing, never-documented value) is treated the
// same as a missing one: never silently accepted.
func TestFetchOrgAPIInsightsNegativeCountMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "summary-stats") {
			writeJSON(t, writer, map[string]any{"total_request_count": -1, "rate_limited_request_count": 0})
			return
		}
		writeJSON(t, writer, []map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	now := time.Now()

	result, _, err := FetchOrgAPIInsights(context.Background(), client, store, scope, "fixture-org", Cloud, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("a negative request count must never be silently accepted as a known, complete value")
	}
}

// ===== org.billing / ent.billing =====

func TestFetchOrgBillingSkippedOnServerDeployment(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgBilling(context.Background(), client, store, scope, "fixture-org", Server)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("org.billing must never be attempted against a GitHub Enterprise Server deployment, got %d requests", requests)
	}
	if result.Complete || result.LegacyBillingGapDisclosure == "" {
		t.Fatalf("expected an incomplete, gap-disclosed result: %+v", result)
	}
	if len(outcomes) != 1 || outcomes[0].Status != NotRun {
		t.Fatalf("expected a single explicit NotRun outcome: %+v", outcomes)
	}
}

// TestFetchOrgBillingOmittedCommittersFieldsNotZero confirms GitHub's
// documented optional (GHAS-not-purchased) committer fields decode as
// unknown pointers, never a confirmed zero.
func TestFetchOrgBillingOmittedCommittersFieldsNotZero(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "advanced-security") {
			writeJSON(t, writer, map[string]any{"repositories": []map[string]any{}})
			return
		}
		writeJSON(t, writer, map[string]any{"usageItems": []map[string]any{
			{"date": "2026-08-01", "product": "actions", "sku": "compute", "quantity": 10, "unitType": "minutes",
				"pricePerUnit": 0.008, "grossAmount": 0.08, "discountAmount": 0, "netAmount": 0.08},
		}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgBilling(context.Background(), client, store, scope, "fixture-org", Cloud)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalAdvancedSecurityCommitters != nil {
		t.Fatalf("an omitted total_advanced_security_committers field must stay nil, not a confirmed zero: %+v", result)
	}
	if result.UsageItemsCount == nil || *result.UsageItemsCount != 1 || result.UsageNetAmountTotal != 0.08 {
		t.Fatalf("expected the single usage item to be summed: %+v", result)
	}
	if !result.Complete {
		t.Fatalf("a present (even if entirely optional-field-empty) committers object and a present usageItems array should be complete: %+v", result)
	}
}

// TestFetchOrgBillingOmittedUsageItemsNotConfirmedEmpty confirms an entirely
// absent usageItems key (nil slice) is distinguished from a confirmed empty
// billing period ([] present).
func TestFetchOrgBillingOmittedUsageItemsNotConfirmedEmpty(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "advanced-security") {
			writeJSON(t, writer, map[string]any{})
			return
		}
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgBilling(context.Background(), client, store, scope, "fixture-org", Cloud)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.UsageItemsCount != nil {
		t.Fatalf("an absent usageItems key must not be confirmed empty: %+v", result)
	}
}

// TestFetchEnterpriseBillingUsesEnterpriseEndpointAndGate confirms
// ent.billing calls the enterprise usage endpoint and is Cloud-gated
// identically to org.billing.
func TestFetchEnterpriseBillingUsesEnterpriseEndpointAndGate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.Contains(request.URL.Path, "/enterprises/fixture-enterprise/settings/billing/usage") {
			t.Errorf("expected the enterprise usage endpoint, got %s", request.URL.Path)
		}
		writeJSON(t, writer, map[string]any{"usageItems": []map[string]any{
			{"date": "2026-08-01", "product": "actions", "sku": "compute", "quantity": 5, "unitType": "minutes",
				"pricePerUnit": 0.008, "grossAmount": 0.04, "discountAmount": 0, "netAmount": 0.04, "organizationName": "fixture-org"},
		}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseBilling(context.Background(), client, store, scope, "fixture-enterprise", Cloud)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.UsageItemsCount == nil || *result.UsageItemsCount != 1 || result.UsageNetAmountTotal != 0.04 {
		t.Fatalf("unexpected enterprise billing result: %+v", result)
	}

	skipped, outcomes, err := FetchEnterpriseBilling(context.Background(), client, store, scope, "fixture-enterprise", Server)
	if err != nil {
		t.Fatal(err)
	}
	if skipped.Complete || outcomes[0].Status != NotRun {
		t.Fatalf("expected ent.billing to be skipped for a Server deployment: %+v / %+v", skipped, outcomes)
	}
}

// TestFetchEnterpriseBillingMissingNetAmountNotZero confirms a usage item
// missing its documented, required netAmount field is excluded from the
// summed total (never silently folded in as a fabricated 0.0) and
// downgrades both the typed result and its outcome.
func TestFetchEnterpriseBillingMissingNetAmountNotZero(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"usageItems": []map[string]any{{"date": "2026-10-05", "product": "Actions"}}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseBilling(context.Background(), client, store, scope, "fixture-enterprise", Cloud)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.UsageNetAmountTotal != 0 || result.UsageItemsWithUnknownAmountCount != 1 {
		t.Fatalf("a usage item missing netAmount must not imply a complete, confirmed-zero billing total: %+v", result)
	}
	if outcomes[0].Status != CollectionPartial || outcomes[0].Reason == "" {
		t.Fatalf("expected the semantic failure to propagate into the outcome: %+v", outcomes[0])
	}
}

// ===== ent.copilot =====

func TestFetchEnterpriseCopilotSkippedOnServerDeployment(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}
	now := time.Now()

	result, outcomes, err := FetchEnterpriseCopilot(context.Background(), client, store, scope, "fixture-enterprise", Server, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("ent.copilot must never be attempted against a GitHub Enterprise Server deployment, got %d requests", requests)
	}
	if result.Complete || result.ObservedWindowDays != entCopilotMetricsObservedWindowDays || result.WindowLimitationReason == "" {
		t.Fatalf("expected a skipped result that still discloses the metrics window limitation: %+v", result)
	}
	if len(outcomes) != 1 || outcomes[0].Status != NotRun {
		t.Fatalf("expected a single explicit NotRun outcome: %+v", outcomes)
	}
}

// TestFetchEnterpriseCopilotSeatsAndMetrics confirms: the envelope's own
// total_seats scalar is preserved (not dropped to 0); recent-activity is
// counted only within the caller's own [since, now] window (an ancient
// lifetime activity timestamp outside that window must not count); the
// metrics array's genuinely latest day is determined by parsing each
// entry's own date (not by assuming the last array element is latest,
// since the fixture deliberately returns them out of chronological order);
// and every clock reading is caller-supplied (never time.Now() read
// directly), so a replay of the same evidence is deterministic.
func TestFetchEnterpriseCopilotSeatsAndMetrics(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -5)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "billing/seats"):
			writeJSON(t, writer, map[string]any{"total_seats": 2, "seats": []map[string]any{
				{"assignee": map[string]any{"login": "octocat", "type": "User"}, "last_activity_at": "2026-08-09T00:00:00Z"},
				{"assignee": map[string]any{"login": "hubot", "type": "User"}},
			}})
		case strings.Contains(request.URL.Path, "copilot/metrics"):
			writeJSON(t, writer, []map[string]any{
				// Deliberately out of chronological order: the LAST array
				// entry is not the latest date, proving this collector does
				// not simply take metrics[len(metrics)-1].
				{"date": "2026-08-10", "total_active_users": 12, "total_engaged_users": 9},
				{"date": "2026-08-09", "total_active_users": 10, "total_engaged_users": 8},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseCopilot(context.Background(), client, store, scope, "fixture-enterprise", Cloud, since, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.SeatsReportedTotal == nil || *result.SeatsReportedTotal != 2 || result.SeatsReturnedCount != 2 || result.MetricsDaysObserved != 2 {
		t.Fatalf("unexpected copilot result: %+v", result)
	}
	if result.SeatsWithRecentActivityCount != 1 {
		t.Fatalf("expected exactly the one seat with activity inside [since, now] to count as recently active: %+v", result)
	}
	if result.MetricsLatestDay != "2026-08-10" ||
		result.MetricsTotalActiveUsersLatestDay == nil || *result.MetricsTotalActiveUsersLatestDay != 12 ||
		result.MetricsTotalEngagedUsersLatestDay == nil || *result.MetricsTotalEngagedUsersLatestDay != 9 {
		t.Fatalf("expected the genuinely latest-dated (not last-indexed) metrics day to be reported: %+v", result)
	}
}

// TestFetchEnterpriseCopilotAncientActivityOutsideWindowNotRecent confirms
// a seat's last_activity_at from long before the caller's requested
// [since, now] window does not count as "recently active": any lifetime
// activity timestamp previously satisfied this count, conflating "has ever
// used Copilot" with "is active within the window this run reports on".
func TestFetchEnterpriseCopilotAncientActivityOutsideWindowNotRecent(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	since := now.AddDate(0, 0, -5)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "billing/seats"):
			writeJSON(t, writer, map[string]any{"total_seats": 1, "seats": []map[string]any{
				{"assignee": map[string]any{"login": "ancient", "type": "User"}, "last_activity_at": "1999-01-01T00:00:00Z"},
			}})
		default:
			writeJSON(t, writer, []map[string]any{})
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseCopilot(context.Background(), client, store, scope, "fixture-enterprise", Cloud, since, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.SeatsWithRecentActivityCount != 0 {
		t.Fatalf("a 1999 activity timestamp must never count as recently active within an 2026 [since, now] window: %+v", result)
	}
}

// TestFetchEnterpriseCopilotInvalidMetricsDateMarksIncomplete confirms a
// metrics entry with a missing or unparseable date is excluded from the
// latest-day determination and downgrades Complete, never silently assumed
// clean.
func TestFetchEnterpriseCopilotInvalidMetricsDateMarksIncomplete(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "billing/seats"):
			writeJSON(t, writer, map[string]any{"total_seats": 0, "seats": []map[string]any{}})
		case strings.Contains(request.URL.Path, "copilot/metrics"):
			writeJSON(t, writer, []map[string]any{{"total_active_users": 5, "total_engaged_users": 3}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseCopilot(context.Background(), client, store, scope, "fixture-enterprise", Cloud, now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.MetricsLatestDay != "" {
		t.Fatalf("a metrics entry missing its date must not be treated as a known latest day or a complete result: %+v", result)
	}
	if outcomes[1].Status != CollectionPartial || outcomes[1].Reason == "" {
		t.Fatalf("expected the semantic failure to propagate into the metrics outcome: %+v", outcomes[1])
	}
}

// ===== ent.policies =====

// TestFetchEnterprisePoliciesPreservesLiteralValues confirms every
// documented policy field decodes to its own literal observed value,
// including the NO_POLICY enum sentinel (never coerced to a shared boolean)
// and the plain-boolean-typed fields.
func TestFetchEnterprisePoliciesPreservesLiteralValues(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"data": map[string]any{"enterprise": map[string]any{"ownerInfo": map[string]any{
			"defaultRepositoryPermissionSetting":              "NO_POLICY",
			"membersCanCreateRepositoriesSetting":             "ALL",
			"membersCanCreatePublicRepositoriesSetting":       true,
			"membersCanCreatePrivateRepositoriesSetting":      false,
			"membersCanCreateInternalRepositoriesSetting":     true,
			"membersCanChangeRepositoryVisibilitySetting":     "ENABLED",
			"membersCanDeleteRepositoriesSetting":             "DISABLED",
			"membersCanDeleteIssuesSetting":                   "NO_POLICY",
			"membersCanInviteCollaboratorsSetting":            "ENABLED",
			"membersCanUpdateProtectedBranchesSetting":        "NO_POLICY",
			"allowPrivateRepositoryForkingSetting":            "ENABLED",
			"allowPrivateRepositoryForkingSettingPolicyValue": "NO_POLICY",
			"twoFactorRequiredSetting":                        "ENABLED",
			"ipAllowListEnabledSetting":                       "NO_POLICY",
			"ipAllowListForInstalledAppsEnabledSetting":       "NO_POLICY",
			"notificationDeliveryRestrictionEnabledSetting":   "NO_POLICY",
			"membersCanViewDependencyInsightsSetting":         "ENABLED",
			"organizationProjectsSetting":                     "ENABLED",
			"repositoryProjectsSetting":                       "NO_POLICY",
			"teamDiscussionsSetting":                          "ENABLED",
		}}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcome, err := FetchEnterprisePolicies(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || outcome.Status != CollectionOK {
		t.Fatalf("expected a fully complete result: %+v / %+v", result, outcome)
	}
	if result.Policies["defaultRepositoryPermissionSetting"] != "NO_POLICY" {
		t.Fatalf("NO_POLICY must be preserved literally, not coerced to a boolean: %+v", result.Policies)
	}
	if result.Policies["membersCanCreatePublicRepositoriesSetting"] != "true" ||
		result.Policies["membersCanCreatePrivateRepositoriesSetting"] != "false" {
		t.Fatalf("plain-boolean policy fields must decode to their literal true/false: %+v", result.Policies)
	}
	if len(result.Policies) != len(entPoliciesFields) {
		t.Fatalf("expected every documented field to be captured, got %d of %d", len(result.Policies), len(entPoliciesFields))
	}
}

// TestFetchEnterprisePoliciesMissingFieldMarksIncomplete confirms a response
// shape missing one of the documented ownerInfo fields downgrades the
// result, rather than silently omitting it from Policies.
func TestFetchEnterprisePoliciesMissingFieldMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"data": map[string]any{"enterprise": map[string]any{
			"ownerInfo": map[string]any{"defaultRepositoryPermissionSetting": "NO_POLICY"},
		}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcome, err := FetchEnterprisePolicies(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("a response missing documented ownerInfo fields must not be reported complete")
	}
	if outcome.Status != CollectionPartial || outcome.Reason == "" {
		t.Fatalf("expected the semantic failure to propagate into the outcome: %+v", outcome)
	}
}

// TestFetchEnterprisePoliciesGraphQLErrorsEnvelopeFails confirms a GraphQL
// "errors" envelope on an HTTP 200 response is treated as a failed
// collection, matching ent.info/org.projects.
func TestFetchEnterprisePoliciesGraphQLErrorsEnvelopeFails(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"errors": []map[string]any{{"message": "field does not exist"}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	_, outcome, err := FetchEnterprisePolicies(context.Background(), client, store, scope, "fixture-enterprise")
	if err == nil {
		t.Fatal("a GraphQL errors envelope must be treated as a failed collection")
	}
	if outcome.Status != CollectionFailed {
		t.Fatalf("expected CollectionFailed, got %+v", outcome)
	}
}

// scimFixtureClient mirrors collectionFixtureClient but with a non-
// NoCredential credential kind, since FetchEnterpriseSCIMUsers explicitly
// refuses to attempt a request at all when no credential is configured.
func scimFixtureClient(t *testing.T, server *httptest.Server, budget *RequestBudget, clock Clock) *CollectionClient {
	t.Helper()
	client := collectionFixtureClient(t, server, budget, clock)
	client.credentialKind = ClassicPAT
	return client
}

// ===== ent.scim_users =====

// TestFetchEnterpriseSCIMUsersUnconfiguredModeMakesNoRequest confirms the
// default empty SCIMMode never infers EMU-vs-SAML-SSO status and never
// reaches the network.
func TestFetchEnterpriseSCIMUsersUnconfiguredModeMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("an unconfigured SCIM mode must never reach the network, got %d requests", requests)
	}
	if result.Complete || len(outcomes) != 1 || outcomes[0].Status != NotRun {
		t.Fatalf("expected a single explicit NotRun outcome: %+v / %+v", result, outcomes)
	}
}

// TestFetchEnterpriseSCIMUsersEMUSkippedOnServerDeployment confirms EMU
// routing (Cloud-only) makes no request against a Server deployment.
func TestFetchEnterpriseSCIMUsersEMUSkippedOnServerDeployment(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Server, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("EMU SCIM must never be attempted against a GitHub Enterprise Server deployment, got %d requests", requests)
	}
	if result.Complete || outcomes[0].Status != NotRun {
		t.Fatalf("expected a skipped result: %+v / %+v", result, outcomes)
	}
}

// TestFetchEnterpriseSCIMUsersNoCredentialMakesNoRequest confirms GitHub's
// SCIM endpoints (which require a specific classic-PAT credential never
// satisfied by "no credential configured") are never attempted when this
// target's credential kind is NoCredential, even for an otherwise valid
// mode/deployment combination.
func TestFetchEnterpriseSCIMUsersNoCredentialMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{}) // defaults to NoCredential
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("SCIM must never be attempted with no credential configured, got %d requests", requests)
	}
	if result.Complete || outcomes[0].Status != NotRun || outcomes[0].Reason == "" {
		t.Fatalf("expected a single explicit NotRun outcome: %+v / %+v", result, outcomes)
	}
}

// TestFetchEnterpriseSCIMUsersFineGrainedPATMakesNoRequest confirms a
// fine-grained PAT or GitHub App installation token -- explicitly
// documented as unsupported for GitHub's SCIM endpoints -- is rejected the
// same way as NoCredential, not silently permitted through a gate that only
// checked for the absence of any credential at all.
func TestFetchEnterpriseSCIMUsersFineGrainedPATMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	client.credentialKind = FineGrainedPAT
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("SCIM must never be attempted with a fine-grained PAT (explicitly unsupported), got %d requests", requests)
	}
	if result.Complete || outcomes[0].Status != NotRun || outcomes[0].Reason == "" {
		t.Fatalf("expected a single explicit NotRun outcome: %+v / %+v", result, outcomes)
	}
}

// TestFetchEnterpriseSCIMUsersSAMLSSOEmptyOrganizationsMakesNoRequest
// confirms "saml_sso" mode with zero configured organizations (a Target
// constructed directly, bypassing validateTarget's own requirement of at
// least one) reports an explicit NotRun rather than Complete=true with no
// outcomes and nothing actually checked.
func TestFetchEnterpriseSCIMUsersSAMLSSOEmptyOrganizationsMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "saml_sso", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("saml_sso with zero organizations must never reach the network, got %d requests", requests)
	}
	if result.Complete || len(outcomes) != 1 || outcomes[0].Status != NotRun {
		t.Fatalf("expected a single explicit NotRun outcome, not a silent Complete=true: %+v / %+v", result, outcomes)
	}
}

// scimUsersPageResponse builds one SCIM ListResponse page's raw JSON for
// test fixtures, with count active users followed by count inactive users,
// each with a unique documented id so cross-page duplicate detection has
// real identities to compare against.
func scimUsersPageResponse(totalResults, startIndex, activeCount, inactiveCount int) map[string]any {
	resources := make([]map[string]any, 0, activeCount+inactiveCount)
	for i := 0; i < activeCount; i++ {
		resources = append(resources, map[string]any{"id": fmt.Sprintf("active-%d-%d", startIndex, i), "active": true})
	}
	for i := 0; i < inactiveCount; i++ {
		resources = append(resources, map[string]any{"id": fmt.Sprintf("inactive-%d-%d", startIndex, i), "active": false})
	}
	return map[string]any{"totalResults": totalResults, "itemsPerPage": len(resources), "startIndex": startIndex, "Resources": resources}
}

// TestFetchEnterpriseSCIMUsersEMUFullPagination confirms full
// startIndex/count/totalResults pagination across more than one page (not
// merely a single page under the default page size).
func TestFetchEnterpriseSCIMUsersEMUFullPagination(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("startIndex") {
		case "1":
			writeJSON(t, writer, scimUsersPageResponse(150, 1, 90, 10))
		case "101":
			writeJSON(t, writer, scimUsersPageResponse(150, 101, 40, 10))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.TotalResultsReported == nil || *result.TotalResultsReported != 150 ||
		result.ResourcesReturnedCount != 150 || result.ActiveCount != 130 || result.InactiveCount != 20 {
		t.Fatalf("expected full 2-page pagination summing to 150 resources (130 active/20 inactive): %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersEMUShortPagesAdvanceByActualSize reproduces
// the regression this round fixed: pagination that blindly advanced by a
// fixed page size silently skipped (or could duplicate) identities the
// moment a real server returned short, irregular pages. Pages of size
// 2/2/1 (never the configured 100) against a disclosed total of 5 must
// still walk all 5 identities, never fewer.
func TestFetchEnterpriseSCIMUsersEMUShortPagesAdvanceByActualSize(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		start, _ := strconv.Atoi(request.URL.Query().Get("startIndex"))
		count := 0
		switch start {
		case 1, 3:
			count = 2
		case 5:
			count = 1
		}
		resources := make([]map[string]any, count)
		for i := range resources {
			resources[i] = map[string]any{"id": strconv.Itoa(start + i), "active": true}
		}
		writeJSON(t, writer, map[string]any{"totalResults": 5, "startIndex": start, "itemsPerPage": count, "Resources": resources})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil || !result.Complete || result.ResourcesReturnedCount != 5 {
		t.Fatalf("short but valid pages must advance by their own actual size without skipping identities: %+v / %v", result, err)
	}
}

// TestFetchEnterpriseSCIMUsersMissingEnvelopeNotComplete confirms a
// response missing the SCIM envelope entirely ({}) can never be reported
// Complete=true with a confirmed-zero roster: no totalResults was ever
// disclosed, so this walk cannot prove the roster is genuinely empty
// rather than simply unreadable.
func TestFetchEnterpriseSCIMUsersMissingEnvelopeNotComplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.ResourcesReturnedCount != 0 {
		t.Fatalf("an empty {} response must never be reported Complete=true with a confirmed zero roster: %+v", result)
	}
	if outcomes[0].Status != CollectionPartial || outcomes[0].Reason == "" {
		t.Fatalf("expected the semantic failure to propagate into the outcome: %+v", outcomes[0])
	}
}

// TestFetchEnterpriseSCIMUsersExplicitZeroTotalIsComplete confirms the one
// case that legitimately is Complete=true with a zero count: the server's
// own typed totalResults explicitly present and equal to 0.
func TestFetchEnterpriseSCIMUsersExplicitZeroTotalIsComplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": []map[string]any{}})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ResourcesReturnedCount != 0 || result.TotalResultsReported == nil || *result.TotalResultsReported != 0 {
		t.Fatalf("an explicit, typed totalResults=0 is the only basis for a confirmed-complete zero roster: %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersDuplicateResourceAcrossPagesMarksIncomplete
// confirms a resource repeated (by its documented id) across two pages --
// a real pagination inconsistency -- is excluded from the second count and
// downgrades Complete, rather than silently double-counted.
func TestFetchEnterpriseSCIMUsersDuplicateResourceAcrossPagesMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("startIndex") {
		case "1":
			writeJSON(t, writer, map[string]any{"totalResults": 3, "startIndex": 1, "itemsPerPage": 2,
				"Resources": []map[string]any{{"id": "1", "active": true}, {"id": "2", "active": true}}})
		case "3":
			// Repeats id "2" from the prior page instead of a genuinely new identity.
			writeJSON(t, writer, map[string]any{"totalResults": 3, "startIndex": 3, "itemsPerPage": 1,
				"Resources": []map[string]any{{"id": "2", "active": true}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.ResourcesReturnedCount != 2 {
		t.Fatalf("a resource id repeated across pages must be excluded from the duplicate count and mark the walk incomplete: %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersSAMLSSOIteratesOrganizations confirms
// "saml_sso" mode queries each configured organization's own SCIM endpoint
// and sums their results, distinct from the EMU enterprise-wide endpoint.
func TestFetchEnterpriseSCIMUsersSAMLSSOIteratesOrganizations(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "/organizations/org-a/Users"):
			writeJSON(t, writer, scimUsersPageResponse(2, 1, 1, 1))
		case strings.Contains(request.URL.Path, "/organizations/org-b/Users"):
			writeJSON(t, writer, scimUsersPageResponse(3, 1, 2, 1))
		default:
			t.Errorf("unexpected SCIM path for saml_sso mode (must be per-organization, not enterprise-wide): %s", request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "saml_sso", Cloud,
		[]string{"org-a", "org-b"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.TotalResultsReported == nil || *result.TotalResultsReported != 5 ||
		result.ResourcesReturnedCount != 5 || result.ActiveCount != 3 || result.InactiveCount != 2 {
		t.Fatalf("expected the sum across both organizations (5 resources, 3 active/2 inactive): %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersSAMLSSOPartialTotalNotReportedAsComplete
// confirms that when only some configured organizations disclose their own
// totalResults, the cross-organization sum is never reported as if it were
// the complete enterprise-wide total.
func TestFetchEnterpriseSCIMUsersSAMLSSOPartialTotalNotReportedAsComplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.Contains(request.URL.Path, "/organizations/org-a/Users"):
			writeJSON(t, writer, scimUsersPageResponse(2, 1, 2, 0))
		case strings.Contains(request.URL.Path, "/organizations/org-b/Users"):
			// org-b never discloses totalResults at all.
			writeJSON(t, writer, map[string]any{"startIndex": 1, "itemsPerPage": 1,
				"Resources": []map[string]any{{"id": "b1", "active": true}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "saml_sso", Cloud,
		[]string{"org-a", "org-b"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.TotalResultsReported != nil {
		t.Fatalf("a sum over only the organizations that disclosed their own total must never be reported as the complete enterprise total: %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersMissingActiveFieldMarksIncomplete confirms a
// resource missing the documented `active` field is counted in neither
// bucket and downgrades the whole walk, never assumed active.
func TestFetchEnterpriseSCIMUsersMissingActiveFieldMarksIncomplete(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"totalResults": 1, "startIndex": 1, "itemsPerPage": 1,
			"Resources": []map[string]any{{"userName": "mystery-user"}}})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.ActiveCount != 0 || result.InactiveCount != 0 {
		t.Fatalf("a resource missing its documented active field must not be assumed active or inactive: %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersGHESUsesApplianceWideEndpoint confirms "ghes"
// mode queries the documented appliance-wide scim/v2/Users relative path --
// no "enterprises/{enterprise}/" or organization path segment, confirmed
// via GitHub's own GHES SCIM documentation -- and is gated to Server
// deployments only.
func TestFetchEnterpriseSCIMUsersGHESUsesApplianceWideEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/scim/v2/Users" {
			t.Errorf("expected the documented appliance-wide relative path with no enterprise/organization segment, got %s", request.URL.Path)
		}
		writeJSON(t, writer, map[string]any{"totalResults": 1, "startIndex": 1, "itemsPerPage": 1,
			"Resources": []map[string]any{{"id": "1", "active": true}}})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "ghes", Server, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ActiveCount != 1 {
		t.Fatalf("unexpected GHES SCIM result: %+v", result)
	}
}

// TestFetchEnterpriseSCIMUsersGHESRejectedForCloudDeployment confirms
// scim_mode "ghes" is refused (zero requests) for a Cloud deployment,
// matching main's review requirement to explicitly reject rather than
// guess when a SCIM mode and Deployment disagree.
func TestFetchEnterpriseSCIMUsersGHESRejectedForCloudDeployment(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "ghes", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 || result.Complete || outcomes[0].Status != NotRun {
		t.Fatalf("scim_mode ghes must be rejected (zero requests) for a Cloud deployment: %+v / %+v", result, outcomes)
	}
}

// TestFetchEnterpriseSCIMUsersSAMLSSORejectedForServerDeployment confirms
// scim_mode "saml_sso" (Cloud-only, non-EMU) is refused for a Server
// deployment rather than silently routed to the wrong endpoint shape.
func TestFetchEnterpriseSCIMUsersSAMLSSORejectedForServerDeployment(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "saml_sso", Server, []string{"org-a"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 || result.Complete || outcomes[0].Status != NotRun {
		t.Fatalf("scim_mode saml_sso must be rejected (zero requests) for a Server deployment: %+v / %+v", result, outcomes)
	}
}

// ===== run-loop wiring (main's reported blocking defect) =====

// TestRunVerticalSliceWiresSAMLSSOSCIMWithoutEnterpriseSlug is a permanent
// regression test for the exact blocking wiring defect this round fixed:
// FetchEnterpriseSCIMUsers was called only inside vertical_slice.go's
// `if target.Enterprise != ""` block, so a legitimate "saml_sso" (Cloud,
// organization-scoped, no enterprise slug needed) configuration never ran
// at all despite ent.scim_users being a registered, run-wired collector
// ID. This exercises the actual runVerticalSliceWithStore run loop, not
// just the Fetch function directly, so the wiring itself is proven, not
// only the function's own behavior in isolation.
func TestRunVerticalSliceWiresSAMLSSOSCIMWithoutEnterpriseSlug(t *testing.T) {
	restServer := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	restClient := scimFixtureClient(t, restServer, budget, SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)

	target := Target{
		Host: restClient.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}, SCIMMode: "saml_sso",
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), restClient.profile, config, []Target{target}, store, SystemClock{},
		func(_ Target, _ EvidenceSource) (*CollectionClient, error) { return restClient, nil })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, outcome := range report.Outcomes {
		if outcome.CollectorID == "ent.scim_users" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ent.scim_users to actually run for a saml_sso target with no enterprise slug configured, not be silently skipped")
	}
	if len(report.Targets) != 1 || report.Targets[0].EnterpriseSCIMUsers == nil || report.Targets[0].EnterpriseSCIMUsers.Mode != "saml_sso" {
		t.Fatalf("expected the target result to carry a populated saml_sso SCIM result: %+v", report.Targets)
	}
}

// TestRunVerticalSliceWiresGHESSCIMWithoutEnterpriseSlug is the Server-
// deployment counterpart: "ghes" mode (appliance-wide, no enterprise or
// organization path segment at all) must also actually run when no
// enterprise slug is configured for the target.
func TestRunVerticalSliceWiresGHESSCIMWithoutEnterpriseSlug(t *testing.T) {
	restServer := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	restClient := scimFixtureClient(t, restServer, budget, SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)

	target := Target{
		Host: restClient.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}, SCIMMode: "ghes",
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\ndeployment: ghes\nghes_host: " + restClient.base.Hostname() + "\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), restClient.profile, config, []Target{target}, store, SystemClock{},
		func(_ Target, _ EvidenceSource) (*CollectionClient, error) { return restClient, nil })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, outcome := range report.Outcomes {
		if outcome.CollectorID == "ent.scim_users" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ent.scim_users to actually run for a ghes target with no enterprise slug configured, not be silently skipped")
	}
	if len(report.Targets) != 1 || report.Targets[0].EnterpriseSCIMUsers == nil || report.Targets[0].EnterpriseSCIMUsers.Mode != "ghes" {
		t.Fatalf("expected the target result to carry a populated ghes SCIM result: %+v", report.Targets)
	}
}
