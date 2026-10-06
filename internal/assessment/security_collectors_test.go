// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fullyEligibleFeatureSignals builds a featureSignals map (the shape
// FetchOrgCodeSecurityConfigurations expects from accumulator.
// featureSignalsByFullName) where every named repository is CONFIRMED
// eligible for both CodeQL and dependency features -- the uniform
// "requires all four features" policy these fixtures were originally
// written against, before per-repository feature-specific eligibility was
// introduced. Tests that specifically exercise the narrower,
// eligibility-derived policy build their own signals map instead.
func fullyEligibleFeatureSignals(fullNames ...string) map[string]RepositoryFeatureSignal {
	signals := make(map[string]RepositoryFeatureSignal, len(fullNames))
	for _, fullName := range fullNames {
		signals[fullName] = RepositoryFeatureSignal{
			FullName: fullName, CodeQLEligibleKnown: true, CodeQLEligible: true,
			DependencyEligibleKnown: true, DependencyEligible: true,
		}
	}
	return signals
}

// TestFetchOrgDependabotAlertsOpenAndClosedLifecycles exercises the open and
// closed (fixed/dismissed/auto_dismissed) state fetches, confirms both are
// folded into one observation set and confirms a dismissed alert is
// preserved (for population completeness) even though the published
// AlertLifecycleMetrics helper excludes dismissals from MTTR.
func TestFetchOrgDependabotAlertsOpenAndClosedLifecycles(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	fixedAt := created.Add(48 * time.Hour)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("state") {
		case "open":
			writeJSON(t, writer, []map[string]any{
				{"number": 1, "state": "open", "created_at": created.Format(time.RFC3339),
					"security_advisory": map[string]any{"severity": "high"}},
			})
		case "fixed,dismissed,auto_dismissed":
			writeJSON(t, writer, []map[string]any{
				{"number": 2, "state": "fixed", "created_at": created.Format(time.RFC3339), "fixed_at": fixedAt.Format(time.RFC3339)},
				{"number": 3, "state": "dismissed", "created_at": created.Format(time.RFC3339), "dismissed_reason": "tolerable_risk"},
			})
		default:
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgDependabotAlerts(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || !result.Complete || len(result.Observations) != 3 {
		t.Fatalf("expected 3 pooled observations from 2 complete state fetches: %+v", result)
	}

	metrics, err := AlertLifecycleMetrics(result.Observations, created.Add(-180*24*time.Hour), created.Add(72*time.Hour), result.Complete)
	if err != nil {
		t.Fatal(err)
	}
	if metrics["mttr_days"].Status != MetricKnown || metrics["mttr_days"].Number == nil || *metrics["mttr_days"].Number != 2 {
		t.Fatalf("expected MTTR computed only from the fixed alert (2 days), dismissals excluded: %+v", metrics["mttr_days"])
	}
	if metrics["median_open_alert_age_days"].Status != MetricKnown {
		t.Fatalf("expected a known open-alert age from the one open alert: %+v", metrics["median_open_alert_age_days"])
	}
}

// TestFetchOrgDependabotAlertsFullPaginationAcrossOrganizationsNoDoubleCount
// uses only synthetic fixture data (no real tenant organization names,
// reports or tokens appear anywhere in this test) to confirm this package's
// alert collection and pooling do not repeat two previously observed
// external failure modes: silently truncating a large alert population at
// a single ~100-item page, and inconsistently mixing enterprise- and
// organization-scoped aggregation so the same alerts are counted more than
// once (or an incomplete organization's gap is masked as a clean figure).
// Organization A alone has 400 alerts spread across 5 actually-fetched
// pages (3 open including 7 critical + 200 high + 13 low, 2 closed/fixed
// including 50 critical-severity fixes); organization B has a clean 17
// open alerts but an induced failure on its closed-alert page, which must
// propagate as an explicit incomplete/unknown result, never a lower-bound
// number presented as clean.
func TestFetchOrgDependabotAlertsFullPaginationAcrossOrganizationsNoDoubleCount(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	fixedAt := created.Add(24 * time.Hour)

	openSeverities := make([]string, 0, 220)
	for i := 0; i < 7; i++ {
		openSeverities = append(openSeverities, "critical")
	}
	for i := 0; i < 200; i++ {
		openSeverities = append(openSeverities, "high")
	}
	for i := 0; i < 13; i++ {
		openSeverities = append(openSeverities, "low")
	}
	const closedTotal = 180
	const closedCriticalCount = 50

	const pageSize = 100
	var orgBClosedAttempts int
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		page := 1
		if value := query.Get("page"); value != "" {
			if parsed, convErr := strconv.Atoi(value); convErr == nil {
				page = parsed
			}
		}
		writePage := func(total int, build func(index int) map[string]any) {
			start := (page - 1) * pageSize
			end := min(start+pageSize, total)
			if start > total {
				start, end = total, total
			}
			if end < total {
				next := *request.URL
				nextQuery := next.Query()
				nextQuery.Set("page", strconv.Itoa(page+1))
				next.RawQuery = nextQuery.Encode()
				writer.Header().Set("Link", "<"+server.URL+next.RequestURI()+">; rel=\"next\"")
			}
			items := make([]map[string]any, 0, end-start)
			for i := start; i < end; i++ {
				items = append(items, build(i))
			}
			writeJSON(t, writer, items)
		}
		switch {
		case request.URL.Path == "/orgs/synthetic-org-a/dependabot/alerts" && query.Get("state") == "open":
			writePage(len(openSeverities), func(i int) map[string]any {
				return map[string]any{
					"number": i + 1, "state": "open", "created_at": created.Format(time.RFC3339),
					"security_advisory": map[string]any{"severity": openSeverities[i]},
				}
			})
		case request.URL.Path == "/orgs/synthetic-org-a/dependabot/alerts" && query.Get("state") == "fixed,dismissed,auto_dismissed":
			writePage(closedTotal, func(i int) map[string]any {
				severity := "low"
				if i < closedCriticalCount {
					severity = "critical"
				}
				return map[string]any{
					"number": 1000 + i, "state": "fixed", "created_at": created.Format(time.RFC3339),
					"fixed_at": fixedAt.Format(time.RFC3339), "security_advisory": map[string]any{"severity": severity},
				}
			})
		case request.URL.Path == "/orgs/synthetic-org-b/dependabot/alerts" && query.Get("state") == "open":
			writePage(17, func(i int) map[string]any {
				return map[string]any{"number": i + 1, "state": "open", "created_at": created.Format(time.RFC3339)}
			})
		case request.URL.Path == "/orgs/synthetic-org-b/dependabot/alerts" && query.Get("state") == "fixed,dismissed,auto_dismissed":
			// Synthetic induced failure: this organization's closed-alert
			// collection always fails, simulating a genuinely incomplete
			// organization rather than an empty, clean one.
			orgBClosedAttempts++
			writer.WriteHeader(http.StatusInternalServerError)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scopeA := Scope{client.base.Hostname(), OrganizationScope, "synthetic-org-a"}
	scopeB := Scope{client.base.Hostname(), OrganizationScope, "synthetic-org-b"}

	resultA, outcomesA, err := FetchOrgDependabotAlerts(context.Background(), client, store, scopeA, "synthetic-org-a")
	if err != nil {
		t.Fatal(err)
	}
	if !resultA.Complete || len(resultA.Observations) != len(openSeverities)+closedTotal {
		t.Fatalf("expected a fully paginated %d-alert organization A population, got %d (complete=%v)",
			len(openSeverities)+closedTotal, len(resultA.Observations), resultA.Complete)
	}
	pagesSeen := 0
	for _, outcome := range outcomesA {
		pagesSeen += outcome.Pages
	}
	if pagesSeen < 5 {
		t.Fatalf("expected at least 5 actually-fetched pages (3 open + 2 closed) for organization A, got %d", pagesSeen)
	}

	resultB, _, err := FetchOrgDependabotAlerts(context.Background(), client, store, scopeB, "synthetic-org-b")
	if err != nil {
		t.Fatal(err)
	}
	if resultB.Complete {
		t.Fatal("organization B's induced closed-alert collection failure must mark the result incomplete, not clean")
	}
	if len(resultB.Observations) != 17 {
		t.Fatalf("organization B's successfully collected open alerts must still be preserved for audit: got %d", len(resultB.Observations))
	}
	if orgBClosedAttempts == 0 {
		t.Fatal("test fixture never actually attempted organization B's closed-alert page")
	}

	accumulator := newMetricAccumulator()
	accumulator.addDependabotAlerts(scopeA.Key(), resultA)
	accumulator.addDependabotAlerts(scopeB.Key(), resultB)

	if got := len(accumulator.dependabot.byOrganization[scopeA.Key()]); got != len(openSeverities)+closedTotal {
		t.Fatalf("organization A's own bucket must hold exactly its own %d alerts, got %d", len(openSeverities)+closedTotal, got)
	}
	if got := len(accumulator.dependabot.byOrganization[scopeB.Key()]); got != 17 {
		t.Fatalf("organization B's own bucket must hold exactly its own 17 alerts, got %d", got)
	}
	wantOverall := len(openSeverities) + closedTotal + 17
	if got := len(accumulator.dependabot.overall); got != wantOverall {
		t.Fatalf("the pooled run-wide bucket must equal the sum of both organizations' alerts exactly once each (%d), got %d -- "+
			"a higher count would indicate double counting (for example an enterprise-level and organization-level aggregation "+
			"of the same alerts), a lower count would indicate silent truncation", wantOverall, got)
	}
	if !accumulator.dependabot.overallIncomplete {
		t.Fatal("one incomplete organization must mark the pooled bucket incomplete, not a clean aggregate")
	}
	if !accumulator.dependabot.incompleteByOrg[scopeB.Key()] {
		t.Fatal("organization B specifically must be flagged incomplete")
	}
	if accumulator.dependabot.incompleteByOrg[scopeA.Key()] {
		t.Fatal("organization A's own completeness must not be downgraded by organization B's unrelated failure")
	}

	metrics := map[string]Metric{}
	if err := accumulator.populateAlertMetrics(metrics, created.Add(-180*24*time.Hour), created.Add(240*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if value := metrics["dependabot_alerts_mttr_days"].PerOrganization[scopeA.Key()]; value.Status != MetricKnown {
		t.Fatalf("organization A's own MTTR must remain known despite organization B's unrelated failure: %+v", value)
	}
	if value := metrics["dependabot_alerts_mttr_days"].PerOrganization[scopeB.Key()]; value.Status != MetricUnavailable {
		t.Fatalf("organization B's incomplete MTTR must be explicitly unavailable, not a false clean/zero value: %+v", value)
	}
	if metrics["dependabot_alerts_mttr_days"].Overall.Status != MetricUnavailable {
		t.Fatalf("the pooled run-wide MTTR must be unavailable, not a clean figure silently computed over an incomplete "+
			"contributor: %+v", metrics["dependabot_alerts_mttr_days"].Overall)
	}
	// SEC-003's exact declared severity-filtered MTTR key, isolated to
	// organization A, must reflect only its own 50 critical-severity fixed
	// alerts (never organization B's, and never diluted by the 13 low-severity
	// open alerts, which carry no eligible fix).
	severityPerOrgA := metrics["dependabot_mttr_days_crit_high"].PerOrganization[scopeA.Key()]
	if severityPerOrgA.Status != MetricKnown || severityPerOrgA.Number == nil || *severityPerOrgA.Number != 1 {
		t.Fatalf("organization A's severity-filtered MTTR must be known and computed only from its 50 critical fixes (1 day each): %+v",
			severityPerOrgA)
	}
}

// TestFetchOrgSecretScanningAlertsResolutionTaxonomyAndRedaction confirms the
// open/resolved state mapping, that revoked/false_positive/unknown
// resolutions are distinguished per the published helper's contract, and
// that the literal secret value is never present in persisted evidence
// despite appearing in the raw upstream response.
func TestFetchOrgSecretScanningAlertsResolutionTaxonomyAndRedaction(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	resolvedAt := created.Add(24 * time.Hour)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("hide_secret") != "true" {
			t.Error("secret-scanning request must set hide_secret=true")
		}
		switch request.URL.Query().Get("state") {
		case "open":
			writeJSON(t, writer, []map[string]any{
				{"number": 1, "state": "open", "secret": "dummy-sensitive-value", "secret_type": "generic",
					"created_at": created.Format(time.RFC3339)},
			})
		case "resolved":
			writeJSON(t, writer, []map[string]any{
				{"number": 2, "state": "resolved", "resolution": "revoked", "secret": "dummy-sensitive-value",
					"created_at": created.Format(time.RFC3339), "resolved_at": resolvedAt.Format(time.RFC3339)},
				{"number": 3, "state": "resolved", "resolution": "false_positive", "secret": "dummy-sensitive-value",
					"created_at": created.Format(time.RFC3339), "resolved_at": resolvedAt.Format(time.RFC3339)},
				{"number": 4, "state": "resolved", "resolution": "pattern_edited", "secret": "dummy-sensitive-value",
					"created_at": created.Format(time.RFC3339), "resolved_at": resolvedAt.Format(time.RFC3339)},
			})
		default:
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgSecretScanningAlerts(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Observations) != 4 {
		t.Fatalf("expected 4 pooled observations: %+v", result)
	}
	if walkErr := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(raw), "dummy-sensitive-value") {
			t.Fatalf("the literal secret value must never survive sanitization: %s", path)
		}
		return nil
	}); walkErr != nil {
		t.Fatal(walkErr)
	}

	metrics, err := AlertLifecycleMetrics(result.Observations, created.Add(-180*24*time.Hour), created.Add(72*time.Hour), result.Complete)
	if err != nil {
		t.Fatal(err)
	}
	// Only the "revoked" resolution counts as fixed; "false_positive" is
	// excluded from MTTR; "pattern_edited" is an unknown/unsupported
	// resolution for this helper's contract and must make the whole MTTR
	// metric unavailable rather than silently dropped or counted.
	if metrics["mttr_days"].Status != MetricUnavailable {
		t.Fatalf("an unrecognized resolution (pattern_edited) must make MTTR unavailable, not silently excluded: %+v", metrics["mttr_days"])
	}
}

// TestFetchOrgCodeScanningAlertsThreeStatesPooled confirms open, dismissed
// and fixed states are each fetched and pooled into one observation set.
func TestFetchOrgCodeScanningAlertsThreeStatesPooled(t *testing.T) {
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := request.URL.Query().Get("state")
		switch state {
		case "open":
			writeJSON(t, writer, []map[string]any{{"number": 1, "state": "open", "created_at": created.Format(time.RFC3339),
				"rule": map[string]any{"security_severity_level": "critical"}}})
		case "dismissed":
			writeJSON(t, writer, []map[string]any{{"number": 2, "state": "dismissed", "created_at": created.Format(time.RFC3339),
				"dismissed_reason": "won't fix"}})
		case "fixed":
			writeJSON(t, writer, []map[string]any{{"number": 3, "state": "fixed", "created_at": created.Format(time.RFC3339),
				"fixed_at": created.Add(24 * time.Hour).Format(time.RFC3339)}})
		default:
			writer.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgCodeScanningAlerts(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 3 || !result.Complete || len(result.Observations) != 3 {
		t.Fatalf("expected 3 pooled observations from 3 state fetches: %+v", result)
	}
}

// TestFetchOrgCodeSecurityConfigurationsHostQualifiedIDsAndUnknownAttachment
// confirms configuration IDs are matched per host (the same numeric ID on
// two different hosts must not collide) and that a non-final attachment
// status (still "updating") leaves coverage unavailable rather than
// assuming disabled.
func TestFetchOrgCodeSecurityConfigurationsHostQualifiedIDsAndUnknownAttachment(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/code-security/configurations":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "target_type": "organization", "enforcement": "enforced",
					"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled",
					"dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
				{"id": 2, "target_type": "organization", "enforcement": "unenforced",
					"secret_scanning": "disabled", "secret_scanning_push_protection": "disabled",
					"dependabot_alerts": "disabled", "code_scanning_default_setup": "disabled"},
			})
		case "/orgs/fixture-org/code-security/configurations/defaults":
			writeJSON(t, writer, []map[string]any{})
		case "/orgs/fixture-org/code-security/configurations/1/repositories":
			writeJSON(t, writer, []map[string]any{
				{"status": "enforced", "repository": map[string]any{"full_name": "fixture-org/repo-001"}},
			})
		case "/orgs/fixture-org/code-security/configurations/2/repositories":
			writeJSON(t, writer, []map[string]any{
				// Still transitioning; must not be assumed disabled.
				{"status": "updating", "repository": map[string]any{"full_name": "fixture-org/repo-002"}},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	metric, _, err := FetchOrgCodeSecurityConfigurations(context.Background(), client, store, scope, "fixture-org",
		[]string{"fixture-org/repo-001", "fixture-org/repo-002"},
		fullyEligibleFeatureSignals("fixture-org/repo-001", "fixture-org/repo-002"))
	if err != nil {
		t.Fatal(err)
	}
	if metric.Status != MetricUnavailable {
		t.Fatalf("an in-flight (updating) attachment must leave coverage unavailable, not assumed disabled: %+v", metric)
	}
}

// TestFetchOrgCodeSecurityConfigurationsFullFeatureOnly confirms a repository
// attached to a configuration where only some required features are enabled
// does not count toward the numerator (every required feature must be
// enabled, not merely "attached").
func TestFetchOrgCodeSecurityConfigurationsFullFeatureOnly(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/code-security/configurations":
			writeJSON(t, writer, []map[string]any{
				{"id": 9, "target_type": "organization", "enforcement": "enforced",
					"secret_scanning": "enabled", "secret_scanning_push_protection": "disabled",
					"dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
			})
		case "/orgs/fixture-org/code-security/configurations/defaults":
			writeJSON(t, writer, []map[string]any{})
		case "/orgs/fixture-org/code-security/configurations/9/repositories":
			writeJSON(t, writer, []map[string]any{
				{"status": "attached", "repository": map[string]any{"full_name": "fixture-org/repo-001"}},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	metric, _, err := FetchOrgCodeSecurityConfigurations(context.Background(), client, store, scope, "fixture-org",
		[]string{"fixture-org/repo-001"}, fullyEligibleFeatureSignals("fixture-org/repo-001"))
	if err != nil {
		t.Fatal(err)
	}
	if metric.Status != MetricKnown || metric.Number == nil || *metric.Number != 0 {
		t.Fatalf("partial feature enablement (push protection disabled) must not count toward full coverage: %+v", metric)
	}
}

// TestFetchOrgCodeSecurityConfigurationsNarrowsRequiredFeaturesPerRepositoryEligibility
// proves the collector-level wiring (not merely the lower-level
// SecurityConfigurationCoverage helper in isolation) actually threads each
// repository's own CodeQL/dependency eligibility signal into its
// required-feature policy: a repository CONFIRMED non-eligible for CodeQL
// (so code_scanning_default_setup is not demanded of it) still counts as
// fully covered despite that one feature being disabled on its attached
// configuration, while a repository this run never analyzed at all (absent
// from featureSignals) leaves the WHOLE metric unavailable rather than
// silently defaulting to "fully eligible, fully required".
func TestFetchOrgCodeSecurityConfigurationsNarrowsRequiredFeaturesPerRepositoryEligibility(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/code-security/configurations":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "target_type": "organization", "enforcement": "enforced",
					"secret_scanning": "enabled", "secret_scanning_push_protection": "enabled",
					"dependabot_alerts": "enabled", "code_scanning_default_setup": "disabled"},
			})
		case "/orgs/fixture-org/code-security/configurations/defaults":
			writeJSON(t, writer, []map[string]any{})
		case "/orgs/fixture-org/code-security/configurations/1/repositories":
			writeJSON(t, writer, []map[string]any{
				{"status": "attached", "repository": map[string]any{"full_name": "fixture-org/repo-codeql-ineligible"}},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	// (1) A repository CONFIRMED CodeQL-ineligible (no supported language)
	// but dependency-eligible is judged only against the features it could
	// plausibly carry; code_scanning_default_setup being disabled must not
	// count against it.
	signals := map[string]RepositoryFeatureSignal{
		"fixture-org/repo-codeql-ineligible": {
			FullName: "fixture-org/repo-codeql-ineligible", CodeQLEligibleKnown: true, CodeQLEligible: false,
			DependencyEligibleKnown: true, DependencyEligible: true,
		},
	}
	metric, _, err := FetchOrgCodeSecurityConfigurations(context.Background(), client, evidenceFixtureStore(t, t.TempDir(), nil),
		scope, "fixture-org", []string{"fixture-org/repo-codeql-ineligible"}, signals)
	if err != nil {
		t.Fatal(err)
	}
	if metric.Status != MetricKnown || metric.Number == nil || *metric.Number != 100 {
		t.Fatalf("a CodeQL-ineligible repository must not need code_scanning_default_setup to count as fully covered: %+v", metric)
	}

	// (2) A repository this run never analyzed (absent from featureSignals
	// entirely) must leave the whole metric unavailable, never silently
	// treated as fully eligible/fully required.
	metric, _, err = FetchOrgCodeSecurityConfigurations(context.Background(), client, evidenceFixtureStore(t, t.TempDir(), nil),
		scope, "fixture-org", []string{"fixture-org/repo-codeql-ineligible", "fixture-org/repo-never-analyzed"}, signals)
	if err != nil {
		t.Fatal(err)
	}
	if metric.Status != MetricUnavailable {
		t.Fatalf("a repository absent from featureSignals must not be treated as confidently eligible: %+v", metric)
	}

	// (3) A repository with an unresolved (not known either way) CodeQL
	// eligibility signal also leaves the whole metric unavailable -- never
	// silently narrowed to "feature not required" just because this run
	// could not confirm eligibility.
	signals["fixture-org/repo-unresolved"] = RepositoryFeatureSignal{
		FullName: "fixture-org/repo-unresolved", CodeQLEligibleKnown: false,
		DependencyEligibleKnown: true, DependencyEligible: true,
	}
	metric, _, err = FetchOrgCodeSecurityConfigurations(context.Background(), client, evidenceFixtureStore(t, t.TempDir(), nil),
		scope, "fixture-org", []string{"fixture-org/repo-codeql-ineligible", "fixture-org/repo-unresolved"}, signals)
	if err != nil {
		t.Fatal(err)
	}
	if metric.Status != MetricUnavailable {
		t.Fatalf("a repository with unresolved CodeQL eligibility must not be treated as confidently eligible: %+v", metric)
	}
}

// TestFetchOrgCodeSecurityConfigurationsMissingFieldsCannotBecomeKnownZero
// confirms three distinct malformed-response shapes are never silently
// excluded as if they simply did not exist: a configuration entry missing
// its own ID, a configuration entry missing (or carrying an unrecognized)
// enforcement value, and an attachment entry missing its own repository
// identity. Each must mark the whole result unavailable (never a
// known-clean 0%/100%), while a genuinely complete, fully-populated
// positive case still reports a confident 100%.
func TestFetchOrgCodeSecurityConfigurationsMissingFieldsCannotBecomeKnownZero(t *testing.T) {
	for _, test := range []struct {
		name        string
		config      map[string]any
		attachments []map[string]any
		wantKnown   bool
	}{
		{
			name: "complete positive", wantKnown: true,
			config: map[string]any{"id": 1, "enforcement": "enforced", "secret_scanning": "enabled",
				"secret_scanning_push_protection": "enabled", "dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
			attachments: []map[string]any{{"repository": map[string]any{"full_name": "fixture-org/repo"}, "status": "attached"}},
		},
		{
			name: "missing enforcement",
			config: map[string]any{"id": 1, "secret_scanning": "enabled", "secret_scanning_push_protection": "enabled",
				"dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
			attachments: []map[string]any{{"repository": map[string]any{"full_name": "fixture-org/repo"}, "status": "attached"}},
		},
		{
			name: "missing configuration identity", config: map[string]any{"name": "unknown-id"},
			attachments: []map[string]any{},
		},
		{
			name: "missing attachment repository",
			config: map[string]any{"id": 1, "enforcement": "enforced", "secret_scanning": "enabled",
				"secret_scanning_push_protection": "enabled", "dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
			attachments: []map[string]any{{"repository": nil, "status": "attached"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/orgs/fixture-org/code-security/configurations":
					writeJSON(t, writer, []map[string]any{test.config})
				case "/orgs/fixture-org/code-security/configurations/defaults":
					writeJSON(t, writer, []map[string]any{})
				case "/orgs/fixture-org/code-security/configurations/1/repositories":
					writeJSON(t, writer, test.attachments)
				default:
					writer.WriteHeader(http.StatusNotFound)
					writeJSON(t, writer, map[string]string{"message": "not found"})
				}
			}))
			t.Cleanup(server.Close)
			client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
			scope := Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "fixture-org"}
			metric, _, err := FetchOrgCodeSecurityConfigurations(context.Background(), client, evidenceFixtureStore(t, t.TempDir(), nil),
				scope, "fixture-org", []string{"fixture-org/repo"}, fullyEligibleFeatureSignals("fixture-org/repo"))
			if test.wantKnown {
				if err != nil || metric.Status != MetricKnown || metric.Number == nil || *metric.Number != 100 {
					t.Fatalf("genuine attached/enforced full configuration did not report 100%%: %+v err=%v", metric, err)
				}
				if len(metric.EvidenceRefs) == 0 {
					t.Fatalf("a genuine known result must retain its observed evidence refs, not report them empty: %+v", metric)
				}
				return
			}
			if err == nil && metric.Status == MetricKnown {
				t.Fatalf("missing required configuration/attachment facts became a known clean-looking zero: %+v", metric)
			}
		})
	}
}

// TestFetchRepositoryCodeScanningDefaultSetupUnknownOnConcealedResponse
// confirms a forbidden/concealed default-setup probe reports unknown
// (nil), never a false "disabled".
func TestFetchRepositoryCodeScanningDefaultSetupUnknownOnConcealedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		writeJSON(t, writer, map[string]string{"message": "must have admin rights"})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	configured, outcome, err := FetchRepositoryCodeScanningDefaultSetup(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if configured != nil {
		t.Fatalf("a forbidden probe must report unknown enablement, not a value: %v", *configured)
	}
	if outcome.Availability != MissingPermission {
		t.Fatalf("expected the outcome to disclose the forbidden access: %+v", outcome)
	}
}

// TestFetchRepositoryContentsProbeRecursiveTreeFindsNestedManifests confirms
// manifest detection walks the full recursive tree (not root-only) and
// correctly parses .github/dependabot.yml for grouped version updates and a
// github-actions ecosystem entry.
func TestFetchRepositoryContentsProbeRecursiveTreeFindsNestedManifests(t *testing.T) {
	dependabotYAML := "version: 2\nupdates:\n  - package-ecosystem: \"npm\"\n    directory: \"/\"\n    schedule:\n      interval: \"weekly\"\n    groups:\n      dev-dependencies:\n        patterns: [\"*\"]\n  - package-ecosystem: \"github-actions\"\n    directory: \"/\"\n    schedule:\n      interval: \"weekly\"\n"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/git/trees/main":
			writeJSON(t, writer, map[string]any{
				"sha": "abc", "truncated": false,
				"tree": []map[string]any{
					{"path": "README.md", "type": "blob"},
					{"path": "services/api/go.mod", "type": "blob"},
					{"path": "services/api/go.sum", "type": "blob"},
					{"path": "ui/package.json", "type": "blob"},
					{"path": "ui", "type": "tree"},
				},
			})
		case "/repos/fixture-org/widget/contents/.github/dependabot.yml":
			writeJSON(t, writer, map[string]any{
				"type": "file", "encoding": "base64", "name": "dependabot.yml",
				"content": base64.StdEncoding.EncodeToString([]byte(dependabotYAML)),
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, outcomes, err := FetchRepositoryContentsProbe(context.Background(), client, store, scope, "fixture-org", "widget", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || result.UsedRootOnlyFallback {
		t.Fatalf("expected the recursive tree path (no fallback): %+v %+v", result, outcomes)
	}
	if result.SupportedManifestCount != 3 {
		t.Fatalf("expected the nested manifests (go.mod, go.sum, package.json) found, not just root-level files: %+v", result.ManifestPaths)
	}
	if !result.DependabotConfigKnown || !result.HasGroupedVersionUpdate || !result.HasActionsEcosystem {
		t.Fatalf("expected dependabot.yml to be parsed with groups and a github-actions ecosystem entry: %+v", result)
	}
}

// TestFetchRepositoryContentsProbeTruncatedTreeFallsBackToRootOnly confirms a
// truncated recursive tree response is explicitly flagged, not silently
// presented as an exhaustive inventory.
func TestFetchRepositoryContentsProbeTruncatedTreeFallsBackToRootOnly(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/git/trees/main":
			writeJSON(t, writer, map[string]any{"sha": "abc", "truncated": true, "tree": []map[string]any{}})
		case "/repos/fixture-org/widget/contents":
			writeJSON(t, writer, []map[string]any{
				{"name": "go.mod", "type": "file"}, {"name": "README.md", "type": "file"},
			})
		case "/repos/fixture-org/widget/contents/.github/dependabot.yml":
			writer.WriteHeader(http.StatusNotFound)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryContentsProbe(context.Background(), client, store, scope, "fixture-org", "widget", "main")
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsedRootOnlyFallback || !result.Complete {
		t.Fatalf("expected a truncated tree to fall back to root-only, explicitly flagged: %+v", result)
	}
	if result.SupportedManifestCount != 1 {
		t.Fatalf("expected the root-level go.mod to be found: %+v", result.ManifestPaths)
	}
	if result.DependabotConfigFound || result.DependabotConfigKnown {
		t.Fatalf("a 404 on dependabot.yml must leave config-known false, not a confirmed absence used as a known 'no groups': %+v", result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesObservesCodeQLAcrossPaginatedHistory
// confirms the analyses list is fully paginated (two pages), a non-CodeQL
// tool entry is counted but does not mark CodeQLAnalysisObserved, and the
// most recent CodeQL analysis timestamp is the true maximum across both
// pages, not merely the first page's own maximum (the second, later page
// here carries the genuinely most recent CodeQL entry). Every entry
// carries an explicit empty "error" (a successful analysis) and a
// default-branch ref, within the [since, now) window.
func TestFetchRepositoryCodeScanningAnalysesObservesCodeQLAcrossPaginatedHistory(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	since, now := base.Add(-24*time.Hour), base.Add(168*time.Hour)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("page") == "2" {
			writeJSON(t, writer, []map[string]any{
				{"tool": map[string]any{"name": "CodeQL"}, "created_at": base.Add(72 * time.Hour).Format(time.RFC3339),
					"ref": "refs/heads/main", "error": ""},
			})
			return
		}
		writer.Header().Set("Link", "<"+server.URL+"/repos/fixture-org/widget/code-scanning/analyses?per_page=100&page=2>; rel=\"next\"")
		writeJSON(t, writer, []map[string]any{
			{"tool": map[string]any{"name": "CodeQL"}, "created_at": base.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
			{"tool": map[string]any{"name": "eslint-security"}, "created_at": base.Add(time.Hour).Format(time.RFC3339),
				"ref": "refs/heads/main", "error": ""},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, outcome, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main", since, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || !outcome.Complete {
		t.Fatalf("expected a fully valid two-page history to be complete: %+v / %+v", result, outcome)
	}
	if !result.CodeQLAnalysisObserved {
		t.Fatalf("expected a CodeQL tool entry to be observed: %+v", result)
	}
	if result.TotalAnalysesObserved != 3 {
		t.Fatalf("expected all 3 valid entries across both pages counted, not just one page: %+v", result)
	}
	wantMostRecent := base.Add(72 * time.Hour)
	if result.MostRecentCodeQLAnalysisAt == nil || !result.MostRecentCodeQLAnalysisAt.Equal(wantMostRecent) {
		t.Fatalf("expected the most recent CodeQL timestamp to be the true maximum across both pages (%s): %+v", wantMostRecent, result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesNoCodeQLToolPresent confirms a
// repository whose only configured scanning tool is not CodeQL correctly
// reports CodeQLAnalysisObserved false (not true merely because the
// endpoint itself returned analyses at all).
func TestFetchRepositoryCodeScanningAnalysesNoCodeQLToolPresent(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"tool": map[string]any{"name": "eslint-security"}, "created_at": created.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main",
		created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.CodeQLAnalysisObserved || result.MostRecentCodeQLAnalysisAt != nil {
		t.Fatalf("a non-CodeQL-only analyses history must not report CodeQL as observed: %+v", result)
	}
	if !result.Complete || result.TotalAnalysesObserved != 1 {
		t.Fatalf("expected the single valid non-CodeQL entry counted and complete: %+v", result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesMalformedEntryMarksIncomplete
// confirms an entry missing its documented tool.name, created_at, ref or
// error downgrades Complete (both the typed result and the
// CollectorOutcome, per markOutcomeIncomplete) rather than being silently
// dropped as if the endpoint had simply never returned it.
func TestFetchRepositoryCodeScanningAnalysesMalformedEntryMarksIncomplete(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"tool": map[string]any{"name": "CodeQL"}, "created_at": created.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
			{"tool": map[string]any{}, "created_at": created.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
			{"tool": map[string]any{"name": "CodeQL"}, "ref": "refs/heads/main", "error": ""},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, outcome, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main",
		created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatalf("expected malformed entries (missing tool.name / created_at) to mark the result incomplete: %+v", result)
	}
	if outcome.Complete || outcome.Reason == "" {
		t.Fatalf("expected the semantic failure to be disclosed on the outcome itself, not only the typed result: %+v", outcome)
	}
	if !result.CodeQLAnalysisObserved || result.TotalAnalysesObserved != 1 {
		t.Fatalf("expected the one well-formed CodeQL entry still counted despite the other malformed entries: %+v", result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesForbiddenLeavesUnknown confirms a
// 403 (GitHub Advanced Security not enabled, or the credential lacks
// security_events scope) leaves the result unknown (Complete false, zero
// observations) rather than a false "no analyses" -- matching
// FetchRepositoryCodeScanningDefaultSetup's own documented contract -- with
// the forbidden access disclosed on the outcome's Availability, and no Go
// error returned (a collection-layer failure is conveyed through the
// outcome/result, never propagated as a hard error for this collector).
func TestFetchRepositoryCodeScanningAnalysesForbiddenLeavesUnknown(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		writeJSON(t, writer, map[string]string{"message": "advanced security must be enabled for this repository"})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	result, outcome, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main",
		now.Add(-time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.CodeQLAnalysisObserved || result.TotalAnalysesObserved != 0 {
		t.Fatalf("a forbidden probe must report unknown status, not a false clean zero: %+v", result)
	}
	if outcome.Availability != MissingPermission {
		t.Fatalf("expected the outcome to disclose the forbidden access: %+v", outcome)
	}
}

// TestFetchRepositoryCodeScanningAnalysesErrorBearingEntryIsNotPositive
// migrates main's own reproduction overlay: a genuine-shaped CodeQL entry
// (correct tool, correct default-branch ref, a timestamp inside the window)
// whose documented "error" field is non-empty is an explicitly FAILED
// analysis attempt and must never establish CodeQLAnalysisObserved, no
// matter how otherwise well-formed the entry looks.
func TestFetchRepositoryCodeScanningAnalysesErrorBearingEntryIsNotPositive(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"id": 1, "tool": map[string]any{"name": "CodeQL"}, "ref": "refs/heads/main",
				"created_at": created.Format(time.RFC3339), "error": "analysis could not be processed", "results_count": 0},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main",
		created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.CodeQLAnalysisObserved {
		t.Fatalf("an explicitly failed CodeQL analysis cannot establish successful operational coverage: %+v", result)
	}
	if !result.Complete || result.TotalAnalysesObserved != 1 {
		t.Fatalf("a well-formed (if failed) entry is still a valid, complete, counted observation: %+v", result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesNonDefaultBranchRefIsNotPositive
// confirms a genuinely successful CodeQL analysis on a pull-request-only
// ref (or any ref other than the repository's own default branch) does not
// establish the default branch's own operational status.
func TestFetchRepositoryCodeScanningAnalysesNonDefaultBranchRefIsNotPositive(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"tool": map[string]any{"name": "CodeQL"}, "ref": "refs/pull/42/merge", "created_at": created.Format(time.RFC3339), "error": ""},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main",
		created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if result.CodeQLAnalysisObserved {
		t.Fatalf("a pull-request-only (non-default-branch) ref must not establish default-branch operational status: %+v", result)
	}
	if !result.Complete || result.TotalAnalysesObserved != 1 {
		t.Fatalf("the entry is still well-formed and counted, just not positive for this branch: %+v", result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesZeroResultsCountIsStillPositive
// confirms a genuine, successful (empty error) CodeQL analysis that simply
// found zero findings is still positive evidence -- a clean scan, not a
// failure -- matching the documented results_count field's own semantics.
func TestFetchRepositoryCodeScanningAnalysesZeroResultsCountIsStillPositive(t *testing.T) {
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"tool": map[string]any{"name": "CodeQL"}, "ref": "refs/heads/main", "created_at": created.Format(time.RFC3339),
				"error": "", "results_count": 0},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main",
		created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !result.CodeQLAnalysisObserved {
		t.Fatalf("a clean (zero-finding) successful analysis is still positive evidence of operational status: %+v", result)
	}
}

// TestFetchRepositoryCodeScanningAnalysesWindowExcludesOutOfRangeTimestamps
// confirms the [since, now) window is bound to the caller's explicit
// arguments, not a live wall-clock call: an entry dated before since and
// another dated at-or-after now are both excluded, while one genuinely
// inside the window is observed -- the same frozen-clock determinism every
// other lookback-windowed collector in this package already depends on for
// reproducible replay.
func TestFetchRepositoryCodeScanningAnalysesWindowExcludesOutOfRangeTimestamps(t *testing.T) {
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	now := since.Add(72 * time.Hour)
	tooOld := since.Add(-time.Minute)
	tooNew := now
	inWindow := since.Add(time.Hour)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"tool": map[string]any{"name": "CodeQL"}, "ref": "refs/heads/main", "created_at": tooOld.Format(time.RFC3339), "error": ""},
			{"tool": map[string]any{"name": "CodeQL"}, "ref": "refs/heads/main", "created_at": tooNew.Format(time.RFC3339), "error": ""},
			{"tool": map[string]any{"name": "CodeQL"}, "ref": "refs/heads/main", "created_at": inWindow.Format(time.RFC3339), "error": ""},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryCodeScanningAnalyses(context.Background(), client, store, scope, "fixture-org", "widget", "main", since, now)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CodeQLAnalysisObserved {
		t.Fatalf("expected the single genuinely in-window entry to be observed: %+v", result)
	}
	if result.MostRecentCodeQLAnalysisAt == nil || !result.MostRecentCodeQLAnalysisAt.Equal(inWindow) {
		t.Fatalf("expected the out-of-window entries (before since, at/after now) excluded from the most-recent determination: %+v", result)
	}
}

// TestFetchRepositoryCodeScanningDefaultSetupEmptyStateIsUnknown confirms an
// empty/omitted documented "state" field (neither of the three documented
// enum values) leaves enablement unknown rather than a false "not
// configured" -- the exact gap an empty-object {} response previously
// coerced into a confident false via GetState() == "" == "configured".
func TestFetchRepositoryCodeScanningDefaultSetupEmptyStateIsUnknown(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	configured, outcome, err := FetchRepositoryCodeScanningDefaultSetup(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if configured != nil {
		t.Fatalf("an empty/omitted state field must report unknown enablement, not a value: %v", *configured)
	}
	if outcome.Complete || outcome.Reason == "" {
		t.Fatalf("expected the semantic gap to be disclosed on the outcome: %+v", outcome)
	}
}

// TestFetchRepositoryCodeScanningDefaultSetupNotAvailableIsKnownFalse
// confirms the documented "not-available" state value (distinct from
// "not-configured") is still a confident, known false -- not conflated with
// the empty/unrecognized-value unknown case above.
func TestFetchRepositoryCodeScanningDefaultSetupNotAvailableIsKnownFalse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"state": "not-available"})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	configured, _, err := FetchRepositoryCodeScanningDefaultSetup(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if configured == nil || *configured {
		t.Fatalf("\"not-available\" is a documented, confident false, not unknown: %v", configured)
	}
}
