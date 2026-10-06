// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func outputFixtureReport(t *testing.T) *VerticalSliceReport {
	t.Helper()
	sha := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	return fixtureReport(fixtureOrganization("acme", nil,
		&CriticalPopulationResult{Method: "custom-property", FullNames: []string{"acme/critical"}},
		fixtureRepoResult("acme/critical", fixtureEffectiveProtection(true, true, true, CollectionOK),
			[]ActionReference{
				{Category: "third-party", Owner: "thirdparty", ActionRepo: "action", PinStatus: "sha-pinned", Ref: sha},
				{Category: "github-owned", Owner: "actions", ActionRepo: "checkout", PinStatus: "sha-pinned", Ref: sha},
			}, nil, RepositoryFeatureSignal{DependencyEligible: true, DependencyEligibleKnown: true, DependencyOperational: true, DependencyOperationalKnown: true}),
		fixtureRepoResult("acme/plain", fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}),
	))
}

func TestRunOfflineEvaluationWritesAllRequiredFiles(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := outputFixtureReport(t)
	outputDirectory := t.TempDir()

	summary, err := RunOfflineEvaluation(profile, report, config, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ControlCount != 456 {
		t.Fatalf("expected exactly 456 evaluated controls, got %d", summary.ControlCount)
	}
	if summary.MetricKeyCount != 581 {
		t.Fatalf("expected exactly 581 catalogued metric keys, got %d", summary.MetricKeyCount)
	}

	for _, name := range EvaluationOutputFileNames() {
		path := filepath.Join(outputDirectory, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("required output file %s was not written: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("required output file %s is empty", name)
		}
	}

	resultsCSV, err := os.ReadFile(filepath.Join(outputDirectory, ResultsFileName))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(resultsCSV))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 457 || len(rows[0]) != 10 {
		t.Fatalf("results.csv must have exactly 456 exact-ID rows plus header with 10 columns: %d rows, %d cols", len(rows), len(rows[0]))
	}

	workbookCSV, err := os.ReadFile(filepath.Join(outputDirectory, WorkbookUpdateFileName))
	if err != nil {
		t.Fatal(err)
	}
	workbookRows, err := csv.NewReader(strings.NewReader(string(workbookCSV))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(workbookRows)-1 != 259 {
		t.Fatalf("workbook-update.csv must have exactly 259 non-Manual rows (456-197), got %d", len(workbookRows)-1)
	}

	guide, err := os.ReadFile(filepath.Join(outputDirectory, InterviewGuideFileName))
	if err != nil {
		t.Fatal(err)
	}
	questionCount := 0
	for _, control := range profile.Controls {
		if control.RequiresInterview() {
			questionCount++
		}
	}
	if questionCount != 307 {
		t.Fatalf("expected 307 interview-requiring controls (197 Manual + 109 Partial + PRD-041), got %d", questionCount)
	}
	entries := strings.Count(string(guide), "**"+"ARC-")
	_ = entries // guide content is exercised in exports_test.go; this test asserts the file was actually produced below.
	if len(guide) == 0 {
		t.Fatal("interview-guide.md must not be empty")
	}

	metricsJSON, err := os.ReadFile(filepath.Join(outputDirectory, MetricsFileName))
	if err != nil {
		t.Fatal(err)
	}
	var metrics map[string]Metric
	if err := json.Unmarshal(metricsJSON, &metrics); err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 581 {
		t.Fatalf("metrics.json must contain exactly 581 declared keys, got %d", len(metrics))
	}
	protectionMetric, ok := metrics["repos_with_default_branch_protection_pct"]
	if !ok || protectionMetric.Overall.Status != MetricKnown {
		t.Fatalf("metrics.json must carry ARC-005/GOV-001's genuinely measured value, not a placeholder: %+v", protectionMetric)
	}

	feasibilityJSON, err := os.ReadFile(filepath.Join(outputDirectory, FeasibilityFileName))
	if err != nil {
		t.Fatal(err)
	}
	var feasibility EvaluationFeasibility
	if err := json.Unmarshal(feasibilityJSON, &feasibility); err != nil {
		t.Fatal(err)
	}
	if len(feasibility.Collectors) != 67 {
		t.Fatalf("feasibility.json must report all 67 catalogue collectors, got %d", len(feasibility.Collectors))
	}

	// Evidence paths used by evaluators must never be redacted away by the
	// JSON redaction boundary (they are plain evidence-store object paths,
	// not sensitive data).
	if !strings.Contains(string(metricsJSON), "acme") {
		t.Fatal("metrics.json evidence references were unexpectedly redacted")
	}
}

func TestRunOfflineEvaluationRejectsEmptyOutputDirectory(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	if _, err := RunOfflineEvaluation(profile, outputFixtureReport(t), config, ""); err == nil {
		t.Fatal("empty output directory must be rejected")
	}
}

// TestRunOfflineEvaluationSummaryRetainsCollectionFailures guards against a
// regression where writeExportArtifacts passed a fresh nil outcomes slice to
// RenderAssessmentSummary instead of the run's real report.Outcomes, silently
// dropping genuine collection failures (e.g. a permission-denied
// organization) from summary.md.
func TestRunOfflineEvaluationSummaryRetainsCollectionFailures(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := outputFixtureReport(t)
	report.Outcomes = append(report.Outcomes, CollectorOutcome{
		CollectorID: "org.settings",
		Scope:       Scope{Host: "github.com", Kind: OrganizationScope, Name: "acme"},
		Complete:    false,
		Reason:      "permission denied: organization settings scope not granted",
	})
	outputDirectory := t.TempDir()
	if _, err := RunOfflineEvaluation(profile, report, config, outputDirectory); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outputDirectory, SummaryFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "permission denied: organization settings scope not granted") {
		t.Fatal("summary.md dropped the run's real collection-failure outcome")
	}
}

// TestApplyConfirmationsAndReexportSummaryRetainsCollectionFailures mirrors
// the above regression for the confirm path specifically: it must recover
// the original run's outcomes via LoadCollectionLog, not synthesize an empty
// list, so a re-rendered summary.md after confirmation still discloses the
// same collection failure the initial evaluation reported.
func TestApplyConfirmationsAndReexportSummaryRetainsCollectionFailures(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := outputFixtureReport(t)
	report.Outcomes = append(report.Outcomes, CollectorOutcome{
		CollectorID: "org.settings",
		Scope:       Scope{Host: "github.com", Kind: OrganizationScope, Name: "acme"},
		Complete:    false,
		Reason:      "permission denied: organization settings scope not granted",
	})
	outputDirectory := t.TempDir()
	if _, err := RunOfflineEvaluation(profile, report, config, outputDirectory); err != nil {
		t.Fatal(err)
	}
	before, err := LoadEvaluationResults(profile, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	pending := PendingConfirmations(before)
	if len(pending) == 0 {
		t.Fatal("test assumption broken: expected at least one pending confirmation")
	}
	now := time.Now().UTC()
	decisions := []AssessorInput{{
		ControlID: pending[0], State: NotAssessed, Assessor: "Jane Reviewer (customer SRE team)",
		ConfirmedAt: now.Add(-time.Minute), Rationale: "Reviewed with the customer team; not yet ready to confirm a final state.",
		EvidenceRefs: []string{"interviews/" + pending[0] + ".md"},
	}}
	if _, err := ApplyConfirmationsAndReexport(profile, config, outputDirectory, decisions, now); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outputDirectory, SummaryFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "permission denied: organization settings scope not granted") {
		t.Fatal("re-rendered summary.md after confirmation dropped the original run's collection-failure outcome")
	}
}

func TestApplyConfirmationsAndReexportRoundTrips(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	outputDirectory := t.TempDir()
	if _, err := RunOfflineEvaluation(profile, outputFixtureReport(t), config, outputDirectory); err != nil {
		t.Fatal(err)
	}

	before, err := LoadEvaluationResults(profile, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	pendingBefore := PendingConfirmations(before)
	if len(pendingBefore) == 0 {
		t.Fatal("a fresh evaluation must have at least one pending confirmation")
	}

	now := time.Now().UTC()
	decisions := []AssessorInput{{
		ControlID: pendingBefore[0], State: NotAssessed, Assessor: "Jane Reviewer (customer SRE team)",
		ConfirmedAt: now.Add(-time.Minute), Rationale: "Reviewed with the customer team; not yet ready to confirm a final state.",
		EvidenceRefs: []string{"interviews/" + pendingBefore[0] + ".md"},
	}}
	summary, err := ApplyConfirmationsAndReexport(profile, config, outputDirectory, decisions, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.PendingConfirmations) != len(pendingBefore)-1 {
		t.Fatalf("confirming one control must reduce pending confirmations by exactly one: before=%d after=%d",
			len(pendingBefore), len(summary.PendingConfirmations))
	}

	after, err := LoadEvaluationResults(profile, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	var confirmed ControlResult
	for _, result := range after {
		if result.ControlID == pendingBefore[0] {
			confirmed = result
		}
	}
	if confirmed.Decision == nil || confirmed.Decision.Assessor != "Jane Reviewer (customer SRE team)" {
		t.Fatalf("round-tripped evaluation-results.json must carry the applied decision: %+v", confirmed.Decision)
	}

	guide, err := os.ReadFile(filepath.Join(outputDirectory, InterviewGuideFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), "Assessor decision:") {
		t.Fatal("re-rendered interview-guide.md must reflect the applied assessor decision")
	}
}

func TestApplyConfirmationsAndReexportRejectsInvalidDecisionWithoutPartialWrite(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	outputDirectory := t.TempDir()
	if _, err := RunOfflineEvaluation(profile, outputFixtureReport(t), config, outputDirectory); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(outputDirectory, EvaluationResultsFileName))
	if err != nil {
		t.Fatal(err)
	}
	invalid := []AssessorInput{{ControlID: "NOT-A-REAL-ID", State: Implemented, Assessor: "x", ConfirmedAt: time.Now(), Rationale: "x", EvidenceRefs: []string{"x"}}}
	if _, err := ApplyConfirmationsAndReexport(profile, config, outputDirectory, invalid, time.Now().UTC()); err == nil {
		t.Fatal("an invalid decision must be rejected")
	}
	after, err := os.ReadFile(filepath.Join(outputDirectory, EvaluationResultsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a rejected confirmation batch must not partially rewrite the canonical results file")
	}
}

// TestRunOfflineEvaluationAtProductionScaleSyntheticHarness extends Phase 3's
// established >100-repository pagination fixture pattern to a >=50-repository
// synthetic harness for the evaluate/export pipeline specifically: two
// organizations, 60 repositories total with a deliberate mix of protected,
// unprotected, critical/signed, sha-pinned/unpinned and dependency-eligible
// signals, run end to end through RunOfflineEvaluation. This establishes
// correctness and shape at a larger synthetic scale; it is not a performance
// benchmark and makes no production-acceptance or timing claim.
func TestRunOfflineEvaluationAtProductionScaleSyntheticHarness(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	sha := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"

	buildOrganization := func(name string, repoCount int) OrganizationRunResult {
		var repos []RepositoryRunResult
		var criticalNames []string
		for i := 0; i < repoCount; i++ {
			fullName := name + "/repo-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			protected := i%3 != 0
			fullyProtected := i%4 == 0
			signatures := i%5 == 0
			effective := fixtureEffectiveProtection(protected, fullyProtected, signatures, CollectionOK)
			var references []ActionReference
			if i%2 == 0 {
				references = append(references, ActionReference{Category: "third-party", Owner: "thirdparty", ActionRepo: "action", PinStatus: "sha-pinned", Ref: sha})
			} else {
				references = append(references, ActionReference{Category: "third-party", Owner: "thirdparty", ActionRepo: "action", PinStatus: "not-pinned", Ref: "v1"})
			}
			feature := RepositoryFeatureSignal{
				DependencyEligible: i%2 == 0, DependencyEligibleKnown: true,
				DependencyOperational: i%3 == 0, DependencyOperationalKnown: true,
			}
			repos = append(repos, fixtureRepoResult(fullName, effective, references, nil, feature))
			if i%7 == 0 {
				criticalNames = append(criticalNames, fullName)
			}
		}
		critical := &CriticalPopulationResult{Method: "custom-property", FullNames: criticalNames}
		return fixtureOrganization(name, nil, critical, repos...)
	}

	report := fixtureReport(buildOrganization("acme", 35), buildOrganization("contoso", 25))
	totalRepos := 0
	for _, organization := range report.Organizations {
		totalRepos += len(organization.Repositories)
	}
	if totalRepos < 50 {
		t.Fatalf("synthetic harness must exercise at least 50 repositories, got %d", totalRepos)
	}

	outputDirectory := t.TempDir()
	summary, err := RunOfflineEvaluation(profile, report, config, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ControlCount != 456 || summary.MetricKeyCount != 581 {
		t.Fatalf("production-scale harness lost profile data: %+v", summary)
	}
	for _, name := range EvaluationOutputFileNames() {
		if info, err := os.Stat(filepath.Join(outputDirectory, name)); err != nil || info.Size() == 0 {
			t.Fatalf("production-scale harness did not write a non-empty %s: %v", name, err)
		}
	}
	results, err := LoadEvaluationResults(profile, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ImplementedEvaluatorIDs() {
		found := false
		for _, result := range results {
			if result.ControlID == id {
				found = true
				if result.ProposedState == "" {
					t.Fatalf("%s produced an empty proposed state at production scale", id)
				}
			}
		}
		if !found {
			t.Fatalf("%s missing from production-scale harness results", id)
		}
	}
}

func saveFixtureEvidenceObject(t *testing.T, store *EvidenceStore, profile *Profile, scope Scope, collectorID, baseFeature string) EvidenceRef {
	t.Helper()
	metadata := EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: ProfileVersion, ProfileSHA256: profile.SHA256,
		CollectorID: collectorID, Feature: baseFeature + "-page-000001", Scope: scope,
		CollectedAt: time.Now().UTC(), Endpoint: "https://example.test/fixture", SourceKind: ImportedEvidence,
		CredentialKind: NoCredential, Pages: 1, Complete: true, Redactions: []string{},
	}
	ref, err := store.SaveJSON([]byte(`{"fixture":true}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// fixtureFullPipelineServer serves a large (110-repository, 80-active)
// synthetic organization reusing the established fixtureRepositoryInventory
// population (the same fixture already exercising >100-page pagination and
// the >=50-repository active-population bar), combined with the full set of
// per-repository endpoints needed to exercise inventory -> population ->
// effective-rules -> workflow-analysis -> feature-coverage end to end,
// without any live network access. This is the genuine raw-evidence source
// for full-pipeline replay tests: every evidence object it produces, when
// collected through a real (non-replay) CollectionClient, is exactly what a
// live `ghqr assess run` would have persisted.
func fixtureFullPipelineServer(t *testing.T) *httptest.Server {
	t.Helper()
	repos := fixtureRepositoryInventory()
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	workflowYAML := "name: CI\non: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + sha40 + "\n"
	const pageSize = 100
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			page := 1
			if request.URL.Query().Get("page") == "2" {
				page = 2
			}
			start := (page - 1) * pageSize
			end := min(start+pageSize, len(repos))
			if start > len(repos) {
				start, end = len(repos), len(repos)
			}
			if page == 1 && end < len(repos) {
				next := *request.URL
				query := next.Query()
				query.Set("page", "2")
				next.RawQuery = query.Encode()
				writer.Header().Set("Link", "<"+server.URL+next.RequestURI()+">; rel=\"next\"")
			}
			writeJSON(t, writer, repos[start:end])
		case path == "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/rules/branches/main"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 1, "workflows": []map[string]any{
				{"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
			}})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/contents/.github/workflows/ci.yml"):
			writeJSON(t, writer, map[string]any{
				"type": "file", "encoding": "base64", "path": ".github/workflows/ci.yml", "name": "ci.yml",
				"content": base64.StdEncoding.EncodeToString([]byte(workflowYAML)),
			})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/languages"):
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.Count(path, "/") == 3:
			name := strings.TrimPrefix(path, "/repos/fixture-org/")
			for _, repo := range repos {
				if repo["name"] == name {
					writeJSON(t, writer, repo)
					return
				}
			}
			writer.WriteHeader(http.StatusNotFound)
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// runGenuineFullPipeline performs one real (non-replay) collection pass
// against fixtureFullPipelineServer, persisting every page into a real,
// kept evidence directory, and returns the resulting report alongside that
// directory. This is "collect for real, then verify/replay against what was
// genuinely collected" -- the opposite of hand-building placeholder
// evidence objects, giving every full-pipeline replay test a source report
// and evidence store that are both genuine by construction.
func runGenuineFullPipeline(t *testing.T) (*VerticalSliceReport, string) {
	t.Helper()
	server := fixtureFullPipelineServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	// A deliberately reduced repository_cap keeps this test's real
	// end-to-end cost proportionate while still exercising genuine
	// stratified sampling (55 of 80 genuinely active repositories, still
	// comfortably above the required >=50-active-repository bar on the
	// unsampled ActiveRepositoryCount itself) and -- together with
	// replayConfig's own cap binding -- proves replay reconstructs the same
	// sampled subset a smaller, realistic customer repository_cap would
	// have actually produced, not just the unsampled "cap exceeds
	// population" case every other fixture in this package happens to use.
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 55\n"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return report, evidenceDirectory
}

func TestVerifyReportEvidenceProvesGenuineOutcomesAndRejectsForgedOnes(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	directory := t.TempDir()
	scope := Scope{Host: "github.com", Kind: RepositoryScope, Name: "acme/repo"}
	store := evidenceFixtureStore(t, directory, nil)
	ref := saveFixtureEvidenceObject(t, store, profile, scope, "repo.rules", "branch-rules")

	genuineOutcome := CollectorOutcome{
		CollectorID: "repo.rules", Feature: "branch-rules", Scope: scope, Pages: 1,
		EvidenceRefs: []string{ref.DataPath, ref.MetadataPath},
	}
	// Neither report below carries a ContextRef (hand-built outcomes, not a
	// genuine RunVerticalSlice/WriteRunCollectionContext round trip), so
	// per-page INTEGRITY resolution (genuine vs. forged) is this test's own
	// exercise -- overall Verified/AnalysisVerified is unconditionally
	// false for a context-less report regardless of how cleanly its pages
	// individually resolve, never a generic legacy shortcut.
	report := &VerticalSliceReport{Outcomes: []CollectorOutcome{genuineOutcome}}
	result, err := VerifyReportEvidence(profile, report, directory)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IntegrityVerified || result.PagesVerified != 1 || result.OutcomesChecked != 1 {
		t.Fatalf("genuinely persisted evidence must resolve cleanly at the integrity level: %+v", result)
	}
	if result.Verified || result.AnalysisVerified {
		t.Fatalf("a context-less report must never be Verified/AnalysisVerified, even with genuinely resolving evidence: %+v", result)
	}

	// A forged outcome citing a page that was never actually persisted (a
	// hand-edited run report claiming evidence that doesn't exist) must fail
	// verification rather than being trusted.
	forgedOutcome := CollectorOutcome{
		CollectorID: "repo.rules", Feature: "branch-rules-that-was-never-collected", Scope: scope, Pages: 1,
	}
	forgedReport := &VerticalSliceReport{Outcomes: []CollectorOutcome{genuineOutcome, forgedOutcome}}
	forgedResult, err := VerifyReportEvidence(profile, forgedReport, directory)
	if err != nil {
		t.Fatal(err)
	}
	if forgedResult.Verified || forgedResult.IntegrityVerified || forgedResult.PagesVerified != 1 {
		t.Fatalf("a forged outcome citing never-persisted evidence must fail verification: %+v", forgedResult)
	}
}

// TestCompareEffectiveProtectionDetectsFieldAndCompletenessTampering is a
// direct, pipeline-free unit test of the comparison logic
// VerifyReportEvidence's full-pipeline replay relies on: a claim that
// exactly matches a replayed result must pass silently; a single altered
// boolean field must be caught by name; and a claim of stronger completeness
// than what replay could independently establish (the "missing required
// page" family -- for example a legacy-protection page that was never
// collected at all) must be caught even when every other field matches.
func TestCompareEffectiveProtectionDetectsFieldAndCompletenessTampering(t *testing.T) {
	genuine := &EffectiveBranchProtection{
		PullRequestRequired: true, BlockForcePush: true, BlockDeletion: true, Signatures: true,
		Unprotected: false, Completeness: CollectionOK,
	}
	if mismatches := compareEffectiveProtection(genuine, genuine); len(mismatches) != 0 {
		t.Fatalf("an exactly matching claim must not be flagged: %v", mismatches)
	}

	tamperedField := *genuine
	tamperedField.BlockDeletion = false
	if mismatches := compareEffectiveProtection(&tamperedField, genuine); len(mismatches) == 0 || !strings.Contains(mismatches[0], "block_deletion") {
		t.Fatalf("a single altered boolean field must be named explicitly: %v", mismatches)
	}

	missingPage := *genuine
	missingPage.Completeness = CollectionPartial // replay could only independently establish Partial (e.g. legacy-protection page never collected)
	if mismatches := compareEffectiveProtection(genuine, &missingPage); len(mismatches) == 0 || !strings.Contains(mismatches[0], "completeness") {
		t.Fatalf("a claim of stronger completeness than a missing required page can prove must be caught: %v", mismatches)
	}

	// The reverse is NOT a contradiction: replay independently reaching a
	// stronger completeness than a cautious original claim is fine.
	if mismatches := compareEffectiveProtection(&missingPage, genuine); len(mismatches) != 0 {
		t.Fatalf("replay reaching a stronger completeness than the claim is not itself a contradiction: %v", mismatches)
	}
}

// TestCompareWorkflowAnalysisDetectsTampering is a direct, pipeline-free
// unit test of the workflow-reference comparison logic: an exact match
// passes; an added reference the replayed content never contained is
// caught; and a reclassified pin-status on an otherwise-identical raw
// reference is caught too.
func TestCompareWorkflowAnalysisDetectsTampering(t *testing.T) {
	genuineReference := ActionReference{Raw: "thirdparty/action@sha", Category: "third-party", PinStatus: "sha-pinned"}
	genuine := &WorkflowAnalysisResult{References: []ActionReference{genuineReference}}
	if mismatches := compareWorkflowAnalysis(genuine, genuine); len(mismatches) != 0 {
		t.Fatalf("an exactly matching claim must not be flagged: %v", mismatches)
	}

	tamperedAdded := &WorkflowAnalysisResult{References: []ActionReference{
		genuineReference, {Raw: "thirdparty/never-stored@v1", Category: "third-party", PinStatus: "not-pinned"},
	}}
	if mismatches := compareWorkflowAnalysis(tamperedAdded, genuine); len(mismatches) == 0 {
		t.Fatal("an added reference the replayed content never contained must be caught")
	}

	reclassified := genuineReference
	reclassified.PinStatus = "not-pinned"
	tamperedReclassified := &WorkflowAnalysisResult{References: []ActionReference{reclassified}}
	if mismatches := compareWorkflowAnalysis(tamperedReclassified, genuine); len(mismatches) == 0 {
		t.Fatal("a reclassified pin-status on an otherwise-identical reference must be caught")
	}
}

// TestFullPipelineReplayAcceptsGenuineRunAndRejectsTamperedClaims is the
// required true, >=50-active-repository raw-pipeline fixture: it collects
// for real (no replay) against fixtureFullPipelineServer's 80 genuinely
// active repositories (stratified-sampled down to a 55-repository
// repository_cap, still exercising genuine sampling, not just the
// cap-exceeds-population case), then independently reconstructs that same
// report through the full ReplayVerticalSlice pipeline (not a narrowed
// per-repo helper) exactly once, confirms the genuine claim matches
// cleanly, and proves that several independent kinds of claim tampering are
// each caught by the SAME compareVerticalSliceReports function
// VerifyReportEvidence itself calls: an added workflow action reference, a
// reclassified pin-status, a changed critical-population membership claim,
// a changed reported FullName/DefaultBranch (the report must never be
// trusted on this; replay's own independently-collected inventory is
// authoritative), and an altered pooled metric value. Tamper coverage
// compares against one shared replay result directly rather than
// re-running collection per scenario, since this >=50-repository pipeline
// is too expensive to re-traverse once per scenario; true end-to-end
// acceptance through the full VerifyReportEvidence -> RunVerifiedOfflineEvaluation
// wrapper is proven separately by
// TestRunVerifiedOfflineEvaluationAcceptsGenuinelyProvenReport, against a
// smaller dedicated fixture that only needs to exercise that wrapper once.
func TestFullPipelineReplayAcceptsGenuineRunAndRejectsTamperedClaims(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	report, evidenceDirectory := runGenuineFullPipeline(t)
	if len(report.Organizations) != 1 || report.Organizations[0].Population == nil ||
		report.Organizations[0].Population.ActiveRepositoryCount < 50 {
		t.Fatalf("test fixture assumption broken: expected >=50 genuinely active repositories, got %+v",
			report.Organizations[0].Population)
	}
	if len(report.Organizations[0].Repositories) == 0 {
		t.Fatal("test fixture assumption broken: no repositories were analyzed")
	}

	replayed, contextBound, err := ReplayVerticalSlice(context.Background(), profile, report, evidenceDirectory)
	if err != nil {
		t.Fatalf("replaying a genuinely collected report must succeed: %v", err)
	}
	if !contextBound {
		t.Fatal("a genuinely collected evidence directory with a written RunCollectionContext must report contextBound=true")
	}
	if mismatches := compareVerticalSliceReports(report, replayed); len(mismatches) != 0 {
		t.Fatalf("a genuinely collected report's own claims must match its independently replayed reconstruction: %v", mismatches)
	}

	cloneReport := func() *VerticalSliceReport {
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		var clone VerticalSliceReport
		if err := json.Unmarshal(data, &clone); err != nil {
			t.Fatal(err)
		}
		return &clone
	}

	t.Run("added workflow reference", func(t *testing.T) {
		tampered := cloneReport()
		repository := &tampered.Organizations[0].Repositories[0]
		if repository.Workflows == nil {
			t.Fatal("test fixture assumption broken: first analyzed repository has no claimed workflow analysis")
		}
		repository.Workflows.References = append(repository.Workflows.References, ActionReference{
			Raw: "thirdparty/never-collected@v1", Category: "third-party", PinStatus: "not-pinned",
		})
		if mismatches := compareVerticalSliceReports(tampered, replayed); len(mismatches) == 0 {
			t.Fatal("an added workflow reference absent from the genuinely collected content must be caught")
		}
	})

	t.Run("reclassified pin status", func(t *testing.T) {
		tampered := cloneReport()
		repository := &tampered.Organizations[0].Repositories[0]
		if repository.Workflows == nil || len(repository.Workflows.References) == 0 {
			t.Fatal("test fixture assumption broken: first analyzed repository has no claimed workflow references")
		}
		repository.Workflows.References[0].PinStatus = "not-pinned"
		if mismatches := compareVerticalSliceReports(tampered, replayed); len(mismatches) == 0 {
			t.Fatal("a reclassified pin status contradicting the genuinely collected content must be caught")
		}
	})

	t.Run("changed critical population membership", func(t *testing.T) {
		tampered := cloneReport()
		tampered.Organizations[0].Population.Critical = &CriticalPopulationResult{
			Method: "custom-property", FullNames: []string{"fixture-org/repo-never-analyzed"},
		}
		if mismatches := compareVerticalSliceReports(tampered, replayed); len(mismatches) == 0 {
			t.Fatal("a changed critical-population membership claim must be caught")
		}
	})

	t.Run("changed reported FullName and DefaultBranch cannot be trusted", func(t *testing.T) {
		tampered := cloneReport()
		repository := &tampered.Organizations[0].Repositories[0]
		repository.FullName = "fixture-org/repo-never-actually-analyzed"
		repository.DefaultBranch = "not-the-real-default-branch"
		if mismatches := compareVerticalSliceReports(tampered, replayed); len(mismatches) == 0 {
			t.Fatal("a claimed repository name replay's own independently collected inventory does not contain must be caught")
		}
	})

	t.Run("altered pooled metric value", func(t *testing.T) {
		tampered := cloneReport()
		protectionMetric, ok := tampered.Metrics["repos_with_default_branch_protection_pct"]
		if !ok || protectionMetric.Overall.Status != MetricKnown || protectionMetric.Overall.Number == nil {
			t.Fatal("test fixture assumption broken: repos_with_default_branch_protection_pct is not a known pooled metric")
		}
		alteredValue := *protectionMetric.Overall.Number + 100
		protectionMetric.Overall.Number = &alteredValue
		tampered.Metrics["repos_with_default_branch_protection_pct"] = protectionMetric
		if mismatches := compareVerticalSliceReports(tampered, replayed); len(mismatches) == 0 {
			t.Fatal("an altered pooled metric value must be caught")
		}
	})

	// A genuinely proven report's evaluation must use the independently
	// replayed facts, not the originally supplied report, per
	// RunVerifiedOfflineEvaluation's contract; TestRunVerifiedOfflineEvaluationAcceptsGenuinelyProvenReport
	// proves that end to end through the real production entrypoint (a
	// second full ReplayVerticalSlice traversal) against a smaller, dedicated
	// fixture, so this expensive >=50-repository test is not re-run a third
	// time just to exercise that same wrapper call.
}

// TestRunVerifiedOfflineEvaluationAcceptsGenuinelyProvenReport proves the
// real, public RunVerifiedOfflineEvaluation entrypoint accepts and evaluates
// a genuinely collected, replay-consistent report end to end, through the
// full runVerticalSliceWithStore replay pipeline (not a narrowed per-repo
// helper). It deliberately reuses the small, existing
// newVerticalSliceFixtureServer/TestRunVerticalSliceEndToEndSyntheticOrganization
// fixture (which already genuinely serves org-level repository discovery)
// rather than the larger fixtureFullPipelineServer: this specific assertion
// only needs ONE genuine pass through RunVerifiedOfflineEvaluation's own
// internal ReplayVerticalSlice call to prove the wrapper's acceptance
// contract, and the >=50-repository scale requirement is already proven by
// TestFullPipelineReplayAcceptsGenuineRunAndRejectsTamperedClaims.
func TestRunVerifiedOfflineEvaluationAcceptsGenuinelyProvenReport(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	// Built directly rather than via ParseConfig's single-host YAML shape:
	// this run's own authorized scope (what RunVerifiedOfflineEvaluation's
	// scope-authorization gate checks config.ResolvedTargets() against)
	// must genuinely match the target actually collected against (the
	// local fixture server's own host), not an unrelated default
	// "organizations-only" host resolution (github.com) that a bare
	// ParseConfig("organizations: [...]") call would otherwise produce.
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90, Concurrency: 4,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: "./evidence",
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	outputDirectory := t.TempDir()
	summary, err := RunVerifiedOfflineEvaluation(profile, report, config, outputDirectory, evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EvidenceVerification == nil || !summary.EvidenceVerification.Verified ||
		!summary.EvidenceVerification.IntegrityVerified || !summary.EvidenceVerification.AnalysisVerified ||
		!summary.EvidenceVerification.ContextBound {
		t.Fatalf("a genuinely proven, context-bound report must be accepted and evaluated: %+v", summary.EvidenceVerification)
	}
	if _, err := os.Stat(filepath.Join(outputDirectory, ResultsFileName)); err != nil {
		t.Fatalf("a proven report's evaluation must write its export files: %v", err)
	}
}

func TestRunVerifiedOfflineEvaluationRefusesUnprovenReport(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	evidenceDirectory := t.TempDir()
	scope := Scope{Host: "github.com", Kind: RepositoryScope, Name: "acme/critical"}
	store := evidenceFixtureStore(t, evidenceDirectory, nil)
	saveFixtureEvidenceObject(t, store, profile, scope, "repo.rules", "branch-rules")

	report := outputFixtureReport(t)
	// A forged/hand-edited outcome claiming a page was collected when
	// nothing was ever persisted for it in this freshly created
	// evidenceDirectory; verification must fail and no export files may be
	// written.
	report.Outcomes = append(report.Outcomes, CollectorOutcome{
		CollectorID: "repo.rules", Feature: "a-page-that-was-never-collected", Scope: scope, Pages: 1,
	})
	outputDirectory := t.TempDir()
	if _, err := RunVerifiedOfflineEvaluation(profile, report, config, outputDirectory, evidenceDirectory); err == nil {
		t.Fatal("an unproven report must be refused, not silently evaluated")
	}
	if entries, _ := os.ReadDir(outputDirectory); len(entries) != 0 {
		t.Fatalf("a refused, unproven evaluation must not write any export files: %v", entries)
	}

	// Omitting --evidence-dir (empty string) must behave exactly like the
	// existing, unverified RunOfflineEvaluation path.
	unverifiedSummary, err := RunVerifiedOfflineEvaluation(profile, report, config, outputDirectory, "")
	if err != nil {
		t.Fatal(err)
	}
	if unverifiedSummary.EvidenceVerification != nil {
		t.Fatalf("omitting --evidence-dir must skip verification entirely: %+v", unverifiedSummary.EvidenceVerification)
	}
}

// TestVerifyReportEvidenceReplayDetectsTamperedProtectionField's original
// scenario (a single tampered EffectiveBranchProtection boolean field caught
// despite every EvidenceRef genuinely resolving) required hand-built
// per-repo evidence predating the move to full runVerticalSliceWithStore
// replay; that pipeline now also requires genuine org-level repository-
// discovery evidence (org.repos) before it can reconstruct any per-repository
// fact at all, which that narrow fixture never provided. The same
// tampered-boolean-field/missing-page completeness claims are now covered
// more precisely and far faster by the direct, pipeline-free
// TestCompareEffectiveProtectionDetectsFieldAndCompletenessTampering unit
// test of the same compareEffectiveProtection function VerifyReportEvidence
// itself calls.

// TestCoordinatorVerifiedEvidenceMustBindNonWorkflowAnalysis is this task's
// own permanent copy of the parent's 5th overlay gate: a genuine, immutable,
// digest-verified "repo.rules"/"branch-rules" page whose actual content is
// entirely unrelated to branch protection ({"unrelated_fixture":true}, which
// decodes to a structurally valid but empty github.BranchRules) must not let
// a report's claimed full protection/critical/feature analysis for that same
// repository be accepted as Verified=true. Resolving a genuine evidence
// page's digest/identity only proves the page was persisted; replaying its
// actual content through ComputeEffectiveBranchProtection is what proves (or
// disproves) the claimed derived facts.
func TestCoordinatorVerifiedEvidenceMustBindNonWorkflowAnalysis(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	evidenceDirectory := t.TempDir()
	store := evidenceFixtureStore(t, evidenceDirectory, nil)
	scope := Scope{Host: "github.com", Kind: RepositoryScope, Name: "acme/critical"}
	metadata := EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "repo.rules", Feature: "branch-rules-page-000001", Scope: scope,
		CollectedAt: time.Now().UTC(), Endpoint: "https://api.github.com/repos/acme/critical/rules/branches/main",
		SourceKind: ImportedEvidence, CredentialKind: NoCredential, Pages: 1, Complete: true, Redactions: []string{},
	}
	ref, err := store.SaveJSON([]byte(`{"unrelated_fixture":true}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	report := outputFixtureReport(t)
	report.Outcomes = []CollectorOutcome{{
		CollectorID: "repo.rules", Feature: "branch-rules", Scope: scope, Pages: 1,
		EvidenceRefs: []string{ref.DataPath, ref.MetadataPath},
	}}
	summary, err := RunVerifiedOfflineEvaluation(profile, report, config, t.TempDir(), evidenceDirectory)
	if err == nil && summary.EvidenceVerification != nil && summary.EvidenceVerification.Verified {
		t.Fatal("valid-profile genuine evidence with no branch/critical/feature facts authenticated unrelated supplied computed analysis")
	}
}

// TestVerifyReportEvidenceReplayRejectsClaimExceedingWhatMissingPagesProve's
// scenario (a CollectionOK claim backed only by a partial evidence family,
// missing the legacy-protection page required for full completeness) also
// predated the move to full runVerticalSliceWithStore replay and used the
// same hand-built single-repo evidence lacking the org-level repository
// discovery page that pipeline now genuinely requires first. The same
// completeness-mismatch claim is covered precisely and far faster by the
// direct, pipeline-free TestCompareEffectiveProtectionDetectsFieldAndCompletenessTampering
// unit test of compareEffectiveProtection itself.

// TestRunVerifiedOfflineEvaluationRejectsUnbackedAnalysisWithEmptyOutcomes
// guards against a vacuous-pass regression: a report with populated
// Organizations/Repositories claiming genuinely computed analysis
// (EffectiveProtection, Workflows, Feature signals) but a nil/empty Outcomes
// slice must not be accepted as "Verified=true, 0 pages" merely because the
// verification loop over zero outcomes never finds a failure. Metadata/
// outcome existence does not, by itself, prove any claimed fact was ever
// collected.
func TestRunVerifiedOfflineEvaluationRejectsUnbackedAnalysisWithEmptyOutcomes(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := outputFixtureReport(t)
	report.Outcomes = nil

	result, err := VerifyReportEvidence(profile, report, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatalf("a report claiming computed analysis with zero recorded outcomes must not verify as true: %+v", result)
	}
	if len(result.Failures) == 0 {
		t.Fatal("the vacuous-pass rejection must carry an explicit failure reason")
	}

	summary, err := RunVerifiedOfflineEvaluation(profile, report, config, t.TempDir(), t.TempDir())
	if err == nil {
		t.Fatalf("computed analysis with no persisted supporting pages was accepted as verified: %+v", summary.EvidenceVerification)
	}
}

// TestVerifyReportEvidenceEmptyContextLessReportNeverEarnsAnalysisVerified
// proves the vacuous-pass guard does not over-reject (a report that
// legitimately has no analysis at all -- no organizations, no
// repositories, no known metrics -- and zero outcomes is never treated as
// an ERROR merely for being empty: IntegrityVerified stays true, since
// there is genuinely nothing to disprove), while also proving it never
// over-grants either: without a genuinely bound run collection context,
// AnalysisVerified/Verified must stay honestly false even for this trivial
// case, since an empty, context-less report proves nothing about genuine
// collection-time provenance any more than a non-empty one would.
func TestVerifyReportEvidenceEmptyContextLessReportNeverEarnsAnalysisVerified(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	report := &VerticalSliceReport{}
	result, err := VerifyReportEvidence(profile, report, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !result.IntegrityVerified {
		t.Fatalf("a genuinely empty, unanalyzed report must not be rejected for having zero outcomes: %+v", result)
	}
	if result.AnalysisVerified || result.Verified {
		t.Fatalf("an empty, context-less report must never earn a blanket AnalysisVerified/Verified=true: %+v", result)
	}
	if len(result.Failures) == 0 {
		t.Fatal("the honest false verdict must carry an explicit, disclosed reason")
	}
}
