// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newVerticalSliceFixtureServer serves a small synthetic organization (three
// active repositories, one of which is archived and must be excluded) with
// enough per-repository endpoints wired up to exercise the full
// inventory -> population -> effective-rules -> workflow-analysis ->
// feature-coverage pipeline end to end, without any live network access.
func newVerticalSliceFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	repos := []map[string]any{
		fixtureRepository(1, false, false, 5, "public", "Go"),
		fixtureRepository(2, false, false, 5, "private", "Python"),
		fixtureRepository(3, true, false, 5, "public", "Go"),
	}
	workflowYAML := "name: CI\non: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + sha40 + "\n"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			writeJSON(t, writer, repos)
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
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/code-scanning/analyses"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.Count(path, "/") == 3:
			// GET /repos/{owner}/{repo} (repo.details).
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

func TestRunVerticalSliceEndToEndSyntheticOrganization(t *testing.T) {
	server := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}

	if len(report.ImplementedCollectors) != len(RunImplementedCollectorIDs()) || len(report.ImplementedEvaluators) != 0 {
		t.Fatalf("run did not report a truthful collector/evaluator registry: %+v", report)
	}
	if len(report.Organizations) != 1 {
		t.Fatalf("expected exactly one analyzed organization, got %d", len(report.Organizations))
	}
	organization := report.Organizations[0]
	if organization.Population.TotalRepositories != 3 || organization.Population.ActiveRepositoryCount != 2 {
		t.Fatalf("population did not exclude the archived repository: %+v", organization.Population)
	}
	if organization.Population.Critical.Method != "recent-fallback" || organization.Population.Critical.Caveat == "" {
		t.Fatalf("critical population fallback caveat missing: %+v", organization.Population.Critical)
	}
	if len(organization.Repositories) != 2 {
		t.Fatalf("expected both active repositories to be analyzed, got %d", len(organization.Repositories))
	}
	for _, repo := range organization.Repositories {
		if repo.EffectiveProtection == nil || repo.EffectiveProtection.Source != "none" || !repo.EffectiveProtection.Unprotected {
			t.Fatalf("expected a confirmed unprotected default branch for %s: %+v", repo.FullName, repo.EffectiveProtection)
		}
		if repo.Workflows == nil || len(repo.Workflows.References) == 0 {
			t.Fatalf("expected workflow references for %s", repo.FullName)
		}
	}

	pinMetric, ok := report.Metrics["github_owned_refs_sha_pinned_pct"]
	if !ok || pinMetric.Overall.Status != MetricKnown || pinMetric.Overall.Number == nil || *pinMetric.Overall.Number != 100 {
		t.Fatalf("github-owned SHA pin coverage incorrect: %+v", pinMetric)
	}
	thirdParty, ok := report.Metrics["third_party_refs_sha_pinned_pct"]
	if !ok || thirdParty.Overall.Status != MetricUnavailable {
		t.Fatalf("zero third-party references must report unavailable, not a false 100%%: %+v", thirdParty)
	}
	protectedMetric, ok := report.Metrics["repos_with_default_branch_protection_pct"]
	if !ok || protectedMetric.Overall.Status != MetricKnown || protectedMetric.Overall.Number == nil || *protectedMetric.Overall.Number != 0 {
		t.Fatalf("protection coverage should confidently report 0%% for two confirmed-unprotected repositories: %+v", protectedMetric)
	}
	codeQL, ok := report.Metrics["codeql_operational_coverage_pct"]
	if !ok || codeQL.Overall.Status != MetricKnown || codeQL.Overall.Number == nil || *codeQL.Overall.Number != 0 {
		t.Fatalf("CodeQL operational coverage should report 0%% (no codeql-action step present): %+v", codeQL)
	}
	dependency, ok := report.Metrics["dependabot_security_updates_pct"]
	if !ok || dependency.Overall.Status != MetricUnavailable {
		t.Fatalf("dependency coverage denominator should be unavailable when no repository has an SBOM-eligible manifest: %+v", dependency)
	}
	if len(report.Outcomes) == 0 {
		t.Fatal("run recorded no raw collector outcomes")
	}

	foundEligibleRepos := false
	for _, caveat := range report.Caveats {
		if strings.Contains(caveat, "eligible_repos_count") {
			foundEligibleRepos = true
		}
	}
	if !foundEligibleRepos {
		t.Fatal("run did not disclose the profile's overloaded eligible_repos_count metric key caveat")
	}
}

// TestRunVerticalSliceDerivesCodeQLOperationalFromRealAnalysesNotWorkflowReference
// is a full run-loop (not helper-only) regression proving CodeQLOperational
// is genuinely derived from real, observed, successful CodeQL activity
// rather than a workflow file's mere reference to the github/codeql-action
// step, OR native default setup merely being "configured" (enablement, not
// evidence a scan has ever completed). A frozen fixtureClock bounds the
// [lookbackStart, now) window deterministically, matching the exact window
// FetchRepositoryCodeScanningAnalyses validates against.
//
// repo-001: zero codeql-action workflow reference anywhere (so
// AnalyzeRepositoryWorkflows' own CodeQLOperational signal is false) and
// default setup not configured, yet the repository's own analyses history
// includes a real, successful CodeQL entry -- must report operational
// purely from that real signal.
//
// repo-002: a codeql-action workflow reference (demoted to
// CodeQLWorkflowReferenced; the pre-this-round heuristic would have
// reported operational from this alone) but zero recorded analyses and
// default setup not configured -- must NOT report operational.
//
// repo-003: default setup genuinely CONFIGURED (an enablement signal) but
// an empty analyses history (the first scheduled scan still pending) --
// must NOT report operational either: enablement is diagnostic-only, never
// a proxy for a completed scan.
func TestRunVerticalSliceDerivesCodeQLOperationalFromRealAnalysesNotWorkflowReference(t *testing.T) {
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	created := now.Add(-48 * time.Hour)
	repos := []map[string]any{
		fixtureRepository(1, false, false, 5, "public", "Go"),
		fixtureRepository(2, false, false, 5, "public", "Go"),
		fixtureRepository(3, false, false, 5, "public", "Go"),
	}
	workflowNoReference := "name: CI\non: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + sha40 + "\n"
	workflowWithReference := "name: CodeQL\non: [push]\njobs:\n  analyze:\n    steps:\n      - uses: github/codeql-action/analyze@" + sha40 + "\n"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			writeJSON(t, writer, repos)
		case path == "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/rules/branches/main"), strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 1, "workflows": []map[string]any{
				{"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
			}})
		case path == "/repos/fixture-org/repo-001/contents/.github/workflows/ci.yml",
			path == "/repos/fixture-org/repo-003/contents/.github/workflows/ci.yml":
			writeJSON(t, writer, map[string]any{
				"type": "file", "encoding": "base64", "path": ".github/workflows/ci.yml", "name": "ci.yml",
				"content": base64.StdEncoding.EncodeToString([]byte(workflowNoReference)),
			})
		case path == "/repos/fixture-org/repo-002/contents/.github/workflows/ci.yml":
			writeJSON(t, writer, map[string]any{
				"type": "file", "encoding": "base64", "path": ".github/workflows/ci.yml", "name": "ci.yml",
				"content": base64.StdEncoding.EncodeToString([]byte(workflowWithReference)),
			})
		case strings.HasSuffix(path, "/languages"):
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case path == "/repos/fixture-org/repo-003/code-scanning/default-setup":
			writeJSON(t, writer, map[string]any{"state": "configured"})
		case strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case path == "/repos/fixture-org/repo-001/code-scanning/analyses":
			writeJSON(t, writer, []map[string]any{
				{"tool": map[string]any{"name": "CodeQL"}, "created_at": created.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
			})
		case path == "/repos/fixture-org/repo-002/code-scanning/analyses", path == "/repos/fixture-org/repo-003/code-scanning/analyses":
			writeJSON(t, writer, []map[string]any{})
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
	clock := &fixtureClock{now: now}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, clock,
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Organizations) != 1 || len(report.Organizations[0].Repositories) != 3 {
		t.Fatalf("expected all three repositories analyzed: %+v", report.Organizations)
	}
	byName := map[string]RepositoryRunResult{}
	for _, repo := range report.Organizations[0].Repositories {
		byName[repo.FullName] = repo
	}
	repo1 := byName["fixture-org/repo-001"]
	if !repo1.Feature.CodeQLOperational || !repo1.Feature.CodeQLOperationalKnown {
		t.Fatalf("repo-001 has a genuine recorded CodeQL analysis but no codeql-action workflow reference; "+
			"must still be operational from the real signal: %+v", repo1.Feature)
	}
	if repo1.Feature.CodeQLWorkflowReferenced {
		t.Fatalf("repo-001's workflow never references codeql-action; diagnostic signal must be false: %+v", repo1.Feature)
	}
	if repo1.CodeScanningAnalyses == nil || !repo1.CodeScanningAnalyses.CodeQLAnalysisObserved || !repo1.CodeScanningAnalyses.Complete {
		t.Fatalf("repo-001's code-scanning analyses evidence was not collected/exposed: %+v", repo1.CodeScanningAnalyses)
	}

	repo2 := byName["fixture-org/repo-002"]
	if repo2.Feature.CodeQLOperational {
		t.Fatalf("repo-002's workflow merely references codeql-action with zero recorded analyses and no default "+
			"setup; the demoted heuristic must no longer report it operational: %+v", repo2.Feature)
	}
	if !repo2.Feature.CodeQLOperationalKnown {
		t.Fatalf("repo-002's analyses probe succeeded (empty, complete); operational status is confidently known false: %+v", repo2.Feature)
	}
	if !repo2.Feature.CodeQLWorkflowReferenced {
		t.Fatalf("repo-002's workflow does reference codeql-action; the diagnostic signal must still disclose it: %+v", repo2.Feature)
	}

	repo3 := byName["fixture-org/repo-003"]
	if repo3.Feature.CodeQLOperational {
		t.Fatalf("repo-003's default setup is merely CONFIGURED (enablement) with zero recorded analyses (first "+
			"scan still pending); this must NOT be reported operational: %+v", repo3.Feature)
	}
	if !repo3.Feature.CodeQLDefaultSetupConfigured || !repo3.Feature.CodeQLDefaultSetupConfiguredKnown {
		t.Fatalf("repo-003's default setup IS genuinely configured; that diagnostic signal must still disclose it: %+v", repo3.Feature)
	}

	codeQL, ok := report.Metrics["codeql_operational_coverage_pct"]
	if !ok || codeQL.Overall.Status != MetricKnown || codeQL.Overall.Numerator == nil || codeQL.Overall.Denominator == nil ||
		*codeQL.Overall.Numerator != 1 || *codeQL.Overall.Denominator != 3 {
		t.Fatalf("expected exactly one of three CodeQL-eligible repositories pooled as operational (1/3): %+v", codeQL)
	}
}

// TestRunVerticalSliceLanguagesProbeFailureLeavesCodeQLEligibilityUnknown
// confirms a concealed/failed languages probe (HTTP 403) does not silently
// collapse into a confident "not eligible": the failed-probe repository
// must be excluded from BOTH AggregateFeatureCoverage's numerator and
// denominator (never counted as a confirmed-ineligible population member),
// with its uncertainty disclosed via FeatureCoverage.UnknownEligibilityCount
// -- otherwise a genuinely eligible-and-operational repository elsewhere in
// the same run could misleadingly appear as 100% coverage, hiding the fact
// that one repository's eligibility was never actually determined at all.
func TestRunVerticalSliceLanguagesProbeFailureLeavesCodeQLEligibilityUnknown(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	created := now.Add(-48 * time.Hour)
	repos := []map[string]any{
		fixtureRepository(1, false, false, 5, "public", "Go"),
		fixtureRepository(2, false, false, 5, "public", "Go"),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			writeJSON(t, writer, repos)
		case path == "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/rules/branches/main"), strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 0, "workflows": []map[string]any{}})
		case strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case path == "/repos/fixture-org/repo-001/languages":
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case path == "/repos/fixture-org/repo-002/languages":
			writer.WriteHeader(http.StatusForbidden)
			writeJSON(t, writer, map[string]string{"message": "must have admin rights"})
		case path == "/repos/fixture-org/repo-001/code-scanning/analyses":
			writeJSON(t, writer, []map[string]any{
				{"tool": map[string]any{"name": "CodeQL"}, "created_at": created.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
			})
		case path == "/repos/fixture-org/repo-002/code-scanning/analyses":
			writeJSON(t, writer, []map[string]any{})
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
	clock := &fixtureClock{now: now}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, clock,
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]RepositoryRunResult{}
	for _, repo := range report.Organizations[0].Repositories {
		byName[repo.FullName] = repo
	}
	repo2 := byName["fixture-org/repo-002"]
	if repo2.Feature.CodeQLEligibleKnown {
		t.Fatalf("repo-002's languages probe was forbidden; eligibility must be unknown, not a confident value: %+v", repo2.Feature)
	}
	if repo2.Feature.CodeQLEligible {
		t.Fatalf("an unknown eligibility must never read as a confident true: %+v", repo2.Feature)
	}

	codeQL, ok := report.Metrics["codeql_operational_coverage_pct"]
	if !ok {
		t.Fatal("expected codeql_operational_coverage_pct to be reported")
	}
	if codeQL.Overall.Status == MetricKnown {
		t.Fatalf("an unresolved eligibility peer must force the pooled metric unavailable, not a confident known "+
			"value merely because the known subset happens to compute cleanly: %+v", codeQL.Overall)
	}
	if codeQL.Overall.Number != nil {
		t.Fatalf("an unavailable metric must not carry a Number: %+v", codeQL.Overall)
	}
	if codeQL.Overall.Numerator == nil || codeQL.Overall.Denominator == nil ||
		*codeQL.Overall.Numerator != 1 || *codeQL.Overall.Denominator != 1 {
		t.Fatalf("the confidently-known 1/1 subset must still be retained on the metric even though Status is "+
			"unavailable, not the forbidden-probe repository silently folded in as a confirmed ineligible/excluded "+
			"population member: %+v", codeQL.Overall)
	}
	if codeQL.Overall.Reason == "" {
		t.Fatalf("expected the forbidden-probe repository's uncertainty disclosed via an explicit Reason: %+v", codeQL.Overall)
	}
}

// TestRunVerticalSliceUnknownPeerInOneOrgDoesNotInvalidateAnotherOrgsKnownCoverage
// confirms per-organization pooling is genuinely independent: an
// organization whose every repository's CodeQL eligibility and operational
// status is confidently known reports its own true, confident
// PerOrganization value even when the Overall (pooled across every
// organization in the run) is forced unavailable by an unresolved
// repository in a COMPLETELY DIFFERENT organization. Per-organization and
// Overall are computed from the identical underlying signals (the same
// AggregateFeatureCoverage call, once per organization's own subset and
// once over the full pooled set), never two divergent implementations.
func TestRunVerticalSliceUnknownPeerInOneOrgDoesNotInvalidateAnotherOrgsKnownCoverage(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	created := now.Add(-48 * time.Hour)
	// fixtureRepository hardcodes a "fixture-org/" full_name prefix (shared
	// by every other single-organization test in this file); this test
	// needs two DISTINCT organization owners, so its repository records are
	// built directly rather than through that shared single-org helper.
	orgRepo := func(org string, index int) map[string]any {
		return map[string]any{
			"name": fmt.Sprintf("repo-%03d", index), "full_name": fmt.Sprintf("%s/repo-%03d", org, index),
			"visibility": "public", "private": false, "archived": false, "fork": false,
			"default_branch": "main", "language": "Go",
			"pushed_at":  now.AddDate(0, 0, -5).Format(time.RFC3339),
			"created_at": now.AddDate(-2, 0, 0).Format(time.RFC3339),
		}
	}
	reposA := []map[string]any{orgRepo("fixture-org-a", 1)}
	reposB := []map[string]any{orgRepo("fixture-org-b", 1), orgRepo("fixture-org-b", 2)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org-a" || path == "/orgs/fixture-org-b":
			writeJSON(t, writer, map[string]any{"login": strings.TrimPrefix(path, "/orgs/"), "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org-a/repos":
			writeJSON(t, writer, reposA)
		case path == "/orgs/fixture-org-b/repos":
			writeJSON(t, writer, reposB)
		case path == "/orgs/fixture-org-a/properties/schema", path == "/orgs/fixture-org-b/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/rules/branches/main"), strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 0, "workflows": []map[string]any{}})
		case strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case path == "/repos/fixture-org-a/repo-001/languages", path == "/repos/fixture-org-b/repo-001/languages":
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case path == "/repos/fixture-org-b/repo-002/languages":
			writer.WriteHeader(http.StatusForbidden)
			writeJSON(t, writer, map[string]string{"message": "must have admin rights"})
		case path == "/repos/fixture-org-a/repo-001/code-scanning/analyses":
			writeJSON(t, writer, []map[string]any{
				{"tool": map[string]any{"name": "CodeQL"}, "created_at": created.Format(time.RFC3339), "ref": "refs/heads/main", "error": ""},
			})
		case path == "/repos/fixture-org-b/repo-001/code-scanning/analyses", path == "/repos/fixture-org-b/repo-002/code-scanning/analyses":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org-a/repo-") && strings.Count(path, "/") == 3:
			name := strings.TrimPrefix(path, "/repos/fixture-org-a/")
			for _, repo := range reposA {
				if repo["name"] == name {
					writeJSON(t, writer, repo)
					return
				}
			}
			writer.WriteHeader(http.StatusNotFound)
		case strings.HasPrefix(path, "/repos/fixture-org-b/repo-") && strings.Count(path, "/") == 3:
			name := strings.TrimPrefix(path, "/repos/fixture-org-b/")
			for _, repo := range reposB {
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
	clock := &fixtureClock{now: now}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org-a", "fixture-org-b"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org-a, fixture-org-b]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, clock,
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	var orgAKey, orgBKey string
	for _, organization := range report.Organizations {
		switch strings.ToLower(organization.Scope.Name) {
		case "fixture-org-a":
			orgAKey = organization.Scope.Key()
		case "fixture-org-b":
			orgBKey = organization.Scope.Key()
		}
	}
	if orgAKey == "" || orgBKey == "" {
		t.Fatalf("expected both organizations analyzed: %+v", report.Organizations)
	}

	codeQL, ok := report.Metrics["codeql_operational_coverage_pct"]
	if !ok {
		t.Fatal("expected codeql_operational_coverage_pct to be reported")
	}
	orgAValue, ok := codeQL.PerOrganization[orgAKey]
	if !ok {
		t.Fatalf("expected a per-organization value for fixture-org-a: %+v", codeQL)
	}
	if orgAValue.Status != MetricKnown || orgAValue.Number == nil || *orgAValue.Number != 100 {
		t.Fatalf("fixture-org-a's own repository is fully known and operational; its own per-organization value "+
			"must remain a confident 100%%, untouched by fixture-org-b's unresolved repository: %+v", orgAValue)
	}
	orgBValue, ok := codeQL.PerOrganization[orgBKey]
	if !ok {
		t.Fatalf("expected a per-organization value for fixture-org-b: %+v", codeQL)
	}
	if orgBValue.Status == MetricKnown {
		t.Fatalf("fixture-org-b itself has an unresolved-eligibility repository; its own per-organization value "+
			"must be unavailable, not a false known value: %+v", orgBValue)
	}
	if codeQL.Overall.Status == MetricKnown {
		t.Fatalf("the pooled Overall value spans both organizations and must be unavailable because of "+
			"fixture-org-b's unresolved repository, even though fixture-org-a alone is fully known: %+v", codeQL.Overall)
	}
}

func TestRunVerticalSliceDependabotSecurityUpdatesOmittedStatusLeavesDependencyOperationalUnknown(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := map[string]any{
		"name": "repo-001", "full_name": "fixture-org/repo-001", "visibility": "public", "private": false,
		"archived": false, "fork": false, "default_branch": "main", "language": "Go",
		"pushed_at": now.AddDate(0, 0, -5).Format(time.RFC3339), "created_at": now.AddDate(-2, 0, 0).Format(time.RFC3339),
	}
	// security_and_analysis.dependabot_security_updates present as an empty
	// object (status field omitted) -- a genuinely documented shape
	// (feature enabled for the account but no explicit status recorded
	// yet, or an API/account edge case), never a confirmed "disabled".
	repoDetails := map[string]any{
		"name": "repo-001", "full_name": "fixture-org/repo-001", "default_branch": "main",
		"security_and_analysis": map[string]any{"dependabot_security_updates": map[string]any{}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			writeJSON(t, writer, []map[string]any{repo})
		case path == "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/rules/branches/main"), strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 0, "workflows": []map[string]any{}})
		case strings.HasSuffix(path, "/languages"):
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case strings.HasSuffix(path, "/code-scanning/analyses"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/git/trees/main"):
			writeJSON(t, writer, map[string]any{"sha": "abc", "truncated": false, "tree": []map[string]any{
				{"path": "go.mod", "type": "blob"},
			}})
		case strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case path == "/repos/fixture-org/repo-001":
			writeJSON(t, writer, repoDetails)
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	clock := &fixtureClock{now: now}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, clock,
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Organizations) != 1 || len(report.Organizations[0].Repositories) != 1 {
		t.Fatalf("expected the one repository analyzed: %+v", report.Organizations)
	}
	feature := report.Organizations[0].Repositories[0].Feature
	if !feature.DependencyEligible || !feature.DependencyEligibleKnown {
		t.Fatalf("expected the confirmed go.mod manifest to establish known dependency eligibility: %+v", feature)
	}
	if feature.DependencyOperationalKnown {
		t.Fatalf("an omitted dependabot_security_updates.status must leave operational status unknown, not a "+
			"confident false coerced from GetStatus() returning an empty string: %+v", feature)
	}

	dependency, ok := report.Metrics["dependabot_security_updates_pct"]
	if !ok {
		t.Fatal("expected dependabot_security_updates_pct to be reported")
	}
	if dependency.Overall.Status == MetricKnown {
		t.Fatalf("the one known-eligible repository's unresolved operational status must force the pooled metric "+
			"unavailable, not a confident value: %+v", dependency.Overall)
	}
	if dependency.Overall.Number != nil {
		t.Fatalf("an unavailable metric must not carry a Number: %+v", dependency.Overall)
	}
	if dependency.Overall.Numerator == nil || dependency.Overall.Denominator == nil ||
		*dependency.Overall.Numerator != 0 || *dependency.Overall.Denominator != 1 {
		t.Fatalf("the confidently-known 0/1 subset must still be retained even though Status is unavailable: %+v", dependency.Overall)
	}
}

// TestRunVerticalSliceDependabotSecurityUpdatesExplicitDisabledIsKnownZero is
// the direct contrast to the omitted-status test above: an explicit,
// documented "disabled" status is a confident known false, correctly
// pooled as a genuine 0% rather than forced unavailable.
func TestRunVerticalSliceDependabotSecurityUpdatesExplicitDisabledIsKnownZero(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := map[string]any{
		"name": "repo-001", "full_name": "fixture-org/repo-001", "visibility": "public", "private": false,
		"archived": false, "fork": false, "default_branch": "main", "language": "Go",
		"pushed_at": now.AddDate(0, 0, -5).Format(time.RFC3339), "created_at": now.AddDate(-2, 0, 0).Format(time.RFC3339),
	}
	repoDetails := map[string]any{
		"name": "repo-001", "full_name": "fixture-org/repo-001", "default_branch": "main",
		"security_and_analysis": map[string]any{"dependabot_security_updates": map[string]any{"status": "disabled"}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			writeJSON(t, writer, []map[string]any{repo})
		case path == "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/rules/branches/main"), strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 0, "workflows": []map[string]any{}})
		case strings.HasSuffix(path, "/languages"):
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case strings.HasSuffix(path, "/code-scanning/analyses"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasSuffix(path, "/git/trees/main"):
			writeJSON(t, writer, map[string]any{"sha": "abc", "truncated": false, "tree": []map[string]any{
				{"path": "go.mod", "type": "blob"},
			}})
		case strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case path == "/repos/fixture-org/repo-001":
			writeJSON(t, writer, repoDetails)
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	clock := &fixtureClock{now: now}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, clock,
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	feature := report.Organizations[0].Repositories[0].Feature
	if !feature.DependencyOperationalKnown || feature.DependencyOperational {
		t.Fatalf("an explicit documented \"disabled\" status is a confident known false: %+v", feature)
	}

	dependency, ok := report.Metrics["dependabot_security_updates_pct"]
	if !ok {
		t.Fatal("expected dependabot_security_updates_pct to be reported")
	}
	if dependency.Overall.Status != MetricKnown || dependency.Overall.Number == nil || *dependency.Overall.Number != 0 {
		t.Fatalf("an explicit disabled status must remain a confident known 0%%, not forced unavailable: %+v", dependency.Overall)
	}
}

func TestRunVerticalSliceSamplesWhenActivePopulationExceedsCap(t *testing.T) {
	server := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: client.base.Hostname(), Deployment: Cloud, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 1\n"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	population := report.Organizations[0].Population
	if population.Sample == nil || population.Sample.Cap != 1 || len(population.EligibleFullNames) != 1 {
		t.Fatalf("a two-repository active population over a cap of one was not sampled: %+v", population)
	}
	if len(report.Organizations[0].Repositories) != 1 {
		t.Fatalf("analysis did not respect the sampled eligible set: %d repositories analyzed", len(report.Organizations[0].Repositories))
	}
}

// TestRunVerticalSliceWiresEnterpriseInfoAndGHESManageBasics confirms the
// run loop constructs an additional GraphQL-sourced and Management-sourced
// CollectionClient (sharing the same request budget) per target and
// populates report.Targets, exactly once per target rather than once per
// organization.
func TestRunVerticalSliceWiresEnterpriseInfoAndGHESManageBasics(t *testing.T) {
	restServer := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	restClient := collectionFixtureClient(t, restServer, budget, SystemClock{})

	graphQLServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/graphql" || request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, writer, map[string]any{"data": map[string]any{"enterprise": map[string]any{
			"name": "Fixture Enterprise", "slug": "fixture-enterprise",
			"organizations": map[string]any{"totalCount": 1, "nodes": []map[string]any{{"login": "fixture-org"}}},
			"ownerInfo":     map[string]any{"admins": map[string]any{"totalCount": 1, "nodes": []map[string]any{{"login": "octocat"}}}},
		}}})
	}))
	t.Cleanup(graphQLServer.Close)
	graphQLClient := graphQLFixtureClient(t, graphQLServer, budget, SystemClock{})

	manageServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/manage/v1/version":
			writeJSON(t, writer, map[string]any{"version": "3.18.0"})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(manageServer.Close)
	manageClient := managementFixtureClient(t, manageServer, budget, SystemClock{}, "admin", "fixture-password")

	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{
		Host: restClient.base.Hostname(), Deployment: Server, Enterprise: "fixture-enterprise", Organizations: []string{"fixture-org"},
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\ndeployment: ghes\nghes_host: " + restClient.base.Hostname() + "\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}

	graphQLCalls, manageCalls := 0, 0
	report, err := runVerticalSliceWithStore(context.Background(), restClient.profile, config, []Target{target}, store, SystemClock{},
		func(_ Target, source EvidenceSource) (*CollectionClient, error) {
			switch source {
			case GraphQLEvidence:
				graphQLCalls++
				return graphQLClient, nil
			case ManagementEvidence:
				manageCalls++
				return manageClient, nil
			default:
				return restClient, nil
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	if graphQLCalls != 1 || manageCalls != 1 {
		t.Fatalf("expected exactly one GraphQL and one Management client built per target, got %d/%d", graphQLCalls, manageCalls)
	}
	if len(report.Targets) != 1 || report.Targets[0].EnterpriseInfo == nil || report.Targets[0].GHESManageBasics == nil {
		t.Fatalf("expected one target result with both enterprise info and GHES manage basics populated: %+v", report.Targets)
	}
	if report.Targets[0].EnterpriseInfo.Slug != "fixture-enterprise" || report.Targets[0].EnterpriseInfo.OrganizationCount != 1 {
		t.Fatalf("unexpected enterprise info: %+v", report.Targets[0].EnterpriseInfo)
	}
	if !report.Targets[0].GHESManageBasics.VersionAvailable {
		t.Fatalf("expected the GHES manage version probe to succeed: %+v", report.Targets[0].GHESManageBasics)
	}

	// Spot-check a sample of the new exact-profile-key metrics this phase
	// adds are present (even if unavailable, given this fixture server does
	// not serve every new org-level endpoint) rather than silently absent.
	for _, key := range []string{
		"custom_apps_count", "hooks_without_secret_pct", "fine_grained_pat_grants_count", "pending_pat_requests",
		"owner_count", "members_without_2fa", "review_coverage_pct", "ci_success_rate_90d",
	} {
		if _, ok := report.Metrics[key]; !ok {
			t.Errorf("expected metric key %q to be present in the run's measured metrics", key)
		}
	}
}
