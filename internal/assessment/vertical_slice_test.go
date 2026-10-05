// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
