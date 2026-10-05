// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-github/v83/github"
)

// fixtureRepository builds one synthetic org.repos-shaped repository record.
func fixtureRepository(index int, archived, fork bool, pushedDaysAgo int, visibility, language string) map[string]any {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	return map[string]any{
		"name": fmt.Sprintf("repo-%03d", index), "full_name": fmt.Sprintf("fixture-org/repo-%03d", index),
		"visibility": visibility, "private": visibility == "private",
		"archived": archived, "fork": fork, "default_branch": "main", "language": language,
		"pushed_at":  now.AddDate(0, 0, -pushedDaysAgo).Format(time.RFC3339),
		"created_at": now.AddDate(-2, 0, 0).Format(time.RFC3339),
	}
}

// fixtureRepositoryInventory builds a 110-repository population: 10 archived,
// 10 forked, 10 pushed outside the 365-day window and 80 genuinely active,
// exercising both the >100 pagination requirement and a >=50-repository active
// population without any live network access.
func fixtureRepositoryInventory() []map[string]any {
	repos := make([]map[string]any, 0, 110)
	index := 0
	languages := []string{"Go", "Python", "TypeScript"}
	visibilities := []string{"public", "private"}
	next := func(archived, fork bool, pushedDaysAgo int) map[string]any {
		index++
		repo := fixtureRepository(index, archived, fork, pushedDaysAgo, visibilities[index%2], languages[index%3])
		return repo
	}
	for i := 0; i < 10; i++ {
		repos = append(repos, next(true, false, 5))
	}
	for i := 0; i < 10; i++ {
		repos = append(repos, next(false, true, 5))
	}
	for i := 0; i < 10; i++ {
		repos = append(repos, next(false, false, 400))
	}
	for i := 0; i < 80; i++ {
		repos = append(repos, next(false, false, 5))
	}
	return repos
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Error(err)
	}
}

func fixturePopulationServer(t *testing.T, repos []map[string]any, propertySchema []map[string]any, propertyValues []map[string]any) *httptest.Server {
	t.Helper()
	const pageSize = 100
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/repos":
			page := 1
			if value := request.URL.Query().Get("page"); value == "2" {
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
		case "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, propertySchema)
		case "/orgs/fixture-org/properties/values":
			writeJSON(t, writer, propertyValues)
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRepositoryInventoryPaginatesBeyond100AndFiltersActivePopulation(t *testing.T) {
	repos := fixtureRepositoryInventory()
	if len(repos) != 110 {
		t.Fatalf("fixture inventory size = %d, want 110", len(repos))
	}
	server := fixturePopulationServer(t, repos, nil, nil)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	inventory, outcome, err := FetchOrganizationRepositoryInventory(context.Background(), client, store, scope, "fixture-org")
	if err != nil || outcome.Pages != 2 || len(inventory) != 110 {
		t.Fatalf("paginated inventory incomplete: pages=%d len=%d err=%v", outcome.Pages, len(inventory), err)
	}

	active := ActiveRepositories(inventory, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	if len(active) != 80 {
		t.Fatalf("active repository count = %d, want 80 (excluding archived, forked and stale repositories)", len(active))
	}
	for _, repo := range active {
		if repo.GetArchived() || repo.GetFork() {
			t.Fatalf("active population leaked an archived or forked repository: %+v", repo)
		}
	}
}

func TestEligibleRepositoriesSampleIsDeterministicStratifiedAndCapped(t *testing.T) {
	repos := fixtureRepositoryInventory()
	active := ActiveRepositories(repos2github(repos), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	if len(active) != 80 {
		t.Fatalf("test fixture active count = %d, want 80", len(active))
	}
	eligibleA, sampleA := EligibleRepositories(active, 25, "fixture-org-seed")
	eligibleB, sampleB := EligibleRepositories(active, 25, "fixture-org-seed")
	if sampleA == nil || sampleB == nil {
		t.Fatal("sampling over the cap did not produce a SampleResult")
	}
	if len(eligibleA) > 25 || len(eligibleB) > 25 {
		t.Fatalf("sample exceeded the cap: %d/%d", len(eligibleA), len(eligibleB))
	}
	if len(sampleA.SelectedFullNames) != len(sampleB.SelectedFullNames) {
		t.Fatal("deterministic sample changed size across identical calls")
	}
	for index, name := range sampleA.SelectedFullNames {
		if sampleB.SelectedFullNames[index] != name {
			t.Fatalf("deterministic sample selection changed across identical seed/population/cap calls at index %d", index)
		}
	}
	if sampleA.PopulationSize != 80 || sampleA.Cap != 25 {
		t.Fatalf("sample diagnostics incorrect: %+v", sampleA)
	}
	if len(sampleA.Strata) < 2 {
		t.Fatal("stratified sample did not record multiple strata for a mixed visibility/language population")
	}

	// A population at or under the cap is never sampled.
	smallActive := active[:10]
	eligibleSmall, sampleSmall := EligibleRepositories(smallActive, 25, "fixture-org-seed")
	if sampleSmall != nil || len(eligibleSmall) != 10 {
		t.Fatal("a population under the cap was unexpectedly sampled")
	}
}

func TestCriticalPopulationUsesCustomPropertyWhenDefined(t *testing.T) {
	repos := fixtureRepositoryInventory()
	active := ActiveRepositories(repos2github(repos), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	schema := []map[string]any{{"property_name": "criticality", "value_type": "single_select", "allowed_values": []string{"critical", "high", "low"}}}
	values := []map[string]any{
		{"repository_name": "repo-031", "repository_full_name": "fixture-org/repo-031", "properties": []map[string]any{{"property_name": "criticality", "value": "critical"}}},
		{"repository_name": "repo-032", "repository_full_name": "fixture-org/repo-032", "properties": []map[string]any{{"property_name": "criticality", "value": "low"}}},
	}
	server := fixturePopulationServer(t, repos, schema, values)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}

	result, _, err := ComputeCriticalPopulation(context.Background(), client, store, scope, "fixture-org", active, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Method != "custom-property" || len(result.FullNames) != 1 || result.FullNames[0] != "fixture-org/repo-031" {
		t.Fatalf("critical population did not use the custom property signal: %+v", result)
	}
}

func TestCriticalPopulationFallsBackWithoutDefaultingMissingEnvironmentDataToFalse(t *testing.T) {
	repos := fixtureRepositoryInventory()
	active := ActiveRepositories(repos2github(repos), time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC))
	server := fixturePopulationServer(t, repos, []map[string]any{}, nil)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}

	result, _, err := ComputeCriticalPopulation(context.Background(), client, store, scope, "fixture-org", active, config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Method != "recent-fallback" || len(result.FullNames) != criticalFallbackRecentCount {
		t.Fatalf("fallback critical population incorrect: %+v", result)
	}
	if result.Caveat == "" {
		t.Fatal("fallback critical population did not flag that production environment data is not collected " +
			"(missing environment evidence must never be silently treated as \"not production\")")
	}
}

// repos2github round-trips raw fixture maps through JSON to produce the same
// *github.Repository values ActiveRepositories/EligibleRepositories operate on,
// matching how collectJSONArray decodes evidence in production.
func repos2github(repos []map[string]any) []*github.Repository {
	data, err := json.Marshal(repos)
	if err != nil {
		panic(err)
	}
	var decoded []*github.Repository
	if err := json.Unmarshal(data, &decoded); err != nil {
		panic(err)
	}
	return decoded
}
