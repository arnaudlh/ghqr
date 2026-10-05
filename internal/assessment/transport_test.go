// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReadOnlyGraphQLGuard(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		allowed bool
	}{
		{"shorthand", `{ viewer { login } }`, true},
		{"named query", `query Viewer { viewer { login } }`, true},
		{"comment and quoted keyword", "# mutation is not an operation here\nquery { repository(name: \"mutation\") { id } }", true},
		{"block string", `query { search(query: """mutation { x }""") { issueCount } }`, true},
		{"mutation", `mutation { deleteRepository(input: {}) { clientMutationId } }`, false},
		{"trailing mutation", `query { viewer { id } } mutation { x }`, false},
		{"subscription", `subscription { x }`, false},
		{"multiple operations", `query First { x } query Second { y }`, false},
		{"unclosed selection", `query { viewer { login }`, false},
		{"unclosed string", `query { search(query: "unclosed) { id } }`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"query": tt.query})
			if err != nil {
				t.Fatal(err)
			}
			if got := readOnlyGraphQL(raw); got != tt.allowed {
				t.Fatalf("read-only decision = %v, want %v", got, tt.allowed)
			}
		})
	}
}

func TestTransportBlocksRESTWritesAndCrossOriginCredentials(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if _, err := writer.Write([]byte(`{"data":{"viewer":{"login":"fixture"}}}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	transport := client.http.Transport.(*readTransport)
	transport.graphQLPath = "/graphql"
	transport.token = "fixture-scoped-token"
	tests := []struct {
		method  string
		path    string
		body    string
		allowed bool
	}{
		{http.MethodGet, "/orgs/fixture", "", true},
		{http.MethodPost, "/graphql", `{"query":"query { viewer { login } }"}`, true},
		{http.MethodPost, "/graphql", `{"query":"mutation { deleteRepository(input:{}) { clientMutationId } }"}`, false},
		{http.MethodPost, "/orgs/fixture", `{}`, false},
		{http.MethodGet, "/graphql?query=mutation", "", false},
		{http.MethodGet, "/repos/fixture/repo/dependency-graph/sbom/generate-report", "", false},
	}
	for _, test := range tests {
		request, err := http.NewRequestWithContext(context.Background(), test.method, server.URL+test.path, bytes.NewReader([]byte(test.body)))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.http.Do(request)
		if (err == nil) != test.allowed {
			t.Fatalf("method/operation guard = %v, want %v: %v", err == nil, test.allowed, err)
		}
		if response != nil {
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	request, err := http.NewRequest(http.MethodGet, "https://outside.example.test/orgs/fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.http.Do(request); err == nil {
		t.Fatal("cross-origin token route was accepted")
	}
	if calls.Load() != 2 {
		t.Fatalf("blocked operations reached the network: %d calls", calls.Load())
	}
}

func TestManagementCredentialsAreNotPATsOrCrossHostFallbacks(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIXTURE_API_TOKEN", "fixture-api-value")
	t.Setenv("FIXTURE_MANAGE_USER", "api_key")
	t.Setenv("FIXTURE_MANAGE_PASSWORD", "fixture-management-value")
	target := Target{
		Host: "ghes.example.test", Deployment: Server,
		Credentials: CredentialReferences{Kind: ClassicPAT, TokenEnv: "FIXTURE_API_TOKEN",
			ManagementUsernameEnv: "FIXTURE_MANAGE_USER", ManagementPasswordEnv: "FIXTURE_MANAGE_PASSWORD"},
	}
	api, err := NewCollectionClient(target, RESTEvidence, profile, fixtureBudget(t), SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	management, err := NewCollectionClient(target, ManagementEvidence, profile, fixtureBudget(t), SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	apiTransport := api.http.Transport.(*readTransport)
	manageTransport := management.http.Transport.(*readTransport)
	if api.base.String() != "https://ghes.example.test/api/v3/" || apiTransport.token == "" || apiTransport.password != "" ||
		management.base.String() != "https://ghes.example.test:8443/manage/v1/" || manageTransport.token != "" ||
		manageTransport.username != "api_key" || management.credentialKind != ManagementConsole {
		t.Fatal("management credentials were mixed with the REST PAT route")
	}
	t.Setenv("FIXTURE_API_TOKEN", "")
	t.Setenv("GH_TOKEN", "must-not-cross-host")
	if _, err := NewCollectionClient(target, RESTEvidence, profile, fixtureBudget(t), SystemClock{}); err == nil {
		t.Fatal("missing per-host token fell back to global GH_TOKEN")
	}
}

func TestRateLimitHintsAndExhaustion(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, header := range []http.Header{
		{"Retry-After": []string{"120"}},
		{"Retry-After": []string{now.Add(2 * time.Minute).Format(http.TimeFormat)}},
		{"X-Ratelimit-Reset": []string{fmt.Sprintf("%d", now.Add(2*time.Minute).Unix())}},
	} {
		if delay := assessmentRetryDelay(&http.Response{Header: header}, now, 0); delay != 2*time.Minute {
			t.Fatalf("rate hint not honored: %v", delay)
		}
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		writer.Header().Set("Retry-After", "1")
		writer.WriteHeader(403)
		if _, err := writer.Write([]byte(`{"message":"exhausted budget"}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	clock := &fixtureClock{now: now}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture"}
	outcome, err := client.CollectGET(context.Background(), store, scope, "org.settings", "settings", "orgs/fixture", "", false)
	if err == nil || outcome.Availability != RateLimited || outcome.Complete || calls.Load() != 6 ||
		!reflect.DeepEqual(clock.waits, []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute}) {
		t.Fatalf("rate exhaustion looked like permission or success: %+v %v %v", outcome, err, clock.waits)
	}
}

func TestPaginationRejectsChangedScopeAndFilters(t *testing.T) {
	current, err := url.Parse("https://api.github.com/orgs/fixture/secret-scanning/alerts?state=open&per_page=100")
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{
		`<https://outside.example.test/orgs/fixture/secret-scanning/alerts?state=open&per_page=100&page=2>; rel="next"`,
		`<https://api.github.com/orgs/other/secret-scanning/alerts?state=open&per_page=100&page=2>; rel="next"`,
		`<https://api.github.com/orgs/fixture/secret-scanning/alerts?state=closed&per_page=100&page=2>; rel="next"`,
	} {
		if _, err := nextLink(link, current); err == nil {
			t.Fatal("pagination escaped its scope/filter")
		}
	}
	next, err := nextLink(`<https://api.github.com/orgs/fixture/secret-scanning/alerts?state=open&per_page=100&after=opaque-cursor>; rel="next"`, current)
	if err != nil || !strings.Contains(next, "after=opaque-cursor") {
		t.Fatal("cursor pagination was lost")
	}
}
