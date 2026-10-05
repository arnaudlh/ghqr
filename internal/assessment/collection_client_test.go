// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func (c *fixtureClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixtureClock) Sleep(ctx context.Context, wait time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, wait)
	c.now = c.now.Add(wait)
	return nil
}

func collectionFixtureClient(t *testing.T, server *httptest.Server, budget *RequestBudget, clock Clock) *CollectionClient {
	t.Helper()
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	transport := &readTransport{base: base, budget: budget, clock: clock, wrapped: server.Client().Transport}
	return &CollectionClient{
		http: &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		base: base, source: RESTEvidence, credentialKind: NoCredential, profile: profile, clock: clock, redactor: NewRedactor(),
	}
}

func fixtureBudget(t *testing.T) *RequestBudget {
	t.Helper()
	budget, err := NewRequestBudget(4)
	if err != nil {
		t.Fatal(err)
	}
	return budget
}

func TestCollectionFollowsAllPagesAndRetainsPerPageProvenance(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("per_page") != "100" {
			t.Error("collection did not request the full page size")
		}
		count := 100
		if request.URL.Query().Get("page") == "2" {
			count = 25
		} else {
			writer.Header().Set("Link", "<"+server.URL+`/orgs/fixture/repos?page=2&per_page=100>; rel="next"`)
		}
		records := make([]map[string]int, count)
		for index := range records {
			records[index] = map[string]int{"id": index}
		}
		if err := json.NewEncoder(writer).Encode(records); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture"}
	result, err := client.CollectGET(context.Background(), store, scope, "org.repos", "repos", "orgs/fixture/repos", "", true)
	if err != nil || !result.Complete || result.Status != CollectionOK || result.Pages != 2 {
		t.Fatalf("paginated collection incomplete: %+v %v", result, err)
	}
	total := 0
	for page := 1; page <= 2; page++ {
		_, metadata, _, err := store.LoadJSON(scope, "org.repos", fmt.Sprintf("repos-page-%06d", page))
		if err != nil || metadata.RecordCount == nil || metadata.HTTPStatus == nil || *metadata.HTTPStatus != 200 ||
			metadata.CredentialKind != NoCredential || metadata.SourceKind != RESTEvidence {
			t.Fatalf("page provenance missing: %+v %v", metadata, err)
		}
		total += *metadata.RecordCount
	}
	if total != 125 {
		t.Fatalf("pagination lost records beyond 100: %d", total)
	}
}

func TestCollectionDoesNotHideMissingPagesOrSecretsInSuccessfulAlerts(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   Availability
	}{
		{"permission", http.StatusForbidden, MissingPermission},
		{"concealed endpoint", http.StatusNotFound, AmbiguousNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Query().Get("hide_secret") != "true" {
					t.Error("secret values were not explicitly hidden at the request boundary")
				}
				if request.URL.Query().Get("page") == "2" {
					writer.WriteHeader(tt.status)
					if _, err := writer.Write([]byte(`{"message":"dummy-sensitive-value for person@example.test"}`)); err != nil {
						t.Error(err)
					}
					return
				}
				writer.Header().Set("Link", "<"+server.URL+`/orgs/fixture/secret-scanning/alerts?page=2&per_page=100>; rel="next"`)
				if _, err := writer.Write([]byte(`[{"secret":"dummy-sensitive-value","resolution_comment":"revoked dummy-sensitive-value","resolved_by":{"email":"person@example.test"},"state":"open","secret_type":"generic"}]`)); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
			store := evidenceFixtureStore(t, t.TempDir(), nil)
			scope := Scope{client.base.Hostname(), OrganizationScope, "fixture"}
			result, err := client.CollectGET(context.Background(), store, scope, "org.secret_scanning_alerts", "open",
				"orgs/fixture/secret-scanning/alerts", "", true)
			if err == nil || result.Complete || result.Status != CollectionPartial || result.Availability != tt.want || result.Pages != 2 {
				t.Fatalf("missing page looked successful: %+v %v", result, err)
			}
			for page := 1; page <= 2; page++ {
				raw, _, _, err := store.LoadJSON(scope, result.CollectorID, fmt.Sprintf("open-page-%06d", page))
				if err != nil {
					t.Fatal(err)
				}
				if bytesContainAny(raw, "dummy-sensitive-value", "person@example.test") {
					t.Fatal("secret or email survived a successful/error collection page")
				}
			}
		})
	}
}

func TestRateRetriesUseFixtureClockAndDistinguishPermission(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		message   string
		wantCalls int
		wantWaits []time.Duration
	}{
		{"429", 429, `{"message":"rate limit"}`, 3, []time.Duration{time.Minute, 2 * time.Minute}},
		{"message-only secondary", 403, `{"message":"secondary rate limit"}`, 3, []time.Duration{time.Minute, 2 * time.Minute}},
		{"permission is not retried", 403, `{"message":"forbidden"}`, 1, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				call := calls.Add(1)
				if call <= 2 {
					writer.WriteHeader(tt.status)
					if _, err := writer.Write([]byte(tt.message)); err != nil {
						t.Error(err)
					}
					return
				}
				if _, err := writer.Write([]byte(`{"ok":true}`)); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			clock := &fixtureClock{now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}
			client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
			store := evidenceFixtureStore(t, t.TempDir(), nil)
			scope := Scope{client.base.Hostname(), OrganizationScope, "fixture"}
			_, err := client.CollectGET(context.Background(), store, scope, "org.settings", "settings", "orgs/fixture", "", false)
			if tt.wantCalls == 3 && err != nil {
				t.Fatal(err)
			}
			if calls.Load() != int32(tt.wantCalls) || !reflect.DeepEqual(clock.waits, tt.wantWaits) {
				t.Fatalf("retry calls/waits = %d %v, want %d %v", calls.Load(), clock.waits, tt.wantCalls, tt.wantWaits)
			}
		})
	}
}

func TestAllCollectionRequestsShareTheFourRequestLimit(t *testing.T) {
	var active, peak atomic.Int32
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for observed := peak.Load(); current > observed; observed = peak.Load() {
			if peak.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		if _, err := writer.Write([]byte(`{"observed":true}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture"}
	var workers sync.WaitGroup
	for index := 0; index < 16; index++ {
		workers.Go(func() {
			if _, err := client.CollectGET(context.Background(), store, scope, "org.settings", fmt.Sprintf("settings-%d", index),
				"orgs/fixture", "", false); err != nil {
				t.Error(err)
			}
		})
	}
	for index := 0; index < 4; index++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("shared request slots did not become active")
		}
	}
	close(release)
	workers.Wait()
	if peak.Load() != 4 {
		t.Fatalf("maximum in-flight requests = %d, want 4", peak.Load())
	}
}

func bytesContainAny(data []byte, values ...string) bool {
	for _, value := range values {
		if strings.Contains(string(data), value) {
			return true
		}
	}
	return false
}
