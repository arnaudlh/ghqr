// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestGraphQLRateEnvelopeOnHTTP200UsesRetryBudget(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			writer.Header().Set("X-RateLimit-Remaining", "0")
			if _, err := writer.Write([]byte(`{"errors":[{"type":"RATE_LIMITED","message":"secondary rate limit; private text"}]}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := writer.Write([]byte(`{"data":{"viewer":{"login":"fixture"}}}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	clock := &fixtureClock{now: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}
	client := collectionFixtureClient(t, server, fixtureBudget(t), clock)
	client.http.Transport.(*readTransport).graphQLPath = "/graphql"
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/graphql",
		bytes.NewReader([]byte(`{"query":"query { viewer { login } }"}`)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read query response: %v %v", readErr, closeErr)
	}
	var result struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Data) == 0 || calls.Load() != 3 ||
		!reflect.DeepEqual(clock.waits, []time.Duration{time.Minute, 2 * time.Minute}) {
		t.Fatalf("HTTP200 GraphQL error envelope was treated as success: %s %v", raw, clock.waits)
	}
}

func TestSuccessfulGraphQLResponseAtZeroBudgetIsNotRetried(t *testing.T) {
	response := &http.Response{StatusCode: 200, Header: http.Header{"X-Ratelimit-Remaining": []string{"0"}}}
	if assessmentRateLimited(response, []byte(`{"data":{"viewer":{"id":"fixture"}}}`)) {
		t.Fatal("a successful exhausted-budget query was repeated")
	}
	if !assessmentRateLimited(response, []byte(`{"errors":[{"type":"RATE_LIMITED"}]}`)) {
		t.Fatal("an exhausted-budget GraphQL error was not recognized")
	}
}
