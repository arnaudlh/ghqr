// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestGraphQLCommentsAndSelectedOperationsCannotConcealMutations(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		operation string
		allowed   bool
	}{
		{"CR comment mutation", "query Read { viewer { login } }\n# comment\rmutation Write { __typename }", "Write", false},
		{"CRLF comment mutation", "query Read { viewer { login } }\r\n# comment\r\nmutation Write { __typename }", "Write", false},
		{"named selection", "query Read { viewer { login } }", "Read", true},
		{"missing selected operation", "query Read { viewer { login } }", "Write", false},
		{"quoted fake operation", `query Read { repository(name: "mutation Write { x }") { id } }`, "Read", true},
		{"block-string fake operation", `query Read { search(query: """# text
mutation Write { x }""") { issueCount } }`, "Read", true},
		{"comment followed by read", "# comment\rquery Read { viewer { login } }", "Read", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"query": tt.query, "operationName": tt.operation})
			if err != nil {
				t.Fatal(err)
			}
			if readOnlyGraphQL(raw) != tt.allowed {
				t.Fatalf("selected-operation guard should allow=%v", tt.allowed)
			}
		})
	}
}

func TestRedactionPreservesExplicitEmptyOrAbsentValues(t *testing.T) {
	raw := []byte(`{"description":"","config":{"secret":"","url":"https://hook.example.test/private"},"password":null,"token":false,"emails":[],"credentials":{}}`)
	clean, _, err := NewRedactor().JSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(clean, &result); err != nil {
		t.Fatal(err)
	}
	config := result["config"].(map[string]any)
	if result["description"] != "" || config["secret"] != "" || result["password"] != nil ||
		result["token"] != false || !reflect.DeepEqual(result["emails"], []any{}) ||
		!reflect.DeepEqual(result["credentials"], map[string]any{}) || config["url"] != "hook.example.test" {
		t.Fatalf("redaction turned absence into nonempty presence: %s", clean)
	}
}

type gatedBudgetClock struct {
	mu       sync.Mutex
	now      time.Time
	observed chan struct{}
	sleeping chan struct{}
	advance  chan struct{}
}

func (c *gatedBudgetClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case c.observed <- struct{}{}:
	default:
	}
	return c.now
}

func (c *gatedBudgetClock) Sleep(ctx context.Context, wait time.Duration) error {
	c.sleeping <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.advance:
		c.mu.Lock()
		c.now = c.now.Add(wait)
		c.mu.Unlock()
		return nil
	}
}

func TestQueuedRequestRechecksPauseAfterAcquiringSlot(t *testing.T) {
	budget, err := NewRequestBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	budget.slots <- struct{}{}
	clock := &gatedBudgetClock{
		now:      time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		observed: make(chan struct{}, 10), sleeping: make(chan struct{}, 1), advance: make(chan struct{}),
	}
	base, err := url.Parse("https://api.github.com/")
	if err != nil {
		t.Fatal(err)
	}
	transport := &readTransport{base: base, budget: budget, clock: clock}
	acquired := make(chan error, 1)
	go func() { acquired <- transport.acquireRequestSlot(context.Background()) }()
	select {
	case <-clock.observed:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not queue")
	}
	transport.pauseUntil(clock.Now().Add(time.Minute))
	<-budget.slots
	select {
	case <-clock.sleeping:
	case <-acquired:
		t.Fatal("queued worker bypassed the published rate pause")
	case <-time.After(5 * time.Second):
		t.Fatal("queued worker did not honor the pause")
	}
	if len(budget.slots) != 0 {
		t.Fatal("rate wait held a request slot")
	}
	close(clock.advance)
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not acquire after the fixture clock advanced")
	}
	<-budget.slots
}
