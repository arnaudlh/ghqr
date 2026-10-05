// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxEvidenceResponseBytes = 16 << 20
const maxAssessmentRateRetries = 5

// Clock makes all collection waits and timestamps controllable in fixtures.
type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

// SystemClock uses cancellable real time for explicitly requested live collection.
type SystemClock struct{}

// Now returns the UTC collection time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// Sleep waits without holding a request slot and respects cancellation.
func (SystemClock) Sleep(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RequestBudget is shared by every REST, GraphQL and management client in a run.
type RequestBudget struct {
	slots  chan struct{}
	mu     sync.Mutex
	pauses map[string]time.Time
}

// NewRequestBudget enforces the contractual maximum of four in-flight requests.
func NewRequestBudget(concurrency int) (*RequestBudget, error) {
	if concurrency < 1 || concurrency > 4 {
		return nil, fmt.Errorf("assessment request concurrency must be between 1 and 4")
	}
	return &RequestBudget{slots: make(chan struct{}, concurrency), pauses: map[string]time.Time{}}, nil
}

type requestCapture struct {
	status      int
	body        []byte
	endpoint    string
	attempts    int
	rateLimited bool
}

type captureContextKey struct{}

type readTransport struct {
	base        *url.URL
	graphQLPath string
	token       string
	username    string
	password    string
	budget      *RequestBudget
	clock       Clock
	wrapped     http.RoundTripper
}

func (t *readTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := t.validateRequest(request); err != nil {
		return nil, err
	}
	if request.Body != nil && request.GetBody == nil {
		return nil, fmt.Errorf("read-only query body must support safe retries")
	}
	if request.Body != nil {
		if err := request.Body.Close(); err != nil {
			return nil, fmt.Errorf("close original query body")
		}
	}
	for attempt := 0; attempt <= maxAssessmentRateRetries; attempt++ {
		if err := t.acquireRequestSlot(request.Context()); err != nil {
			return nil, err
		}
		clone, err := t.cloneRequest(request)
		if err != nil {
			<-t.budget.slots
			return nil, err
		}
		response, raw, err := t.roundTrip(clone)
		if err != nil {
			<-t.budget.slots
			return nil, err
		}
		if capture, ok := request.Context().Value(captureContextKey{}).(*requestCapture); ok {
			capture.status = response.StatusCode
			capture.body = raw
			capture.endpoint = clone.URL.String()
			capture.attempts = attempt + 1
			capture.rateLimited = assessmentRateLimited(response, raw)
		}
		limited := assessmentRateLimited(response, raw)
		if limited {
			wait := assessmentRetryDelay(response, t.clock.Now(), attempt)
			t.pauseUntil(t.clock.Now().Add(wait))
		} else {
			t.recordPrimaryBudget(response)
		}
		// Publish the shared pause before a queued request can acquire this slot.
		<-t.budget.slots
		if !limited || attempt == maxAssessmentRateRetries {
			return response, nil
		}
		if err := response.Body.Close(); err != nil {
			return nil, fmt.Errorf("close rate-limited response: %w", err)
		}
	}
	return nil, fmt.Errorf("assessment rate retry loop exhausted unexpectedly")
}

func (t *readTransport) validateRequest(request *http.Request) error {
	if request.URL.Scheme != t.base.Scheme || request.URL.Host != t.base.Host || request.URL.User != nil ||
		!strings.HasPrefix(request.URL.Path, t.base.Path) {
		return fmt.Errorf("assessment request is outside its credential route")
	}
	if request.Method == http.MethodGet {
		if strings.HasSuffix(strings.TrimSuffix(request.URL.Path, "/"), "/sbom/generate-report") {
			return fmt.Errorf("assessment prohibits side-effecting SBOM generation, including GET generation endpoints")
		}
		if request.URL.Path == "/graphql" || request.URL.Path == "/api/graphql" {
			return fmt.Errorf("GraphQL operations require an inspected query body")
		}
		return nil
	}
	if request.Method != http.MethodPost || t.graphQLPath == "" || request.URL.Path != t.graphQLPath || request.GetBody == nil {
		return fmt.Errorf("assessment prohibits REST writes and non-query operations")
	}
	body, err := request.GetBody()
	if err != nil {
		return fmt.Errorf("read query body: %w", err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, maxEvidenceResponseBytes+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || len(raw) > maxEvidenceResponseBytes {
		return fmt.Errorf("query body could not be safely inspected")
	}
	if !readOnlyGraphQL(raw) {
		return fmt.Errorf("assessment only permits read-only GraphQL queries")
	}
	return nil
}

func (t *readTransport) cloneRequest(request *http.Request) (*http.Request, error) {
	clone := request.Clone(request.Context())
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return nil, fmt.Errorf("clone query body: %w", err)
		}
		clone.Body = body
	}
	if t.username != "" {
		clone.SetBasicAuth(t.username, t.password)
	} else if t.token != "" {
		clone.Header.Set("Authorization", "Bearer "+t.token)
	}
	if strings.Contains(clone.URL.Path, "/secret-scanning/alerts") {
		query := clone.URL.Query()
		query.Set("hide_secret", "true")
		clone.URL.RawQuery = query.Encode()
	}
	return clone, nil
}

func (t *readTransport) roundTrip(request *http.Request) (*http.Response, []byte, error) {
	response, err := t.wrapped.RoundTrip(request)
	if err != nil {
		// Transport errors can include proxy credentials or untrusted server text.
		return nil, nil, fmt.Errorf("assessment network request failed")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maxEvidenceResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, nil, fmt.Errorf("assessment response body could not be read")
	}
	if len(raw) > maxEvidenceResponseBytes {
		return nil, nil, fmt.Errorf("assessment response exceeds the evidence size limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, raw, nil
}

func (t *readTransport) waitForBudget(ctx context.Context) error {
	t.budget.mu.Lock()
	reset := t.budget.pauses[t.base.Host]
	t.budget.mu.Unlock()
	if wait := reset.Sub(t.clock.Now()); wait > 0 {
		if err := t.clock.Sleep(ctx, wait); err != nil {
			return fmt.Errorf("wait for assessment request budget: %w", err)
		}
	}
	return nil
}

func (t *readTransport) pauseUntil(reset time.Time) {
	t.budget.mu.Lock()
	defer t.budget.mu.Unlock()
	if reset.After(t.budget.pauses[t.base.Host]) {
		t.budget.pauses[t.base.Host] = reset
	}
}

func (t *readTransport) recordPrimaryBudget(response *http.Response) {
	if response.Header.Get("X-RateLimit-Remaining") != "0" {
		return
	}
	epoch, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64)
	if err == nil {
		t.pauseUntil(time.Unix(epoch, 0))
	}
}

func assessmentRateLimited(response *http.Response, raw []byte) bool {
	if response.StatusCode == http.StatusOK {
		var envelope struct {
			Errors []struct {
				Type    string `json:"type"`
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Errors) == 0 {
			return false
		}
		for _, item := range envelope.Errors {
			message := strings.ToLower(item.Message)
			if item.Type == "RATE_LIMITED" || item.Code == "RATE_LIMITED" ||
				strings.Contains(message, "secondary rate limit") ||
				strings.Contains(message, "api rate limit exceeded") ||
				response.Header.Get("X-RateLimit-Remaining") == "0" {
				return true
			}
		}
		return false
	}
	if response.StatusCode != http.StatusForbidden && response.StatusCode != http.StatusTooManyRequests {
		return false
	}
	message := strings.ToLower(string(raw))
	return response.StatusCode == http.StatusTooManyRequests || response.Header.Get("Retry-After") != "" ||
		response.Header.Get("X-RateLimit-Remaining") == "0" ||
		strings.Contains(message, "secondary rate limit") || strings.Contains(message, "abuse detection")
}

func assessmentRetryDelay(response *http.Response, now time.Time, attempt int) time.Duration {
	wait := time.Minute * time.Duration(1<<attempt)
	if seconds, err := strconv.ParseInt(response.Header.Get("Retry-After"), 10, 64); err == nil && seconds > 0 {
		if delay := time.Duration(seconds) * time.Second; delay > wait {
			wait = delay
		}
	} else if date, err := http.ParseTime(response.Header.Get("Retry-After")); err == nil && date.Sub(now) > wait {
		wait = date.Sub(now)
	}
	if epoch, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		if delay := time.Unix(epoch, 0).Sub(now); delay > wait {
			wait = delay
		}
	}
	return wait
}
