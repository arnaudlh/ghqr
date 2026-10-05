// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v83/github"
	"github.com/microsoft/ghqr/internal/config"
)

// EvidenceSource distinguishes live API evidence from explicitly imported material.
type EvidenceSource string

// Each source keeps its credential route and provenance independent.
const (
	RESTEvidence       EvidenceSource = "rest"
	GraphQLEvidence    EvidenceSource = "graphql"
	ManagementEvidence EvidenceSource = "manage"
	ImportedEvidence   EvidenceSource = "import"
)

// CollectionClient binds one API plane to a host and a run-wide request budget.
type CollectionClient struct {
	http           *http.Client
	base           *url.URL
	source         EvidenceSource
	credentialKind CredentialKind
	profile        *Profile
	clock          Clock
	redactor       *Redactor
}

// NewCollectionClient resolves only explicit per-host environment references.
// It does not discover accounts, invoke endpoints or reuse cross-host GH_TOKEN fallbacks.
func NewCollectionClient(target Target, source EvidenceSource, profile *Profile, budget *RequestBudget, clock Clock) (*CollectionClient, error) {
	if err := validateTarget(target); err != nil {
		return nil, fmt.Errorf("validate collection target: %w", err)
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate collection profile: %w", err)
	}
	if budget == nil {
		return nil, fmt.Errorf("collection client requires a shared request budget")
	}
	if clock == nil {
		clock = SystemClock{}
	}
	var address, graphQLPath, token, username, password string
	kind := target.Credentials.Kind
	switch source {
	case RESTEvidence:
		address = config.RESTBaseURL(target.Host)
		if target.Deployment == Server {
			address = "https://" + target.Host + "/api/v3/"
		}
	case GraphQLEvidence:
		address = "https://api." + target.Host + "/"
		graphQLPath = "/graphql"
		if target.Host == "github.com" {
			address = "https://api.github.com/"
		}
		if target.Deployment == Server {
			address = "https://" + target.Host + "/"
			graphQLPath = "/api/graphql"
		}
	case ManagementEvidence:
		if target.Deployment != Server {
			return nil, fmt.Errorf("management evidence only applies to a server target")
		}
		address = "https://" + target.Host + ":8443/manage/v1/"
		username = os.Getenv(target.Credentials.ManagementUsernameEnv)
		password = os.Getenv(target.Credentials.ManagementPasswordEnv)
		if username == "" || password == "" {
			return nil, fmt.Errorf("management credential references are unavailable")
		}
		kind = ManagementConsole
	default:
		return nil, fmt.Errorf("unsupported collection API plane")
	}
	if source != ManagementEvidence {
		if kind == "" || kind == NoCredential {
			kind = NoCredential
		} else {
			token = os.Getenv(target.Credentials.TokenEnv)
			if token == "" {
				return nil, fmt.Errorf("API credential reference is unavailable for the target")
			}
		}
	}
	base, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("parse collection endpoint: %w", err)
	}
	transport := &readTransport{
		base: base, graphQLPath: graphQLPath, token: token, username: username, password: password,
		budget: budget, clock: clock, wrapped: http.DefaultTransport,
	}
	return &CollectionClient{
		http: &http.Client{Transport: transport, Timeout: 2 * time.Minute,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		base: base, source: source, credentialKind: kind, profile: profile, clock: clock,
		redactor: NewRedactor(token, password),
	}, nil
}

// CollectGET retains every page and failure as sanitized, host-qualified evidence.
// A failed or missing page leaves the feature incomplete, even after successful pages.
func (c *CollectionClient) CollectGET(ctx context.Context, store *EvidenceStore, scope Scope, collectorID, feature, endpoint, arrayField string, paginate bool) (CollectorOutcome, error) {
	outcome := CollectorOutcome{
		CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: Ready,
		Availability: NotChecked, Status: NotRun, CredentialKind: c.credentialKind, EvidenceRefs: []string{},
	}
	if store == nil {
		return outcome, fmt.Errorf("collection requires an evidence store")
	}
	if err := validateEvidenceIdentity(scope, collectorID, feature); err != nil {
		return outcome, err
	}
	if scope.Host != c.base.Hostname() && "api."+scope.Host != c.base.Hostname() {
		return outcome, fmt.Errorf("collection scope is outside its host credential route")
	}
	next := endpoint
	seen := map[string]bool{}
	for next != "" {
		if seen[next] {
			outcome.Status = CollectionPartial
			outcome.Reason = "pagination cycle detected"
			return outcome, fmt.Errorf("collection pagination cycle detected")
		}
		seen[next] = true
		// A fresh SDK request client keeps its real-clock rate cache out of the shared fixtureable transport.
		sdk := github.NewClient(c.http)
		sdk.BaseURL = c.base
		request, err := sdk.NewRequest(http.MethodGet, next, nil)
		if err != nil {
			outcome.Status = CollectionFailed
			outcome.Reason = "endpoint request could not be constructed"
			return outcome, fmt.Errorf("construct collection request")
		}
		query := request.URL.Query()
		if paginate {
			query.Set("per_page", "100")
		}
		request.URL.RawQuery = query.Encode()
		request.Header.Set("X-GitHub-Api-Version", c.profile.APIVersionHeader)
		request.Header.Set("Accept", "application/vnd.github+json")
		capture := &requestCapture{}
		requestCtx := context.WithValue(ctx, captureContextKey{}, capture)
		var buffer bytes.Buffer
		response, requestErr := sdk.Do(requestCtx, request, &buffer)
		if capture.status == 0 {
			outcome.Status = CollectionFailed
			outcome.Reason = "request failed before an HTTP response was observed"
			return outcome, fmt.Errorf("collection request failed without an HTTP response")
		}
		status := capture.status
		outcome.HTTPStatus = &status
		outcome.Availability = responseAvailability(status, capture.body)
		if capture.rateLimited {
			outcome.Availability = RateLimited
		}
		clean, redactions, err := c.redactor.JSON(capture.body)
		if err != nil {
			outcome.Status = CollectionFailed
			outcome.Reason = "response is not supported structured JSON evidence"
			return outcome, err
		}
		count, countErr := responseRecordCount(clean, arrayField, paginate)
		complete := requestErr == nil && countErr == nil && status >= 200 && status < 300
		metadata := EvidenceMetadata{
			SchemaVersion: "1", ProfileVersion: c.profile.Version, ProfileSHA256: c.profile.SHA256,
			CollectorID: collectorID, Feature: fmt.Sprintf("%s-page-%06d", feature, outcome.Pages+1),
			Scope: scope, CollectedAt: c.clock.Now(), Endpoint: c.redactor.Text(capture.endpoint),
			SourceKind: c.source, APIVersion: c.profile.APIVersionHeader,
			CredentialKind: c.credentialKind, HTTPStatus: &status, Pages: 1, RecordCount: count,
			Complete: complete, Redactions: redactions,
		}
		ref, err := store.SaveJSON(clean, metadata)
		if err != nil {
			outcome.Status = CollectionFailed
			outcome.Reason = "sanitized evidence could not be persisted"
			return outcome, err
		}
		outcome.Pages++
		outcome.EvidenceRefs = append(outcome.EvidenceRefs, ref.DataPath, ref.MetadataPath)
		if !complete {
			outcome.Status = CollectionPartial
			outcome.Reason = "one or more pages failed access or required response-shape validation"
			return outcome, fmt.Errorf("collection feature is incomplete (HTTP %d)", status)
		}
		if !paginate {
			break
		}
		if response == nil {
			outcome.Status = CollectionPartial
			outcome.Reason = "pagination response metadata is missing"
			return outcome, fmt.Errorf("collection pagination metadata is missing")
		}
		next, err = nextLink(response.Header.Get("Link"), request.URL)
		if err != nil {
			outcome.Status = CollectionPartial
			outcome.Reason = "pagination next link is invalid"
			return outcome, err
		}
	}
	outcome.Status = CollectionOK
	outcome.Availability = Available
	outcome.Complete = true
	return outcome, nil
}

// CollectGraphQL executes a single read-only GraphQL query (the shared read
// transport independently re-validates it is a read-only, single-operation
// query before it ever reaches the network) and stores its sanitized
// response as one evidence object. Unlike CollectGET, GraphQL has no REST
// Link-header pagination: a query needing more results than fits in one
// response uses a larger first/last value or a follow-up query with an
// explicit cursor variable, which is a caller concern, not this method's.
// The CollectionClient must have been constructed with GraphQLEvidence; its
// relative request path is derived from the shared read transport's
// configured graphQLPath ("graphql" for Cloud, "api/graphql" for Server), not
// hardcoded here, so Cloud/Server routing stays centralized in one place.
func (c *CollectionClient) CollectGraphQL(ctx context.Context, store *EvidenceStore, scope Scope, collectorID, feature, query string,
	variables map[string]any) (CollectorOutcome, []byte, error) {
	outcome := CollectorOutcome{
		CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: Ready,
		Availability: NotChecked, Status: NotRun, CredentialKind: c.credentialKind, EvidenceRefs: []string{},
	}
	if store == nil {
		return outcome, nil, fmt.Errorf("collection requires an evidence store")
	}
	if c.source != GraphQLEvidence {
		return outcome, nil, fmt.Errorf("CollectGraphQL requires a GraphQL-sourced collection client")
	}
	if err := validateEvidenceIdentity(scope, collectorID, feature); err != nil {
		return outcome, nil, err
	}
	if scope.Host != c.base.Hostname() && "api."+scope.Host != c.base.Hostname() {
		return outcome, nil, fmt.Errorf("collection scope is outside its host credential route")
	}
	transport, ok := c.http.Transport.(*readTransport)
	if !ok || transport.graphQLPath == "" {
		return outcome, nil, fmt.Errorf("GraphQL collection client is missing its configured query path")
	}
	sdk := github.NewClient(c.http)
	sdk.BaseURL = c.base
	body := map[string]any{"query": query, "variables": variables}
	request, err := sdk.NewRequest(http.MethodPost, strings.TrimPrefix(transport.graphQLPath, "/"), body)
	if err != nil {
		outcome.Status = CollectionFailed
		outcome.Reason = "GraphQL request could not be constructed"
		return outcome, nil, fmt.Errorf("construct GraphQL collection request")
	}
	request.Header.Set("X-GitHub-Api-Version", c.profile.APIVersionHeader)
	request.Header.Set("Accept", "application/vnd.github+json")
	capture := &requestCapture{}
	requestCtx := context.WithValue(ctx, captureContextKey{}, capture)
	var buffer bytes.Buffer
	_, requestErr := sdk.Do(requestCtx, request, &buffer)
	if capture.status == 0 {
		outcome.Status = CollectionFailed
		outcome.Reason = "request failed before an HTTP response was observed"
		return outcome, nil, fmt.Errorf("GraphQL collection request failed without an HTTP response")
	}
	status := capture.status
	outcome.HTTPStatus = &status
	outcome.Availability = responseAvailability(status, capture.body)
	if capture.rateLimited {
		outcome.Availability = RateLimited
	}
	clean, redactions, err := c.redactor.JSON(capture.body)
	if err != nil {
		outcome.Status = CollectionFailed
		outcome.Reason = "response is not supported structured JSON evidence"
		return outcome, nil, err
	}
	complete := requestErr == nil && status >= 200 && status < 300
	metadata := EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: c.profile.Version, ProfileSHA256: c.profile.SHA256,
		CollectorID: collectorID, Feature: pageFeatureName(feature, 1),
		Scope: scope, CollectedAt: c.clock.Now(), Endpoint: c.redactor.Text(capture.endpoint),
		SourceKind: c.source, APIVersion: c.profile.APIVersionHeader,
		CredentialKind: c.credentialKind, HTTPStatus: &status, Pages: 1, Complete: complete, Redactions: redactions,
	}
	ref, err := store.SaveJSON(clean, metadata)
	if err != nil {
		outcome.Status = CollectionFailed
		outcome.Reason = "sanitized evidence could not be persisted"
		return outcome, nil, err
	}
	outcome.Pages = 1
	outcome.EvidenceRefs = append(outcome.EvidenceRefs, ref.DataPath, ref.MetadataPath)
	if !complete {
		outcome.Status = CollectionPartial
		outcome.Reason = "the query failed access or returned a non-2xx response"
		return outcome, clean, fmt.Errorf("GraphQL collection is incomplete (HTTP %d)", status)
	}
	outcome.Status = CollectionOK
	outcome.Complete = true
	return outcome, clean, nil
}

func responseAvailability(status int, raw []byte) Availability {
	response := &http.Response{StatusCode: status, Header: http.Header{}}
	if assessmentRateLimited(response, raw) {
		return RateLimited
	}
	switch {
	case status >= 200 && status < 300:
		return Available
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return MissingPermission
	case status == http.StatusNotFound:
		return AmbiguousNotFound
	case status == http.StatusGone:
		return EndpointUnavailable
	default:
		return RequestFailed
	}
}

func responseRecordCount(raw []byte, arrayField string, required bool) (*int, error) {
	var value json.RawMessage = raw
	if arrayField != "" {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, fmt.Errorf("response does not contain the required collection object")
		}
		var exists bool
		value, exists = object[arrayField]
		if !exists {
			return nil, fmt.Errorf("response collection field is absent")
		}
	}
	var records []json.RawMessage
	if err := json.Unmarshal(value, &records); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		if required || arrayField != "" {
			return nil, fmt.Errorf("response does not contain a known collection array")
		}
		return nil, nil
	}
	count := len(records)
	return &count, nil
}

func nextLink(header string, current *url.URL) (string, error) {
	for _, entry := range strings.Split(header, ",") {
		parts := strings.Split(entry, ";")
		hasNext := false
		for _, parameter := range parts[1:] {
			parameter = strings.TrimSpace(parameter)
			if strings.HasPrefix(parameter, "rel=") {
				for _, relation := range strings.Fields(strings.Trim(strings.TrimPrefix(parameter, "rel="), `"`)) {
					if relation == "next" {
						hasNext = true
					}
				}
			}
		}
		if !hasNext {
			continue
		}
		address := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(address, "<") || !strings.HasSuffix(address, ">") {
			return "", fmt.Errorf("pagination link is malformed")
		}
		next, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(address, "<"), ">"))
		if err != nil {
			return "", fmt.Errorf("pagination link is invalid")
		}
		next = current.ResolveReference(next)
		if next.Scheme != current.Scheme || next.Host != current.Host || next.User != nil || next.Path != current.Path {
			return "", fmt.Errorf("pagination link is outside its credential origin")
		}
		for key, values := range current.Query() {
			switch key {
			case "page", "after", "before", "cursor", "startIndex":
				continue
			}
			if strings.Join(next.Query()[key], "\x00") != strings.Join(values, "\x00") {
				return "", fmt.Errorf("pagination changed the collection filter")
			}
		}
		return next.String(), nil
	}
	return "", nil
}
