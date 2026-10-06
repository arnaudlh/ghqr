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
	// replaySource, when non-nil, makes CollectGET/CollectGraphQL serve
	// already-persisted pages from this store instead of making a live HTTP
	// request: no network call is ever made, and every page's original
	// SourceKind/CredentialKind/CollectedAt metadata survives unchanged (so
	// imported-vs-collected provenance is never re-stamped as if this were a
	// fresh collection). A feature with zero replayed pages fails exactly
	// like a genuine live collection failure would (CollectionFailed with an
	// explicit reason), never silently treated as a success. This field is
	// set only via a same-package replay constructor; the live collection
	// path (NewCollectionClient) never populates it, so every existing
	// caller's behavior is completely unchanged.
	replaySource *EvidenceStore
	// originalOutcomes, when non-nil (replay clients only), is the bound,
	// trusted original CollectorOutcome inventory keyed by
	// outcomeIdentityKey -- consulted ONLY by collectFromReplay's own
	// "ran out of stored pages" fallthrough (see that function's own doc),
	// never mutated and never used to alter any actually-stored page's own
	// content/metadata. The live collection path (NewCollectionClient)
	// never populates it.
	originalOutcomes map[string]CollectorOutcome
}

// resolveCollectionEndpointAddress computes the base URL (and, for GraphQL,
// its query path) for a given target/source pair, with no credential
// resolution at all: this is the one platform-routing formula every
// constructor of a *CollectionClient shares, live (NewCollectionClient) or
// replay-only (NewReplayCollectionClient in evidence_replay.go), so the two
// never drift into duplicated, independently-maintained copies of the same
// REST/GraphQL/management-console host-routing rules.
func resolveCollectionEndpointAddress(target Target, source EvidenceSource) (base *url.URL, graphQLPath string, err error) {
	var address string
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
			return nil, "", fmt.Errorf("management evidence only applies to a server target")
		}
		address = "https://" + target.Host + ":8443/manage/v1/"
	default:
		return nil, "", fmt.Errorf("unsupported collection API plane")
	}
	base, err = url.Parse(address)
	if err != nil {
		return nil, "", fmt.Errorf("parse collection endpoint: %w", err)
	}
	return base, graphQLPath, nil
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
	base, graphQLPath, err := resolveCollectionEndpointAddress(target, source)
	if err != nil {
		return nil, err
	}
	var token, username, password string
	kind := target.Credentials.Kind
	if source == ManagementEvidence {
		username = os.Getenv(target.Credentials.ManagementUsernameEnv)
		password = os.Getenv(target.Credentials.ManagementPasswordEnv)
		if username == "" || password == "" {
			return nil, fmt.Errorf("management credential references are unavailable")
		}
		kind = ManagementConsole
	} else {
		if kind == "" || kind == NoCredential {
			kind = NoCredential
		} else {
			token = os.Getenv(target.Credentials.TokenEnv)
			if token == "" {
				return nil, fmt.Errorf("API credential reference is unavailable for the target")
			}
		}
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
	if c.replaySource != nil {
		return c.collectFromReplay(store, scope, collectorID, feature, paginate)
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
		// A read-only peek at the SAME Link header the unmodified pagination
		// logic below also consults, computed here purely to record this
		// page's own terminal-pagination proof in its immutable metadata; it
		// changes no control flow and duplicates no decision the existing
		// next/err handling after the pagination/break checks still makes
		// unchanged. See EvidenceMetadata.PaginationContinues' own doc for
		// the exact true/false/nil tri-state this computes.
		var paginationContinues *bool
		switch {
		case !paginate:
			paginationContinues = boolPtr(false)
		case response == nil:
			paginationContinues = nil
		default:
			peekNext, peekErr := nextLink(response.Header.Get("Link"), request.URL)
			switch {
			case peekErr != nil:
				paginationContinues = nil
			case peekNext != "":
				paginationContinues = boolPtr(true)
			default:
				paginationContinues = boolPtr(false)
			}
		}
		metadata := EvidenceMetadata{
			SchemaVersion: "1", ProfileVersion: c.profile.Version, ProfileSHA256: c.profile.SHA256,
			CollectorID: collectorID, Feature: fmt.Sprintf("%s-page-%06d", feature, outcome.Pages+1),
			Scope: scope, CollectedAt: c.clock.Now(), Endpoint: c.redactor.Text(capture.endpoint),
			SourceKind: c.source, APIVersion: c.profile.APIVersionHeader,
			CredentialKind: c.credentialKind, HTTPStatus: &status, Pages: 1, RecordCount: count,
			Complete: complete, Redactions: redactions, PaginationContinues: paginationContinues,
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

// collectFromReplay serves CollectGET's identity-addressed pages from
// c.replaySource (an already-populated evidence store from a prior
// collection pass) instead of making a live HTTP request, re-persisting each
// found page's exact original bytes and metadata into the active store
// parameter unchanged. It preserves imported-vs-collected provenance
// verbatim (SourceKind/CredentialKind/CollectedAt are never re-stamped as if
// this were a fresh collection) and never falls back to the network: a
// feature with zero replayed pages fails exactly like a genuine live
// collection failure (CollectionFailed, an explicit reason), never silently
// treated as a success. A page recorded incomplete at original collection
// time is replayed as the same CollectionPartial failure a live retry of
// that same incomplete collection would have produced. Pagination stops the
// first time a page is not found in the replay source; this is a faithful
// replay of what was actually persisted, not a re-derivation of whether
// further pages existed but were never collected, which the stored evidence
// shape alone cannot distinguish from a genuine end of pagination.
func (c *CollectionClient) collectFromReplay(store *EvidenceStore, scope Scope, collectorID, feature string, paginate bool) (CollectorOutcome, error) {
	outcome := CollectorOutcome{
		CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: Ready,
		Availability: NotChecked, Status: NotRun, CredentialKind: c.credentialKind, EvidenceRefs: []string{},
	}
	for page := 1; ; page++ {
		raw, metadata, _, loadErr := c.replaySource.LoadJSON(scope, collectorID, pageFeatureName(feature, page))
		if loadErr != nil {
			if page == 1 {
				outcome.Status = CollectionFailed
				outcome.Reason = "no replay evidence is stored for this feature"
				return outcome, fmt.Errorf("replay evidence missing for %s/%s", collectorID, feature)
			}
			break
		}
		ref, saveErr := store.SaveJSON(raw, metadata)
		if saveErr != nil {
			outcome.Status = CollectionFailed
			outcome.Reason = "replayed evidence could not be re-persisted"
			return outcome, saveErr
		}
		outcome.Pages++
		outcome.EvidenceRefs = append(outcome.EvidenceRefs, ref.DataPath, ref.MetadataPath)
		if metadata.HTTPStatus != nil {
			outcome.HTTPStatus = metadata.HTTPStatus
			// Derived identically to the live path's own
			// responseAvailability(status, body) call, not unconditionally
			// forced to Available: a replayed page recorded at original
			// collection time with a non-2xx status (a confident 404, a
			// permission-denied 401/403, and so on) must reproduce that
			// SAME Availability classification on replay, not silently
			// upgrade to Available merely because a stored page was found
			// at all. HTTPStatus alone already carries this information on
			// both paths, but any collector that branches on Availability
			// specifically (not HTTPStatus) deserves a faithful replay too.
			outcome.Availability = responseAvailability(*metadata.HTTPStatus, raw)
		} else {
			// Imported evidence recorded no HTTP status at all (its
			// SourceKind is ImportedEvidence, never a live REST/GraphQL/
			// management response): Available is the only honest
			// classification a status-less, successfully-loaded page can
			// carry.
			outcome.Availability = Available
		}
		if !metadata.Complete {
			outcome.Status = CollectionPartial
			outcome.Reason = "replayed evidence was recorded incomplete at original collection time"
			return outcome, fmt.Errorf("replay evidence incomplete for %s/%s", collectorID, feature)
		}
		if !paginate {
			break
		}
	}
	// Reached only when pagination "ran out" of stored pages for a
	// paginated call (not a page-1 miss, not an incomplete page -- both
	// already returned above): every page actually found replayed intact
	// and complete, and there is simply no further page stored beyond this
	// one. An absence in the replay source alone cannot distinguish two
	// genuinely different cases that look identical from here: pagination
	// may have genuinely, cleanly ended at this exact page, OR the
	// original run's own collection may have failed to continue PAST this
	// exact page (for example an invalid/malformed next-link, or a denied
	// follow-up page) while this page itself still replayed fine. The
	// bound original outcome's own claimed terminal state -- consulted
	// here, never mutated, never inferred from page counts or directory
	// presence -- is the one authoritative source for which case this
	// actually was: an outcome whose own original claim is anything other
	// than a clean CollectionOK/Complete:true finish for this EXACT
	// identity has that exact terminal state (Status/Complete/Reason/
	// Availability/HTTPStatus) faithfully reproduced instead of silently
	// defaulting to a clean finish it never genuinely reached.
	if c.originalOutcomes != nil {
		if original, ok := c.originalOutcomes[outcomeIdentityKey(scope, collectorID, feature)]; ok &&
			(original.Status != CollectionOK || !original.Complete) {
			outcome.Status = original.Status
			outcome.Complete = original.Complete
			outcome.Reason = original.Reason
			outcome.Availability = original.Availability
			outcome.HTTPStatus = original.HTTPStatus
			return outcome, fmt.Errorf("replay evidence for %s/%s genuinely incomplete at original collection "+
				"time (reproducing the original run's own recorded terminal state, not a clean finish)", collectorID, feature)
		}
	}
	outcome.Status = CollectionOK
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
	if c.replaySource != nil {
		replayOutcome, replayErr := c.collectFromReplay(store, scope, collectorID, feature, false)
		if replayErr != nil {
			return replayOutcome, nil, replayErr
		}
		raw, _, _, loadErr := store.LoadJSON(scope, collectorID, pageFeatureName(feature, 1))
		if loadErr != nil {
			return replayOutcome, nil, loadErr
		}
		return replayOutcome, raw, nil
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
		// A GraphQL collection call is never paginated through this
		// REST-style Link-header pagination mechanism at all, so this
		// single page is unconditionally terminal by construction, not
		// merely "no next link observed".
		PaginationContinues: boolPtr(false),
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
