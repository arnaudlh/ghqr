// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package assessment defines the versioned, evidence-backed assessment workflow,
// independently of the legacy scan recommendation model.
package assessment

import (
	"fmt"
	"math"
	"time"
)

// Automation describes the assessment profile's collection and confirmation level.
type Automation string

// Profile automation levels are offering classifications, not framework mandates.
const (
	Full    Automation = "Full"
	Partial Automation = "Partial"
	Manual  Automation = "Manual"
)

// Origin preserves the distinction between framework statements and extensions.
type Origin string

// Supported origins retain the supplied profile's exact labels.
const (
	FrameworkChecklist Origin = "Framework checklist"
	SecurityDeepDive   Origin = "Security deep dive"
)

// State is an assessment state, not a legacy recommendation identifier.
type State string

// Assessment states distinguish missing evidence from a negative finding.
const (
	Implemented          State = "IMPLEMENTED"
	PartiallyImplemented State = "PARTIAL"
	NotImplemented       State = "NOT_IMPLEMENTED"
	NotApplicable        State = "N/A"
	NotAssessed          State = "NOT_ASSESSED"
)

// Validate rejects states outside the assessment export contract.
func (s State) Validate() error {
	switch s {
	case Implemented, PartiallyImplemented, NotImplemented, NotApplicable, NotAssessed:
		return nil
	default:
		return fmt.Errorf("unsupported assessment state %q", s)
	}
}

// Availability records observed access to one collector or feature.
type Availability string

// An unprobed or concealed endpoint is never assumed available or inapplicable.
const (
	NotChecked          Availability = "not-checked"
	Available           Availability = "ok"
	MissingPermission   Availability = "missing-permission"
	Inapplicable        Availability = "not-applicable"
	EndpointUnavailable Availability = "endpoint-unavailable"
	AmbiguousNotFound   Availability = "ambiguous-not-found"
	RateLimited         Availability = "rate-limited"
	RequestFailed       Availability = "failed"
)

// Readiness describes implemented capability independently of runtime access.
type Readiness string

// Readiness values must not be used as successful preflight results.
const (
	Unimplemented Readiness = "unimplemented"
	Ready         Readiness = "implemented"
	ImportOnly    Readiness = "import-only"
)

// OutcomeStatus records collection completeness separately from permissions.
type OutcomeStatus string

// Collection outcomes include an explicit state for work that has not run.
const (
	NotRun            OutcomeStatus = "not-run"
	CollectionOK      OutcomeStatus = "succeeded"
	CollectionPartial OutcomeStatus = "partial"
	CollectionFailed  OutcomeStatus = "failed"
)

// CredentialKind identifies the credential route without recording a secret.
type CredentialKind string

// Management Console credentials are distinct from GitHub API credentials.
const (
	NoCredential    CredentialKind = "none"
	ClassicPAT      CredentialKind = "classic-pat"
	FineGrainedPAT  CredentialKind = "fine-grained-pat"
	AppInstallation CredentialKind = "app-installation"
	// OAuthUser is a GitHub OAuth App user-to-server token (the `gho_`
	// prefix family): an ordinary Bearer-authenticated, read-only REST/
	// GraphQL credential route, identical in transport terms to
	// ClassicPAT/FineGrainedPAT -- it is its own distinct kind, never
	// relabeled as ClassicPAT, because SCIM's own documented authentication
	// contract is narrower than "any Bearer token" (see
	// FetchEnterpriseSCIMUsers' own ClassicPAT-only gate) and a genuine
	// credential-kind record must never claim a narrower route's
	// authorization than what was actually used.
	OAuthUser         CredentialKind = "oauth-user"
	ManagementConsole CredentialKind = "management-console"
)

// EvidenceMetadata is the provenance sidecar contract for a raw evidence object.
type EvidenceMetadata struct {
	SchemaVersion  string         `json:"schema_version"`
	ProfileVersion string         `json:"profile_version"`
	ProfileSHA256  string         `json:"profile_sha256"`
	CollectorID    string         `json:"collector_id"`
	Feature        string         `json:"feature"`
	Scope          Scope          `json:"scope"`
	CollectedAt    time.Time      `json:"collected_at"`
	Endpoint       string         `json:"endpoint"`
	SourceKind     EvidenceSource `json:"source_kind"`
	APIVersion     string         `json:"api_version"`
	CredentialKind CredentialKind `json:"credential_kind"`
	HTTPStatus     *int           `json:"http_status"`
	Pages          int            `json:"pages"`
	RecordCount    *int           `json:"record_count"`
	ContentSHA256  string         `json:"content_sha256"`
	Complete       bool           `json:"complete"`
	Redactions     []string       `json:"redactions"`
	WindowStart    *time.Time     `json:"window_start,omitempty"`
	WindowEnd      *time.Time     `json:"window_end,omitempty"`
	// PaginationContinues is a tri-state terminal-pagination proof,
	// recorded once per page at collection time from that page's own Link
	// header: true means a valid Link rel="next" was genuinely present,
	// proving pagination was not yet done after this page (regardless of
	// whether that next page was later fetched successfully -- a next page
	// that then fails access/validation is exactly how a genuine
	// partial-pagination outcome arises); false means this page's response
	// was validly checked and genuinely carried no next link (or
	// pagination was never requested for this call at all -- a
	// non-paginated single fetch has no "further page" concept to begin
	// with, by construction, not merely "none observed"); nil means
	// genuinely unknown and must never be treated as equivalent to false:
	// a page collected before this field existed (an older stored evidence
	// bundle, which simply never recorded it, decoding to nil rather than
	// a false the JSON schema never actually asserted) and a page whose
	// Link header could not even be parsed (a malformed header still often
	// indicates the server WAS trying to express a next link, so this is
	// never proof pagination ended there either) both decode/compute to
	// nil, not false -- only a genuinely checked, valid, empty Link header
	// (or an explicitly non-paginated call) ever earns a confident false.
	PaginationContinues *bool `json:"pagination_continues,omitempty"`
}

// CollectorOutcome is scoped to a host, collector and feature, not a whole token.
type CollectorOutcome struct {
	CollectorID    string         `json:"collector_id"`
	Feature        string         `json:"feature"`
	Scope          Scope          `json:"scope"`
	Readiness      Readiness      `json:"readiness"`
	Availability   Availability   `json:"availability"`
	Status         OutcomeStatus  `json:"status"`
	HTTPStatus     *int           `json:"http_status"`
	CredentialKind CredentialKind `json:"credential_kind"`
	Pages          int            `json:"pages"`
	Complete       bool           `json:"complete"`
	EvidenceRefs   []string       `json:"evidence_refs"`
	Reason         string         `json:"reason"`
}

// MetricStatus distinguishes known values from unavailable or inapplicable data.
type MetricStatus string

// Zero is a known number only when the evidence establishes it.
const (
	MetricKnown        MetricStatus = "known"
	MetricUnavailable  MetricStatus = "unavailable"
	MetricInapplicable MetricStatus = "not-applicable"
)

// MetricValue is a typed, nullable value with its population and provenance.
type MetricValue struct {
	Status       MetricStatus        `json:"status"`
	Number       *float64            `json:"number,omitempty"`
	Boolean      *bool               `json:"boolean,omitempty"`
	Text         *string             `json:"text,omitempty"`
	List         *[]string           `json:"list,omitempty"`
	Dictionary   *map[string]float64 `json:"dictionary,omitempty"`
	Numerator    *float64            `json:"numerator,omitempty"`
	Denominator  *float64            `json:"denominator,omitempty"`
	Baseline     *float64            `json:"baseline,omitempty"`
	Current      *float64            `json:"current,omitempty"`
	Population   string              `json:"population"`
	Sampled      bool                `json:"sampled"`
	EvidenceRefs []string            `json:"evidence_refs"`
	Reason       string              `json:"reason,omitempty"`
}

// Validate rejects unknown values disguised as false or zero.
func (v MetricValue) Validate() error {
	if (v.Baseline == nil) != (v.Current == nil) {
		return fmt.Errorf("signed change metrics require both baseline and current observations")
	}
	if v.Baseline != nil {
		if math.IsNaN(*v.Baseline) || math.IsNaN(*v.Current) ||
			math.IsInf(*v.Baseline, 0) || math.IsInf(*v.Current, 0) || *v.Baseline < 0 || *v.Current < 0 {
			return fmt.Errorf("signed change observations must be finite and nonnegative")
		}
		if v.Numerator != nil || v.Denominator != nil {
			return fmt.Errorf("signed change and coverage ratio populations cannot be combined")
		}
	}
	if (v.Numerator == nil) != (v.Denominator == nil) {
		return fmt.Errorf("ratio metrics require both numerator and denominator")
	}
	if v.Numerator != nil {
		if math.IsNaN(*v.Numerator) || math.IsNaN(*v.Denominator) ||
			math.IsInf(*v.Numerator, 0) || math.IsInf(*v.Denominator, 0) ||
			*v.Numerator < 0 || *v.Denominator < 0 || *v.Numerator > *v.Denominator {
			return fmt.Errorf("metric ratio requires finite valid population counts")
		}
	}
	values := 0
	if v.Number != nil {
		values++
		if math.IsNaN(*v.Number) || math.IsInf(*v.Number, 0) {
			return fmt.Errorf("metric number must be finite")
		}
	}
	if v.Boolean != nil {
		values++
	}
	if v.Text != nil {
		values++
	}
	if v.List != nil {
		values++
		if *v.List == nil {
			return fmt.Errorf("known list payload must be an array, not null")
		}
	}
	if v.Dictionary != nil {
		values++
		if *v.Dictionary == nil {
			return fmt.Errorf("known dictionary payload must be an object, not null")
		}
		for key, number := range *v.Dictionary {
			if key == "" || math.IsNaN(number) || math.IsInf(number, 0) {
				return fmt.Errorf("dictionary entries require nonempty keys and finite numbers")
			}
		}
	}
	switch v.Status {
	case MetricKnown:
		if values != 1 {
			return fmt.Errorf("known metric requires exactly one typed value")
		}
		if v.Denominator != nil && (*v.Denominator <= 0 || math.IsNaN(*v.Denominator) || math.IsInf(*v.Denominator, 0)) {
			return fmt.Errorf("known metric requires a finite positive denominator")
		}
		if v.Numerator != nil && v.Number == nil {
			return fmt.Errorf("known ratio metric requires a numeric value")
		}
		if v.Baseline != nil && (*v.Baseline == 0 || v.Number == nil) {
			return fmt.Errorf("known signed change requires a positive baseline and numeric value")
		}
	case MetricUnavailable, MetricInapplicable:
		if values != 0 || v.Reason == "" {
			return fmt.Errorf("unavailable metric requires a reason and no typed value")
		}
	default:
		return fmt.Errorf("unknown metric status %q", v.Status)
	}
	return nil
}

// Percentage computes a pooled ratio; an empty population remains unknown.
func Percentage(numerator, denominator float64, population string) (MetricValue, error) {
	if math.IsNaN(numerator) || math.IsNaN(denominator) || math.IsInf(numerator, 0) || math.IsInf(denominator, 0) ||
		numerator < 0 || denominator < 0 || numerator > denominator {
		return MetricValue{}, fmt.Errorf("invalid percentage numerator or denominator")
	}
	value := MetricValue{
		Numerator: &numerator, Denominator: &denominator, Population: population,
		EvidenceRefs: []string{},
	}
	if denominator == 0 {
		value.Status = MetricUnavailable
		value.Reason = "population has zero eligible observations"
		return value, nil
	}

	percentage := numerator / denominator * 100
	value.Status = MetricKnown
	value.Number = &percentage
	return value, nil
}

// Metric carries both pooled and host-qualified per-organization observations.
type Metric struct {
	Key             string                 `json:"key"`
	Overall         MetricValue            `json:"overall"`
	PerOrganization map[string]MetricValue `json:"per_organization"`
}

// Confidence describes evidence confidence, not an AI-generated score.
type Confidence string

// Confidence levels follow the export contract.
const (
	HighConfidence   Confidence = "high"
	MediumConfidence Confidence = "medium"
	LowConfidence    Confidence = "low"
)

// ResultFlag supports simultaneous confirmation and endpoint warnings.
type ResultFlag string

// Result flags are emitted deterministically when their conditions hold.
const (
	Confirm        ResultFlag = "confirm"
	VerifyEndpoint ResultFlag = "verify-endpoint"
)

// AssessorDecision records an explicit confirmation or override and its rationale.
type AssessorDecision struct {
	State        State     `json:"state"`
	Assessor     string    `json:"assessor"`
	ConfirmedAt  time.Time `json:"confirmed_at"`
	Rationale    string    `json:"rationale"`
	EvidenceRefs []string  `json:"evidence_refs"`
}

// ControlResult keeps a proposed state distinct from a confirmed assessor state.
type ControlResult struct {
	ControlID            string            `json:"control_id"`
	Sheet                string            `json:"sheet"`
	Pillar               string            `json:"pillar"`
	Origin               Origin            `json:"origin"`
	Automation           Automation        `json:"automation"`
	ProposedState        State             `json:"proposed_state"`
	Confidence           Confidence        `json:"confidence"`
	Flags                []ResultFlag      `json:"flags"`
	RequiresConfirmation bool              `json:"requires_confirmation"`
	Metrics              map[string]Metric `json:"metrics"`
	EvidenceRefs         []string          `json:"evidence_refs"`
	Notes                string            `json:"notes"`
	RuleDefinitionSHA256 string            `json:"rule_definition_sha256,omitempty"`
	Discussion           *InterviewAnswer  `json:"discussion,omitempty"`
	Decision             *AssessorDecision `json:"assessor_decision,omitempty"`
}

// RequiresInterview preserves the profile's exceptional mandatory confirmation.
func (c Control) RequiresInterview() bool {
	return c.Automation != Full || c.ID == "PRD-041"
}
