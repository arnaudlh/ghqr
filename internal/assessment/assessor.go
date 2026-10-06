// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"strings"
	"time"
)

// AssessorInput is the caller-supplied, externally authored shape for one
// explicit assessor decision: a control ID, a decided state, the identity and
// time of the person confirming it, their rationale and supporting evidence
// references. It is read from an external JSON import (a file, a form
// submission, or any other out-of-band channel); nothing in this package ever
// synthesizes one from a proposed state, a rule's text, or an interview
// question. RAI/automated explanations and unconfirmed interviews must never
// rate an unobserved control themselves; only a validated AssessorInput may
// finalize a confirmation-requiring control.
type AssessorInput struct {
	ControlID    string    `json:"control_id"`
	State        State     `json:"state"`
	Assessor     string    `json:"assessor"`
	ConfirmedAt  time.Time `json:"confirmed_at"`
	Rationale    string    `json:"rationale"`
	EvidenceRefs []string  `json:"evidence_refs"`
}

// Validate rejects an unknown control ID or state, an empty assessor identity
// or rationale, a zero, far-future (relative to now) or otherwise unusable
// timestamp, and a decision supplied with no evidence reference at all. A
// future-dated confirmation is rejected outright rather than silently
// accepted or clamped: it could otherwise be used to fabricate a confirmation
// for work that has not actually happened yet, which this validation treats
// as a fake permission grant rather than a legitimate assessor action.
func (input AssessorInput) Validate(knownControlIDs map[string]bool, now time.Time) error {
	if input.ControlID == "" || !knownControlIDs[input.ControlID] {
		return fmt.Errorf("assessor decision references an unknown control ID %q", input.ControlID)
	}
	if err := input.State.Validate(); err != nil {
		return fmt.Errorf("assessor decision for %s: %w", input.ControlID, err)
	}
	if strings.TrimSpace(input.Assessor) == "" {
		return fmt.Errorf("assessor decision for %s requires a named assessor identity", input.ControlID)
	}
	if input.ConfirmedAt.IsZero() {
		return fmt.Errorf("assessor decision for %s requires a confirmation timestamp", input.ControlID)
	}
	if input.ConfirmedAt.After(now) {
		return fmt.Errorf("assessor decision for %s has a confirmation timestamp in the future; "+
			"a future-dated confirmation cannot be genuine and is rejected rather than accepted as a fake permission grant", input.ControlID)
	}
	if strings.TrimSpace(input.Rationale) == "" {
		return fmt.Errorf("assessor decision for %s requires a non-empty rationale", input.ControlID)
	}
	nonEmptyEvidence := false
	for _, ref := range input.EvidenceRefs {
		if strings.TrimSpace(ref) != "" {
			nonEmptyEvidence = true
			break
		}
	}
	if !nonEmptyEvidence {
		return fmt.Errorf("assessor decision for %s requires at least one evidence reference "+
			"(an evidence store path, an interview record identifier, or a document reference)", input.ControlID)
	}
	return nil
}

// ApplyAssessorDecisions attaches validated, explicit assessor decisions onto
// a copy of an existing proposed-result list. It never mutates a result's
// proposed side (ProposedState, Confidence, Flags, Metrics, EvidenceRefs,
// Notes come from genuinely measured evidence computed earlier); it only ever
// sets the separate Decision field, preserving the contract that a proposal
// and its confirmation are always distinguishable. Every input is validated
// before any result is touched, so a single invalid decision in a batch fails
// the whole batch rather than partially applying it.
func ApplyAssessorDecisions(profile *Profile, results []ControlResult, decisions []AssessorInput, now time.Time) ([]ControlResult, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate assessor profile: %w", err)
	}
	if len(results) != len(profile.Controls) {
		return nil, fmt.Errorf("assessor confirmation requires exactly %d proposed results, got %d", len(profile.Controls), len(results))
	}
	knownControlIDs := make(map[string]bool, len(profile.Controls))
	for _, control := range profile.Controls {
		knownControlIDs[control.ID] = true
	}
	seen := make(map[string]bool, len(decisions))
	for _, decision := range decisions {
		if err := decision.Validate(knownControlIDs, now); err != nil {
			return nil, err
		}
		if seen[decision.ControlID] {
			return nil, fmt.Errorf("duplicate assessor decision for control %s; supply exactly one decision per control per batch", decision.ControlID)
		}
		seen[decision.ControlID] = true
	}

	byControlID := make(map[string]AssessorInput, len(decisions))
	for _, decision := range decisions {
		byControlID[decision.ControlID] = decision
	}
	updated := make([]ControlResult, len(results))
	for index, result := range results {
		updated[index] = result
		decision, ok := byControlID[result.ControlID]
		if !ok {
			continue
		}
		evidenceRefs := make([]string, 0, len(decision.EvidenceRefs))
		for _, ref := range decision.EvidenceRefs {
			if trimmed := strings.TrimSpace(ref); trimmed != "" {
				evidenceRefs = append(evidenceRefs, trimmed)
			}
		}
		updated[index].Decision = &AssessorDecision{
			State: decision.State, Assessor: strings.TrimSpace(decision.Assessor), ConfirmedAt: decision.ConfirmedAt,
			Rationale: strings.TrimSpace(decision.Rationale), EvidenceRefs: evidenceRefs,
		}
	}
	return updated, nil
}

// PendingConfirmations lists every control still awaiting assessor
// confirmation in a result list: every control flagged RequiresConfirmation
// that has not yet received a Decision. This never finalizes a Manual,
// Partial or PRD-041 control on the caller's behalf; it only reports the
// outstanding gap so a workflow can ensure confirmations are gathered before
// treating an assessment as complete.
func PendingConfirmations(results []ControlResult) []string {
	pending := make([]string, 0, len(results))
	for _, result := range results {
		if result.RequiresConfirmation && result.Decision == nil {
			pending = append(pending, result.ControlID)
		}
	}
	return pending
}
