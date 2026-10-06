// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"testing"
	"time"
)

func assessorFixtureResults(t *testing.T) (*Profile, []ControlResult) {
	t.Helper()
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := fixtureReport(fixtureOrganization("acme", nil, nil))
	results, err := EvaluateReport(profile, report, config)
	if err != nil {
		t.Fatal(err)
	}
	return profile, results
}

func TestAssessorInputValidateRejectsEveryInvalidShape(t *testing.T) {
	known := map[string]bool{"ARC-005": true}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	base := AssessorInput{
		ControlID: "ARC-005", State: Implemented, Assessor: "reviewer@example.test",
		ConfirmedAt: now.Add(-time.Hour), Rationale: "Confirmed via manual review of the ruleset export.",
		EvidenceRefs: []string{"objects/arc-005-review.json"},
	}
	if err := base.Validate(known, now); err != nil {
		t.Fatalf("valid input should pass: %v", err)
	}

	unknownID := base
	unknownID.ControlID = "ZZZ-999"
	if err := unknownID.Validate(known, now); err == nil {
		t.Fatal("unknown control ID must be rejected")
	}

	unknownState := base
	unknownState.State = State("FAKE_STATE")
	if err := unknownState.Validate(known, now); err == nil {
		t.Fatal("unknown state must be rejected")
	}

	emptyAssessor := base
	emptyAssessor.Assessor = "   "
	if err := emptyAssessor.Validate(known, now); err == nil {
		t.Fatal("empty assessor identity must be rejected")
	}

	emptyRationale := base
	emptyRationale.Rationale = ""
	if err := emptyRationale.Validate(known, now); err == nil {
		t.Fatal("empty rationale must be rejected")
	}

	zeroTimestamp := base
	zeroTimestamp.ConfirmedAt = time.Time{}
	if err := zeroTimestamp.Validate(known, now); err == nil {
		t.Fatal("zero confirmation timestamp must be rejected")
	}

	futureTimestamp := base
	futureTimestamp.ConfirmedAt = now.Add(24 * time.Hour)
	if err := futureTimestamp.Validate(known, now); err == nil {
		t.Fatal("future-dated confirmation must be rejected as a fake permission grant")
	}

	noEvidence := base
	noEvidence.EvidenceRefs = nil
	if err := noEvidence.Validate(known, now); err == nil {
		t.Fatal("decision with no evidence reference must be rejected")
	}

	blankEvidence := base
	blankEvidence.EvidenceRefs = []string{"   ", ""}
	if err := blankEvidence.Validate(known, now); err == nil {
		t.Fatal("decision with only blank evidence references must be rejected")
	}
}

func TestApplyAssessorDecisionsPreservesProposalImmutability(t *testing.T) {
	profile, results := assessorFixtureResults(t)
	now := time.Now().UTC()
	var target ControlResult
	for _, result := range results {
		if result.ControlID == "PRD-001" {
			target = result
		}
	}
	if target.ControlID == "" {
		t.Fatal("fixture did not produce the expected control")
	}
	decisions := []AssessorInput{{
		ControlID: "PRD-001", State: PartiallyImplemented, Assessor: "reviewer@example.test",
		ConfirmedAt: now.Add(-time.Minute), Rationale: "Inventory exists but has not been reviewed in the last 12 months.",
		EvidenceRefs: []string{"interviews/PRD-001.md"},
	}}
	updated, err := ApplyAssessorDecisions(profile, results, decisions, now)
	if err != nil {
		t.Fatal(err)
	}
	var updatedTarget ControlResult
	for _, result := range updated {
		if result.ControlID == "PRD-001" {
			updatedTarget = result
		}
	}
	if updatedTarget.Decision == nil || updatedTarget.Decision.State != PartiallyImplemented ||
		updatedTarget.Decision.Assessor != "reviewer@example.test" || updatedTarget.Decision.Rationale == "" {
		t.Fatalf("decision was not attached correctly: %+v", updatedTarget.Decision)
	}
	if updatedTarget.ProposedState != target.ProposedState || updatedTarget.Confidence != target.Confidence ||
		updatedTarget.Notes != target.Notes {
		t.Fatalf("applying a decision must never mutate the original proposal fields: before=%+v after=%+v", target, updatedTarget)
	}
	// The original slice element must be untouched (no aliasing through the Decision pointer).
	if target.Decision != nil {
		t.Fatal("original result must not be mutated in place")
	}

	var untouched ControlResult
	for _, result := range results {
		if result.ControlID == "ARC-005" {
			untouched = result
		}
	}
	var updatedUntouched ControlResult
	for _, result := range updated {
		if result.ControlID == "ARC-005" {
			updatedUntouched = result
		}
	}
	if updatedUntouched.Decision != nil {
		t.Fatal("a control without a supplied decision must remain unconfirmed")
	}
	if updatedUntouched.ProposedState != untouched.ProposedState {
		t.Fatal("an unrelated control's proposal must be unaffected by applying a different control's decision")
	}
}

func TestApplyAssessorDecisionsRejectsDuplicateOrInvalidBatch(t *testing.T) {
	profile, results := assessorFixtureResults(t)
	now := time.Now().UTC()
	valid := AssessorInput{
		ControlID: "PRD-001", State: Implemented, Assessor: "reviewer@example.test",
		ConfirmedAt: now.Add(-time.Minute), Rationale: "Reviewed and current.", EvidenceRefs: []string{"interviews/PRD-001.md"},
	}
	duplicate := []AssessorInput{valid, valid}
	if _, err := ApplyAssessorDecisions(profile, results, duplicate, now); err == nil {
		t.Fatal("duplicate decisions for the same control in one batch must be rejected")
	}

	invalidInBatch := []AssessorInput{valid, {ControlID: "PRD-002", State: Implemented, Assessor: "", ConfirmedAt: now, Rationale: "x", EvidenceRefs: []string{"a"}}}
	if _, err := ApplyAssessorDecisions(profile, results, invalidInBatch, now); err == nil {
		t.Fatal("one invalid decision must fail the entire batch, not apply partially")
	}
}

func TestPendingConfirmationsTracksOutstandingControls(t *testing.T) {
	profile, results := assessorFixtureResults(t)
	before := PendingConfirmations(results)
	if len(before) == 0 {
		t.Fatal("a fresh evaluation with Manual/Partial/PRD-041 controls must have pending confirmations")
	}
	now := time.Now().UTC()
	decisions := []AssessorInput{{
		ControlID: before[0], State: NotAssessed, Assessor: "reviewer@example.test",
		ConfirmedAt: now.Add(-time.Minute), Rationale: "Not yet reviewed by the customer team.", EvidenceRefs: []string{"interviews/" + before[0] + ".md"},
	}}
	updated, err := ApplyAssessorDecisions(profile, results, decisions, now)
	if err != nil {
		t.Fatal(err)
	}
	after := PendingConfirmations(updated)
	if len(after) != len(before)-1 {
		t.Fatalf("confirming exactly one control should reduce the pending count by one: before=%d after=%d", len(before), len(after))
	}
}
