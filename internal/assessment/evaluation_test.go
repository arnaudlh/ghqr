// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// fixtureEffectiveProtection builds a synthetic effective branch-protection
// record for boundary testing, matching the real collector's field shapes
// without any network access.
func fixtureEffectiveProtection(protected, fullyProtected, signatures bool, completeness OutcomeStatus) *EffectiveBranchProtection {
	minApprovals := 0
	var statusChecks []string
	if fullyProtected {
		minApprovals = 1
		statusChecks = []string{"ci"}
	}
	return &EffectiveBranchProtection{
		Repository: "fixture/repo", DefaultBranch: "main",
		PullRequestRequired: protected || fullyProtected, MinApprovals: minApprovals, StatusChecks: statusChecks,
		BlockForcePush: protected || fullyProtected, BlockDeletion: fullyProtected, Signatures: signatures,
		Completeness:       completeness,
		ApplicableRulesets: []RulesetReference{}, BypassActors: []RulesetBypassActorRef{}, Notes: []string{}, RequiredWorkflows: []string{},
	}
}

func fixtureRepoResult(name string, protection *EffectiveBranchProtection, references []ActionReference, workflowNotes []string, feature RepositoryFeatureSignal) RepositoryRunResult {
	var workflows *WorkflowAnalysisResult
	if references != nil || workflowNotes != nil {
		notes := workflowNotes
		if notes == nil {
			notes = []string{}
		}
		workflows = &WorkflowAnalysisResult{Repository: name, References: references, Notes: notes}
	}
	feature.FullName = name
	return RepositoryRunResult{FullName: name, DefaultBranch: "main", EffectiveProtection: protection, Workflows: workflows, Feature: feature}
}

func fixtureOrganization(org string, sample *SampleResult, critical *CriticalPopulationResult, repos ...RepositoryRunResult) OrganizationRunResult {
	scope := Scope{Host: "github.com", Kind: OrganizationScope, Name: org}
	return OrganizationRunResult{
		Scope:        scope,
		Population:   &OrganizationPopulation{Scope: scope, Sample: sample, Critical: critical},
		Repositories: repos,
	}
}

func fixtureReport(organizations ...OrganizationRunResult) *VerticalSliceReport {
	outcomes := []CollectorOutcome{}
	for _, organization := range organizations {
		for _, repository := range organization.Repositories {
			repoScope := Scope{Host: organization.Scope.Host, Kind: RepositoryScope, Name: repository.FullName}
			if repository.EffectiveProtection != nil {
				outcomes = append(outcomes, CollectorOutcome{
					CollectorID: "repo.rules", Feature: "branch-rules", Scope: repoScope, Readiness: Ready,
					Availability: Available, Status: CollectionOK, Complete: true,
					EvidenceRefs: []string{"objects/" + repository.FullName + "-rules.json", "objects/" + repository.FullName + "-rules.meta.json"},
				})
			}
			if repository.Workflows != nil {
				outcomes = append(outcomes, CollectorOutcome{
					CollectorID: "repo.workflows", Feature: "workflows", Scope: repoScope, Readiness: Ready,
					Availability: Available, Status: CollectionOK, Complete: true,
					EvidenceRefs: []string{"objects/" + repository.FullName + "-workflows.json", "objects/" + repository.FullName + "-workflows.meta.json"},
				})
			}
			outcomes = append(outcomes, CollectorOutcome{
				CollectorID: "repo.sbom", Feature: "sbom", Scope: repoScope, Readiness: Ready,
				Availability: Available, Status: CollectionOK, Complete: true,
				EvidenceRefs: []string{"objects/" + repository.FullName + "-sbom.json", "objects/" + repository.FullName + "-sbom.meta.json"},
			})
		}
	}
	return &VerticalSliceReport{
		Profile: ProfileSummary{}, CollectedAt: time.Now().UTC(), ImplementedCollectors: RunImplementedCollectorIDs(),
		ImplementedEvaluators: ImplementedEvaluatorIDs(), Organizations: organizations, Metrics: map[string]Metric{},
		Outcomes: outcomes, Caveats: []string{},
	}
}

func fixtureEvaluationConfig(t *testing.T) *CustomerConfig {
	t.Helper()
	config, err := ParseConfig([]byte("organizations: [acme]\n"))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func fixtureEvaluationInput(t *testing.T, report *VerticalSliceReport) *EvaluationInput {
	t.Helper()
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	return &EvaluationInput{Profile: profile, Report: report, Targets: targets, Thresholds: config.Thresholds}
}

func fixtureEvaluationInputWithThresholds(t *testing.T, report *VerticalSliceReport, thresholds map[string]float64) *EvaluationInput {
	t.Helper()
	input := fixtureEvaluationInput(t, report)
	input.Thresholds = thresholds
	return input
}

// fixtureProfileWithDefault loads the real bundled profile: evaluator
// correctness tests need the exact ARC-005/GOV-001/GOV-070/GOV-072/
// SEC-043/SEC-099 rule text and automation levels, which the package's
// synthetic fixtureProfile helper (used by contract-only tests) does not
// preserve.
func fixtureProfileWithDefault(t *testing.T) *Profile {
	t.Helper()
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func findControl(t *testing.T, profile *Profile, id string) Control {
	t.Helper()
	for _, control := range profile.Controls {
		if control.ID == id {
			return control
		}
	}
	t.Fatalf("control %s not found in profile", id)
	return Control{}
}

func TestThresholdTierInclusiveBoundaries(t *testing.T) {
	cases := []struct {
		value    float64
		expected State
	}{
		{95, Implemented}, {94.999, PartiallyImplemented},
		{70, PartiallyImplemented}, {69.999, NotImplemented},
		{100, Implemented}, {0, NotImplemented},
	}
	for _, testCase := range cases {
		if got := thresholdTier(testCase.value, 70, 95); got != testCase.expected {
			t.Fatalf("thresholdTier(%v, 70, 95) = %s, want %s", testCase.value, got, testCase.expected)
		}
	}
}

func TestGatedTierRefusesImplementedWithoutSecondarySignal(t *testing.T) {
	passingSecondary, failingSecondary := 100.0, 0.0
	if tier, confirmed := gatedTier(96, 70, 95, nil, 95); confirmed || tier != "" {
		t.Fatalf("gate reaching IMPL floor without secondary signal must not confirm a tier: %s, %v", tier, confirmed)
	}
	if tier, confirmed := gatedTier(96, 70, 95, &passingSecondary, 95); !confirmed || tier != Implemented {
		t.Fatalf("gate reaching IMPL floor with a passing secondary signal should confirm IMPLEMENTED: %s, %v", tier, confirmed)
	}
	// The profile's literal PART/NOT text for these rules never mentions the
	// secondary; a gate at its IMPL floor combined with a known-but-failing
	// secondary has no textual mapping and must never be guessed as PARTIAL.
	if tier, confirmed := gatedTier(96, 70, 95, &failingSecondary, 95); confirmed || tier != "" {
		t.Fatalf("profile defines no tier for a top-range gate with a known-failing secondary; must not invent a "+
			"confirmed tier: %s, %v", tier, confirmed)
	}
	if tier, confirmed := gatedTier(80, 70, 95, nil, 95); !confirmed || tier != PartiallyImplemented {
		t.Fatalf("PART must not require the secondary signal: %s, %v", tier, confirmed)
	}
	if tier, confirmed := gatedTier(50, 70, 95, nil, 95); !confirmed || tier != NotImplemented {
		t.Fatalf("NOT_IMPLEMENTED must not require the secondary signal: %s, %v", tier, confirmed)
	}
}

func TestConfidenceForRules(t *testing.T) {
	// 82 sits between the 70/95 floors: 12 points above the partial floor and
	// 13 points below the implemented floor, so both distances exceed 10.
	if confidenceFor(82, 70, 95, true, false) != HighConfidence {
		t.Fatal("complete, unsampled, far-from-both-boundaries measurement should be high confidence")
	}
	if confidenceFor(90, 70, 95, true, false) != MediumConfidence {
		t.Fatal("complete, unsampled, within-10-points-of-a-boundary measurement should be medium confidence")
	}
	if confidenceFor(99, 70, 95, false, false) != LowConfidence {
		t.Fatal("incomplete collection must cap confidence at low regardless of distance from a boundary")
	}
	if confidenceFor(99, 70, 95, true, true) != LowConfidence {
		t.Fatal("a sampled population must cap confidence at low regardless of distance from a boundary")
	}
}

func TestVerifyEndpointFlagOnlyFromVerifiedCollector(t *testing.T) {
	profile := &Profile{Collectors: []Collector{
		{ID: "org.bypass_requests", Verify: true},
		{ID: "repo.rules", Verify: false},
	}}
	if flags := verifyEndpointFlag(profile, "repo.rules"); flags != nil {
		t.Fatalf("non-verified collector must never emit verify-endpoint: %v", flags)
	}
	flags := verifyEndpointFlag(profile, "org.bypass_requests")
	if len(flags) != 1 || flags[0] != VerifyEndpoint {
		t.Fatalf("verified collector must emit exactly one verify-endpoint flag: %v", flags)
	}
}

func TestEvaluateARC005Boundaries(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "ARC-005")
	if control.Automation != Full {
		t.Fatalf("ARC-005 fixture assumption changed: automation is %s", control.Automation)
	}

	// 9 of 10 protected => 90% exactly => IMPLEMENTED (inclusive upper floor).
	var repos []RepositoryRunResult
	for i := 0; i < 9; i++ {
		repos = append(repos, fixtureRepoResult(fmt.Sprintf("acme/protected-%d", i), fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	repos = append(repos, fixtureRepoResult("acme/unprotected", fixtureEffectiveProtection(false, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	report := fixtureReport(fixtureOrganization("acme", nil, nil, repos...))
	input := fixtureEvaluationInput(t, report)
	result := evaluateARC005(control, input)
	if result.ProposedState != Implemented {
		t.Fatalf("90%% exactly must be IMPLEMENTED (inclusive upper boundary): %+v", result)
	}
	if result.Confidence != MediumConfidence {
		t.Fatalf("90%% sits exactly on the implemented floor (0 points away), so confidence should be medium, not high: %s", result.Confidence)
	}
	metric := result.Metrics["repos_with_default_branch_protection_pct"]
	if metric.Overall.Status != MetricKnown || metric.Overall.Number == nil || *metric.Overall.Number != 90 {
		t.Fatalf("expected a known 90%% pooled metric: %+v", metric.Overall)
	}
	if len(metric.Overall.EvidenceRefs) == 0 {
		t.Fatal("ARC-005 must carry real evidence references, not an empty list")
	}
	if organizationValue, ok := metric.PerOrganization["github.com/organization/acme"]; !ok || organizationValue.Status != MetricKnown {
		t.Fatalf("per-organization breakdown missing for acme: %+v", metric.PerOrganization)
	}
	if control.RequiresInterview() {
		t.Fatal("test assumption broken: ARC-005 should not require confirmation")
	}
	if result.RequiresConfirmation || len(result.Flags) != 0 {
		t.Fatalf("Full, non-PRD-041 ARC-005 must not require confirmation: %+v", result)
	}

	// Exactly at the 90% boundary minus one repository tips to 80% => PARTIAL.
	// Uses a fresh backing array (not append(repos[:7], ...)) to avoid
	// silently mutating the shared `repos`/`report` backing array that later
	// assertions in this test still depend on.
	partialReport := fixtureReport(fixtureOrganization("acme", nil, nil, append(append([]RepositoryRunResult{}, repos[:7]...), repos[9])...))
	partialResult := evaluateARC005(control, fixtureEvaluationInput(t, partialReport))
	if partialResult.ProposedState != PartiallyImplemented {
		t.Fatalf("7 of 8 protected (87.5%%) should be PARTIAL: %+v", partialResult)
	}

	// 75% sits comfortably inside the 60-90% partial range (15 points from
	// each floor), demonstrating confidenceFor can genuinely reach high.
	var midRepos []RepositoryRunResult
	for i := 0; i < 15; i++ {
		midRepos = append(midRepos, fixtureRepoResult(fmt.Sprintf("acme/mid-protected-%d", i), fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	for i := 0; i < 5; i++ {
		midRepos = append(midRepos, fixtureRepoResult(fmt.Sprintf("acme/mid-unprotected-%d", i), fixtureEffectiveProtection(false, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	midResult := evaluateARC005(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil, midRepos...))))
	if midResult.ProposedState != PartiallyImplemented || midResult.Confidence != HighConfidence {
		t.Fatalf("75%% is 15 points from both the 60%% and 90%% floors and should be a high-confidence PARTIAL: %+v", midResult)
	}

	// Zero analyzed repositories => unavailable population => NOT_ASSESSED.
	emptyReport := fixtureReport(fixtureOrganization("acme", nil, nil))
	emptyResult := evaluateARC005(control, fixtureEvaluationInput(t, emptyReport))
	if emptyResult.ProposedState != NotAssessed || emptyResult.Notes == "" {
		t.Fatalf("zero population must be NOT_ASSESSED with a reason, not a false 0%%: %+v", emptyResult)
	}

	// An incomplete repository must never be silently excluded: the pooled
	// metric reports unavailable even though the complete subset remains
	// 100% protected.
	incomplete := append(append([]RepositoryRunResult{}, repos[:2]...),
		fixtureRepoResult("acme/incomplete", fixtureEffectiveProtection(false, false, false, CollectionPartial), nil, nil, RepositoryFeatureSignal{}))
	incompleteResult := evaluateARC005(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil, incomplete...))))
	if incompleteResult.ProposedState != NotAssessed {
		t.Fatalf("an incomplete repository must force NOT_ASSESSED rather than a falsely clean percentage: %+v", incompleteResult)
	}
	incompleteMetric := incompleteResult.Metrics["repos_with_default_branch_protection_pct"].Overall
	if incompleteMetric.Status != MetricUnavailable || incompleteMetric.Numerator == nil || *incompleteMetric.Numerator != 2 {
		t.Fatalf("incomplete pool must preserve its confidently known numerator/denominator for audit: %+v", incompleteMetric)
	}

	// A customer-accepted threshold override replacing the IMPLEMENTED floor
	// must actually be honored, not silently ignored: 90% measured protection
	// against an overridden 100% floor must NOT be accepted as IMPLEMENTED.
	overriddenInput := fixtureEvaluationInputWithThresholds(t, report, map[string]float64{"repos_with_default_branch_protection_pct": 100})
	overriddenResult := evaluateARC005(control, overriddenInput)
	if overriddenResult.ProposedState == Implemented {
		t.Fatalf("a 100%% accepted threshold override must not let 90%% measured protection be proposed as "+
			"IMPLEMENTED: %+v", overriddenResult)
	}
	if overriddenResult.ProposedState != PartiallyImplemented {
		t.Fatalf("90%% against an overridden 100%% floor (partial floor unchanged at 60%%) should resolve to "+
			"PARTIAL: %+v", overriddenResult)
	}
	if !strings.Contains(overriddenResult.Notes, "100.0%") || !strings.Contains(overriddenResult.Notes, "override") {
		t.Fatalf("the applied override value must be disclosed in Notes, not silently applied: %s", overriddenResult.Notes)
	}

	// The override must also be reflected in confidence: 90% is now 10
	// points away from the overridden 100% floor (medium), not 0 points away
	// from the stale default 90% floor (which would read as "on the floor").
	if overriddenResult.Confidence != MediumConfidence {
		t.Fatalf("confidence must be computed against the overridden floor, not the stale default: %s", overriddenResult.Confidence)
	}

	// A LOWER override (below the measured value) must also be honored and
	// must let IMPLEMENTED be confirmed even though the default floor would
	// not have been reached.
	lowerOverrideInput := fixtureEvaluationInputWithThresholds(t, partialReport, map[string]float64{"repos_with_default_branch_protection_pct": 80})
	lowerOverrideResult := evaluateARC005(control, lowerOverrideInput)
	if lowerOverrideResult.ProposedState != Implemented {
		t.Fatalf("87.5%% against an overridden 80%% floor should confirm IMPLEMENTED: %+v", lowerOverrideResult)
	}
}

func TestEvaluateGOV001AlwaysRequiresConfirmation(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "GOV-001")
	if control.Automation != Partial {
		t.Fatalf("GOV-001 fixture assumption changed: automation is %s", control.Automation)
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil,
		fixtureRepoResult("acme/one", fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{})))
	result := evaluateGOV001(control, fixtureEvaluationInput(t, report))
	if !result.RequiresConfirmation || len(result.Flags) != 1 || result.Flags[0] != Confirm {
		t.Fatalf("GOV-001 is Partial automation and must always require confirmation: %+v", result)
	}
	if result.ProposedState != Implemented {
		t.Fatalf("100%% protected should propose IMPLEMENTED pending confirmation: %+v", result)
	}

	// Even with zero evidence, the Partial automation still requires
	// confirmation; it must not silently skip the mandatory interview.
	emptyResult := evaluateGOV001(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil))))
	if !emptyResult.RequiresConfirmation {
		t.Fatal("GOV-001 confirmation requirement must hold even when the proposal itself is NOT_ASSESSED")
	}
}

func TestEvaluateCOL027AlwaysRequiresConfirmation(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "COL-027")
	if control.Automation != Partial {
		t.Fatalf("COL-027 fixture assumption changed: automation is %s", control.Automation)
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil))
	value := 95.0
	report.Metrics["team_based_access_pct"] = Metric{Key: "team_based_access_pct", Overall: MetricValue{Status: MetricKnown, Number: &value}}
	result := evaluateCOL027(control, fixtureEvaluationInput(t, report))
	if !result.RequiresConfirmation || len(result.Flags) != 1 || result.Flags[0] != Confirm {
		t.Fatalf("COL-027 is Partial automation and must always require confirmation: %+v", result)
	}
	if result.ProposedState != Implemented {
		t.Fatalf("95%% team-based access should propose IMPLEMENTED pending confirmation: %+v", result)
	}

	partialValue := 75.0
	report.Metrics["team_based_access_pct"] = Metric{Key: "team_based_access_pct", Overall: MetricValue{Status: MetricKnown, Number: &partialValue}}
	partialResult := evaluateCOL027(control, fixtureEvaluationInput(t, report))
	if partialResult.ProposedState != PartiallyImplemented {
		t.Fatalf("75%% team-based access should propose PARTIAL: %+v", partialResult)
	}

	// With no computed team_based_access_pct at all, confirmation is still
	// always required even though the proposal itself is NOT_ASSESSED.
	emptyResult := evaluateCOL027(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil))))
	if !emptyResult.RequiresConfirmation || emptyResult.ProposedState != NotAssessed {
		t.Fatalf("COL-027 confirmation requirement must hold even when the proposal itself is NOT_ASSESSED: %+v", emptyResult)
	}
}

func TestEvaluateGOV070RefusesImplementedWithoutSecondarySignal(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "GOV-070")
	var repos []RepositoryRunResult
	for i := 0; i < 20; i++ {
		repos = append(repos, fixtureRepoResult(fmt.Sprintf("acme/fully-%d", i), fixtureEffectiveProtection(false, true, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil, repos...))
	result := evaluateGOV070(control, fixtureEvaluationInput(t, report))
	if result.ProposedState != NotAssessed {
		t.Fatalf("100%% fully protected reaches the IMPL floor but the org-wide ruleset-breadth secondary signal is "+
			"unmeasured; GOV-070 must stay NOT_ASSESSED rather than guessing IMPLEMENTED: %+v", result)
	}

	// Below the 95% IMPL floor, PART/NOT do not depend on the secondary
	// signal and must resolve directly.
	mixed := append(repos[:16], fixtureRepoResult("acme/partial", fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	mixedResult := evaluateGOV070(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil, mixed...))))
	if mixedResult.ProposedState != PartiallyImplemented {
		t.Fatalf("16 of 17 fully protected (~94%%) is below the 95%% floor and must resolve to PARTIAL directly: %+v", mixedResult)
	}
}

func fixtureEffectiveProtectionDetailed(pullRequest, statusChecks, blockForcePush, blockDeletion bool, completeness OutcomeStatus) *EffectiveBranchProtection {
	var checks []string
	if statusChecks {
		checks = []string{"ci"}
	}
	minApprovals := 0
	if pullRequest {
		minApprovals = 1
	}
	return &EffectiveBranchProtection{
		Repository: "fixture/repo", DefaultBranch: "main",
		PullRequestRequired: pullRequest, MinApprovals: minApprovals, StatusChecks: checks,
		BlockForcePush: blockForcePush, BlockDeletion: blockDeletion, Completeness: completeness,
		ApplicableRulesets: []RulesetReference{}, BypassActors: []RulesetBypassActorRef{}, Notes: []string{}, RequiredWorkflows: []string{},
	}
}

func TestMissingRuleTypeDeterminesWideningSignal(t *testing.T) {
	if _, _, determinable := missingRuleType(ruleTypeCoveragePool{counts: map[string]int{}}); determinable {
		t.Fatal("a zero-denominator pool must be reported indeterminate, not guessed")
	}
	allPresent := ruleTypeCoveragePool{denominator: 10, counts: map[string]int{"pull_request": 10, "required_status_checks": 10, "non_fast_forward": 10, "deletion": 10}}
	if _, exactlyOne, determinable := missingRuleType(allPresent); !determinable || exactlyOne {
		t.Fatal("zero missing rule types must not trigger the widening clause")
	}
	oneMissing := ruleTypeCoveragePool{denominator: 10, counts: map[string]int{"pull_request": 10, "required_status_checks": 10, "non_fast_forward": 10, "deletion": 0}}
	ruleType, exactlyOne, determinable := missingRuleType(oneMissing)
	if !determinable || !exactlyOne || ruleType != "deletion" {
		t.Fatalf("exactly one zero-coverage rule type must be identified by name: %s %v %v", ruleType, exactlyOne, determinable)
	}
	twoMissing := ruleTypeCoveragePool{denominator: 10, counts: map[string]int{"pull_request": 10, "required_status_checks": 10, "non_fast_forward": 0, "deletion": 0}}
	if _, exactlyOne, determinable := missingRuleType(twoMissing); !determinable || exactlyOne {
		t.Fatal("two missing rule types must not trigger the widening clause (not exactly one)")
	}
}

func TestEvaluateGOV070AppliesMissingOneRuleTypeWidening(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "GOV-070")

	// Every repository has pull_request, required_status_checks and
	// non_fast_forward, but none has deletion protection: repos_fully_
	// protected_pct is 0% (clearly NOT_IMPLEMENTED by the plain percentage),
	// but exactly one required rule type (deletion) is organization-wide
	// missing, so the rule's widening clause should rescue it to PARTIAL.
	var widenedRepos []RepositoryRunResult
	for i := 0; i < 10; i++ {
		widenedRepos = append(widenedRepos, fixtureRepoResult(fmt.Sprintf("acme/missing-deletion-%d", i),
			fixtureEffectiveProtectionDetailed(true, true, true, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	widenedResult := evaluateGOV070(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil, widenedRepos...))))
	if widenedResult.ProposedState != PartiallyImplemented {
		t.Fatalf("a single organization-wide-missing rule type must widen NOT_IMPLEMENTED to PARTIAL: %+v", widenedResult)
	}
	if !strings.Contains(widenedResult.Notes, "Widened from NOT_IMPLEMENTED to PARTIAL") || !strings.Contains(widenedResult.Notes, "deletion") {
		t.Fatalf("widening must be explicitly disclosed by name: %s", widenedResult.Notes)
	}

	// Two required rule types missing (deletion and non_fast_forward) must
	// not trigger the widening clause; the plain percentage tier stands.
	var notWidenedRepos []RepositoryRunResult
	for i := 0; i < 10; i++ {
		notWidenedRepos = append(notWidenedRepos, fixtureRepoResult(fmt.Sprintf("acme/missing-two-%d", i),
			fixtureEffectiveProtectionDetailed(true, true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	notWidenedResult := evaluateGOV070(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil, notWidenedRepos...))))
	if notWidenedResult.ProposedState != NotImplemented {
		t.Fatalf("two organization-wide-missing rule types must not trigger the widening clause: %+v", notWidenedResult)
	}
	if !strings.Contains(notWidenedResult.Notes, "does not apply") {
		t.Fatalf("non-widening must still be explicitly disclosed: %s", notWidenedResult.Notes)
	}
}

func TestEvaluateGOV070ConfirmsOrLeavesAmbiguousWithMeasuredSecondary(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "GOV-070")
	var repos []RepositoryRunResult
	for i := 0; i < 20; i++ {
		repos = append(repos, fixtureRepoResult(fmt.Sprintf("acme/fully-%d", i), fixtureEffectiveProtection(false, true, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}))
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil, repos...))

	active := true
	report.Metrics["org_default_branch_rulesets_active"] = Metric{Key: "org_default_branch_rulesets_active", Overall: MetricValue{Status: MetricKnown, Boolean: &active}}
	confirmedResult := evaluateGOV070(control, fixtureEvaluationInput(t, report))
	if confirmedResult.ProposedState != Implemented {
		t.Fatalf("100%% fully protected with a confirmed-true org ruleset secondary must confirm IMPLEMENTED: %+v", confirmedResult)
	}

	// GOV-070's literal PART/NOT text conditions those tiers purely on
	// repos_fully_protected_pct; it never mentions org_default_branch_rulesets_active.
	// A top-range gate with a confirmed-FALSE secondary therefore has no
	// mapping in the rule's text and must stay NOT_ASSESSED/ambiguous, never
	// be guessed as PARTIAL.
	inactive := false
	report.Metrics["org_default_branch_rulesets_active"] = Metric{Key: "org_default_branch_rulesets_active", Overall: MetricValue{Status: MetricKnown, Boolean: &inactive}}
	ambiguousResult := evaluateGOV070(control, fixtureEvaluationInput(t, report))
	if ambiguousResult.ProposedState != NotAssessed {
		t.Fatalf("100%% fully protected with a confirmed-false org ruleset secondary has no textual mapping and must "+
			"stay NOT_ASSESSED, not be guessed as PARTIAL: %+v", ambiguousResult)
	}
	if !strings.Contains(ambiguousResult.Notes, "ambiguous/unmapped") {
		t.Fatalf("the ambiguous/unmapped combination must be explicitly disclosed: %s", ambiguousResult.Notes)
	}
}

func TestEvaluateGOV072CriticalSignatureCoverage(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "GOV-072")
	critical := &CriticalPopulationResult{Method: "custom-property", FullNames: []string{"acme/critical-a", "acme/critical-b"}}
	repos := []RepositoryRunResult{
		fixtureRepoResult("acme/critical-a", fixtureEffectiveProtection(true, true, true, CollectionOK), nil, nil, RepositoryFeatureSignal{}),
		fixtureRepoResult("acme/critical-b", fixtureEffectiveProtection(true, true, true, CollectionOK), nil, nil, RepositoryFeatureSignal{}),
		fixtureRepoResult("acme/noncritical", fixtureEffectiveProtection(false, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{}),
	}
	report := fixtureReport(fixtureOrganization("acme", nil, critical, repos...))
	result := evaluateGOV072(control, fixtureEvaluationInput(t, report))
	// 100% of critical repos require signatures, reaching the IMPL floor;
	// verified_commit_ratio_pct has no implemented collector, so IMPLEMENTED
	// must not be confirmed.
	if result.ProposedState != NotAssessed {
		t.Fatalf("missing verified_commit_ratio_pct must block IMPLEMENTED confirmation: %+v", result)
	}
	metric := result.Metrics["critical_repos_requiring_signatures_pct"].Overall
	if metric.Status != MetricKnown || metric.Number == nil || *metric.Number != 100 {
		t.Fatalf("critical signature coverage should confidently measure 100%% over the 2 critical repos: %+v", metric)
	}

	// An unresolved critical population (method "unknown") must not be
	// silently excluded from the pooled accounting.
	unknownCritical := &CriticalPopulationResult{Method: "unknown", Reason: "schema access failed"}
	unknownReport := fixtureReport(fixtureOrganization("acme", nil, unknownCritical, repos...))
	unknownResult := evaluateGOV072(control, fixtureEvaluationInput(t, unknownReport))
	if unknownResult.ProposedState != NotAssessed || unknownResult.Metrics["critical_repos_requiring_signatures_pct"].Overall.Status != MetricUnavailable {
		t.Fatalf("an unresolved critical population must report unavailable, not a false measurement: %+v", unknownResult)
	}

	// The recent-fallback caveat must be surfaced in Notes, not silently dropped.
	fallbackCritical := &CriticalPopulationResult{Method: "recent-fallback", FullNames: []string{"acme/critical-a"}, Caveat: "production environment evidence is not collected"}
	fallbackReport := fixtureReport(fixtureOrganization("acme", nil, fallbackCritical, repos...))
	fallbackResult := evaluateGOV072(control, fixtureEvaluationInput(t, fallbackReport))
	if !strings.Contains(fallbackResult.Notes, "recent-pushed fallback") {
		t.Fatalf("recent-fallback caveat must be surfaced: %s", fallbackResult.Notes)
	}

	// With verified_commit_ratio_pct now genuinely measured, IMPLEMENTED can
	// be confirmed (both metrics >=95%).
	passingRatio := 96.0
	report.Metrics["verified_commit_ratio_pct"] = Metric{Key: "verified_commit_ratio_pct", Overall: MetricValue{Status: MetricKnown, Number: &passingRatio}}
	confirmedResult := evaluateGOV072(control, fixtureEvaluationInput(t, report))
	if confirmedResult.ProposedState != Implemented {
		t.Fatalf("100%% signature coverage with a >=95%% verified commit ratio must confirm IMPLEMENTED: %+v", confirmedResult)
	}

	// GOV-072's literal PART clause is an OR of two independent sub-bands:
	// "rule present 50-95%" OR "verified ratio 80-95%". A secondary within
	// its own 80-95% PART band must confirm PARTIAL even while the primary
	// sits at its own IMPLEMENTED floor.
	partialRatio := 85.0
	report.Metrics["verified_commit_ratio_pct"] = Metric{Key: "verified_commit_ratio_pct", Overall: MetricValue{Status: MetricKnown, Number: &partialRatio}}
	partialResult := evaluateGOV072(control, fixtureEvaluationInput(t, report))
	if partialResult.ProposedState != PartiallyImplemented {
		t.Fatalf("a verified_commit_ratio_pct within its own 80-95%% PART band must confirm PARTIAL via the rule's "+
			"literal OR clause: %+v", partialResult)
	}

	// A secondary BELOW its own 80% PART floor (not within either of the
	// rule's two literal PART sub-bands) combined with a top-range primary
	// has no mapping in the rule's literal text at all: neither metric's own
	// band is satisfied, so this must stay NOT_ASSESSED/ambiguous, never be
	// guessed as PARTIAL.
	belowFloorRatio := 40.0
	report.Metrics["verified_commit_ratio_pct"] = Metric{Key: "verified_commit_ratio_pct", Overall: MetricValue{Status: MetricKnown, Number: &belowFloorRatio}}
	ambiguousResult := evaluateGOV072(control, fixtureEvaluationInput(t, report))
	if ambiguousResult.ProposedState != NotAssessed {
		t.Fatalf("100%% signature coverage with a verified commit ratio below its own 80%% PART floor has no literal "+
			"mapping and must stay NOT_ASSESSED, not be guessed as PARTIAL: %+v", ambiguousResult)
	}
	if !strings.Contains(ambiguousResult.Notes, "ambiguous/unmapped") {
		t.Fatalf("the ambiguous/unmapped combination must be explicitly disclosed: %s", ambiguousResult.Notes)
	}
}

func TestEvaluateSEC043GateAndSubstitutionDisclosure(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "SEC-043")
	var repos []RepositoryRunResult
	for i := 0; i < 9; i++ {
		repos = append(repos, fixtureRepoResult(fmt.Sprintf("acme/dep-%d", i), nil, nil, nil,
			RepositoryFeatureSignal{DependencyEligible: true, DependencyEligibleKnown: true, DependencyOperational: true, DependencyOperationalKnown: true}))
	}
	repos = append(repos, fixtureRepoResult("acme/dep-off", nil, nil, nil, RepositoryFeatureSignal{
		DependencyEligible: true, DependencyEligibleKnown: true, DependencyOperational: false, DependencyOperationalKnown: true}))
	report := fixtureReport(fixtureOrganization("acme", nil, nil, repos...))
	result := evaluateSEC043(control, fixtureEvaluationInput(t, report))
	// 90% exactly reaches the IMPL floor; the grouped version-update
	// secondary metric is unmeasured, so NOT_ASSESSED is required.
	if result.ProposedState != NotAssessed {
		t.Fatalf("90%% dependabot_security_updates_pct without the secondary grouping signal must stay NOT_ASSESSED: %+v", result)
	}
	if !strings.Contains(result.Notes, "repo.contents_probe") {
		t.Fatalf("SEC-043 must disclose its collector substitution: %s", result.Notes)
	}

	// Within the 60-90% partial range resolves directly without the secondary signal.
	var lowRepos []RepositoryRunResult
	for i := 0; i < 20; i++ {
		lowRepos = append(lowRepos, fixtureRepoResult(fmt.Sprintf("acme/low-%d", i), nil, nil, nil,
			RepositoryFeatureSignal{DependencyEligible: true, DependencyEligibleKnown: true, DependencyOperational: i < 15, DependencyOperationalKnown: true}))
	}
	lowResult := evaluateSEC043(control, fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("acme", nil, nil, lowRepos...))))
	if lowResult.ProposedState != PartiallyImplemented {
		t.Fatalf("75%% dependabot_security_updates_pct is within 60-90%% and should resolve to PARTIAL: %+v", lowResult)
	}

	// With repos_with_grouped_version_updates_pct now genuinely measured and
	// confirmed at or above its own 70% floor, IMPLEMENTED can be confirmed.
	passingGrouped := 75.0
	report.Metrics["repos_with_grouped_version_updates_pct"] = Metric{Key: "repos_with_grouped_version_updates_pct", Overall: MetricValue{Status: MetricKnown, Number: &passingGrouped}}
	confirmedResult := evaluateSEC043(control, fixtureEvaluationInput(t, report))
	if confirmedResult.ProposedState != Implemented {
		t.Fatalf("90%% dependabot_security_updates_pct with a >=70%% grouped-updates ratio must confirm IMPLEMENTED: %+v", confirmedResult)
	}

	// SEC-043's literal PART ("60-90%") and NOT ("<60%") text conditions
	// those tiers purely on dependabot_security_updates_pct; it never
	// mentions the grouped version-update secondary. A top-range gate with a
	// known-but-failing secondary therefore has no textual mapping and must
	// stay NOT_ASSESSED/ambiguous, never be guessed as PARTIAL.
	failingGrouped := 10.0
	report.Metrics["repos_with_grouped_version_updates_pct"] = Metric{Key: "repos_with_grouped_version_updates_pct", Overall: MetricValue{Status: MetricKnown, Number: &failingGrouped}}
	ambiguousResult := evaluateSEC043(control, fixtureEvaluationInput(t, report))
	if ambiguousResult.ProposedState != NotAssessed {
		t.Fatalf("90%% dependabot_security_updates_pct with a <70%% grouped-updates ratio has no literal mapping and "+
			"must stay NOT_ASSESSED, not be guessed as PARTIAL: %+v", ambiguousResult)
	}
	if !strings.Contains(ambiguousResult.Notes, "ambiguous/unmapped") {
		t.Fatalf("the ambiguous/unmapped combination must be explicitly disclosed: %s", ambiguousResult.Notes)
	}
}

func TestEvaluateSEC099GateAndSeparateGitHubOwnedReporting(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "SEC-099")
	sha := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	var references []ActionReference
	for i := 0; i < 19; i++ {
		references = append(references, ActionReference{Category: "third-party", Owner: "thirdparty", ActionRepo: "action", PinStatus: "sha-pinned", Ref: sha})
	}
	references = append(references, ActionReference{Category: "third-party", Owner: "thirdparty", ActionRepo: "action2", PinStatus: "not-pinned", Ref: "v1"})
	references = append(references, ActionReference{Category: "github-owned", Owner: "actions", ActionRepo: "checkout", PinStatus: "sha-pinned", Ref: sha})
	report := fixtureReport(fixtureOrganization("acme", nil, nil,
		fixtureRepoResult("acme/repo", nil, references, nil, RepositoryFeatureSignal{})))
	result := evaluateSEC099(control, fixtureEvaluationInput(t, report))
	// 19/20 third-party pinned = 95% exactly, reaching the IMPL floor; the
	// dependabot.yml ecosystem-update secondary metric is unmeasured.
	if result.ProposedState != NotAssessed {
		t.Fatalf("95%% third-party pin coverage without the secondary ecosystem-update signal must stay NOT_ASSESSED: %+v", result)
	}
	githubMetric := result.Metrics["github_owned_refs_sha_pinned_pct"].Overall
	if githubMetric.Status != MetricKnown || githubMetric.Number == nil || *githubMetric.Number != 100 {
		t.Fatalf("GitHub-owned pinning must still be reported, separately, as a known value: %+v", githubMetric)
	}
	if !strings.Contains(result.Notes, "reported separately") {
		t.Fatalf("SEC-099 must disclose GitHub-owned pinning is reported separately, not gating: %s", result.Notes)
	}

	// Zero third-party references must report unavailable, not a false 100%.
	onlyGithub := []ActionReference{{Category: "github-owned", Owner: "actions", ActionRepo: "checkout", PinStatus: "sha-pinned", Ref: sha}}
	zeroReport := fixtureReport(fixtureOrganization("acme", nil, nil, fixtureRepoResult("acme/repo", nil, onlyGithub, nil, RepositoryFeatureSignal{})))
	zeroResult := evaluateSEC099(control, fixtureEvaluationInput(t, zeroReport))
	if zeroResult.ProposedState != NotAssessed || zeroResult.Metrics["third_party_refs_sha_pinned_pct"].Overall.Status != MetricUnavailable {
		t.Fatalf("zero third-party references must be unavailable, not a false 100%%: %+v", zeroResult)
	}

	// With repos_with_actions_ecosystem_updates_pct now genuinely measured
	// and confirmed at or above its own 80% floor, IMPLEMENTED can be
	// confirmed.
	passingEcosystem := 85.0
	report.Metrics["repos_with_actions_ecosystem_updates_pct"] = Metric{Key: "repos_with_actions_ecosystem_updates_pct", Overall: MetricValue{Status: MetricKnown, Number: &passingEcosystem}}
	confirmedResult := evaluateSEC099(control, fixtureEvaluationInput(t, report))
	if confirmedResult.ProposedState != Implemented {
		t.Fatalf("95%% third-party pin coverage with a >=80%% actions-ecosystem-update ratio must confirm IMPLEMENTED: %+v", confirmedResult)
	}

	// SEC-099's literal PART ("70-95%") and NOT ("<70%") text conditions
	// those tiers purely on third_party_refs_sha_pinned_pct; it never
	// mentions the dependabot.yml ecosystem-update secondary. A top-range
	// gate with a known-but-failing secondary therefore has no textual
	// mapping and must stay NOT_ASSESSED/ambiguous, never be guessed as
	// PARTIAL.
	failingEcosystem := 20.0
	report.Metrics["repos_with_actions_ecosystem_updates_pct"] = Metric{Key: "repos_with_actions_ecosystem_updates_pct", Overall: MetricValue{Status: MetricKnown, Number: &failingEcosystem}}
	ambiguousResult := evaluateSEC099(control, fixtureEvaluationInput(t, report))
	if ambiguousResult.ProposedState != NotAssessed {
		t.Fatalf("95%% third-party pin coverage with a <80%% actions-ecosystem-update ratio has no literal mapping "+
			"and must stay NOT_ASSESSED, not be guessed as PARTIAL: %+v", ambiguousResult)
	}
	if !strings.Contains(ambiguousResult.Notes, "ambiguous/unmapped") {
		t.Fatalf("the ambiguous/unmapped combination must be explicitly disclosed: %s", ambiguousResult.Notes)
	}
}

func TestUnimplementedReasonDistinguishesMissingMetrics(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	manual := findControl(t, profile, "PRD-001")
	report := fixtureReport()
	if reason := unimplementedReason(manual, []string{"manual_process_inventory_exists", "inventory_age_months"}, report); !strings.Contains(reason, "Manual control") {
		t.Fatalf("Manual reason must say so explicitly: %s", reason)
	}

	noneComputed := unimplementedReason(Control{Automation: Full}, []string{"nonexistent_metric_key"}, report)
	if !strings.Contains(noneComputed, "not computed by this run's implemented collectors at all") || strings.Contains(noneComputed, "genuinely measured") {
		t.Fatalf("fully-uncomputed metrics should be called out, with no false claim of measurement: %s", noneComputed)
	}

	knownValue := 42.0
	report.Metrics["repos_with_default_branch_protection_pct"] = Metric{
		Key: "repos_with_default_branch_protection_pct", Overall: MetricValue{Status: MetricKnown, Number: &knownValue},
	}
	report.Metrics["dynamic_or_uncertain_metric"] = Metric{
		Key: "dynamic_or_uncertain_metric", Overall: MetricValue{Status: MetricUnavailable, Reason: "dynamic reference"},
	}

	mixedReason := unimplementedReason(Control{Automation: Full},
		[]string{"repos_with_default_branch_protection_pct", "dynamic_or_uncertain_metric", "missing_metric_key"}, report)
	if !strings.Contains(mixedReason, "genuinely measured") || !strings.Contains(mixedReason, "came back inconclusive") ||
		!strings.Contains(mixedReason, "not computed by this run's implemented collectors at all") {
		t.Fatalf("a mix of known, computed-but-unavailable and uncomputed metrics must name all three distinctly: %s", mixedReason)
	}

	allKnown := unimplementedReason(Control{Automation: Full}, []string{"repos_with_default_branch_protection_pct"}, report)
	if !strings.Contains(allKnown, "genuinely measured") || strings.Contains(allKnown, "not computed") {
		t.Fatalf("a fully-known-but-unimplemented reason must not falsely claim any metric is uncomputed: %s", allKnown)
	}
}

func TestBuildMetricsCatalogueNeverLetsUnknownOverwriteKnown(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	known := 42.0
	knownMetric := Metric{Key: "repos_with_default_branch_protection_pct", Overall: MetricValue{Status: MetricKnown, Number: &known}, PerOrganization: map[string]MetricValue{}}
	unknownMetricValue := unknownMetric("repos_with_default_branch_protection_pct", targets)

	withKnownResult := ControlResult{ControlID: "ARC-005", Metrics: map[string]Metric{"repos_with_default_branch_protection_pct": knownMetric}}
	withUnknownResult := ControlResult{ControlID: "GOV-001", Metrics: map[string]Metric{"repos_with_default_branch_protection_pct": unknownMetricValue}}

	// known-first, then unknown: the known value must survive.
	knownFirst, err := BuildMetricsCatalogue(profile, []ControlResult{withKnownResult, withUnknownResult}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if value := knownFirst["repos_with_default_branch_protection_pct"]; value.Overall.Status != MetricKnown || *value.Overall.Number != 42 {
		t.Fatalf("a later unknown placeholder must never overwrite an already-known catalogue value: %+v", value.Overall)
	}

	// unknown-first, then known: the known value must still win.
	unknownFirst, err := BuildMetricsCatalogue(profile, []ControlResult{withUnknownResult, withKnownResult}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if value := unknownFirst["repos_with_default_branch_protection_pct"]; value.Overall.Status != MetricKnown || *value.Overall.Number != 42 {
		t.Fatalf("iteration order must not determine whether a known value survives: %+v", value.Overall)
	}
}

func TestBuildMetricsCatalogueFlagsGenuineConflictAsAmbiguous(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	valueA, valueB := 10.0, 90.0
	resultA := ControlResult{ControlID: "SEC-001", Metrics: map[string]Metric{
		"eligible_repos_count": {Key: "eligible_repos_count", Overall: MetricValue{Status: MetricKnown, Number: &valueA, Population: "dependency-scanning eligible repositories"}},
	}}
	resultB := ControlResult{ControlID: "SEC-004", Metrics: map[string]Metric{
		"eligible_repos_count": {Key: "eligible_repos_count", Overall: MetricValue{Status: MetricKnown, Number: &valueB, Population: "code-scanning eligible repositories"}},
	}}
	catalogue, err := BuildMetricsCatalogue(profile, []ControlResult{resultA, resultB}, targets)
	if err != nil {
		t.Fatal(err)
	}
	value := catalogue["eligible_repos_count"]
	if value.Overall.Status != MetricUnavailable || value.Overall.Number != nil ||
		!strings.Contains(value.Overall.Reason, "SEC-001") || !strings.Contains(value.Overall.Reason, "SEC-004") {
		t.Fatalf("two controls computing different populations under the same shared key must be reported explicitly "+
			"ambiguous, not resolved by last-write-wins: %+v", value.Overall)
	}

	// Two controls that happen to agree (same signal reused) must not be
	// flagged ambiguous.
	resultC := ControlResult{ControlID: "GOV-070", Metrics: map[string]Metric{
		"eligible_repos_count": {Key: "eligible_repos_count", Overall: MetricValue{Status: MetricKnown, Number: &valueA, Population: "dependency-scanning eligible repositories"}},
	}}
	agreeing, err := BuildMetricsCatalogue(profile, []ControlResult{resultA, resultC}, targets)
	if err != nil {
		t.Fatal(err)
	}
	if agreeingValue := agreeing["eligible_repos_count"]; agreeingValue.Overall.Status != MetricKnown || *agreeingValue.Overall.Number != 10 {
		t.Fatalf("two controls reporting the identical known observation must not be flagged ambiguous: %+v", agreeingValue.Overall)
	}
}

func TestUnimplementedControlPreservesGenuinelyMeasuredMetricData(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := fixtureReport(fixtureOrganization("acme", nil, nil,
		fixtureRepoResult("acme/one", fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{})))
	rulesetCount := 3.0
	report.Metrics["active_org_rulesets_count"] = Metric{
		Key: "active_org_rulesets_count", Overall: MetricValue{Status: MetricKnown, Number: &rulesetCount},
	}
	results, err := EvaluateReport(profile, report, config)
	if err != nil {
		t.Fatal(err)
	}
	var sec010 ControlResult
	for _, result := range results {
		if result.ControlID == "SEC-010" {
			sec010 = result
		}
	}
	if sec010.ControlID == "" {
		t.Fatal("SEC-010 not found in evaluation results")
	}
	if sec010.ProposedState != NotAssessed {
		t.Fatalf("SEC-010 has no typed evaluator yet and must remain NOT_ASSESSED regardless of its measured data: %+v", sec010)
	}
	metric := sec010.Metrics["active_org_rulesets_count"]
	if metric.Overall.Status != MetricKnown || metric.Overall.Number == nil || *metric.Overall.Number != 3 {
		t.Fatalf("an unimplemented control must still surface a genuinely measured metric's real value, not blank it out: %+v", metric.Overall)
	}
	if !strings.Contains(sec010.Notes, "genuinely measured") {
		t.Fatalf("notes must reflect that this metric was genuinely measured, not merely declared: %s", sec010.Notes)
	}
}

func TestImplementedEvaluatorIDsAreSortedAndDistinctFromCatalogue(t *testing.T) {
	ids := ImplementedEvaluatorIDs()
	if len(ids) == 0 || len(ids) >= 456 {
		t.Fatalf("implemented evaluator count must be a small, genuine subset of the 456-control catalogue, got %d", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("ImplementedEvaluatorIDs must be sorted and distinct: %v", ids)
		}
	}
}

func numberMetric(key string, value float64) Metric {
	v := value
	return Metric{Key: key, Overall: MetricValue{Status: MetricKnown, Number: &v}}
}

func textMetric(key, value string) Metric {
	v := value
	return Metric{Key: key, Overall: MetricValue{Status: MetricKnown, Text: &v}}
}

func TestEvaluateSEC016FiveCriteriaCount(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "SEC-016")
	if control.Automation != Full {
		t.Fatalf("SEC-016 fixture assumption changed: automation is %s", control.Automation)
	}
	baseMetrics := func() map[string]Metric {
		return map[string]Metric{
			"default_repository_permission":       textMetric("default_repository_permission", "read"),
			"owner_count":                         numberMetric("owner_count", 2),
			"owner_ratio_pct":                     numberMetric("owner_ratio_pct", 2.0),
			"repos_with_direct_collaborators_pct": numberMetric("repos_with_direct_collaborators_pct", 5.0),
			"outside_collab_ratio_pct":            numberMetric("outside_collab_ratio_pct", 1.0),
			"members_without_2fa":                 numberMetric("members_without_2fa", 0),
		}
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil))
	report.Metrics = baseMetrics()
	input := fixtureEvaluationInput(t, report)
	result := evaluateSEC016(control, input)
	if result.ProposedState != Implemented {
		t.Fatalf("all 5 criteria passing must be IMPLEMENTED: %+v", result)
	}
	if result.Confidence != MediumConfidence {
		t.Fatalf("SEC-016 confidence must be capped at medium (never high) for this heterogeneous 5-criteria count: %s", result.Confidence)
	}

	// Exactly one failing criterion (outside collaborators at the floor) => PARTIAL.
	oneFail := baseMetrics()
	oneFail["outside_collab_ratio_pct"] = numberMetric("outside_collab_ratio_pct", 5.0)
	report.Metrics = oneFail
	partialResult := evaluateSEC016(control, fixtureEvaluationInput(t, report))
	if partialResult.ProposedState != PartiallyImplemented {
		t.Fatalf("exactly one failing criterion must be PARTIAL: %+v", partialResult)
	}

	// Two failing criteria => NOT_IMPLEMENTED.
	twoFail := baseMetrics()
	twoFail["outside_collab_ratio_pct"] = numberMetric("outside_collab_ratio_pct", 5.0)
	twoFail["members_without_2fa"] = numberMetric("members_without_2fa", 3)
	report.Metrics = twoFail
	notResult := evaluateSEC016(control, fixtureEvaluationInput(t, report))
	if notResult.ProposedState != NotImplemented {
		t.Fatalf("two or more failing criteria must be NOT_IMPLEMENTED: %+v", notResult)
	}

	// A missing declared metric must stay NOT_ASSESSED rather than guess a count.
	missing := baseMetrics()
	delete(missing, "owner_ratio_pct")
	report.Metrics = missing
	missingResult := evaluateSEC016(control, fixtureEvaluationInput(t, report))
	if missingResult.ProposedState != NotAssessed {
		t.Fatalf("a missing required criterion must stay NOT_ASSESSED, not guess pass/fail: %+v", missingResult)
	}

	// The owner criterion's "or <=2 absolute" escape hatch: a high ratio but
	// an absolute owner count at or below 2 must still pass.
	smallOrg := baseMetrics()
	smallOrg["owner_count"] = numberMetric("owner_count", 2)
	smallOrg["owner_ratio_pct"] = numberMetric("owner_ratio_pct", 50.0)
	report.Metrics = smallOrg
	smallOrgResult := evaluateSEC016(control, fixtureEvaluationInput(t, report))
	if smallOrgResult.ProposedState != Implemented {
		t.Fatalf("owner_count<=2 must pass regardless of owner_ratio_pct (the rule's explicit absolute-count escape "+
			"hatch): %+v", smallOrgResult)
	}
}

// TestEvaluateSEC016OwnerCapEvaluatedPerOrganizationNotPooled guards the
// real multi-organization bug the pooled Overall value introduced: three
// organizations, each individually with 2 owners (well under both the
// absolute-5 cap and the 5%-of-members ratio), pool to a summed
// owner_count of 6 -- incorrectly exceeding the absolute-5 cap when
// compared as one cross-organization total, even though not one of the
// three organizations, on its own, violates anything. The owner criterion
// must evaluate each organization's own figures independently and must not
// fail all three merely because enough individually-healthy organizations
// happen to exist together in one run.
func TestEvaluateSEC016OwnerCapEvaluatedPerOrganizationNotPooled(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "SEC-016")
	perOrgHealthy := func(pooledCount, pooledRatio float64, perOrgCounts, perOrgRatios map[string]float64) map[string]Metric {
		countPerOrg := make(map[string]MetricValue, len(perOrgCounts))
		for key, value := range perOrgCounts {
			v := value
			countPerOrg[key] = MetricValue{Status: MetricKnown, Number: &v}
		}
		ratioPerOrg := make(map[string]MetricValue, len(perOrgRatios))
		for key, value := range perOrgRatios {
			v := value
			ratioPerOrg[key] = MetricValue{Status: MetricKnown, Number: &v}
		}
		count, ratio := pooledCount, pooledRatio
		return map[string]Metric{
			"default_repository_permission":       textMetric("default_repository_permission", "read"),
			"owner_count":                         {Key: "owner_count", Overall: MetricValue{Status: MetricKnown, Number: &count}, PerOrganization: countPerOrg},
			"owner_ratio_pct":                     {Key: "owner_ratio_pct", Overall: MetricValue{Status: MetricKnown, Number: &ratio}, PerOrganization: ratioPerOrg},
			"repos_with_direct_collaborators_pct": numberMetric("repos_with_direct_collaborators_pct", 5.0),
			"outside_collab_ratio_pct":            numberMetric("outside_collab_ratio_pct", 1.0),
			"members_without_2fa":                 numberMetric("members_without_2fa", 0),
		}
	}

	report := fixtureReport(
		fixtureOrganization("acme", nil, nil), fixtureOrganization("contoso", nil, nil), fixtureOrganization("fabrikam", nil, nil))
	report.Metrics = perOrgHealthy(6, 3.0,
		map[string]float64{"github.com/organization/acme": 2, "github.com/organization/contoso": 2, "github.com/organization/fabrikam": 2},
		map[string]float64{"github.com/organization/acme": 2.0, "github.com/organization/contoso": 2.0, "github.com/organization/fabrikam": 2.0})
	result := evaluateSEC016(control, fixtureEvaluationInput(t, report))
	if result.ProposedState != Implemented {
		t.Fatalf("three organizations each individually passing the owner cap must not fail merely because their "+
			"owner_count pools to 6 across all of them: %+v", result)
	}

	// The inverse must also hold: if even ONE organization's own figures
	// genuinely exceed the cap, the criterion must fail and name that
	// organization specifically, even though the pooled sum alone would not
	// have revealed which organization was responsible.
	report.Metrics = perOrgHealthy(9, 3.0,
		map[string]float64{"github.com/organization/acme": 2, "github.com/organization/contoso": 2, "github.com/organization/fabrikam": 7},
		map[string]float64{"github.com/organization/acme": 2.0, "github.com/organization/contoso": 2.0, "github.com/organization/fabrikam": 20.0})
	oneOrgFails := evaluateSEC016(control, fixtureEvaluationInput(t, report))
	if oneOrgFails.ProposedState != PartiallyImplemented {
		t.Fatalf("exactly one organization genuinely exceeding its own owner cap must count as exactly one failed "+
			"criterion (PARTIAL), not be masked or doubled by pooling: %+v", oneOrgFails)
	}
	if !strings.Contains(oneOrgFails.Notes, "fabrikam") {
		t.Fatalf("the failure reason must name the specific organization that failed, not a pooled total: %s", oneOrgFails.Notes)
	}
}

func TestEvaluateCOL001ORCompoundTier(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "COL-001")
	if control.Automation != Partial {
		t.Fatalf("COL-001 fixture assumption changed: automation is %s", control.Automation)
	}
	buildReport := func(coverage, time float64, timeKnown bool) *VerticalSliceReport {
		report := fixtureReport(fixtureOrganization("acme", nil, nil))
		report.Metrics = map[string]Metric{"review_coverage_pct": numberMetric("review_coverage_pct", coverage)}
		if timeKnown {
			report.Metrics["median_time_to_first_review_h"] = numberMetric("median_time_to_first_review_h", time)
		}
		return report
	}

	implemented := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(95, 4, true)))
	if implemented.ProposedState != Implemented {
		t.Fatalf("coverage>=90%% and time<=8h must confirm IMPLEMENTED: %+v", implemented)
	}
	if !implemented.RequiresConfirmation {
		t.Fatal("COL-001 is Partial automation and must always require confirmation")
	}

	// PART via the coverage sub-band alone.
	coverageOnlyPartial := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(75, 4, true)))
	if coverageOnlyPartial.ProposedState != PartiallyImplemented {
		t.Fatalf("coverage in 70-90%% must independently confirm PARTIAL via the OR clause: %+v", coverageOnlyPartial)
	}

	// PART via the time sub-band alone, even with excellent coverage.
	timeOnlyPartial := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(95, 20, true)))
	if timeOnlyPartial.ProposedState != PartiallyImplemented {
		t.Fatalf("time within its own 8-24h band must independently confirm PARTIAL via the OR clause even with "+
			"excellent coverage: %+v", timeOnlyPartial)
	}

	// Ambiguous: coverage excellent but time clearly outside both bands.
	ambiguous := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(95, 48, true)))
	if ambiguous.ProposedState != NotAssessed {
		t.Fatalf("excellent coverage with time beyond both bands has no literal mapping and must stay NOT_ASSESSED: %+v", ambiguous)
	}
	if !strings.Contains(ambiguous.Notes, "ambiguous/unmapped") {
		t.Fatalf("the ambiguous combination must be explicitly disclosed: %s", ambiguous.Notes)
	}

	// Unmeasured secondary must also stay NOT_ASSESSED, not silently confirm.
	unmeasured := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(95, 0, false)))
	if unmeasured.ProposedState != NotAssessed {
		t.Fatalf("an unmeasured secondary must not let IMPLEMENTED be confirmed from coverage alone: %+v", unmeasured)
	}

	// NOT_IMPLEMENTED resolves directly from coverage alone.
	notImplemented := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(50, 2, true)))
	if notImplemented.ProposedState != NotImplemented {
		t.Fatalf("coverage below 70%% must be NOT_IMPLEMENTED regardless of time: %+v", notImplemented)
	}
}

// TestEvaluateCOL001NeverClaimsMeasuredWorkingHours guards against a real
// bug: median_time_to_first_review_h is genuinely computed as raw
// calendar-elapsed time (activity_metrics.go's first.Sub(pr.CreatedAt)), not
// business/working-hours-aware, even though the rule's own IMPL clause is
// phrased in "working hours." This evaluator must never claim to have
// measured working hours directly; it may only disclose the one sound
// inference calendar time supports (a reading at/under the rule's own
// 8-hour ceiling is a sufficient bound proving the working-hours ceiling,
// since working hours can never exceed calendar-elapsed hours), and must
// name the measurement as calendar-elapsed, not working, when disclosing a
// higher reading.
func TestEvaluateCOL001NeverClaimsMeasuredWorkingHours(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "COL-001")
	buildReport := func(coverage, time float64) *VerticalSliceReport {
		report := fixtureReport(fixtureOrganization("acme", nil, nil))
		report.Metrics = map[string]Metric{
			"review_coverage_pct":           numberMetric("review_coverage_pct", coverage),
			"median_time_to_first_review_h": numberMetric("median_time_to_first_review_h", time),
		}
		return report
	}

	withinEightHourBound := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(95, 4)))
	if strings.Contains(withinEightHourBound.Notes, "4.0 working hours") {
		t.Fatalf("must never claim a calendar-elapsed measurement as directly-measured working hours: %s", withinEightHourBound.Notes)
	}
	if !strings.Contains(withinEightHourBound.Notes, "calendar-elapsed") || !strings.Contains(withinEightHourBound.Notes, "sufficient") {
		t.Fatalf("a reading within the 8h band must be disclosed as a sufficient bound on calendar-elapsed time, not a direct working-hours measurement: %s", withinEightHourBound.Notes)
	}

	withinTwentyFourHourBand := evaluateCOL001(control, fixtureEvaluationInput(t, buildReport(95, 20)))
	if strings.Contains(withinTwentyFourHourBand.Notes, "20.0 working hours") {
		t.Fatalf("must never claim a calendar-elapsed measurement as directly-measured working hours: %s", withinTwentyFourHourBand.Notes)
	}
	if !strings.Contains(withinTwentyFourHourBand.Notes, "calendar-elapsed") {
		t.Fatalf("a reading within the 24h band must still be disclosed as calendar-elapsed, not working, time: %s", withinTwentyFourHourBand.Notes)
	}
}

func TestEvaluatePRD016NeverInventsImplementedOrNotImplemented(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "PRD-016")
	if control.Automation != Partial {
		t.Fatalf("PRD-016 fixture assumption changed: automation is %s", control.Automation)
	}
	buildReport := func(successRate, queueTime float64, queueKnown bool) *VerticalSliceReport {
		report := fixtureReport(fixtureOrganization("acme", nil, nil))
		report.Metrics = map[string]Metric{"ci_success_rate_90d": numberMetric("ci_success_rate_90d", successRate)}
		if queueKnown {
			report.Metrics["median_queue_time_min"] = numberMetric("median_queue_time_min", queueTime)
		}
		return report
	}

	// IMPLEMENTED is never proposed, even with excellent success rate and a
	// fast queue time: the rule's IMPL clause requires a confirmed positive
	// review answer, which automation can never observe. "Metrics
	// acceptable but not reviewed" is PART's own literal clause for exactly
	// this unconfirmed case.
	excellentMetrics := evaluatePRD016(control, fixtureEvaluationInput(t, buildReport(95, 1, true)))
	if excellentMetrics.ProposedState != PartiallyImplemented {
		t.Fatalf("excellent success rate and fast queue time must propose PARTIAL (never IMPLEMENTED, since review "+
			"is never automation-confirmed): %+v", excellentMetrics)
	}
	if !excellentMetrics.RequiresConfirmation {
		t.Fatal("PRD-016 is Partial automation and must always require confirmation")
	}
	if !strings.Contains(excellentMetrics.Notes, "could confirm IMPLEMENTED") {
		t.Fatalf("an excellent-metrics PART proposal must disclose that a genuinely positive review answer could still "+
			"confirm IMPLEMENTED: %s", excellentMetrics.Notes)
	}

	// PART also resolves directly from success rate alone in the 75-90% band.
	midBand := evaluatePRD016(control, fixtureEvaluationInput(t, buildReport(80, 10, true)))
	if midBand.ProposedState != PartiallyImplemented {
		t.Fatalf("success rate in 75-90%% must be PARTIAL regardless of queue time: %+v", midBand)
	}
	if !strings.Contains(midBand.Notes, "cannot be confirmed regardless of the review answer") {
		t.Fatalf("a slow queue time must disclose that IMPLEMENTED cannot be reached regardless of review: %s", midBand.Notes)
	}

	// Exact 2-minute queue-time boundary: the rule's own text is "< 2 min",
	// never "<=2 min", so exactly 2.0 minutes must NOT be treated as meeting
	// the IMPLEMENTED-eligibility bound (informational only; ProposedState
	// itself stays PARTIAL either way, but the disclosed IMPL-eligibility
	// framing must reflect the strict boundary correctly).
	exactlyTwoMinutes := evaluatePRD016(control, fixtureEvaluationInput(t, buildReport(95, 2.0, true)))
	if exactlyTwoMinutes.ProposedState != PartiallyImplemented {
		t.Fatalf("a 2.0-minute queue time must still propose PARTIAL: %+v", exactlyTwoMinutes)
	}
	if !strings.Contains(exactlyTwoMinutes.Notes, "cannot be confirmed regardless of the review answer") {
		t.Fatalf("exactly 2.0 minutes must be treated as AT the ceiling, not under it (rule text is strict \"< 2 min\"): %s",
			exactlyTwoMinutes.Notes)
	}
	justUnderTwoMinutes := evaluatePRD016(control, fixtureEvaluationInput(t, buildReport(95, 1.99, true)))
	if !strings.Contains(justUnderTwoMinutes.Notes, "could confirm IMPLEMENTED") {
		t.Fatalf("1.99 minutes is strictly under the 2-minute ceiling and must be disclosed as IMPLEMENTED-eligible: %s",
			justUnderTwoMinutes.Notes)
	}

	// NOT_IMPLEMENTED is never proposed either: it requires confirming "no
	// review," equally unconfirmable by automation, and the rule provides
	// no mapping at all for "<75% AND reviewed=true."
	lowSuccessRate := evaluatePRD016(control, fixtureEvaluationInput(t, buildReport(50, 1, true)))
	if lowSuccessRate.ProposedState != NotAssessed {
		t.Fatalf("success rate below 75%% must stay NOT_ASSESSED (never invented as NOT_IMPLEMENTED from success "+
			"rate alone): %+v", lowSuccessRate)
	}
	if !strings.Contains(lowSuccessRate.Notes, "ambiguous/unmapped") {
		t.Fatalf("the unconfirmable-review ambiguity must be explicitly disclosed: %s", lowSuccessRate.Notes)
	}

	// Monthly-review combinations: regardless of whether queue time is known
	// at all, a success rate at or above the 75% floor always proposes PART
	// (the review question itself is deferred to confirmation uniformly).
	reviewUnknownQueueUnknown := evaluatePRD016(control, fixtureEvaluationInput(t, buildReport(92, 0, false)))
	if reviewUnknownQueueUnknown.ProposedState != PartiallyImplemented {
		t.Fatalf("a high success rate with queue time not computed at all must still propose PARTIAL: %+v", reviewUnknownQueueUnknown)
	}
	if !strings.Contains(reviewUnknownQueueUnknown.Notes, "could not yet confirm IMPLEMENTED") {
		t.Fatalf("an unknown queue time must disclose that IMPLEMENTED cannot yet be confirmed either way: %s", reviewUnknownQueueUnknown.Notes)
	}
}

func TestEvaluatePRD029WebhookSecurityHalf(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "PRD-029")
	if control.Automation != Full {
		t.Fatalf("PRD-029 fixture assumption changed: automation is %s", control.Automation)
	}
	buildReport := func(withoutSecretPct, insecureSSLCount float64) *VerticalSliceReport {
		report := fixtureReport(fixtureOrganization("acme", nil, nil))
		report.Metrics = map[string]Metric{
			"hooks_without_secret_pct":      numberMetric("hooks_without_secret_pct", withoutSecretPct),
			"hooks_insecure_ssl_count":      numberMetric("hooks_insecure_ssl_count", insecureSSLCount),
			"custom_apps_count":             numberMetric("custom_apps_count", 1),
			"fine_grained_pat_grants_count": numberMetric("fine_grained_pat_grants_count", 1),
		}
		return report
	}

	// IMPLEMENTED is never proposed: the rule's authentication-type
	// AND-clause (GitHub Apps vs. classic PAT) is permanently unverifiable
	// with the metrics this profile declares, even when the webhook-secret/
	// SSL half alone reaches its own top tier.
	topTier := evaluatePRD029(control, fixtureEvaluationInput(t, buildReport(0, 0)))
	if topTier.ProposedState != NotAssessed {
		t.Fatalf("0%% hooks without secret and 0 insecure_ssl must never confirm IMPLEMENTED (unverifiable "+
			"authentication-type half): %+v", topTier)
	}
	if !strings.Contains(topTier.Notes, "GitHub-Apps-vs-classic-PAT") {
		t.Fatalf("the permanently unverified integration-type half must be disclosed: %s", topTier.Notes)
	}

	partial := evaluatePRD029(control, fixtureEvaluationInput(t, buildReport(15, 0)))
	if partial.ProposedState != PartiallyImplemented {
		t.Fatalf("0-30%% hooks without secret must be PARTIAL: %+v", partial)
	}

	notImplemented := evaluatePRD029(control, fixtureEvaluationInput(t, buildReport(45, 0)))
	if notImplemented.ProposedState != NotImplemented {
		t.Fatalf(">30%% hooks without secret must be NOT_IMPLEMENTED: %+v", notImplemented)
	}

	// A confirmed-nonzero insecure_ssl_count alongside 0%% without-secret no
	// longer needs separate "ambiguous" handling: since IMPLEMENTED is never
	// proposed at all, this also resolves to the same NOT_ASSESSED top-tier
	// outcome as the clean (0, 0) case above, not a distinct state.
	alsoTopTier := evaluatePRD029(control, fixtureEvaluationInput(t, buildReport(0, 2)))
	if alsoTopTier.ProposedState != NotAssessed {
		t.Fatalf("0%% without secret with a confirmed-nonzero insecure_ssl_count must still stay NOT_ASSESSED, "+
			"never IMPLEMENTED: %+v", alsoTopTier)
	}
}

func TestEvaluateARC093OwnerTeamRoleTriCriteria(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "ARC-093")
	if control.Automation != Full {
		t.Fatalf("ARC-093 fixture assumption changed: automation is %s", control.Automation)
	}
	baseMetrics := func() map[string]Metric {
		return map[string]Metric{
			"owner_count":            numberMetric("owner_count", 2),
			"owner_ratio_pct":        numberMetric("owner_ratio_pct", 2.0),
			"team_based_access_pct":  numberMetric("team_based_access_pct", 95.0),
			"security_manager_teams": numberMetric("security_manager_teams", 1),
			"custom_roles_count":     numberMetric("custom_roles_count", 0),
		}
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil))
	report.Metrics = baseMetrics()
	result := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if result.ProposedState != Implemented {
		t.Fatalf("all 3 criteria passing must be IMPLEMENTED: %+v", result)
	}
	if result.Confidence != MediumConfidence {
		t.Fatalf("ARC-093 confidence must be capped at medium: %s", result.Confidence)
	}
	if result.Metrics["roles_in_use"].Overall.Number == nil || *result.Metrics["roles_in_use"].Overall.Number != 1 {
		t.Fatalf("roles_in_use must be the sum of known security_manager_teams/custom_roles_count: %+v", result.Metrics["roles_in_use"])
	}
	if _, ok := result.Metrics["owner_ratio_pct"]; ok {
		t.Fatal("owner_ratio_pct is not one of ARC-093's own declared metric keys and must not be separately published")
	}

	// Exactly one failing criterion (team-based access below floor) => PARTIAL.
	oneFail := baseMetrics()
	oneFail["team_based_access_pct"] = numberMetric("team_based_access_pct", 80.0)
	report.Metrics = oneFail
	partialResult := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if partialResult.ProposedState != PartiallyImplemented {
		t.Fatalf("exactly one failing criterion must be PARTIAL: %+v", partialResult)
	}

	// Two failing criteria => NOT_IMPLEMENTED.
	twoFail := baseMetrics()
	twoFail["team_based_access_pct"] = numberMetric("team_based_access_pct", 80.0)
	twoFail["security_manager_teams"] = numberMetric("security_manager_teams", 0)
	twoFail["custom_roles_count"] = numberMetric("custom_roles_count", 0)
	report.Metrics = twoFail
	notResult := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if notResult.ProposedState != NotImplemented {
		t.Fatalf("two or more failing criteria must be NOT_IMPLEMENTED: %+v", notResult)
	}

	// A missing required metric must stay NOT_ASSESSED rather than guess.
	missing := baseMetrics()
	delete(missing, "team_based_access_pct")
	report.Metrics = missing
	missingResult := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if missingResult.ProposedState != NotAssessed {
		t.Fatalf("a missing required criterion must stay NOT_ASSESSED: %+v", missingResult)
	}

	// A known-zero security_manager_teams paired with a wholly unmeasured
	// custom_roles_count (not merely absent from this map, but never
	// resolved by this run's collectors) must NOT be treated as a confirmed
	// failure of the "roles used beyond owner/member" criterion: the
	// unmeasured custom-role signal could still be positive, which is
	// exactly the "known-zero lower bound" mistake this control must not
	// make. The whole control must stay NOT_ASSESSED, never downgrade to
	// PARTIAL/NOT_IMPLEMENTED from an invented criterion failure.
	knownZeroUnknownOther := baseMetrics()
	knownZeroUnknownOther["security_manager_teams"] = numberMetric("security_manager_teams", 0)
	delete(knownZeroUnknownOther, "custom_roles_count")
	report.Metrics = knownZeroUnknownOther
	zeroUnknownResult := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if zeroUnknownResult.ProposedState != NotAssessed {
		t.Fatalf("a known-zero security_manager_teams with a wholly unmeasured custom_roles_count must not count "+
			"the roles-beyond-owner/member criterion as a confirmed failure: %+v", zeroUnknownResult)
	}

	// ARC-104 declares the identical rule text; confirm it is wired too.
	control104 := findControl(t, profile, "ARC-104")
	report.Metrics = baseMetrics()
	result104 := evaluateARC104(control104, fixtureEvaluationInput(t, report))
	if result104.ProposedState != Implemented {
		t.Fatalf("ARC-104 must evaluate the identical rule text as ARC-093: %+v", result104)
	}
}

// TestNewTypedRulesNeverInventUnknownTierFromMissingClauses covers each
// newly implemented evaluator with a case that pairs a single
// genuinely-known metric with every other declared metric for its control
// left wholly unmeasured (not merely absent from the map but never
// resolved at all), the exact shape a real but incomplete collector surface
// produces. None of these combinations license any tier other than
// NOT_ASSESSED under the controls' own literal rule text (see each
// evaluator's own doc comment for the specific missing clause).
func TestNewTypedRulesNeverInventUnknownTierFromMissingClauses(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	known := func(value float64) Metric {
		return Metric{Overall: MetricValue{Status: MetricKnown, Number: &value}}
	}
	for _, test := range []struct {
		name      string
		controlID string
		evaluate  EvaluatorFunc
		metrics   map[string]Metric
	}{
		{
			name: "security manager present but staff-owner purpose unknown", controlID: "SEC-132", evaluate: evaluateSEC132,
			metrics: map[string]Metric{"security_manager_teams": known(1)},
		},
		{
			name: "security manager absent but custom security role unknown", controlID: "SEC-132", evaluate: evaluateSEC132,
			metrics: map[string]Metric{"security_manager_teams": known(0)},
		},
		{
			name: "low collaborator ratio but justification and review cadence unknown", controlID: "GOV-065", evaluate: evaluateGOV065,
			metrics: map[string]Metric{"outside_collab_ratio_pct": known(1)},
		},
		{
			name: "zero security managers is not known absence of unknown custom roles", controlID: "ARC-093", evaluate: evaluateARC093,
			metrics: map[string]Metric{
				"owner_count": known(1), "owner_ratio_pct": known(1),
				"team_based_access_pct": known(100), "security_manager_teams": known(0),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			profileControl := findControl(t, profile, test.controlID)
			report := fixtureReport(fixtureOrganization("acme", nil, nil))
			report.Metrics = test.metrics
			result := test.evaluate(profileControl, fixtureEvaluationInput(t, report))
			if result.ProposedState != NotAssessed {
				t.Fatalf("literal rule does not license an invented tier with missing clauses: %s; %s", result.ProposedState, result.Notes)
			}
		})
	}
}

func TestEvaluateARC093OwnerCapOrRatioEvaluatedPerOrganizationNotPooled(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "ARC-093")
	perOrgMetrics := func(pooledCount, pooledRatio float64, perOrgCounts, perOrgRatios map[string]float64) map[string]Metric {
		countPerOrg := make(map[string]MetricValue, len(perOrgCounts))
		for key, value := range perOrgCounts {
			v := value
			countPerOrg[key] = MetricValue{Status: MetricKnown, Number: &v}
		}
		ratioPerOrg := make(map[string]MetricValue, len(perOrgRatios))
		for key, value := range perOrgRatios {
			v := value
			ratioPerOrg[key] = MetricValue{Status: MetricKnown, Number: &v}
		}
		count, ratio := pooledCount, pooledRatio
		return map[string]Metric{
			"owner_count":            {Key: "owner_count", Overall: MetricValue{Status: MetricKnown, Number: &count}, PerOrganization: countPerOrg},
			"owner_ratio_pct":        {Key: "owner_ratio_pct", Overall: MetricValue{Status: MetricKnown, Number: &ratio}, PerOrganization: ratioPerOrg},
			"team_based_access_pct":  numberMetric("team_based_access_pct", 95.0),
			"security_manager_teams": numberMetric("security_manager_teams", 1),
			"custom_roles_count":     numberMetric("custom_roles_count", 0),
		}
	}
	report := fixtureReport(
		fixtureOrganization("acme", nil, nil), fixtureOrganization("contoso", nil, nil), fixtureOrganization("fabrikam", nil, nil))
	// Each organization independently has exactly 5 owners (at the cap) but
	// the pooled sum (15) would exceed any single absolute cap if summed.
	report.Metrics = perOrgMetrics(15, 7.0,
		map[string]float64{"github.com/organization/acme": 5, "github.com/organization/contoso": 5, "github.com/organization/fabrikam": 5},
		map[string]float64{"github.com/organization/acme": 50.0, "github.com/organization/contoso": 50.0, "github.com/organization/fabrikam": 50.0})
	result := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if result.ProposedState != Implemented {
		t.Fatalf("three organizations each individually at the owner cap must not fail merely because their "+
			"owner_count pools to 15 across all of them: %+v", result)
	}

	// One organization genuinely exceeding both the absolute cap and the
	// ratio cap must fail the criterion and name that organization.
	report.Metrics = perOrgMetrics(17, 7.0,
		map[string]float64{"github.com/organization/acme": 5, "github.com/organization/contoso": 5, "github.com/organization/fabrikam": 7},
		map[string]float64{"github.com/organization/acme": 50.0, "github.com/organization/contoso": 50.0, "github.com/organization/fabrikam": 60.0})
	oneOrgFails := evaluateARC093(control, fixtureEvaluationInput(t, report))
	if oneOrgFails.ProposedState != PartiallyImplemented {
		t.Fatalf("exactly one organization genuinely exceeding its own owner cap must count as exactly one failed "+
			"criterion (PARTIAL): %+v", oneOrgFails)
	}
	if !strings.Contains(oneOrgFails.Notes, "fabrikam") {
		t.Fatalf("the failure reason must name the specific organization that failed: %s", oneOrgFails.Notes)
	}
}

func TestEvaluateSEC132NeverInventsATierWithoutAssessorConfirmation(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "SEC-132")
	if control.Automation != Full {
		t.Fatalf("SEC-132 fixture assumption changed: automation is %s", control.Automation)
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil))

	// A genuine security_manager_teams assignment satisfies security_manager
	// being assigned, but PART's own literal text additionally requires
	// knowing that SOME security staff also hold owner -- unmeasured here,
	// so this must stay NOT_ASSESSED, never invent PART from the known-
	// positive assignment alone.
	report.Metrics = map[string]Metric{"security_manager_teams": numberMetric("security_manager_teams", 1)}
	assigned := evaluateSEC132(control, fixtureEvaluationInput(t, report))
	if assigned.ProposedState != NotAssessed {
		t.Fatalf("a genuine security_manager_teams assignment with unmeasured staff-owner status must stay "+
			"NOT_ASSESSED, never invent PARTIAL: %+v", assigned)
	}
	for _, key := range []string{"security_manager_teams", "security_staff_owners", "custom_security_role"} {
		if _, ok := assigned.Metrics[key]; !ok {
			t.Fatalf("SEC-132's own declared metric %s must be present even when not genuinely computed: %+v", key, assigned.Metrics)
		}
	}

	// A known-zero security_manager_teams does not confirm NOT's own
	// "owner only" clause, since an unmeasured custom role could still
	// exist -- this must also stay NOT_ASSESSED, never invent NOT_IMPLEMENTED
	// from the known-zero assignment alone.
	report.Metrics = map[string]Metric{"security_manager_teams": numberMetric("security_manager_teams", 0)}
	none := evaluateSEC132(control, fixtureEvaluationInput(t, report))
	if none.ProposedState != NotAssessed {
		t.Fatalf("a known-zero security_manager_teams with unmeasured custom-role status must stay NOT_ASSESSED, "+
			"never invent NOT_IMPLEMENTED: %+v", none)
	}

	report.Metrics = map[string]Metric{}
	missing := evaluateSEC132(control, fixtureEvaluationInput(t, report))
	if missing.ProposedState != NotAssessed {
		t.Fatalf("a never-measured security_manager_teams must stay NOT_ASSESSED: %+v", missing)
	}
}

func TestEvaluateGOV065OutsideCollabRatioNeverReachesImplementedWithoutConfirmation(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	control := findControl(t, profile, "GOV-065")
	if control.Automation != Partial {
		t.Fatalf("GOV-065 fixture assumption changed: automation is %s", control.Automation)
	}
	report := fixtureReport(fixtureOrganization("acme", nil, nil))

	// Below the 5% floor: the ratio clause alone satisfies IMPLEMENTED's own
	// ratio sub-clause, but neither IMPLEMENTED (justification-register/
	// review-cadence unmeasured) nor PART (whose own literal band is 5-10%,
	// which this ratio does not fall within) is licensed by the rule's own
	// text for this specific combination -- this must stay NOT_ASSESSED,
	// never invent PARTIAL merely because the ratio itself is favorable.
	report.Metrics = map[string]Metric{"outside_collab_ratio_pct": numberMetric("outside_collab_ratio_pct", 2.0)}
	belowFloor := evaluateGOV065(control, fixtureEvaluationInput(t, report))
	if belowFloor.ProposedState != NotAssessed {
		t.Fatalf("a ratio below the 5%% floor does not fall within PART's own literal 5-10%% band and must stay "+
			"NOT_ASSESSED, never invent PARTIAL: %+v", belowFloor)
	}
	for _, key := range []string{"outside_collab_ratio_pct", "outside_collab_with_justification_pct", "access_review_cadence"} {
		if _, ok := belowFloor.Metrics[key]; !ok {
			t.Fatalf("GOV-065's own declared metric %s must be present: %+v", key, belowFloor.Metrics)
		}
	}

	// Within the rule's own literal 5-10% PARTIAL band.
	report.Metrics = map[string]Metric{"outside_collab_ratio_pct": numberMetric("outside_collab_ratio_pct", 7.0)}
	withinBand := evaluateGOV065(control, fixtureEvaluationInput(t, report))
	if withinBand.ProposedState != PartiallyImplemented {
		t.Fatalf("7%% is within the rule's own literal 5-10%% PARTIAL band: %+v", withinBand)
	}

	// Above the rule's own literal 10% NOT_IMPLEMENTED ceiling: a genuine
	// NOT_IMPLEMENTED regardless of the unrelated unverifiable clauses.
	report.Metrics = map[string]Metric{"outside_collab_ratio_pct": numberMetric("outside_collab_ratio_pct", 15.0)}
	aboveCeiling := evaluateGOV065(control, fixtureEvaluationInput(t, report))
	if aboveCeiling.ProposedState != NotImplemented {
		t.Fatalf("15%% exceeds the rule's own literal 10%% NOT_IMPLEMENTED ceiling: %+v", aboveCeiling)
	}

	report.Metrics = map[string]Metric{}
	missing := evaluateGOV065(control, fixtureEvaluationInput(t, report))
	if missing.ProposedState != NotAssessed {
		t.Fatalf("a never-measured outside_collab_ratio_pct must stay NOT_ASSESSED: %+v", missing)
	}
}
