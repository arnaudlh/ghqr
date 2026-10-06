// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// EvaluationInput is the full, already-collected evidence surface available to
// a typed evaluator: the vertical-slice run's pooled and per-repository
// results, and the resolved customer targets used for deployment-scope
// applicability. An evaluator reads from Report/Targets only; it never issues
// network calls or re-interprets Control.Rule as natural language.
type EvaluationInput struct {
	Profile    *Profile
	Report     *VerticalSliceReport
	Targets    []Target
	Thresholds map[string]float64
	Checks     *SimpleChecks
}

// EvaluatorFunc produces one control's typed, deterministic proposed result
// from already-collected evidence. Every branch is an explicit, reviewable Go
// boundary derived from the exact profile rule text and a genuinely measured
// signal; it must never fabricate a state the available evidence cannot
// support.
type EvaluatorFunc func(control Control, input *EvaluationInput) ControlResult

// evaluatorRegistry maps a profile control ID to its genuinely implemented,
// typed evaluator. A control ID absent from this registry has no automatic
// rule implementation yet; EvaluateReport proposes NOT_ASSESSED for it with an
// explicit, generated reason instead of a blank or guessed default. Expanding
// this registry is the primary way to grow genuine automatic coverage; see
// docs/assessment.md for the exact rule text each entry implements and why the
// remaining controls are not yet in this map.
var evaluatorRegistry = map[string]EvaluatorFunc{
	"ARC-005": evaluateARC005,
	"GOV-001": evaluateGOV001,
	"COL-027": evaluateCOL027,
	"GOV-070": evaluateGOV070,
	"GOV-072": evaluateGOV072,
	"SEC-043": evaluateSEC043,
	"SEC-099": evaluateSEC099,
	"COL-001": evaluateCOL001,
	"PRD-016": evaluatePRD016,
	"PRD-029": evaluatePRD029,
	"SEC-016": evaluateSEC016,
	"ARC-093": evaluateARC093,
	"ARC-104": evaluateARC104,
	"SEC-132": evaluateSEC132,
	"GOV-065": evaluateGOV065,
}

// ImplementedEvaluatorIDs reports the control IDs with a genuine typed
// evaluator, kept separate from the profile's 456-control catalogue and from
// RunImplementedCollectorIDs' collector registry. It must never be inferred
// from the length of an evaluation result list: producing 456 NOT_ASSESSED
// rows is not the same as genuinely evaluating 456 controls.
func ImplementedEvaluatorIDs() []string {
	ids := make([]string, 0, len(evaluatorRegistry))
	for id := range evaluatorRegistry {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// EvaluateReport proposes one ControlResult per profile control from an
// already-collected VerticalSliceReport. Controls excluded by explicit
// deployment scope remain N/A; controls with a registered typed evaluator get
// a genuinely computed proposal; every other control gets an explicit
// NOT_ASSESSED reason identifying which of its declared metrics this run did
// or did not compute, never a blank default.
func EvaluateReport(profile *Profile, report *VerticalSliceReport, config *CustomerConfig) ([]ControlResult, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate evaluation profile: %w", err)
	}
	if report == nil {
		return nil, fmt.Errorf("evaluation requires an already-collected vertical-slice run report")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate evaluation configuration: %w", err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, fmt.Errorf("resolve evaluation targets: %w", err)
	}
	checks := config.CheckDefinitions
	if checks == nil {
		checks, err = LoadSimpleChecks(profile, "")
		if err != nil {
			return nil, err
		}
	}
	if err := checks.Validate(profile); err != nil {
		return nil, fmt.Errorf("validate evaluation checks: %w", err)
	}
	input := &EvaluationInput{Profile: profile, Report: report, Targets: targets, Thresholds: config.Thresholds, Checks: checks}

	results := make([]ControlResult, 0, len(profile.Controls))
	for _, control := range profile.Controls {
		keys, err := control.MetricKeys()
		if err != nil {
			return nil, fmt.Errorf("read evaluation metric keys for %s: %w", control.ID, err)
		}
		base := initialResult(control, targets)
		if base.ProposedState == NotApplicable {
			for _, key := range keys {
				base.Metrics[key] = unknownMetric(key, targets)
			}
			results = append(results, base)
			continue
		}
		if evaluator, ok := evaluatorRegistry[control.ID]; ok {
			result := evaluator(control, input)
			if control.ID == "SEC-043" && config.CheckDefinitions != nil {
				extraction := config.CheckDefinitions.Extractions[0]
				result.RuleDefinitionSHA256 = config.CheckDefinitions.SHA256
				result.Notes += fmt.Sprintf(" Configuration-fact source: %s%s (%s); enabled %s %v. "+
					"Explicit extraction policy SHA-256 %s; population/eligibility calculations remain separate.",
					extraction.CollectorID, extraction.FieldPath, extraction.Type, extraction.Enabled.Operator,
					extraction.Enabled.ExpectedValues, config.CheckDefinitions.SHA256)
			}
			results = append(results, result)
			continue
		}
		base.Notes = unimplementedReason(control, keys, report)
		for _, key := range keys {
			base.Metrics[key] = metricForUnimplementedControl(report, key, targets)
		}
		results = append(results, base)
	}
	return ApplyInterviewAnswers(profile, results, config.InterviewAnswers, time.Now().UTC())
}

// metricForUnimplementedControl preserves data separately from score: a
// control without a typed evaluator is always NOT_ASSESSED (no automatic rule
// exists to turn its data into a state), but when this run genuinely computed
// one of its declared metric keys, that real Metric (known or a genuinely
// computed but inconclusive observation) is reused as-is rather than being
// blanked out to a fresh "not implemented" placeholder. Only a metric key this
// run never computed at all falls back to the offline-plan baseline.
func metricForUnimplementedControl(report *VerticalSliceReport, key string, targets []Target) Metric {
	if metric, ok := report.Metrics[key]; ok {
		return metric
	}
	return unknownMetric(key, targets)
}

// unimplementedReason explains, per control, exactly why no typed evaluator
// exists yet: a Manual control has no automatic rule by profile design; a
// Full/Partial control without an evaluator further distinguishes, by this
// run's actual MetricStatus (never mere map-key presence), which of its
// declared metrics are genuinely known, which were computed but came back
// inconclusive, and which this run never attempted to compute at all. This
// scales honestly to every control the registry does not yet cover, instead
// of a single generic placeholder string, and never claims a metric is
// "computed" just because a map entry happens to exist for its key.
func unimplementedReason(control Control, keys []string, report *VerticalSliceReport) string {
	if control.Automation == Manual {
		return "NOT_ASSESSED: Manual control; the automation profile defines no automatic rule for this control. " +
			"It requires an explicit assessor decision (interview, document review or judgment) via the assessor " +
			"confirmation input; this run does not fabricate one."
	}
	var known, computedButUnavailable, uncomputed []string
	for _, key := range keys {
		metric, exists := report.Metrics[key]
		switch {
		case !exists:
			uncomputed = append(uncomputed, key)
		case metric.Overall.Status == MetricKnown:
			known = append(known, key)
		default:
			computedButUnavailable = append(computedButUnavailable, key)
		}
	}
	sentence := "NOT_ASSESSED: no typed evaluator is implemented for this control."
	if len(known) > 0 {
		sentence += fmt.Sprintf(" Metric(s) %s are genuinely measured by this run (see this control's own Metrics "+
			"entry for the actual value); a typed evaluator could score them once implemented.", strings.Join(known, ", "))
	}
	if len(computedButUnavailable) > 0 {
		sentence += fmt.Sprintf(" Metric(s) %s were computed by this run but the observation itself came back "+
			"inconclusive (see each metric's own reason).", strings.Join(computedButUnavailable, ", "))
	}
	if len(uncomputed) > 0 {
		sentence += fmt.Sprintf(" Metric(s) %s are not computed by this run's implemented collectors at all.", strings.Join(uncomputed, ", "))
	}
	return sentence
}

// metricValuesEquivalent reports whether two MetricValue observations
// represent the same underlying signal (same status, population, payload and
// reason), as opposed to two genuinely different computations that happen to
// share a profile metric key (the automation profile reuses some metric
// names, such as eligible_repos_count, across controls with different
// feature-specific populations).
func metricValuesEquivalent(a, b MetricValue) bool {
	if a.Status != b.Status || a.Population != b.Population || a.Reason != b.Reason {
		return false
	}
	return floatPointersEqual(a.Number, b.Number) && boolPointersEqual(a.Boolean, b.Boolean) &&
		stringPointersEqual(a.Text, b.Text) && stringSlicePointersEqual(a.List, b.List) &&
		dictionaryPointersEqual(a.Dictionary, b.Dictionary) && floatPointersEqual(a.Numerator, b.Numerator) &&
		floatPointersEqual(a.Denominator, b.Denominator) && floatPointersEqual(a.Baseline, b.Baseline) &&
		floatPointersEqual(a.Current, b.Current)
}

func floatPointersEqual(a, b *float64) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func boolPointersEqual(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func stringPointersEqual(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func stringSlicePointersEqual(a, b *[]string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	if len(*a) != len(*b) {
		return false
	}
	for index, value := range *a {
		if (*b)[index] != value {
			return false
		}
	}
	return true
}

func dictionaryPointersEqual(a, b *map[string]float64) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	if len(*a) != len(*b) {
		return false
	}
	for key, value := range *a {
		if other, ok := (*b)[key]; !ok || other != value {
			return false
		}
	}
	return true
}

// ambiguousMetric reports a genuine conflict between two or more controls'
// computed values for the same shared metric key as an explicit, honest
// unavailable observation, rather than silently picking one control's value
// (which would misrepresent the other control's context as agreeing with it).
func ambiguousMetric(key string, targets []Target, conflictingControlIDs []string) Metric {
	sorted := append([]string{}, conflictingControlIDs...)
	sort.Strings(sorted)
	reason := fmt.Sprintf(
		"this metric key is referenced by multiple controls (%s) that computed genuinely different observations for "+
			"it (the profile reuses some metric keys, such as eligible_repos_count, across controls with different "+
			"feature-specific populations); this catalogue reports it explicitly ambiguous rather than silently "+
			"picking one control's value. See each control's own Metrics entry in results.csv/evaluation-results.json "+
			"for its specific, correctly scoped observation.", strings.Join(sorted, ", "))
	value := MetricValue{Status: MetricUnavailable, Population: "ambiguous across multiple controls", EvidenceRefs: []string{}, Reason: reason}
	metric := Metric{Key: key, Overall: value, PerOrganization: map[string]MetricValue{}}
	for _, target := range targets {
		for _, organization := range target.Organizations {
			metric.PerOrganization[(Scope{target.Host, OrganizationScope, organization}).Key()] = value
		}
	}
	return metric
}

// BuildMetricsCatalogue assembles every metric key declared across the
// profile's controls (581 distinct keys for the supplied version-2 profile)
// into one map. A key with no genuinely known value anywhere keeps the same
// explicit-unavailable baseline the offline plan uses. A key with exactly one
// genuinely known source (possibly reused, byte-for-byte, across several
// controls that share the same signal) carries that source's Metric,
// including its own per-organization breakdown. A key where two different
// controls computed two different known observations is reported explicitly
// ambiguous rather than resolved by iteration order ("last write wins"), and
// once a key is marked ambiguous it stays ambiguous for the rest of this
// build. No key is ever silently dropped, and a not-yet-known observation
// (whether a plan-style placeholder or a genuinely computed-but-inconclusive
// one) never overwrites an already-known value.
func BuildMetricsCatalogue(profile *Profile, results []ControlResult, targets []Target) (map[string]Metric, error) {
	catalogue := make(map[string]Metric, 581)
	for _, control := range profile.Controls {
		keys, err := control.MetricKeys()
		if err != nil {
			return nil, fmt.Errorf("read catalogue metric keys for %s: %w", control.ID, err)
		}
		for _, key := range keys {
			if _, exists := catalogue[key]; !exists {
				catalogue[key] = unknownMetric(key, targets)
			}
		}
	}
	knownSourceControlID := make(map[string]string, len(catalogue))
	ambiguous := make(map[string]bool, len(catalogue))
	for _, result := range results {
		for key, metric := range result.Metrics {
			if metric.Overall.Status != MetricKnown || ambiguous[key] {
				continue
			}
			existingSource, haveKnownSource := knownSourceControlID[key]
			if !haveKnownSource {
				catalogue[key] = metric
				knownSourceControlID[key] = result.ControlID
				continue
			}
			if existingSource == result.ControlID || metricValuesEquivalent(catalogue[key].Overall, metric.Overall) {
				continue
			}
			catalogue[key] = ambiguousMetric(key, targets, []string{existingSource, result.ControlID})
			ambiguous[key] = true
		}
	}
	return catalogue, nil
}

// newControlResult seeds the taxonomy fields the export contract requires to
// exactly match the source control (exports.go's validateExportResult rejects
// any mismatch), including the profile's mandatory interview/confirmation
// flag, leaving ProposedState/Confidence/Metrics/EvidenceRefs/Notes for the
// caller to fill from genuinely measured data.
func newControlResult(control Control) ControlResult {
	flags := []ResultFlag{}
	requiresConfirmation := control.RequiresInterview()
	if requiresConfirmation {
		flags = append(flags, Confirm)
	}
	return ControlResult{
		ControlID: control.ID, Sheet: "Controls", Pillar: control.Pillar,
		Origin: control.Origin, Automation: control.Automation,
		Flags: flags, RequiresConfirmation: requiresConfirmation,
		Metrics: map[string]Metric{}, EvidenceRefs: []string{},
	}
}

// effectiveImplementedFloor honors an explicit customer-accepted threshold
// override for metricKey (config.Thresholds), replacing the profile-derived
// IMPLEMENTED floor with the customer's own accepted value; overridden
// reports whether an override was actually in effect so a caller can both
// apply it in the predicate and disclose the actual applied value in its
// Notes, never computing with one number while printing a different one as
// if it had been applied. An absent override leaves defaultFloor unchanged.
func effectiveImplementedFloor(thresholds map[string]float64, metricKey string, defaultFloor float64) (floor float64, overridden bool) {
	if value, ok := thresholds[metricKey]; ok {
		return value, true
	}
	return defaultFloor, false
}

// thresholdTier classifies a measured percentage against an inclusive-upper
// IMPLEMENTED floor and an inclusive-lower PARTIAL floor: a value exactly on
// either floor counts toward the tier that floor defines.
func thresholdTier(value, partialFloor, implementedFloor float64) State {
	switch {
	case value >= implementedFloor:
		return Implemented
	case value >= partialFloor:
		return PartiallyImplemented
	default:
		return NotImplemented
	}
}

// gatedTier resolves PARTIAL/NOT_IMPLEMENTED purely from the single measured
// gate metric, matching every profile rule in this registry whose PART/NOT
// text conditions only on that one metric (GOV-070, SEC-043, SEC-099's
// literal PART/NOT clauses never mention their secondary metric at all).
// When the gate alone reaches the IMPL floor, IMPLEMENTED is confirmed only
// if secondary is also known and meets secondaryFloor (the AND-condition's
// own literal threshold from the rule text, never an invented number).
// confirmed is false in two distinct situations the caller must
// distinguish by inspecting secondary itself: secondary is nil (this run
// never computed it at all) or secondary is known but below secondaryFloor.
// The latter is deliberately NOT resolved to PARTIAL: these rules' literal
// PART/NOT text defines those tiers purely via the primary gate, so "gate
// at/above its IMPL floor, but a known-failing secondary" is a combination
// the rule's literal text does not map to any state at all, and guessing
// PARTIAL for it would misrepresent an unspecified combination as a
// textually-defined one. The caller must report this as an explicit
// ambiguous/unmapped-rule NOT_ASSESSED, never a generic downgrade.
func gatedTier(gateValue, partialFloor, implementedFloor float64, secondary *float64, secondaryFloor float64) (tier State, confirmed bool) {
	tier = thresholdTier(gateValue, partialFloor, implementedFloor)
	if tier != Implemented {
		return tier, true
	}
	if secondary == nil || *secondary < secondaryFloor {
		return "", false
	}
	return Implemented, true
}

// booleanSecondary converts a report-reused boolean MetricValue into
// gatedTier's *float64/secondaryFloor=1 convention (true >= 1, false < 1),
// returning nil exactly when the metric itself is not genuinely known.
func booleanSecondary(value MetricValue) *float64 {
	if value.Status != MetricKnown || value.Boolean == nil {
		return nil
	}
	result := 0.0
	if *value.Boolean {
		result = 1.0
	}
	return &result
}

// percentageSecondary extracts gatedTier's secondary input from a
// report-reused percentage MetricValue, returning nil exactly when the
// metric itself is not genuinely known.
func percentageSecondary(value MetricValue) *float64 {
	if value.Status != MetricKnown || value.Number == nil {
		return nil
	}
	result := *value.Number
	return &result
}

// confidenceFor reports high confidence only when every repository
// contributing to the gate metric was confidently (non-partially) assessed,
// the organization's active population was not reduced by sampling, and the
// measured value sits more than 10 percentage points from both tier
// boundaries; it reports medium confidence for an otherwise-complete
// measurement within 10 points of a boundary, and low confidence whenever any
// contributing collection was sampled or incomplete.
func confidenceFor(value, partialFloor, implementedFloor float64, complete, sampled bool) Confidence {
	if !complete || sampled {
		return LowConfidence
	}
	nearest := math.Abs(value - partialFloor)
	if distance := math.Abs(value - implementedFloor); distance < nearest {
		nearest = distance
	}
	if nearest > 10 {
		return HighConfidence
	}
	return MediumConfidence
}

// anySampled reports whether any analyzed organization's active repository
// population was reduced by the deterministic stratified sample, which caps
// confidence at low regardless of how far a measured value sits from a tier
// boundary.
func anySampled(report *VerticalSliceReport) bool {
	for _, organization := range report.Organizations {
		if organization.Population != nil && organization.Population.Sample != nil {
			return true
		}
	}
	return false
}

// verifyEndpointFlag adds the VerifyEndpoint flag only when one of the
// supplied collector IDs is itself marked `verify: true` in the loaded
// profile's collector catalogue; an evaluator that never touches a
// verify-flagged collector never emits this flag.
func verifyEndpointFlag(profile *Profile, collectorIDs ...string) []ResultFlag {
	wanted := make(map[string]bool, len(collectorIDs))
	for _, id := range collectorIDs {
		wanted[id] = true
	}
	for _, collector := range profile.Collectors {
		if wanted[collector.ID] && collector.Verify {
			return []ResultFlag{VerifyEndpoint}
		}
	}
	return nil
}

// evidenceRefsForScopedCollectors deduplicates and sorts every raw/metadata
// evidence path from outcomes matching one of collectorIDs. When repoNames is
// non-nil, only repository-scoped outcomes whose repository is a member of
// repoNames are included (used to scope a per-organization metric's evidence
// to that organization's own repositories); a nil repoNames includes every
// matching outcome in the run.
func evidenceRefsForScopedCollectors(report *VerticalSliceReport, repoNames map[string]bool, collectorIDs []string) []string {
	wanted := make(map[string]bool, len(collectorIDs))
	for _, id := range collectorIDs {
		wanted[id] = true
	}
	seen := map[string]bool{}
	refs := []string{}
	for _, outcome := range report.Outcomes {
		if !wanted[outcome.CollectorID] {
			continue
		}
		if repoNames != nil && (outcome.Scope.Kind != RepositoryScope || !repoNames[outcome.Scope.Name]) {
			continue
		}
		for _, ref := range outcome.EvidenceRefs {
			if !seen[ref] {
				seen[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	sort.Strings(refs)
	return refs
}

// organizationRepositoryNames returns the set of repository full names this
// run actually analyzed for one organization, for scoping per-organization
// evidence references.
func organizationRepositoryNames(organization OrganizationRunResult) map[string]bool {
	names := make(map[string]bool, len(organization.Repositories))
	for _, repository := range organization.Repositories {
		names[repository.FullName] = true
	}
	return names
}

// evidenceRefsPerOrganization scopes evidenceRefsForScopedCollectors to each
// analyzed organization's own repositories, so a per-organization MetricValue
// carries only the raw/metadata evidence paths that actually contributed to
// that organization's observation, not the whole run's.
func evidenceRefsPerOrganization(report *VerticalSliceReport, collectorIDs []string) map[string][]string {
	perOrganization := make(map[string][]string, len(report.Organizations))
	for _, organization := range report.Organizations {
		perOrganization[organization.Scope.Key()] = evidenceRefsForScopedCollectors(
			report, organizationRepositoryNames(organization), collectorIDs)
	}
	return perOrganization
}

// applyPerOrganizationEvidenceRefs overwrites each per-organization
// MetricValue's EvidenceRefs with its organization-scoped evidence paths,
// leaving every other field (status, number, population, reason) untouched.
func applyPerOrganizationEvidenceRefs(values map[string]MetricValue, refs map[string][]string) map[string]MetricValue {
	for key, value := range values {
		value.EvidenceRefs = refs[key]
		values[key] = value
	}
	return values
}

// metricSummary renders a MetricValue as a short human-readable fragment for
// a control's Notes field, distinguishing a known percentage from an
// unavailable reason without duplicating MetricValue's JSON shape in prose.
func metricSummary(value MetricValue) string {
	if value.Status == MetricKnown && value.Number != nil {
		return fmt.Sprintf("%.1f%%", *value.Number)
	}
	if value.Reason != "" {
		return "unavailable (" + value.Reason + ")"
	}
	return "unavailable"
}

// protectionPool accumulates a boolean effective-branch-protection predicate
// across every analyzed repository, summing numerators and denominators
// (never averaging per-organization percentages) and tracking how many
// repositories could not be confidently assessed, so an incomplete repository
// is never silently dropped from the overall accounting.
type protectionPool struct {
	numerator, denominator, incomplete int
	perOrganization                    map[string]*protectionPoolOrganization
}

type protectionPoolOrganization struct {
	numerator, denominator, incomplete int
}

// poolEffectiveProtection folds every analyzed repository's effective
// branch-protection record through predicate, mirroring the same
// confidently-assessed-only denominator contract documented for the run-wide
// repos_with_default_branch_protection_pct/repos_fully_protected_pct metrics:
// a repository with no effective-protection record, or whose assessment was
// not CollectionOK, counts toward incomplete instead of being excluded as if
// it had never been analyzed.
func poolEffectiveProtection(report *VerticalSliceReport, predicate func(*EffectiveBranchProtection) bool) protectionPool {
	pool := protectionPool{perOrganization: map[string]*protectionPoolOrganization{}}
	for _, organization := range report.Organizations {
		orgPool := &protectionPoolOrganization{}
		for _, repository := range organization.Repositories {
			effective := repository.EffectiveProtection
			if effective == nil || effective.Completeness != CollectionOK {
				orgPool.incomplete++
				continue
			}
			orgPool.denominator++
			if predicate(effective) {
				orgPool.numerator++
			}
		}
		pool.numerator += orgPool.numerator
		pool.denominator += orgPool.denominator
		pool.incomplete += orgPool.incomplete
		pool.perOrganization[organization.Scope.Key()] = orgPool
	}
	return pool
}

// protectedPredicate mirrors the pooled repos_with_default_branch_protection_pct
// numerator definition: a pull request is required and force pushes are blocked.
func protectedPredicate(effective *EffectiveBranchProtection) bool {
	return effective.PullRequestRequired && effective.BlockForcePush
}

// fullyProtectedPredicate mirrors GOV-070's pooled repos_fully_protected_pct
// numerator definition: pull_request (>=1 approval), required_status_checks
// (>=1 context), non_fast_forward and deletion protection. Required
// signatures are GOV-072's separate criterion and are intentionally excluded.
func fullyProtectedPredicate(effective *EffectiveBranchProtection) bool {
	return effective.PullRequestRequired && effective.MinApprovals >= 1 && len(effective.StatusChecks) > 0 &&
		effective.BlockForcePush && effective.BlockDeletion
}

// poolToMetric converts a protectionPool into a pooled MetricValue and a
// per-organization breakdown, marking any pool with incomplete repositories
// explicitly unavailable (preserving its confidently known numerator and
// denominator for audit) rather than silently narrowing to the confidently
// known subset.
func poolToMetric(pool protectionPool, population string) (MetricValue, map[string]MetricValue) {
	overall, _ := Percentage(float64(pool.numerator), float64(pool.denominator), population)
	if pool.incomplete > 0 {
		overall = markCoverageUncertain(overall, fmt.Sprintf(
			"%d of %d analyzed repositories had an incomplete effective default-branch protection assessment; the "+
				"confidently known subset above is preserved for audit but is not a complete coverage figure",
			pool.incomplete, pool.incomplete+pool.denominator))
	}
	perOrganization := make(map[string]MetricValue, len(pool.perOrganization))
	for key, orgPool := range pool.perOrganization {
		value, _ := Percentage(float64(orgPool.numerator), float64(orgPool.denominator), population)
		if orgPool.incomplete > 0 {
			value = markCoverageUncertain(value, fmt.Sprintf(
				"%d of this organization's analyzed repositories had an incomplete effective default-branch protection assessment",
				orgPool.incomplete))
		}
		perOrganization[key] = value
	}
	return overall, perOrganization
}

// reportedMetricValue safely reads an already-computed pooled metric's
// Overall observation out of the run's Metrics map, falling back to the same
// explicit-unavailable baseline the offline plan uses when this run never
// computed that key at all (as opposed to computing it as genuinely
// unavailable, which the map lookup already preserves).
func reportedMetricValue(report *VerticalSliceReport, key string, targets []Target) MetricValue {
	if metric, ok := report.Metrics[key]; ok {
		return metric.Overall
	}
	return unknownMetric(key, targets).Overall
}

// reportedMetric safely reads an already-computed metric (Overall and any
// genuine per-organization breakdown) out of the run's Metrics map wholesale,
// falling back to the same explicit-unavailable baseline the offline plan
// uses when this run never computed that key at all. Unlike
// reportedMetricValue, this preserves a genuine per-organization breakdown
// when the collecting run already computed one (for example
// org_default_branch_rulesets_active/verified_commit_ratio_pct/
// repos_with_grouped_version_updates_pct/repos_with_actions_ecosystem_
// updates_pct, which the collector pipeline populates per organization).
func reportedMetric(report *VerticalSliceReport, key string, targets []Target) Metric {
	if metric, ok := report.Metrics[key]; ok {
		return metric
	}
	return unknownMetric(key, targets)
}

var repoRulesCollectors = []string{"repo.rules"}
var workflowCollectors = []string{"repo.workflows"}
var dependabotCollectors = []string{"repo.sbom", "repo.details"}

const effectiveProtectionGatePopulation = "active repositories with a confidently assessed default-branch effective protection record"

// evaluateARC005 implements: "IMPL if >= 90% of active repos have effective
// default-branch protection (PR required + block force push); PART if
// 60-90%; NOT if < 60%." This control's sole declared metric
// (repos_with_default_branch_protection_pct) is the only required signal, so
// no secondary AND-condition gating applies. A customer-accepted threshold
// override for this metric key (config.Thresholds) replaces the 90%
// IMPLEMENTED floor; the override is honored in the tier predicate, the
// confidence boundary distance and the disclosed Notes text together, never
// computed with one floor while a different one is printed as applied.
func evaluateARC005(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	pool := poolEffectiveProtection(input.Report, protectedPredicate)
	overall, perOrganization := poolToMetric(pool, effectiveProtectionGatePopulation)
	overall.EvidenceRefs = evidenceRefsForScopedCollectors(input.Report, nil, repoRulesCollectors)
	perOrganization = applyPerOrganizationEvidenceRefs(perOrganization, evidenceRefsPerOrganization(input.Report, repoRulesCollectors))
	result.Metrics["repos_with_default_branch_protection_pct"] = Metric{
		Key: "repos_with_default_branch_protection_pct", Overall: overall, PerOrganization: perOrganization,
	}
	result.EvidenceRefs = overall.EvidenceRefs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, repoRulesCollectors...)...)

	return evaluateSimpleCheck(control, input, result, pool.incomplete == 0)
}

// evaluateGOV001 implements: "Data: active org rulesets targeting default
// branches (~DEFAULT_BRANCH include), % active repos with effective
// default-branch protection. IMPL if >= 90% of active repos are protected AND
// teams can explain the intent of the rules (interview); PART if 60-90%; NOT
// if < 60%." GOV-001 is Partial automation, so every proposal here always
// requires assessor confirmation (control.RequiresInterview() is true for
// every Partial control); this evaluator proposes a tier from the measured
// protection percentage alone and explicitly defers the interview half of the
// compound rule to that mandatory confirmation, rather than guessing whether
// teams understand the ruleset intent.
func evaluateGOV001(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	pool := poolEffectiveProtection(input.Report, protectedPredicate)
	overall, perOrganization := poolToMetric(pool, effectiveProtectionGatePopulation)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, repoRulesCollectors)
	overall.EvidenceRefs = refs
	perOrganization = applyPerOrganizationEvidenceRefs(perOrganization, evidenceRefsPerOrganization(input.Report, repoRulesCollectors))
	result.Metrics["repos_with_default_branch_protection_pct"] = Metric{
		Key: "repos_with_default_branch_protection_pct", Overall: overall, PerOrganization: perOrganization,
	}
	result.Metrics["active_org_rulesets_count"] = reportedMetric(input.Report, "active_org_rulesets_count", input.Targets)
	result.EvidenceRefs = refs

	return evaluateSimpleCheck(control, input, result, pool.incomplete == 0)
}

// evaluateCOL027 implements: "Data: teams count, nested teams, team-vs-direct
// access ratio, repos with team maintainers. IMPL if >= 90% of repository
// access is granted through teams and teams map to real delivery teams
// (interview); PART if 70-90% through teams; NOT if < 70%." COL-027 is
// Partial automation, so every proposal here always requires assessor
// confirmation (control.RequiresInterview() is true for every Partial
// control); this evaluator proposes a tier from the measured team-based
// access percentage alone and explicitly defers the interview half of the
// compound rule (whether teams map to real delivery teams) to that mandatory
// confirmation, rather than guessing it. teams_count/nested_teams_count are
// reused as supplementary context, not independently gating. A
// customer-accepted threshold override for team_based_access_pct replaces
// the 90% IMPLEMENTED floor, honored in the predicate, confidence and Notes
// together. Confidence is deliberately capped at low regardless of distance
// from either boundary: team_based_access_pct's formula (team grants over
// team-plus-direct grants, excluding bots) is a cross-team data-completeness
// concern under active review as of this evaluator's authorship, so this
// control never claims collector-complete trust in that metric's current
// value until that is confirmed resolved.
func evaluateCOL027(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	teamBasedAccess := reportedMetric(input.Report, "team_based_access_pct", input.Targets)
	result.Metrics["team_based_access_pct"] = teamBasedAccess
	result.Metrics["teams_count"] = reportedMetric(input.Report, "teams_count", input.Targets)
	result.Metrics["nested_teams_count"] = reportedMetric(input.Report, "nested_teams_count", input.Targets)
	result.EvidenceRefs = teamBasedAccess.Overall.EvidenceRefs

	dataQualityCaveat := " team_based_access_pct's exact formula (team grants / (team + direct grants), bots " +
		"excluded) is a known cross-team data-completeness item under active coordination as of this evaluator's " +
		"authorship; confidence is capped at low until that is confirmed resolved, independent of distance from " +
		"either boundary."

	if teamBasedAccess.Overall.Status != MetricKnown {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED pending confirmation: " + teamBasedAccess.Overall.Reason +
			" This control is Partial automation and always requires assessor confirmation regardless of proposed state." + dataQualityCaveat
		return result
	}
	value := *teamBasedAccess.Overall.Number
	implementedFloor, overridden := effectiveImplementedFloor(input.Thresholds, "team_based_access_pct", 90)
	result.ProposedState = thresholdTier(value, 70, implementedFloor)
	result.Confidence = LowConfidence
	overrideNote := ""
	if overridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override: implemented floor is %.1f%%, not the profile default 90%%)", implementedFloor)
	}
	result.Notes = fmt.Sprintf(
		"Proposed from measured %.1f%% of repository access granted through teams; thresholds: >=%.1f%% implemented%s, "+
			"70-%.1f%% partial. This control's interview half (whether teams map to real delivery teams and who "+
			"maintains membership) is not observable by any collector and is never assumed satisfied; the mandatory "+
			"assessor confirmation for this Partial control must evaluate it before this proposal can finalize.%s",
		value, implementedFloor, overrideNote, implementedFloor, dataQualityCaveat)
	return result
}

// ~DEFAULT_BRANCH across all/most repos AND effective default-branch rules on
// >= 95% of active repos include pull_request (>= 1 approval),
// required_status_checks (>= 1 context), non_fast_forward (block force push)
// and deletion; PART if 80-95% or missing one rule type; NOT if < 80%." The
// gate (repos_fully_protected_pct) is this run's exact documented definition
// for this control; the secondary AND-condition
// (org_default_branch_rulesets_active, confirming an org ruleset targets
// ~DEFAULT_BRANCH across all/most repos specifically, not merely that one
// applies to some analyzed repository) has no implemented collector signal,
// so IMPLEMENTED is never confirmed by this evaluator alone. This pass also
// does not independently evaluate the rule's "or missing one rule type"
// partial-widening clause against rule_type_coverage.
// govSeventyRuleTypes are the four required rule types gating GOV-070's
// fully-protected determination and its "missing one rule type" widening
// clause: pull_request, required_status_checks, non_fast_forward and
// deletion. required_signatures is deliberately excluded (GOV-072's separate
// criterion; "no extra signatures" folded into this unrelated control).
var govSeventyRuleTypes = []string{"pull_request", "required_status_checks", "non_fast_forward", "deletion"}

// ruleTypePresent mirrors effectiveRuleTypesPresent's per-type conditions for
// exactly the four types GOV-070 requires, so this evaluator's own widening
// computation uses the identical criteria the pooled rule_type_coverage
// dictionary is built from.
func ruleTypePresent(effective *EffectiveBranchProtection, ruleType string) bool {
	switch ruleType {
	case "pull_request":
		return effective.PullRequestRequired
	case "required_status_checks":
		return len(effective.StatusChecks) > 0
	case "non_fast_forward":
		return effective.BlockForcePush
	case "deletion":
		return effective.BlockDeletion
	default:
		return false
	}
}

// ruleTypeCoveragePool counts, across every confidently-assessed repository
// (the same CollectionOK-only population repos_fully_protected_pct uses), how
// many repositories have each of GOV-070's four required rule types present,
// independently of this run's pooled rule_type_coverage dictionary (so the
// widening clause below never depends on that dictionary's own availability).
type ruleTypeCoveragePool struct {
	denominator int
	counts      map[string]int
}

func poolRuleTypeCoverage(report *VerticalSliceReport) ruleTypeCoveragePool {
	pool := ruleTypeCoveragePool{counts: make(map[string]int, len(govSeventyRuleTypes))}
	for _, ruleType := range govSeventyRuleTypes {
		pool.counts[ruleType] = 0
	}
	for _, organization := range report.Organizations {
		for _, repository := range organization.Repositories {
			effective := repository.EffectiveProtection
			if effective == nil || effective.Completeness != CollectionOK {
				continue
			}
			pool.denominator++
			for _, ruleType := range govSeventyRuleTypes {
				if ruleTypePresent(effective, ruleType) {
					pool.counts[ruleType]++
				}
			}
		}
	}
	return pool
}

// missingRuleType identifies GOV-070's "missing one rule type" widening
// signal: a required rule type is "missing" only when it has zero coverage
// across every confidently-assessed repository (never merely under-covered),
// the least arbitrary, uninvented reading of "missing" the rule text itself
// supports. The widening applies only when the math assigns exactly one such
// type; zero, two, three or four types at zero coverage are all left
// unwidened rather than guessed. determinable is false only when there is no
// confidently-assessed population to evaluate at all.
func missingRuleType(pool ruleTypeCoveragePool) (ruleType string, exactlyOne, determinable bool) {
	if pool.denominator == 0 {
		return "", false, false
	}
	var missing []string
	for _, candidate := range govSeventyRuleTypes {
		if pool.counts[candidate] == 0 {
			missing = append(missing, candidate)
		}
	}
	if len(missing) == 1 {
		return missing[0], true, true
	}
	return "", false, true
}

// evaluateGOV070 implements: "IMPL if >= 1 active org ruleset targets
// ~DEFAULT_BRANCH across all/most repos AND effective default-branch rules on
// >= 95% of active repos include pull_request (>= 1 approval),
// required_status_checks (>= 1 context), non_fast_forward (block force push)
// and deletion; PART if 80-95% or missing one rule type; NOT if < 80%." The
// gate (repos_fully_protected_pct) is this run's exact documented definition
// for this control; a customer-accepted threshold override for that metric
// key replaces the 95% IMPLEMENTED floor, honored in the predicate,
// confidence and Notes together. The secondary AND-condition
// (org_default_branch_rulesets_active, a directly enumerated org.rulesets
// observation of whether an active, branch-target ruleset's ref-name
// conditions include the literal "~DEFAULT_BRANCH" sentinel) is pooled by
// this run as an OR across analyzed organizations; across more than one
// organization that pooled OR cannot by itself prove the condition holds
// broadly (a single small, compliant organization could mask a large
// organization's gap), so this evaluator requires every organization's own
// per-organization observation to agree before treating the secondary as
// confirmed (crossOrganizationSecondary). This control's literal PART/NOT
// text (80-95%/<80%, plus the "missing one rule type" widening) never
// mentions the secondary at all: when the gate alone reaches the IMPLEMENTED
// floor but the secondary is known yet fails (false, or disagreeing across
// organizations), that exact combination has no mapping in the rule's
// literal text and is reported NOT_ASSESSED as an explicit ambiguous/
// unmapped combination, never guessed as PARTIAL. The "or missing one rule
// type" widening clause is independently evaluated against a self-computed
// per-rule-type coverage pool (see missingRuleType): a measured
// NOT_IMPLEMENTED tier is widened to PARTIAL only when the math can assign
// exactly one of the four required rule types as having zero coverage across
// every confidently-assessed repository; an indeterminate or non-single-type
// result leaves the plain percentage tier unchanged and discloses why.
func evaluateGOV070(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	pool := poolEffectiveProtection(input.Report, fullyProtectedPredicate)
	overall, perOrganization := poolToMetric(pool, effectiveProtectionGatePopulation)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, repoRulesCollectors)
	overall.EvidenceRefs = refs
	perOrganization = applyPerOrganizationEvidenceRefs(perOrganization, evidenceRefsPerOrganization(input.Report, repoRulesCollectors))
	result.Metrics["repos_fully_protected_pct"] = Metric{Key: "repos_fully_protected_pct", Overall: overall, PerOrganization: perOrganization}
	result.Metrics["rule_type_coverage"] = Metric{
		Key: "rule_type_coverage", Overall: reportedMetricValue(input.Report, "rule_type_coverage", input.Targets), PerOrganization: map[string]MetricValue{},
	}
	rulesetActiveMetric := reportedMetric(input.Report, "org_default_branch_rulesets_active", input.Targets)
	result.Metrics["org_default_branch_rulesets_active"] = rulesetActiveMetric
	result.EvidenceRefs = refs

	if overall.Status != MetricKnown {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + overall.Reason
		return result
	}
	value := *overall.Number
	implementedFloor, overridden := effectiveImplementedFloor(input.Thresholds, "repos_fully_protected_pct", 95)
	tier := thresholdTier(value, 80, implementedFloor)
	wideningNote := ""
	if tier == NotImplemented {
		typePool := poolRuleTypeCoverage(input.Report)
		missingType, exactlyOne, determinable := missingRuleType(typePool)
		switch {
		case !determinable:
			wideningNote = " The rule's \"missing one rule type\" widening clause could not be evaluated (no " +
				"confidently assessed rule-type data); this measured tier is reported without applying that clause."
		case exactlyOne:
			tier = PartiallyImplemented
			wideningNote = fmt.Sprintf(" Widened from NOT_IMPLEMENTED to PARTIAL per the rule's \"missing one rule "+
				"type\" clause: %s shows zero coverage across all %d confidently assessed repositories while the "+
				"other three required rule types each have at least one.", missingType, typePool.denominator)
		default:
			wideningNote = " The rule's \"missing one rule type\" widening clause does not apply here (zero, two, " +
				"three or all four required rule types show zero coverage, not exactly one)."
		}
	}
	overrideNote := ""
	if overridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override: implemented floor is %.1f%%, not the profile default 95%%)", implementedFloor)
	}
	if tier == Implemented {
		secondary := crossOrganizationSecondary(rulesetActiveMetric)
		_, confirmed := gatedTier(value, 80, implementedFloor, secondary, 1)
		if !confirmed {
			result.ProposedState, result.Confidence = NotAssessed, LowConfidence
			if secondary == nil {
				result.Notes = fmt.Sprintf(
					"Measured %.1f%% fully protected (>=%.1f%% implemented floor reached%s), but org_default_branch_rulesets_active "+
						"(an active org ruleset confirmed to target ~DEFAULT_BRANCH across all/most repos, agreeing across every "+
						"analyzed organization) is not computed by this run's implemented collectors, so IMPLEMENTED cannot be "+
						"confirmed for this compound rule.", value, implementedFloor, overrideNote)
			} else {
				result.Notes = fmt.Sprintf(
					"Measured %.1f%% fully protected (>=%.1f%% implemented floor reached%s), but org_default_branch_rulesets_active "+
						"is confirmed false for at least one analyzed organization (a pooled \"any organization\" OR cannot prove this "+
						"condition holds broadly, so every organization's own observation must agree). This exact combination (gate at "+
						"its IMPL floor, secondary known but failing) has no mapping in the rule's literal PART/NOT text, which "+
						"conditions those tiers only on the gate; reported NOT_ASSESSED as an explicit ambiguous/unmapped rule "+
						"combination rather than guessed as PARTIAL.", value, implementedFloor, overrideNote)
			}
			return result
		}
	}
	result.ProposedState = tier
	result.Confidence = confidenceFor(value, 80, implementedFloor, pool.incomplete == 0, anySampled(input.Report))
	result.Notes = fmt.Sprintf(
		"Measured %.1f%% (%d/%d) of analyzed active repositories with effective default-branch rules including "+
			"pull_request (>=1 approval), required_status_checks (>=1 context), non_fast_forward and deletion; "+
			"thresholds: >=%.1f%% implemented%s, 80-%.1f%% partial.%s",
		value, pool.numerator, pool.denominator, implementedFloor, overrideNote, implementedFloor, wideningNote)
	return result
}

// crossOrganizationSecondary extracts gatedTier's secondary input from a
// boolean metric this run pools as an OR across analyzed organizations
// (org_default_branch_rulesets_active): across more than one organization,
// the pooled Overall OR cannot by itself prove the condition holds broadly
// (one small, compliant organization could mask a large organization's gap),
// so every organization's own per-organization observation must agree before
// this returns a confirmed-true (1.0) signal; any organization with a
// confirmed-false observation returns a confirmed-false (0.0) signal (not
// masked by other organizations being true); any organization whose own
// observation is itself unknown returns nil (cannot confirm either way). A
// metric with no per-organization breakdown at all falls back to its pooled
// Overall value, which is the correct, unambiguous signal for a single
// analyzed organization.
func crossOrganizationSecondary(metric Metric) *float64 {
	if len(metric.PerOrganization) == 0 {
		return booleanSecondary(metric.Overall)
	}
	anyKnown, allTrue := false, true
	for _, value := range metric.PerOrganization {
		if value.Status != MetricKnown || value.Boolean == nil {
			return nil
		}
		anyKnown = true
		if !*value.Boolean {
			allTrue = false
		}
	}
	if !anyKnown {
		return nil
	}
	result := 0.0
	if allTrue {
		result = 1.0
	}
	return &result
}

const criticalSignaturePopulation = "critical repositories with a confirmed critical-population membership and a confidently assessed default-branch effective protection record"

// poolCriticalSignatures folds required_signatures presence across each
// organization's confirmed critical population only (not every analyzed
// repository): an organization whose critical population could not be
// confirmed (ComputeCriticalPopulation's "unknown" method) counts its entire
// contribution as incomplete rather than being excluded, so the pooled metric
// never silently narrows to the organizations that happened to resolve.
func poolCriticalSignatures(report *VerticalSliceReport) (pool protectionPool, fallbackCaveat string) {
	pool.perOrganization = map[string]*protectionPoolOrganization{}
	for _, organization := range report.Organizations {
		orgPool := &protectionPoolOrganization{}
		if organization.Population == nil || organization.Population.Critical == nil || organization.Population.Critical.Method == "unknown" {
			orgPool.incomplete++
			pool.incomplete++
			pool.perOrganization[organization.Scope.Key()] = orgPool
			continue
		}
		critical := organization.Population.Critical
		if critical.Caveat != "" && fallbackCaveat == "" {
			fallbackCaveat = critical.Caveat
		}
		byName := make(map[string]RepositoryRunResult, len(organization.Repositories))
		for _, repository := range organization.Repositories {
			byName[repository.FullName] = repository
		}
		for _, fullName := range critical.FullNames {
			repository, known := byName[fullName]
			effective := repository.EffectiveProtection
			if !known || effective == nil || effective.Completeness != CollectionOK {
				orgPool.incomplete++
				continue
			}
			orgPool.denominator++
			if effective.Signatures {
				orgPool.numerator++
			}
		}
		pool.numerator += orgPool.numerator
		pool.denominator += orgPool.denominator
		pool.incomplete += orgPool.incomplete
		pool.perOrganization[organization.Scope.Key()] = orgPool
	}
	return pool, fallbackCaveat
}

// evaluateGOV072 implements: "IMPL if required_signatures is in the effective
// default-branch rules for >= 95% of critical repos AND >= 95% of the last
// 100 default-branch commits on those repos are verified; PART if rule
// present on 50-95% or verified ratio 80-95%; NOT if < 50%
// (web_commit_signoff_required alone does not count)." Unlike the other
// compound rules in this registry, GOV-072's PART clause explicitly ORs two
// independent sub-conditions across both metrics ("rule present on 50-95%"
// OR "verified ratio 80-95%"), so this evaluator implements the full
// two-variable tier matrix directly (govSeventyTwoCompoundTier) rather than
// routing through the single-gate gatedTier helper: IMPLEMENTED requires
// both the signature-presence gate and the commit-verification ratio to
// independently reach their own 95% floor (each possibly a customer-accepted
// threshold override); PARTIAL triggers whenever either metric's own
// inclusive tier (via thresholdTier) lands in its stated PART band,
// regardless of the other metric's value; NOT_IMPLEMENTED triggers purely
// from the signature-presence gate falling below 50% (the rule's stated
// condition never mentions the secondary). The one combination the rule's
// literal text does not map to any tier — the signature-presence gate at or
// above 95% while the commit-verification ratio is known but below 80% — is
// reported NOT_ASSESSED as an explicit ambiguous/unmapped combination,
// exactly like this registry's other compound rules, never guessed as
// PARTIAL. The gate (critical_repos_requiring_signatures_pct) is derived
// directly from each organization's confirmed critical population and each
// critical repository's effective required_signatures rule, matching the
// rule text exactly.
func evaluateGOV072(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	pool, fallbackCaveat := poolCriticalSignatures(input.Report)
	overall, perOrganization := poolToMetric(pool, criticalSignaturePopulation)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, repoRulesCollectors)
	overall.EvidenceRefs = refs
	perOrganization = applyPerOrganizationEvidenceRefs(perOrganization, evidenceRefsPerOrganization(input.Report, repoRulesCollectors))
	result.Metrics["critical_repos_requiring_signatures_pct"] = Metric{
		Key: "critical_repos_requiring_signatures_pct", Overall: overall, PerOrganization: perOrganization,
	}
	verifiedCommitMetric := reportedMetric(input.Report, "verified_commit_ratio_pct", input.Targets)
	result.Metrics["verified_commit_ratio_pct"] = verifiedCommitMetric
	result.EvidenceRefs = refs

	var notes []string
	if fallbackCaveat != "" {
		notes = append(notes, "One or more organizations' critical population used the recent-pushed fallback rather "+
			"than a confirmed criticality property: "+fallbackCaveat)
	}

	if overall.Status != MetricKnown {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = strings.Join(append([]string{"NOT_ASSESSED: " + overall.Reason}, notes...), " ")
		return result
	}
	primary := *overall.Number
	primaryFloor, primaryOverridden := effectiveImplementedFloor(input.Thresholds, "critical_repos_requiring_signatures_pct", 95)
	secondaryFloor, secondaryOverridden := effectiveImplementedFloor(input.Thresholds, "verified_commit_ratio_pct", 95)
	var secondary *float64
	if verifiedCommitMetric.Overall.Status == MetricKnown && verifiedCommitMetric.Overall.Number != nil {
		value := *verifiedCommitMetric.Overall.Number
		secondary = &value
	}
	tier, ambiguous := govSeventyTwoCompoundTier(primary, primaryFloor, secondary, secondaryFloor)
	overrideNote := ""
	if primaryOverridden || secondaryOverridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override(s) in effect: signature-presence implemented "+
			"floor %.1f%%, commit-verification floor %.1f%%)", primaryFloor, secondaryFloor)
	}
	if ambiguous {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		secondarySummary := "not computed by this run"
		if secondary != nil {
			secondarySummary = fmt.Sprintf("%.1f%%, below its own 80%% PART floor", *secondary)
		}
		notes = append([]string{fmt.Sprintf(
			"Measured %.1f%% of critical repositories require signatures (>=%.1f%% implemented floor reached%s), but "+
				"verified_commit_ratio_pct is %s. This exact combination has no mapping in the rule's literal PART/NOT "+
				"text (PART requires either metric's own stated band, NOT is defined purely via the signature-presence "+
				"gate); reported NOT_ASSESSED as an explicit ambiguous/unmapped rule combination rather than guessed as "+
				"PARTIAL.", primary, primaryFloor, overrideNote, secondarySummary)}, notes...)
		result.Notes = strings.Join(notes, " ")
		return result
	}
	result.ProposedState = tier
	result.Confidence = confidenceFor(primary, 50, primaryFloor, pool.incomplete == 0, anySampled(input.Report))
	notes = append([]string{fmt.Sprintf(
		"Measured %.1f%% (%d/%d) of this run's confirmed critical repositories with required_signatures present in "+
			"their effective default-branch rules (web_commit_signoff_required does not count toward this signal); "+
			"thresholds: >=%.1f%% implemented%s, >=50%% partial. verified_commit_ratio_pct: %s.",
		primary, pool.numerator, pool.denominator, primaryFloor, overrideNote, metricSummary(verifiedCommitMetric.Overall))}, notes...)
	result.Notes = strings.Join(notes, " ")
	return result
}

// orMatrixTier implements the shared two-variable OR-compound tier pattern
// this registry uses for every rule whose literal PART clause independently
// ORs two metrics' own bands rather than gating a single shared floor
// (GOV-072's "rule present 50-95% OR verified ratio 80-95%", COL-001's
// "coverage 70-90% OR first review <=24h"): IMPLEMENTED requires both tiers
// to independently reach Implemented; PARTIAL triggers whenever either
// tier's own classification is PartiallyImplemented, regardless of the
// other; NOT triggers purely from primaryTier falling to NotImplemented,
// matching every one of these rules' literal NOT clause being defined only
// via the primary variable. The one remaining, textually unmapped
// combination (primary at/above its own floor, secondary unmeasured or
// known-but-below-its-own-PART-band) is reported ambiguous rather than
// guessed.
func orMatrixTier(primaryTier State, secondaryTier State, secondaryKnown bool) (tier State, ambiguous bool) {
	switch {
	case primaryTier == Implemented && secondaryKnown && secondaryTier == Implemented:
		return Implemented, false
	case primaryTier == PartiallyImplemented || (secondaryKnown && secondaryTier == PartiallyImplemented):
		return PartiallyImplemented, false
	case primaryTier == NotImplemented:
		return NotImplemented, false
	default:
		return "", true
	}
}

// govSeventyTwoCompoundTier implements GOV-072's exact two-variable tier
// matrix with inclusive boundaries (reusing thresholdTier for each metric
// independently, then orMatrixTier's shared IMPL/PART/NOT/ambiguous
// classification): IMPLEMENTED requires both primary and secondary to
// independently reach their own implementedFloor; PARTIAL triggers whenever
// either metric's own tier (via thresholdTier against [implementedFloor-15,
// implementedFloor], matching the rule's stated 15-point PART bands for both
// halves) is PartiallyImplemented, regardless of the other metric; NOT
// triggers purely from primary falling below its own PART floor, matching
// the rule's literal "NOT if <50%" text, which never mentions secondary. The
// one remaining, textually unmapped combination (primary at/above its floor,
// secondary known but below its own PART floor) is reported ambiguous.
func govSeventyTwoCompoundTier(primary, primaryFloor float64, secondary *float64, secondaryFloor float64) (tier State, ambiguous bool) {
	const primaryPartialFloor = 50   // literal rule text: "rule present on 50-95%"
	const secondaryPartialFloor = 80 // literal rule text: "verified ratio 80-95%"
	primaryTier := thresholdTier(primary, primaryPartialFloor, primaryFloor)
	var secondaryTier State
	secondaryKnown := secondary != nil
	if secondaryKnown {
		secondaryTier = thresholdTier(*secondary, secondaryPartialFloor, secondaryFloor)
	}
	return orMatrixTier(primaryTier, secondaryTier, secondaryKnown)
}

// evaluateSEC043 implements: "IMPL if dependabot_security_updates is enabled
// on >= 90% of eligible repos AND >= 70% have dependabot.yml version updates
// with grouping; PART if security updates 60-90%; NOT if < 60%." The profile
// cites repo.contents_probe and org.code_security_configs as this control's
// collectors; the org.code_security_configs half is not implemented in this
// run. Instead, this evaluator reuses the already-computed
// dependabot_security_updates_pct signal (the same declared metric key,
// derived from the repo.sbom eligibility proxy and repo.details'
// security_and_analysis operational status), explicitly disclosing that
// substitution rather than hiding it. A customer-accepted threshold override
// for dependabot_security_updates_pct replaces the 90% IMPLEMENTED floor.
// This rule's literal PART ("60-90%") and NOT ("<60%") text conditions those
// tiers purely on dependabot_security_updates_pct, never mentioning the
// grouped version-update secondary at all: when the gate alone reaches the
// IMPLEMENTED floor but the secondary is known yet below its own 70% floor,
// that exact combination has no mapping in the rule's literal text and is
// reported NOT_ASSESSED as an explicit ambiguous/unmapped combination, never
// guessed as PARTIAL.
func evaluateSEC043(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	allSignals, perOrganizationSignals := collectFeatureSignals(input.Report)
	_, dependency := AggregateFeatureCoverage(allSignals)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, dependabotCollectors)
	overall := dependency.Metric
	overall.EvidenceRefs = refs
	perOrganization := make(map[string]MetricValue, len(perOrganizationSignals))
	for key, signals := range perOrganizationSignals {
		_, orgDependency := AggregateFeatureCoverage(signals)
		perOrganization[key] = orgDependency.Metric
	}
	perOrganization = applyPerOrganizationEvidenceRefs(perOrganization, evidenceRefsPerOrganization(input.Report, dependabotCollectors))
	result.Metrics["dependabot_security_updates_pct"] = Metric{
		Key: "dependabot_security_updates_pct", Overall: overall, PerOrganization: perOrganization,
	}
	groupedUpdatesMetric := reportedMetric(input.Report, "repos_with_grouped_version_updates_pct", input.Targets)
	result.Metrics["repos_with_grouped_version_updates_pct"] = groupedUpdatesMetric
	result.EvidenceRefs = refs

	substitutionNote := "The profile cites repo.contents_probe/org.code_security_configs for this control; this run " +
		"instead reuses the repo.sbom-eligibility/repo.details-operational dependabot_security_updates_pct signal " +
		"(same declared metric key) because repo.contents_probe and org.code_security_configs are not implemented " +
		"collectors in this run. " + dependency.Notes

	implementedFloor, overridden := effectiveImplementedFloor(input.Thresholds, "dependabot_security_updates_pct", 90)
	overrideNote := ""
	if overridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override: implemented floor is %.1f%%, not the profile default 90%%)", implementedFloor)
	}

	if overall.Status != MetricKnown {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + overall.Reason + " " + substitutionNote
		return result
	}
	value := *overall.Number
	secondary := percentageSecondary(groupedUpdatesMetric.Overall)
	tier, confirmed := gatedTier(value, 60, implementedFloor, secondary, 70)
	// The repo.sbom/repo.details substitution above cannot distinguish a
	// disabled dependency graph from a genuinely absent manifest (see
	// dependency.Notes), so this evaluator never claims collector-complete
	// confidence for this control.
	if !confirmed {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		if secondary == nil {
			result.Notes = fmt.Sprintf(
				"Measured %.1f%% dependabot_security_updates_pct (>=%.1f%% implemented floor reached%s), but "+
					"repos_with_grouped_version_updates_pct (>=70%% of eligible repos with dependabot.yml version updates "+
					"using groups:) is not computed by this run, so IMPLEMENTED cannot be confirmed for this compound "+
					"rule. %s", value, implementedFloor, overrideNote, substitutionNote)
		} else {
			result.Notes = fmt.Sprintf(
				"Measured %.1f%% dependabot_security_updates_pct (>=%.1f%% implemented floor reached%s), and "+
					"repos_with_grouped_version_updates_pct is confirmed at %.1f%%, below its own 70%% floor. This "+
					"exact combination has no mapping in the rule's literal PART/NOT text (which conditions those "+
					"tiers only on dependabot_security_updates_pct); reported NOT_ASSESSED as an explicit "+
					"ambiguous/unmapped rule combination rather than guessed as PARTIAL. %s",
				value, implementedFloor, overrideNote, *secondary, substitutionNote)
		}
		return result
	}
	result.ProposedState = tier
	result.Confidence = confidenceFor(value, 60, implementedFloor, false, anySampled(input.Report))
	result.Notes = fmt.Sprintf(
		"Measured %.1f%% (%d/%d) of SBOM-eligible repositories with dependabot_security_updates enabled per "+
			"repo.details; thresholds: >=%.1f%% implemented%s, 60-%.1f%% partial. %s",
		value, dependency.Numerator, dependency.Denominator, implementedFloor, overrideNote, implementedFloor, substitutionNote)
	return result
}

// collectFeatureSignals gathers every analyzed repository's feature-coverage
// signal, both pooled and grouped per organization, for feature-coverage
// evaluators to pass through the exported AggregateFeatureCoverage helper.
func collectFeatureSignals(report *VerticalSliceReport) (all []RepositoryFeatureSignal, perOrganization map[string][]RepositoryFeatureSignal) {
	perOrganization = map[string][]RepositoryFeatureSignal{}
	for _, organization := range report.Organizations {
		signals := make([]RepositoryFeatureSignal, 0, len(organization.Repositories))
		for _, repository := range organization.Repositories {
			signals = append(signals, repository.Feature)
		}
		perOrganization[organization.Scope.Key()] = signals
		all = append(all, signals...)
	}
	return all, perOrganization
}

// evaluateSEC099 implements: "For every uses: reference to a non-local,
// non-GitHub-owned action: pinned = 40-hex SHA. IMPL if >= 95% of third-party
// action references are SHA-pinned AND >= 80% of repos with workflows have
// dependabot.yml with package-ecosystem: github-actions; PART if 70-95%
// pinned; NOT if < 70%. Also report GitHub-owned pinning % separately." The
// gate (third_party_refs_sha_pinned_pct) and the separately-reported
// github_owned_refs_sha_pinned_pct are both genuinely computed from this
// run's workflow analysis. A customer-accepted threshold override for
// third_party_refs_sha_pinned_pct replaces the 95% IMPLEMENTED floor. This
// rule's literal PART ("70-95%") and NOT ("<70%") text conditions those
// tiers purely on third_party_refs_sha_pinned_pct, never mentioning the
// dependabot.yml ecosystem-update secondary at all: when the gate alone
// reaches the IMPLEMENTED floor but the secondary is known yet below its own
// 80% floor, that exact combination has no mapping in the rule's literal
// text and is reported NOT_ASSESSED as an explicit ambiguous/unmapped
// combination, never guessed as PARTIAL.
func evaluateSEC099(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	var allReferences []ActionReference
	perOrganizationReferences := map[string][]ActionReference{}
	complete := true
	for _, organization := range input.Report.Organizations {
		var references []ActionReference
		for _, repository := range organization.Repositories {
			if repository.Workflows == nil {
				continue
			}
			references = append(references, repository.Workflows.References...)
			if len(repository.Workflows.Notes) > 0 {
				complete = false
			}
		}
		perOrganizationReferences[organization.Scope.Key()] = references
		allReferences = append(allReferences, references...)
	}
	pins := AggregateActionPinCoverage(allReferences)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, workflowCollectors)
	thirdParty, githubOwned := pins.ThirdParty.Metric, pins.GitHubOwned.Metric
	thirdParty.EvidenceRefs, githubOwned.EvidenceRefs = refs, refs

	perOrganizationThird := make(map[string]MetricValue, len(perOrganizationReferences))
	perOrganizationGitHub := make(map[string]MetricValue, len(perOrganizationReferences))
	for key, references := range perOrganizationReferences {
		orgPins := AggregateActionPinCoverage(references)
		perOrganizationThird[key] = orgPins.ThirdParty.Metric
		perOrganizationGitHub[key] = orgPins.GitHubOwned.Metric
	}
	orgRefs := evidenceRefsPerOrganization(input.Report, workflowCollectors)
	perOrganizationThird = applyPerOrganizationEvidenceRefs(perOrganizationThird, orgRefs)
	perOrganizationGitHub = applyPerOrganizationEvidenceRefs(perOrganizationGitHub, orgRefs)
	result.Metrics["third_party_refs_sha_pinned_pct"] = Metric{Key: "third_party_refs_sha_pinned_pct", Overall: thirdParty, PerOrganization: perOrganizationThird}
	result.Metrics["github_owned_refs_sha_pinned_pct"] = Metric{Key: "github_owned_refs_sha_pinned_pct", Overall: githubOwned, PerOrganization: perOrganizationGitHub}
	actionsEcosystemMetric := reportedMetric(input.Report, "repos_with_actions_ecosystem_updates_pct", input.Targets)
	result.Metrics["repos_with_actions_ecosystem_updates_pct"] = actionsEcosystemMetric
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, workflowCollectors...)...)

	separateNote := "GitHub-owned action references are reported separately (not gating): " + metricSummary(githubOwned) + "."
	implementedFloor, overridden := effectiveImplementedFloor(input.Thresholds, "third_party_refs_sha_pinned_pct", 95)
	overrideNote := ""
	if overridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override: implemented floor is %.1f%%, not the profile default 95%%)", implementedFloor)
	}

	if thirdParty.Status != MetricKnown {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + thirdParty.Reason + " " + separateNote
		return result
	}
	value := *thirdParty.Number
	secondary := percentageSecondary(actionsEcosystemMetric.Overall)
	tier, confirmed := gatedTier(value, 70, implementedFloor, secondary, 80)
	if !confirmed {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		if secondary == nil {
			result.Notes = fmt.Sprintf(
				"Measured %.1f%% third-party action references SHA-pinned (>=%.1f%% implemented floor reached%s), but "+
					"repos_with_actions_ecosystem_updates_pct (>=80%% of repos with workflows have dependabot.yml with "+
					"package-ecosystem: github-actions) is not computed by this run, so IMPLEMENTED cannot be confirmed "+
					"for this compound rule. %s", value, implementedFloor, overrideNote, separateNote)
		} else {
			result.Notes = fmt.Sprintf(
				"Measured %.1f%% third-party action references SHA-pinned (>=%.1f%% implemented floor reached%s), and "+
					"repos_with_actions_ecosystem_updates_pct is confirmed at %.1f%%, below its own 80%% floor. This "+
					"exact combination has no mapping in the rule's literal PART/NOT text (which conditions those tiers "+
					"only on third_party_refs_sha_pinned_pct); reported NOT_ASSESSED as an explicit ambiguous/unmapped "+
					"rule combination rather than guessed as PARTIAL. %s", value, implementedFloor, overrideNote, *secondary, separateNote)
		}
		return result
	}
	result.ProposedState = tier
	result.Confidence = confidenceFor(value, 70, implementedFloor, complete, anySampled(input.Report))
	result.Notes = fmt.Sprintf(
		"Measured %.1f%% (%d/%d) of third-party action references pinned to an exact 40-hex commit SHA; thresholds: "+
			">=%.1f%% implemented%s, 70-%.1f%% partial. %s",
		value, pins.ThirdParty.Numerator, pins.ThirdParty.Denominator, implementedFloor, overrideNote, implementedFloor, separateNote)
	return result
}

var col001Collectors = []string{"repo.prs"}

// evaluateCOL001 implements: "Data: share of PRs with >= 1 comment or review
// before merge; median time to first review. IMPL if review coverage >= 90%
// and median time to first review <= 8 working hours, and teams describe
// design discussions before implementation (interview); PART if coverage
// 70-90% or first review <= 24h; NOT if coverage < 70%." COL-001 is Partial
// automation, so every proposal here always requires assessor confirmation;
// this evaluator proposes a tier from review_coverage_pct and
// median_time_to_first_review_h alone and explicitly defers the
// design-discussion interview half to that mandatory confirmation.
//
// The rule's PART clause independently ORs two bands (coverage 70-90%, OR
// first-review time within its own <=24h band) while its NOT clause is
// defined purely via coverage; this is the same shape orMatrixTier already
// serves for GOV-072, generalized here for a lower-is-better secondary
// (faster is better, so its own Implemented/Partial bands are <=8h/<=24h
// rather than a percentage floor/ceiling).
func evaluateCOL001(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	coverageMetric := reportedMetric(input.Report, "review_coverage_pct", input.Targets)
	timeMetric := reportedMetric(input.Report, "median_time_to_first_review_h", input.Targets)
	result.Metrics["review_coverage_pct"] = coverageMetric
	result.Metrics["median_time_to_first_review_h"] = timeMetric
	refs := evidenceRefsForScopedCollectors(input.Report, nil, col001Collectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, col001Collectors...)...)

	if coverageMetric.Overall.Status != MetricKnown || coverageMetric.Overall.Number == nil {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + coverageMetric.Overall.Reason
		return result
	}
	coverage := *coverageMetric.Overall.Number
	implementedFloor, overridden := effectiveImplementedFloor(input.Thresholds, "review_coverage_pct", 90)
	overrideNote := ""
	if overridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override: implemented floor is %.1f%%, not the profile default 90%%)", implementedFloor)
	}
	coverageTier := thresholdTier(coverage, 70, implementedFloor)

	// median_time_to_first_review_h is genuinely computed as raw calendar-
	// elapsed time (first-review timestamp minus PR-creation timestamp, with
	// no weekend/holiday/business-hours exclusion anywhere in its
	// derivation -- see activity_metrics.go), never true working-hours-
	// elapsed time, even though the rule's own IMPL clause is phrased in
	// "working hours." This evaluator never claims to have measured working
	// hours directly; instead it discloses the one sound inference calendar
	// time DOES support: working hours can never exceed calendar-elapsed
	// hours, so a calendar reading at or under the rule's own 8-hour IMPL
	// ceiling is sufficient proof that the working-hours ceiling is also
	// met, while a higher reading neither confirms nor refutes it (a PR
	// whose first review landed just after a weekend could show a large
	// calendar gap despite a small genuine working-hours gap). The rule's
	// PART band ("<=24h") is not itself qualified as working hours in the
	// profile's literal text, so that threshold is evaluated directly
	// against the calendar measurement with no translation needed.
	timeKnown := timeMetric.Overall.Status == MetricKnown && timeMetric.Overall.Number != nil
	var timeTier State
	var timeValue float64
	if timeKnown {
		timeValue = *timeMetric.Overall.Number
		switch {
		case timeValue <= 8:
			timeTier = Implemented
		case timeValue <= 24:
			timeTier = PartiallyImplemented
		default:
			timeTier = NotImplemented
		}
	}
	tier, ambiguous := orMatrixTier(coverageTier, timeTier, timeKnown)
	interviewNote := " The design-discussion interview half of this control's IMPLEMENTED clause is always deferred to mandatory assessor confirmation (COL-001 is Partial automation), never assumed satisfied."
	if ambiguous {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		if !timeKnown {
			result.Notes = fmt.Sprintf(
				"Measured %.1f%% PR review coverage (>=%.1f%% implemented floor reached%s), but "+
					"median_time_to_first_review_h is not computed by this run, so IMPLEMENTED cannot be confirmed for "+
					"this compound rule.%s", coverage, implementedFloor, overrideNote, interviewNote)
		} else {
			result.Notes = fmt.Sprintf(
				"Measured %.1f%% PR review coverage (>=%.1f%% implemented floor reached%s), and median time to first "+
					"review is %.1f calendar-elapsed hours (not working-hours-aware; see this evaluator's own "+
					"documentation), above the rule's own <=24h plain-calendar PART band -- a measurement this high "+
					"does not sufficiently prove the rule's separate <=8-working-hour IMPL ceiling is violated, since a "+
					"genuine working-hours figure could still be lower across a weekend/holiday gap, but it is too high "+
					"to independently confirm either OR-clause member either. This exact combination has no mapping in "+
					"the rule's literal PART/NOT text (which conditions those tiers only on review coverage); reported "+
					"NOT_ASSESSED as an explicit ambiguous/unmapped rule combination rather than guessed as "+
					"PARTIAL.%s", coverage, implementedFloor, overrideNote, timeValue, interviewNote)
		}
		return result
	}
	result.ProposedState = tier
	result.Confidence = confidenceFor(coverage, 70, implementedFloor, true, anySampled(input.Report))
	timeSummary := "not computed by this run"
	if timeKnown {
		switch {
		case timeValue <= 8:
			timeSummary = fmt.Sprintf(
				"%.1f calendar-elapsed hours, a sufficient (not directly measured) bound proving the rule's own "+
					"<=8-working-hour IMPL ceiling, since working hours can never exceed calendar-elapsed hours", timeValue)
		default:
			timeSummary = fmt.Sprintf(
				"%.1f calendar-elapsed hours (not working-hours-aware), within the rule's own <=24h plain-calendar PART band", timeValue)
		}
	}
	result.Notes = fmt.Sprintf(
		"Measured %.1f%% PR review coverage (share of PRs with >=1 comment or review before merge); thresholds: "+
			">=%.1f%% implemented%s, 70-%.1f%% partial, below not implemented. Median time to first review: %s "+
			"(<=8h/<=24h bands independently contribute to the IMPLEMENTED/PARTIAL OR clause).%s",
		coverage, implementedFloor, overrideNote, implementedFloor, timeSummary, interviewNote)
	return result
}

var prd016Collectors = []string{"repo.actions_runs"}

// evaluatePRD016 implements: "Data: 90-day CI success rate, median duration,
// median queue time, failure trend. IMPL if success rate >= 90%, median
// queue time < 2 min, and the customer reviews Actions performance metrics
// at least monthly (interview); PART if metrics are acceptable but not
// reviewed, or reviewed with success rate 75-90%; NOT if success rate < 75%
// and no review." PRD-016 is Partial automation, so every proposal here
// always requires assessor confirmation; this evaluator proposes a tier from
// ci_success_rate_90d/median_queue_time_min alone and explicitly defers the
// "reviewed at least monthly" interview half (which also modulates this
// rule's PART/NOT tiers, not only its IMPL tier) to that mandatory
// confirmation, treating it uniformly as an unconfirmed fact this run cannot
// observe at every tier rather than assuming any answer.
//
// The rule's only literal numeric band for the secondary queue-time signal
// is a single IMPL-gating ceiling ("< 2 min"), with no separate PART-band
// ceiling given, unlike COL-001/GOV-072's two-independent-band secondaries:
// this reuses gatedTier (via a floor-convention negation: a "must be <=2min"
// requirement expressed as "-queueTime >= -2.0") rather than the two-
// variable orMatrixTier/govSeventyTwoCompoundTier pattern. The <2 min
// boundary is treated inclusively (<=2 min) for consistency with every
// other evaluator's inclusive-floor convention in this registry.
// evaluatePRD016 implements: "Data: 90-day CI success rate, median duration,
// median queue time, failure trend. IMPL if success rate >= 90%, median
// queue time < 2 min, and the customer reviews Actions performance metrics
// at least monthly (interview); PART if metrics are acceptable but not
// reviewed, or reviewed with success rate 75-90%; NOT if success rate < 75%
// and no review." PRD-016 is Partial automation, so every proposal here
// always requires assessor confirmation.
//
// Every one of this rule's three tiers is itself a compound AND/OR
// condition over the "reviewed at least monthly" interview fact, which this
// run can never observe: IMPL requires reviewed=true; NOT requires
// reviewed=false ("no review"); only PART's "acceptable but not reviewed"
// clause is satisfiable from automation's perspective alone, since
// automation never has affirmative proof of review and that clause is
// defined for exactly that unconfirmed case. This evaluator therefore never
// proposes IMPLEMENTED (same reasoning as PRD-029's permanently-unverifiable
// authentication-type clause) and never proposes NOT_IMPLEMENTED purely
// from a low success rate (gatedTier's convenience shortcut of treating any
// non-Implemented tier as independently confirmable was wrong here: it
// would invent NOT_IMPLEMENTED from success<75% alone despite "no review"
// being just as unconfirmable as "reviewed" is for IMPL). Any success rate
// at or above the rule's own NOT-floor (75%) proposes PART, matching
// "metrics are acceptable but not reviewed" directly (median queue time is
// informational only at this stage -- it gates what an assessor would need
// to ALSO confirm, alongside a genuinely positive review answer, before
// finalizing IMPLEMENTED, not what this evaluator proposes). A success rate
// below 75% has no literal mapping without knowing the review answer (NOT
// requires confirming "no review"; nothing in the rule maps "<75% AND
// reviewed=true" to anything at all) and is reported ambiguous/unmapped,
// deferring entirely to assessor confirmation. The "< 2 min" queue-time
// ceiling is evaluated with a strict inequality, matching the rule's own
// literal "<" wording exactly (unlike this registry's usual inclusive-floor
// convention, which does not apply here since the rule itself never writes
// "<=").
func evaluatePRD016(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	successMetric := reportedMetric(input.Report, "ci_success_rate_90d", input.Targets)
	queueMetric := reportedMetric(input.Report, "median_queue_time_min", input.Targets)
	durationMetric := reportedMetric(input.Report, "median_run_duration_min", input.Targets)
	result.Metrics["ci_success_rate_90d"] = successMetric
	result.Metrics["median_queue_time_min"] = queueMetric
	result.Metrics["median_run_duration_min"] = durationMetric
	refs := evidenceRefsForScopedCollectors(input.Report, nil, prd016Collectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, prd016Collectors...)...)

	if successMetric.Overall.Status != MetricKnown || successMetric.Overall.Number == nil {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + successMetric.Overall.Reason
		return result
	}
	value := *successMetric.Overall.Number
	const notFloor float64 = 75
	implementedFloor, overridden := effectiveImplementedFloor(input.Thresholds, "ci_success_rate_90d", 90)
	overrideNote := ""
	if overridden {
		overrideNote = fmt.Sprintf(" (customer-accepted threshold override: implemented floor is %.1f%%, not the profile default 90%%)", implementedFloor)
	}
	queueKnown := queueMetric.Overall.Status == MetricKnown && queueMetric.Overall.Number != nil
	var queueValue float64
	queueMeetsImplBound := false
	if queueKnown {
		queueValue = *queueMetric.Overall.Number
		queueMeetsImplBound = queueValue < 2.0 // strict: the rule's own text is "< 2 min", never "<=2 min"
	}
	queueSummary := "not computed by this run"
	if queueKnown {
		queueSummary = fmt.Sprintf("%.1f minutes", queueValue)
	}
	interviewNote := " Whether the customer reviews Actions performance metrics at least monthly is always deferred to " +
		"mandatory assessor confirmation (PRD-016 is Partial automation); automation alone can never affirmatively " +
		"confirm either a positive review (required for IMPLEMENTED) or its absence (required for NOT_IMPLEMENTED)."

	if value < notFloor {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = fmt.Sprintf(
			"Measured %.1f%% 90-day CI success rate, below the rule's own 75%% NOT-floor. NOT_IMPLEMENTED additionally "+
				"requires confirming \"no review\" (an interview-only fact this run cannot observe), and the rule "+
				"provides no mapping at all for a confirmed review alongside this success rate; reported NOT_ASSESSED "+
				"as an explicit ambiguous/unmapped combination rather than guessed as NOT_IMPLEMENTED.%s",
			value, interviewNote)
		return result
	}
	result.ProposedState, result.Confidence = PartiallyImplemented, confidenceFor(value, notFloor, implementedFloor, true, anySampled(input.Report))
	implEligibility := "median queue time is not computed by this run, so even a genuinely positive review answer could not yet confirm IMPLEMENTED"
	if queueKnown {
		if queueMeetsImplBound {
			implEligibility = fmt.Sprintf("median queue time (%s) is within the rule's own <2 minute IMPLEMENTED ceiling, "+
				"so a genuinely positive review answer alone could confirm IMPLEMENTED", queueSummary)
		} else {
			implEligibility = fmt.Sprintf("median queue time (%s) is at or above the rule's own <2 minute IMPLEMENTED "+
				"ceiling, so IMPLEMENTED cannot be confirmed regardless of the review answer", queueSummary)
		}
	}
	result.Notes = fmt.Sprintf(
		"Measured %.1f%% 90-day CI success rate (>=%.1f%% NOT-floor%s): this alone satisfies the rule's own \"metrics "+
			"acceptable but not reviewed\" PART clause, since automation never has affirmative proof of review. Median "+
			"queue time: %s; %s.%s",
		value, notFloor, overrideNote, queueSummary, implEligibility, interviewNote)
	return result
}

var prd029Collectors = []string{"org.installations", "org.hooks", "org.pat_governance"}

// evaluatePRD029 implements: "IMPL if custom integrations authenticate as
// GitHub Apps (installations with owner != marketplace vendor) or
// fine-grained PATs with expiry, and webhooks use a secret with
// insecure_ssl = 0; PART if some custom integrations use classic PATs or
// webhooks without secrets (<= 30%); NOT if > 30% of hooks lack secrets or
// classic PATs dominate." PRD-029 is Full automation: an evaluator here must
// never confirm a tier it cannot actually prove, with no mandatory
// confirmation safety net to catch an overclaim.
//
// IMPLEMENTED's AND-clause requires BOTH the webhook-secret/SSL half AND
// the GitHub-Apps-vs-classic-PAT authentication-type half; the profile
// declares no classic-PAT-count metric at all (only
// fine_grained_pat_grants_count, a raw count with no denominator to express
// "dominate" against), so the authentication-type half can never be
// verified by this run, under any observed combination of the available
// counts. IMPLEMENTED is therefore never proposed, full stop, regardless of
// how clean hooks_without_secret_pct/hooks_insecure_ssl_count look: a
// missing, permanently-unverifiable AND-clause member means NOT_ASSESSED,
// not a guess that the unverified half happens to be satisfied.
//
// PART and NOT, by contrast, are each independently satisfiable from the
// webhook-secret half alone, because the rule's literal text explicitly ORs
// that half with the authentication-type condition for both of those tiers
// ("...or webhooks without secrets (<=30%)"; "...or classic PATs
// dominate") — hooks_without_secret_pct crossing its own PART/NOT band is
// sufficient on its own, independent of what the unverifiable
// authentication-type half would have shown.
func evaluatePRD029(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	hooksWithoutSecretMetric := reportedMetric(input.Report, "hooks_without_secret_pct", input.Targets)
	insecureSSLMetric := reportedMetric(input.Report, "hooks_insecure_ssl_count", input.Targets)
	customAppsMetric := reportedMetric(input.Report, "custom_apps_count", input.Targets)
	patGrantsMetric := reportedMetric(input.Report, "fine_grained_pat_grants_count", input.Targets)
	result.Metrics["hooks_without_secret_pct"] = hooksWithoutSecretMetric
	result.Metrics["hooks_insecure_ssl_count"] = insecureSSLMetric
	result.Metrics["custom_apps_count"] = customAppsMetric
	result.Metrics["fine_grained_pat_grants_count"] = patGrantsMetric
	refs := evidenceRefsForScopedCollectors(input.Report, nil, prd029Collectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, prd029Collectors...)...)

	integrationTypeNote := " The GitHub-Apps-vs-classic-PAT authentication-type AND-clause required for IMPLEMENTED " +
		"is never independently verifiable by this run (the profile declares no classic-PAT-count metric to compare " +
		fmt.Sprintf("against fine_grained_pat_grants_count=%s, custom_apps_count=%s", metricSummary(patGrantsMetric.Overall), metricSummary(customAppsMetric.Overall)) +
		"); IMPLEMENTED is therefore never proposed by this evaluator, regardless of the webhook-secret/SSL half."

	if hooksWithoutSecretMetric.Overall.Status != MetricKnown || hooksWithoutSecretMetric.Overall.Number == nil {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + hooksWithoutSecretMetric.Overall.Reason + integrationTypeNote
		return result
	}
	hooksWithoutSecret := *hooksWithoutSecretMetric.Overall.Number
	// hooks_without_secret_pct is lower-is-better; invert it (100 - x) so
	// thresholdTier's standard >=implementedFloor/>=partialFloor convention
	// applies directly: 0% without secret (100% with) reaches the top tier,
	// (0,30] without secret lands in PARTIAL's band, >30% without secret
	// falls to NOT_IMPLEMENTED.
	hooksWithSecret := 100 - hooksWithoutSecret
	tier := thresholdTier(hooksWithSecret, 70, 100)
	// The "Implemented" case is deliberately never returned to the caller as
	// IMPLEMENTED (see below): PART/NOT resolve directly from this tier,
	// but reaching the top tier is downgraded to NOT_ASSESSED instead,
	// since IMPLEMENTED can never be independently confirmed without the
	// permanently-unverifiable authentication-type half.
	switch tier {
	case NotImplemented:
		result.ProposedState = NotImplemented
		result.Confidence = confidenceFor(hooksWithSecret, 70, 100, true, anySampled(input.Report))
		result.Notes = fmt.Sprintf(
			"Measured %.1f%% of webhooks without a secret, above the rule's >30%% NOT_IMPLEMENTED floor; this alone "+
				"independently satisfies NOT_IMPLEMENTED per the rule's literal OR clause, regardless of custom "+
				"integration authentication type.%s", hooksWithoutSecret, integrationTypeNote)
	case PartiallyImplemented:
		result.ProposedState = PartiallyImplemented
		result.Confidence = confidenceFor(hooksWithSecret, 70, 100, true, anySampled(input.Report))
		result.Notes = fmt.Sprintf(
			"Measured %.1f%% of webhooks without a secret, within the rule's 0-30%% PARTIAL band; this alone "+
				"independently satisfies PARTIAL per the rule's literal OR clause, regardless of custom integration "+
				"authentication type.%s", hooksWithoutSecret, integrationTypeNote)
	default:
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		insecureSSLKnown := insecureSSLMetric.Overall.Status == MetricKnown && insecureSSLMetric.Overall.Number != nil
		sslSummary := "not computed by this run"
		if insecureSSLKnown {
			sslSummary = metricSummary(insecureSSLMetric.Overall)
		}
		result.Notes = fmt.Sprintf(
			"Measured 0%% of webhooks without a secret (hooks_insecure_ssl_count: %s), reaching the webhook-secret/"+
				"SSL half's own top tier. But IMPLEMENTED requires BOTH that half AND the authentication-type half, "+
				"which this run can never verify; NOT_ASSESSED rather than assuming the unverified half is "+
				"satisfied.%s", sslSummary, integrationTypeNote)
	}
	return result
}

var sec016Collectors = []string{"org.settings", "org.members", "org.outside_collaborators", "repo.access"}

// sec016OwnerCriterionResult reports whether the owner-count criterion
// ("owners <= max(2, 5% of members) and <= 5 absolute") is satisfied,
// evaluated per organization rather than against a cross-organization
// pooled sum: the rule's "5 absolute" cap is a per-organization governance
// bound (an organization's own owners should be few), not a budget shared
// across every organization this run happens to analyze together. Pooling
// owner_count's Overall value (a plain sum across organizations) before
// comparing it to the absolute-5 cap would fail every healthy organization
// collectively merely because enough of them exist (for example three
// organizations each with 2 owners -- individually well under both the
// absolute cap and the 5%-of-members ratio -- pool to 6, incorrectly
// exceeding the cap even though none of them, on its own, violates
// anything). Each organization's own owner_count/owner_ratio_pct must
// therefore independently satisfy the criterion; the overall criterion
// fails only when at least one organization's own figures fail it, and the
// disclosed reason names that organization specifically rather than a
// pooled total that was never the rule's actual subject.
type sec016OwnerCriterionResult struct {
	confirmed  bool
	pass       bool
	failingOrg string
	summary    string
}

func evaluateSEC016OwnerCriterionPerOrganization(countMetric, ratioMetric Metric) sec016OwnerCriterionResult {
	if len(countMetric.PerOrganization) == 0 && len(ratioMetric.PerOrganization) == 0 {
		// No per-organization breakdown at all (for example a single
		// analyzed organization, where Overall already IS that one
		// organization's own figure with nothing to pool across): Overall
		// is the correct, unambiguous signal in this case.
		if countMetric.Overall.Status != MetricKnown || countMetric.Overall.Number == nil ||
			ratioMetric.Overall.Status != MetricKnown || ratioMetric.Overall.Number == nil {
			return sec016OwnerCriterionResult{confirmed: false}
		}
		count, ratio := *countMetric.Overall.Number, *ratioMetric.Overall.Number
		pass := count <= 5 && (count <= 2 || ratio <= 5.0)
		return sec016OwnerCriterionResult{confirmed: true, pass: pass,
			summary: fmt.Sprintf("owner_count=%.0f, owner_ratio_pct=%.1f%%", count, ratio)}
	}
	organizationKeys := make(map[string]bool, len(countMetric.PerOrganization)+len(ratioMetric.PerOrganization))
	for key := range countMetric.PerOrganization {
		organizationKeys[key] = true
	}
	for key := range ratioMetric.PerOrganization {
		organizationKeys[key] = true
	}
	keys := make([]string, 0, len(organizationKeys))
	for key := range organizationKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count, countKnown := countMetric.PerOrganization[key]
		ratio, ratioKnown := ratioMetric.PerOrganization[key]
		if !countKnown || !ratioKnown || count.Status != MetricKnown || count.Number == nil ||
			ratio.Status != MetricKnown || ratio.Number == nil {
			return sec016OwnerCriterionResult{confirmed: false}
		}
		if !(*count.Number <= 5 && (*count.Number <= 2 || *ratio.Number <= 5.0)) {
			return sec016OwnerCriterionResult{confirmed: true, pass: false, failingOrg: key,
				summary: fmt.Sprintf("%s: owner_count=%.0f, owner_ratio_pct=%.1f%%", key, *count.Number, *ratio.Number)}
		}
	}
	return sec016OwnerCriterionResult{confirmed: true, pass: true, summary: "every analyzed organization independently satisfies its own owner cap"}
}

// evaluateSEC016 implements: "IMPL if default_repository_permission in
// (read, none), owners <= max(2, 5% of members) and <= 5 absolute (or per
// agreed baseline), <= 10% of sampled repos have direct collaborators,
// outside collaborators < 5% of members, and 2FA disabled members = 0; PART
// if one criterion fails; NOT if >= 2 fail." This is a literal 5-criteria
// pass/fail count, not a percentage-floor/ceiling tier: every criterion must
// be independently, confidently known before any can be counted as
// pass/fail (a missing criterion could be either, so the rule cannot be
// evaluated at all until every declared metric genuinely resolves). The
// owner-count/owner-ratio criterion is evaluated per organization (see
// evaluateSEC016OwnerCriterionPerOrganization), never against a pooled
// cross-organization sum. Confidence is deliberately capped at Medium
// (never High): a 5-criterion pass/fail count combines heterogeneous units
// (a text enum, two absolute counts and ratios, a percentage, a raw count)
// with no single, clean "distance from boundary" concept this registry's
// confidenceFor helper already generalizes for a single percentage gate.
func evaluateSEC016(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	permissionMetric := reportedMetric(input.Report, "default_repository_permission", input.Targets)
	ownerCountMetric := reportedMetric(input.Report, "owner_count", input.Targets)
	ownerRatioMetric := reportedMetric(input.Report, "owner_ratio_pct", input.Targets)
	directCollabMetric := reportedMetric(input.Report, "repos_with_direct_collaborators_pct", input.Targets)
	outsideCollabMetric := reportedMetric(input.Report, "outside_collab_ratio_pct", input.Targets)
	withoutTwoFAMetric := reportedMetric(input.Report, "members_without_2fa", input.Targets)
	result.Metrics["default_repository_permission"] = permissionMetric
	result.Metrics["owner_count"] = ownerCountMetric
	result.Metrics["owner_ratio_pct"] = ownerRatioMetric
	result.Metrics["repos_with_direct_collaborators_pct"] = directCollabMetric
	result.Metrics["outside_collab_ratio_pct"] = outsideCollabMetric
	result.Metrics["members_without_2fa"] = withoutTwoFAMetric
	refs := evidenceRefsForScopedCollectors(input.Report, nil, sec016Collectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, sec016Collectors...)...)

	ownerCriterion := evaluateSEC016OwnerCriterionPerOrganization(ownerCountMetric, ownerRatioMetric)

	var missing []string
	if permissionMetric.Overall.Status != MetricKnown || permissionMetric.Overall.Text == nil {
		missing = append(missing, "default_repository_permission")
	}
	if !ownerCriterion.confirmed {
		missing = append(missing, "owner_count/owner_ratio_pct (every analyzed organization's own figures)")
	}
	if directCollabMetric.Overall.Status != MetricKnown || directCollabMetric.Overall.Number == nil {
		missing = append(missing, "repos_with_direct_collaborators_pct")
	}
	if outsideCollabMetric.Overall.Status != MetricKnown || outsideCollabMetric.Overall.Number == nil {
		missing = append(missing, "outside_collab_ratio_pct")
	}
	if withoutTwoFAMetric.Overall.Status != MetricKnown || withoutTwoFAMetric.Overall.Number == nil {
		missing = append(missing, "members_without_2fa")
	}
	if len(missing) > 0 {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = fmt.Sprintf(
			"NOT_ASSESSED: this control's literal 5-criteria pass/fail count requires every declared metric to be "+
				"confidently known before any criterion can be counted as pass or fail; not yet measured: %s.",
			strings.Join(missing, ", "))
		return result
	}

	permission := strings.ToLower(strings.TrimSpace(*permissionMetric.Overall.Text))
	permissionPass := permission == "read" || permission == "none"
	directCollabPass := *directCollabMetric.Overall.Number <= 10.0
	outsideCollabPass := *outsideCollabMetric.Overall.Number < 5.0
	twoFAPass := *withoutTwoFAMetric.Overall.Number == 0

	var failedCriteria []string
	if !permissionPass {
		failedCriteria = append(failedCriteria, fmt.Sprintf("default_repository_permission=%q not in (read, none)", permission))
	}
	if !ownerCriterion.pass {
		failedCriteria = append(failedCriteria, fmt.Sprintf(
			"owner cap exceeded for at least one analyzed organization (evaluated per organization, not pooled): %s", ownerCriterion.summary))
	}
	if !directCollabPass {
		failedCriteria = append(failedCriteria, fmt.Sprintf(
			"repos_with_direct_collaborators_pct=%.1f%% exceeds 10%%", *directCollabMetric.Overall.Number))
	}
	if !outsideCollabPass {
		failedCriteria = append(failedCriteria, fmt.Sprintf(
			"outside_collab_ratio_pct=%.1f%% is not below 5%%", *outsideCollabMetric.Overall.Number))
	}
	if !twoFAPass {
		failedCriteria = append(failedCriteria, fmt.Sprintf(
			"members_without_2fa=%.0f is not exactly 0", *withoutTwoFAMetric.Overall.Number))
	}

	switch len(failedCriteria) {
	case 0:
		result.ProposedState = Implemented
	case 1:
		result.ProposedState = PartiallyImplemented
	default:
		result.ProposedState = NotImplemented
	}
	result.Confidence = MediumConfidence
	if anySampled(input.Report) {
		result.Confidence = LowConfidence
	}
	failureSummary := "none"
	if len(failedCriteria) > 0 {
		failureSummary = strings.Join(failedCriteria, "; ")
	}
	result.Notes = fmt.Sprintf(
		"Measured against the profile's literal 5-criteria pass/fail count (default_repository_permission in "+
			"{read, none}; owners <= max(2, 5%% of members) and <=5 absolute; <=10%% of sampled repos have direct "+
			"collaborators; outside collaborators <5%% of members; 2FA-disabled members =0): %d of 5 failed (%s). "+
			"IMPLEMENTED requires 0 failures, PARTIAL exactly 1, NOT_IMPLEMENTED >=2.", len(failedCriteria), failureSummary)
	return result
}

var ownerTeamRolesCollectors = []string{"org.members", "org.roles", "org.teams"}

// rolesBeyondOwnerMemberCount derives ARC-093/ARC-104's declared
// "roles_in_use" metric from the two genuinely measured role signals this
// phase's collectors actually produce (security_manager_teams,
// custom_roles_count) rather than inventing a separate "roles_in_use"
// collector key the profile's own rule text never names a source for: the
// rule's own parenthetical "(security_manager/custom)" identifies these two
// signals as its own named examples of "roles used beyond owner/member".
// The sum is a genuine count when BOTH components are known; when only one
// is known, that component alone is reported with a disclosed lower-bound
// caveat (it can only undercount, never overcount, the true total); the
// metric is Unavailable only when NEITHER component resolved at all.
func rolesBeyondOwnerMemberCount(securityManagerTeams, customRoles MetricValue) MetricValue {
	securityKnown := securityManagerTeams.Status == MetricKnown && securityManagerTeams.Number != nil
	customKnown := customRoles.Status == MetricKnown && customRoles.Number != nil
	population := "analyzed organizations' security_manager team assignments plus custom organization/repository roles"
	switch {
	case securityKnown && customKnown:
		total := *securityManagerTeams.Number + *customRoles.Number
		return MetricValue{Status: MetricKnown, Number: &total, Population: population, EvidenceRefs: []string{}}
	case securityKnown:
		total := *securityManagerTeams.Number
		return MetricValue{Status: MetricKnown, Number: &total, Population: population, EvidenceRefs: []string{},
			Reason: "custom_roles_count was not resolved this run; this figure is security_manager_teams alone, a lower bound on the true total"}
	case customKnown:
		total := *customRoles.Number
		return MetricValue{Status: MetricKnown, Number: &total, Population: population, EvidenceRefs: []string{},
			Reason: "security_manager_teams was not resolved this run; this figure is custom_roles_count alone, a lower bound on the true total"}
	default:
		return MetricValue{Status: MetricUnavailable, Population: population, EvidenceRefs: []string{},
			Reason: "neither security_manager_teams nor custom_roles_count was resolved this run"}
	}
}

// ownerCapOrRatioCriterionResult is evaluateOwnerCapOrRatioPerOrganization's
// return: confirmed is false only when at least one analyzed organization's
// owner_count or owner_ratio_pct was not genuinely known, meaning this
// criterion cannot be counted as pass or fail at all yet (never guessed).
type ownerCapOrRatioCriterionResult struct {
	confirmed  bool
	pass       bool
	failingOrg string
	summary    string
}

// evaluateOwnerCapOrRatioPerOrganization implements ARC-093/ARC-104/
// GOV-017's literal "owners <= 5 (or <= 5% of members)" clause -- a plain OR
// between an absolute cap and a ratio cap, distinct from SEC-016's own
// stricter "owners <= 5 AND (owners <= 2 OR ratio <= 5%)" formula for the
// same two metric keys; the two controls' literal rule text differ and must
// not share one formula. Evaluated per organization, never pooled: a
// pooled owner_count summed across several healthy organizations could
// exceed 5 while every single organization independently satisfies its own
// cap, which must never read as a failure (the same pooling bug fixed for
// SEC-016 in an earlier round, applied here from the start).
func evaluateOwnerCapOrRatioPerOrganization(countMetric, ratioMetric Metric) ownerCapOrRatioCriterionResult {
	pass := func(count, ratio float64) bool { return count <= 5 || ratio <= 5.0 }
	if len(countMetric.PerOrganization) == 0 && len(ratioMetric.PerOrganization) == 0 {
		if countMetric.Overall.Status != MetricKnown || countMetric.Overall.Number == nil ||
			ratioMetric.Overall.Status != MetricKnown || ratioMetric.Overall.Number == nil {
			return ownerCapOrRatioCriterionResult{confirmed: false}
		}
		count, ratio := *countMetric.Overall.Number, *ratioMetric.Overall.Number
		return ownerCapOrRatioCriterionResult{confirmed: true, pass: pass(count, ratio),
			summary: fmt.Sprintf("owner_count=%.0f, owner_ratio_pct=%.1f%%", count, ratio)}
	}
	organizationKeys := make(map[string]bool, len(countMetric.PerOrganization)+len(ratioMetric.PerOrganization))
	for key := range countMetric.PerOrganization {
		organizationKeys[key] = true
	}
	for key := range ratioMetric.PerOrganization {
		organizationKeys[key] = true
	}
	keys := make([]string, 0, len(organizationKeys))
	for key := range organizationKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		count, countKnown := countMetric.PerOrganization[key]
		ratio, ratioKnown := ratioMetric.PerOrganization[key]
		if !countKnown || !ratioKnown || count.Status != MetricKnown || count.Number == nil ||
			ratio.Status != MetricKnown || ratio.Number == nil {
			return ownerCapOrRatioCriterionResult{confirmed: false}
		}
		if !pass(*count.Number, *ratio.Number) {
			return ownerCapOrRatioCriterionResult{confirmed: true, pass: false, failingOrg: key,
				summary: fmt.Sprintf("%s: owner_count=%.0f, owner_ratio_pct=%.1f%%", key, *count.Number, *ratio.Number)}
		}
	}
	return ownerCapOrRatioCriterionResult{confirmed: true, pass: true,
		summary: "every analyzed organization independently satisfies owners <=5 or owner_ratio_pct <=5%"}
}

// rolesBeyondCriterionResult is evaluateRolesBeyondOwnerMemberCriterion's
// return: confirmed is false whenever the criterion's pass/fail status
// cannot yet be counted at all (see that function's own doc for exactly
// which combinations this covers).
type rolesBeyondCriterionResult struct {
	confirmed bool
	pass      bool
}

// evaluateRolesBeyondOwnerMemberCriterion implements ARC-093/ARC-104's
// "roles used beyond owner/member (security_manager/custom)" criterion as a
// genuine tri-state, not a plain boolean OR collapsed from two
// possibly-unknown signals: a positive, confirmed security_manager_teams or
// custom_roles_count count (> 0, genuinely known) confirms the criterion
// PASSED regardless of the other signal's own status (one is enough). The
// criterion can only be confirmed FAILED when BOTH signals are
// independently, genuinely known to be exactly zero -- a single
// known-zero signal (for example security_manager_teams confirmed 0) paired
// with the OTHER signal still entirely unmeasured (custom_roles_count
// unknown) must NOT be treated as "effectively zero" and counted as a
// failure: an unmeasured custom organization role could still exist,
// confirming the criterion actually passed, and there is no genuine
// evidence here to rule that out. Any other combination (either or both
// signals unknown, with neither confirmed positive) returns confirmed:false,
// so the caller can propagate it into the same NOT_ASSESSED path as every
// other missing-metric case, never guessing a tier from an unconfirmed
// absence.
func evaluateRolesBeyondOwnerMemberCriterion(securityManagerTeams, customRoles MetricValue) rolesBeyondCriterionResult {
	securityManagerKnown := securityManagerTeams.Status == MetricKnown && securityManagerTeams.Number != nil
	customRolesKnown := customRoles.Status == MetricKnown && customRoles.Number != nil
	if securityManagerKnown && *securityManagerTeams.Number > 0 {
		return rolesBeyondCriterionResult{confirmed: true, pass: true}
	}
	if customRolesKnown && *customRoles.Number > 0 {
		return rolesBeyondCriterionResult{confirmed: true, pass: true}
	}
	if securityManagerKnown && customRolesKnown {
		return rolesBeyondCriterionResult{confirmed: true, pass: false}
	}
	return rolesBeyondCriterionResult{confirmed: false}
}

// evaluateOwnerTeamRoleTriCriteria implements the literal 3-criteria
// pass/fail count ARC-093 and ARC-104 share verbatim ("IMPL if owners <= 5
// (or <= 5% of members), team-based access >= 90%, and roles used beyond
// owner/member (security_manager/custom); PART if one criterion fails; NOT
// if two or more"): the owner cap-or-ratio clause (evaluated per
// organization, never pooled), a single team_based_access_pct >= 90%
// threshold, and "roles used beyond owner/member" via
// evaluateRolesBeyondOwnerMemberCriterion's genuine tri-state (see its own
// doc). Every criterion must be confidently known before any can be counted
// as pass or fail; a missing one is explicit NOT_ASSESSED, never guessed.
// Confidence is capped at Medium for the same heterogeneous-units reason
// SEC-016 documents (a per-organization pass/fail, a single percentage
// threshold and a count-presence check have no single "distance from
// boundary" concept to report High confidence from).
func evaluateOwnerTeamRoleTriCriteria(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	ownerCountMetric := reportedMetric(input.Report, "owner_count", input.Targets)
	ownerRatioMetric := reportedMetric(input.Report, "owner_ratio_pct", input.Targets)
	teamBasedMetric := reportedMetric(input.Report, "team_based_access_pct", input.Targets)
	securityManagerMetric := reportedMetricValue(input.Report, "security_manager_teams", input.Targets)
	customRolesMetric := reportedMetricValue(input.Report, "custom_roles_count", input.Targets)
	rolesInUseMetric := rolesBeyondOwnerMemberCount(securityManagerMetric, customRolesMetric)
	result.Metrics["owner_count"] = ownerCountMetric
	result.Metrics["team_based_access_pct"] = teamBasedMetric
	result.Metrics["roles_in_use"] = Metric{Key: "roles_in_use", Overall: rolesInUseMetric, PerOrganization: map[string]MetricValue{}}
	refs := evidenceRefsForScopedCollectors(input.Report, nil, ownerTeamRolesCollectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, ownerTeamRolesCollectors...)...)

	ownerCriterion := evaluateOwnerCapOrRatioPerOrganization(ownerCountMetric, ownerRatioMetric)

	var missing []string
	if !ownerCriterion.confirmed {
		missing = append(missing, "owner_count/owner_ratio_pct (every analyzed organization's own figures)")
	}
	if teamBasedMetric.Overall.Status != MetricKnown || teamBasedMetric.Overall.Number == nil {
		missing = append(missing, "team_based_access_pct")
	}
	rolesCriterion := evaluateRolesBeyondOwnerMemberCriterion(securityManagerMetric, customRolesMetric)
	if !rolesCriterion.confirmed {
		missing = append(missing, "security_manager_teams/custom_roles_count (both must be confidently known to "+
			"count this criterion as failed; a single known-zero signal paired with the other signal still "+
			"unmeasured cannot rule out a role this run simply never measured)")
	}
	if len(missing) > 0 {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = fmt.Sprintf(
			"NOT_ASSESSED: this control's literal 3-criteria pass/fail count requires every declared metric to be "+
				"confidently known before any criterion can be counted as pass or fail; not yet measured: %s.",
			strings.Join(missing, ", "))
		return result
	}

	teamBasedPass := *teamBasedMetric.Overall.Number >= 90.0
	rolesBeyondPass := rolesCriterion.pass

	var failedCriteria []string
	if !ownerCriterion.pass {
		failedCriteria = append(failedCriteria, fmt.Sprintf(
			"owner cap exceeded for at least one analyzed organization (evaluated per organization, not pooled): %s", ownerCriterion.summary))
	}
	if !teamBasedPass {
		failedCriteria = append(failedCriteria, fmt.Sprintf(
			"team_based_access_pct=%.1f%% is below the 90%% floor", *teamBasedMetric.Overall.Number))
	}
	if !rolesBeyondPass {
		failedCriteria = append(failedCriteria, "no security_manager team assignment and no custom organization/repository role observed")
	}

	switch len(failedCriteria) {
	case 0:
		result.ProposedState = Implemented
	case 1:
		result.ProposedState = PartiallyImplemented
	default:
		result.ProposedState = NotImplemented
	}
	result.Confidence = MediumConfidence
	if anySampled(input.Report) {
		result.Confidence = LowConfidence
	}
	failureSummary := "none"
	if len(failedCriteria) > 0 {
		failureSummary = strings.Join(failedCriteria, "; ")
	}
	result.Notes = fmt.Sprintf(
		"Measured against the profile's literal 3-criteria pass/fail count (owners <=5 or owner_ratio_pct <=5%%, "+
			"evaluated per organization; team_based_access_pct >=90%%; a security_manager team assignment or custom "+
			"role observed): %d of 3 failed (%s). IMPLEMENTED requires 0 failures, PARTIAL exactly 1, "+
			"NOT_IMPLEMENTED >=2.", len(failedCriteria), failureSummary)
	return result
}

// evaluateARC093 implements: "IMPL if owners <= 5 (or <= 5% of members),
// team-based access >= 90%, and roles used beyond owner/member
// (security_manager/custom); PART if one criterion fails; NOT if two or
// more." See evaluateOwnerTeamRoleTriCriteria for the shared implementation
// (ARC-104 declares this identical rule text verbatim for a different
// pillar/area).
func evaluateARC093(control Control, input *EvaluationInput) ControlResult {
	return evaluateOwnerTeamRoleTriCriteria(control, input)
}

// evaluateARC104 implements the same literal rule as ARC-093 (see
// evaluateOwnerTeamRoleTriCriteria); the profile declares this control's
// rule text identically under a separate pillar/area.
func evaluateARC104(control Control, input *EvaluationInput) ControlResult {
	return evaluateOwnerTeamRoleTriCriteria(control, input)
}

var securityManagerCollectors = []string{"org.roles", "org.members"}

// evaluateSEC132 implements: "IMPL if the security team is assigned
// security_manager (team) or a custom org role with security permissions
// and no security team member is an org owner solely for security work;
// PART if security_manager assigned but some security staff are owners;
// NOT if security access is through owner only." PART's own literal text
// requires POSITIVELY KNOWING some security staff ARE owners, and NOT's own
// literal text requires POSITIVELY KNOWING access is through owner ONLY
// (meaning no custom org role separately grants it either) -- neither
// clause is satisfied merely by security_manager_teams being known. This
// run's collectors never measure security_staff_owners (which individual
// members are "security staff" and whether any of them separately hold
// owner) or custom_security_role (whether a custom organization role
// grants security permissions) at all, so EVERY tier's own distinguishing
// clause remains unconfirmed regardless of security_manager_teams' own
// value: a known-positive security_manager_teams does not confirm PART's
// "some staff are owners" clause (that could just as easily be false,
// which would make this IMPLEMENTED instead -- inventing PART from an
// unknown staff-ownership status is exactly the "known-zero lower bound"
// mistake this control must not repeat), and a known-zero
// security_manager_teams does not confirm NOT's "owner only" clause either
// (an unmeasured custom role could still exist). This control is therefore
// explicit NOT_ASSESSED in every case given today's collector surface,
// never silently defaulting to a guessed tier merely because
// security_manager_teams itself happens to be known.
func evaluateSEC132(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	securityManagerMetric := reportedMetric(input.Report, "security_manager_teams", input.Targets)
	result.Metrics["security_manager_teams"] = securityManagerMetric
	result.Metrics["security_staff_owners"] = unknownMetric("security_staff_owners", input.Targets)
	result.Metrics["custom_security_role"] = unknownMetric("custom_security_role", input.Targets)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, securityManagerCollectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, securityManagerCollectors...)...)
	result.ProposedState, result.Confidence = NotAssessed, LowConfidence

	if securityManagerMetric.Overall.Status != MetricKnown || securityManagerMetric.Overall.Number == nil {
		result.Notes = "NOT_ASSESSED: " + securityManagerMetric.Overall.Reason
		return result
	}
	if *securityManagerMetric.Overall.Number > 0 {
		result.Notes = fmt.Sprintf(
			"NOT_ASSESSED: security_manager_teams=%.0f (at least one security_manager team assignment observed), "+
				"but PART's own literal text additionally requires knowing that SOME security staff also hold "+
				"owner status, which this run's collectors never measure (no security_staff_owners signal) -- a "+
				"known-positive security_manager_teams alone does not license PART (that staff-ownership status "+
				"could just as easily be false, which would make this IMPLEMENTED instead), so the state remains "+
				"explicit NOT_ASSESSED pending an actual assessor determination of which members are security "+
				"staff and whether any of them separately hold owner.", *securityManagerMetric.Overall.Number)
		return result
	}
	result.Notes = "NOT_ASSESSED: security_manager_teams=0 (no security_manager team assignment observed), but " +
		"NOT's own literal text additionally requires confirming security access is through owner ONLY, which " +
		"requires also knowing no custom organization role separately grants security permissions -- this run's " +
		"collectors never measure custom_security_role, so a known-zero security_manager_teams alone does not " +
		"license NOT_IMPLEMENTED (an unmeasured custom role could still exist); the state remains explicit " +
		"NOT_ASSESSED pending an actual assessor determination of whether any custom organization role grants " +
		"security access."
	return result
}

var outsideCollaboratorsAccessReviewCollectors = []string{"org.outside_collaborators", "org.members"}

// evaluateGOV065 implements: "IMPL if outside collaborators < 5% of
// members, each with a justification in a register, and access reviews
// (members, teams, collaborators) are evidenced quarterly; PART if
// collaborators 5-10% or reviews semi-annual; NOT if > 10% or no reviews."
// The profile's own declared justification-register and review-cadence
// metrics (outside_collab_with_justification_pct, access_review_cadence)
// require a customer-maintained document this run's collectors never
// observe (manual.document). The literal outside_collab_ratio_pct
// threshold IS independently measured and fully determines two of the
// three tiers on its own: > 10% is a genuine NOT_IMPLEMENTED (the rule's
// own NOT clause), and 5-10% is a genuine PARTIAL (the rule's own PART
// clause names this exact band), neither ever softened or escalated by the
// separately-unmeasured justification/review clauses. A ratio <= 5%
// satisfies IMPLEMENTED's OWN ratio sub-clause, but IMPLEMENTED also
// requires BOTH the justification register AND quarterly-evidenced
// reviews, neither of which this run can confirm -- and critically, a
// ratio <= 5% is NOT itself PART's own literal 5-10% band, nor does it
// satisfy PART's alternate "reviews semi-annual" clause (also unmeasured),
// so neither tier's own literal text actually describes this specific
// combination (a ratio below PART's own band, paired with wholly unknown
// justification/review status). Proposing PART here (as if the ratio
// alone, falling short of its own band, could still "round up" into PART
// merely because the measured ratio happens to be favorable) would invent
// a tier the rule's text does not license, exactly the same mistake as
// treating a known-zero lower bound as a confirmed failure elsewhere in
// this profile; this specific combination is therefore explicit
// NOT_ASSESSED, pending an actual assessor confirmation of the
// justification register and review cadence.
func evaluateGOV065(control Control, input *EvaluationInput) ControlResult {
	result := newControlResult(control)
	outsideCollabMetric := reportedMetric(input.Report, "outside_collab_ratio_pct", input.Targets)
	result.Metrics["outside_collab_ratio_pct"] = outsideCollabMetric
	result.Metrics["outside_collab_with_justification_pct"] = unknownMetric("outside_collab_with_justification_pct", input.Targets)
	result.Metrics["access_review_cadence"] = unknownMetric("access_review_cadence", input.Targets)
	refs := evidenceRefsForScopedCollectors(input.Report, nil, outsideCollaboratorsAccessReviewCollectors)
	result.EvidenceRefs = refs
	result.Flags = append(result.Flags, verifyEndpointFlag(input.Profile, outsideCollaboratorsAccessReviewCollectors...)...)

	if outsideCollabMetric.Overall.Status != MetricKnown || outsideCollabMetric.Overall.Number == nil {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: " + outsideCollabMetric.Overall.Reason
		return result
	}
	value := *outsideCollabMetric.Overall.Number
	switch {
	case value > 10:
		result.ProposedState = NotImplemented
		result.Confidence = confidenceFor(value, 5, 10, true, anySampled(input.Report))
		result.Notes = fmt.Sprintf(
			"outside_collab_ratio_pct=%.1f%% exceeds the rule's own 10%% NOT_IMPLEMENTED ceiling, a genuine "+
				"NOT_IMPLEMENTED regardless of the separately-unverifiable justification-register/review-cadence "+
				"clauses.", value)
	case value > 5:
		result.ProposedState = PartiallyImplemented
		result.Confidence = confidenceFor(value, 5, 10, true, anySampled(input.Report))
		result.Notes = fmt.Sprintf(
			"outside_collab_ratio_pct=%.1f%% is within the rule's own 5-10%% PARTIAL band.", value)
	default:
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = fmt.Sprintf(
			"NOT_ASSESSED: outside_collab_ratio_pct=%.1f%% is below PART's own 5-10%% band, so neither IMPLEMENTED "+
				"(which additionally requires a per-collaborator justification register and quarterly-evidenced "+
				"access reviews, neither measured) nor PART (whose own literal text is specifically the 5-10%% "+
				"ratio band or semi-annual reviews, also unmeasured here, neither of which this combination "+
				"satisfies) is licensed by the rule's own text; a human assessor confirmation of the justification "+
				"register and review cadence is required before this control can be assessed.", value)
	}
	return result
}
