// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import "fmt"

// effectiveProtectionPopulation documents the pooled protection/rule-type
// metrics' population so both the clean-known and uncertain/unavailable paths
// describe the same denominator consistently.
const effectiveProtectionPopulation = "analyzed repositories with a confidently assessed default-branch effective protection record"

// metricAccumulator folds per-repository analysis into run-wide pooled metrics.
// Ratio numerators and denominators are always computed from confidently
// assessed repositories, but an incomplete repository is never silently
// dropped from the overall accounting: its existence converts the pooled
// metric into an explicit unavailable result (preserving the confidently known
// subset's numerator/denominator for audit) instead of quietly presenting a
// clean coverage figure over a shrunken, undisclosed population.
type metricAccumulator struct {
	protectionObserved         int
	protectionIncomplete       int
	protectedNumerator         int
	protectedDenominator       int
	fullyProtectedNumerator    int
	fullyProtectedDenominator  int
	ruleTypeCoverage           map[string]float64
	activeOrganizationRulesets map[string]bool
	references                 []ActionReference
	featureSignals             []RepositoryFeatureSignal
}

func newMetricAccumulator() *metricAccumulator {
	return &metricAccumulator{
		ruleTypeCoverage: map[string]float64{}, activeOrganizationRulesets: map[string]bool{},
	}
}

// addEffectiveProtection folds one repository's effective branch protection
// into the pooled protection ratios and rule-type dictionary. A repository
// whose effective protection could not be confidently determined (missing
// permission, concealed endpoint, partial pagination) is counted toward
// protectionIncomplete, which forces populate to report the pooled metrics as
// unavailable rather than silently excluding that repository as if it had
// never been analyzed.
func (a *metricAccumulator) addEffectiveProtection(effective *EffectiveBranchProtection) {
	if effective == nil {
		return
	}
	a.protectionObserved++
	if effective.Completeness != CollectionOK {
		a.protectionIncomplete++
		return
	}
	a.protectedDenominator++
	if effective.PullRequestRequired && effective.BlockForcePush {
		a.protectedNumerator++
	}
	a.fullyProtectedDenominator++
	// GOV-070's "fully protected" criterion is pull_request (>=1 approval),
	// required_status_checks (>=1 context), non_fast_forward and deletion
	// protection. Required signatures are GOV-072's separate criterion and
	// must not be folded in here: an otherwise fully protected but unsigned
	// repository still counts toward GOV-070. Signature presence remains
	// separately tracked via the rule_type_coverage dictionary's
	// "required_signatures" entry.
	fullyProtected := effective.PullRequestRequired && effective.MinApprovals >= 1 && len(effective.StatusChecks) > 0 &&
		effective.BlockForcePush && effective.BlockDeletion
	if fullyProtected {
		a.fullyProtectedNumerator++
	}
	for _, ruleType := range effectiveRuleTypesPresent(effective) {
		a.ruleTypeCoverage[ruleType]++
	}
	for _, ruleset := range effective.ApplicableRulesets {
		if ruleset.SourceType == "Organization" {
			a.activeOrganizationRulesets[fmt.Sprintf("%s/%d", ruleset.Source, ruleset.ID)] = true
		}
	}
}

func (a *metricAccumulator) addReferences(references []ActionReference) {
	a.references = append(a.references, references...)
}

func (a *metricAccumulator) addFeatureSignal(signal RepositoryFeatureSignal) {
	a.featureSignals = append(a.featureSignals, signal)
}

// populate writes every accumulated pooled metric into the run's metrics map.
func (a *metricAccumulator) populate(metrics map[string]Metric) {
	incompleteReason := fmt.Sprintf(
		"%d of %d analyzed repositories had an incomplete effective default-branch protection assessment; "+
			"the confidently known subset below is preserved for audit but is not a complete coverage figure",
		a.protectionIncomplete, a.protectionObserved)

	protectedMetric, _ := Percentage(float64(a.protectedNumerator), float64(a.protectedDenominator), effectiveProtectionPopulation)
	if a.protectionIncomplete > 0 {
		protectedMetric = markCoverageUncertain(protectedMetric, incompleteReason)
	}
	setMetric(metrics, "repos_with_default_branch_protection_pct", protectedMetric)

	fullyProtectedMetric, _ := Percentage(float64(a.fullyProtectedNumerator), float64(a.fullyProtectedDenominator), effectiveProtectionPopulation)
	if a.protectionIncomplete > 0 {
		fullyProtectedMetric = markCoverageUncertain(fullyProtectedMetric, incompleteReason)
	}
	setMetric(metrics, "repos_fully_protected_pct", fullyProtectedMetric)

	ruleTypePopulation := "analyzed repositories' confidently assessed effective default-branch rule types"
	ruleTypeValue := MetricValue{
		Status: MetricUnavailable, Population: ruleTypePopulation, EvidenceRefs: []string{},
		Reason: "no confidently assessed effective rule data was collected",
	}
	if len(a.ruleTypeCoverage) > 0 {
		dictionary := a.ruleTypeCoverage
		ruleTypeValue = MetricValue{Status: MetricKnown, Dictionary: &dictionary, Population: ruleTypePopulation, EvidenceRefs: []string{}}
	}
	if a.protectionIncomplete > 0 {
		ruleTypeValue = MetricValue{Status: MetricUnavailable, Population: ruleTypePopulation, EvidenceRefs: []string{}, Reason: incompleteReason}
	}
	setMetric(metrics, "rule_type_coverage", ruleTypeValue)

	activeOrgRulesetsPopulation := "distinct organization-sourced rulesets observed protecting an analyzed repository's default branch " +
		"(discovered via each repository's inherited ruleset listing, not a direct top-level /orgs/{org}/rulesets enumeration)"
	switch {
	case a.protectionObserved == 0:
		setMetric(metrics, "active_org_rulesets_count", MetricValue{
			Status: MetricUnavailable, Population: activeOrgRulesetsPopulation, EvidenceRefs: []string{},
			Reason: "no repository's effective-rules evidence was observed; no inventory of active organization rulesets was collected",
		})
	case a.protectionIncomplete > 0:
		setMetric(metrics, "active_org_rulesets_count", MetricValue{
			Status: MetricUnavailable, Population: activeOrgRulesetsPopulation, EvidenceRefs: []string{}, Reason: incompleteReason,
		})
	default:
		activeOrgRulesetsCount := float64(len(a.activeOrganizationRulesets))
		setMetric(metrics, "active_org_rulesets_count", MetricValue{
			Status: MetricKnown, Number: &activeOrgRulesetsCount, Population: activeOrgRulesetsPopulation, EvidenceRefs: []string{},
		})
	}

	pins := AggregateActionPinCoverage(a.references)
	setMetric(metrics, pins.GitHubOwned.Feature, pins.GitHubOwned.Metric)
	setMetric(metrics, pins.ThirdParty.Feature, pins.ThirdParty.Metric)
	dockerCount := float64(pins.DockerRefCount)
	setMetric(metrics, "docker_action_refs_count", MetricValue{
		Status: MetricKnown, Number: &dockerCount, EvidenceRefs: []string{},
		Population: "analyzed workflow `uses:` references classified as Docker image references (sha256 digest scheme, not a 40-hex git commit SHA)",
	})
	dynamicCount := float64(pins.DynamicRefCount)
	setMetric(metrics, "dynamic_action_refs_count", MetricValue{
		Status: MetricKnown, Number: &dynamicCount, EvidenceRefs: []string{},
		Population: "analyzed workflow `uses:` references whose ref is a GitHub Actions expression and cannot be statically assessed for pin status",
	})

	codeQLCoverage, dependencyCoverage := AggregateFeatureCoverage(a.featureSignals)
	setMetric(metrics, codeQLCoverage.Feature, codeQLCoverage.Metric)
	setMetric(metrics, dependencyCoverage.Feature, dependencyCoverage.Metric)
}

func setMetric(metrics map[string]Metric, key string, value MetricValue) {
	metrics[key] = Metric{Key: key, Overall: value, PerOrganization: map[string]MetricValue{}}
}
