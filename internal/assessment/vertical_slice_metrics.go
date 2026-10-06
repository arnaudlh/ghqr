// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"time"
)

// effectiveProtectionPopulation documents the pooled protection/rule-type
// metrics' population so both the clean-known and uncertain/unavailable paths
// describe the same denominator consistently.
const effectiveProtectionPopulation = "analyzed repositories with a confidently assessed default-branch effective protection record"

// observationBucket pools one kind of per-repository/per-organization raw
// observation (merged pull requests, workflow runs, lifecycle alerts) into
// both a flat run-wide list and a per-organization-scoped list, plus whether
// any contributing collection was incomplete (overall and per organization).
// A median/ratio computed from a bucket's flat list is always the correct
// pooled figure (unlike averaging already-computed per-organization
// percentages or medians, which is not generally valid); per-organization
// figures are computed the same way from that organization's own sublist.
type observationBucket[T any] struct {
	overall           []T
	byOrganization    map[string][]T
	overallIncomplete bool
	incompleteByOrg   map[string]bool
}

func newObservationBucket[T any]() observationBucket[T] {
	return observationBucket[T]{byOrganization: map[string][]T{}, incompleteByOrg: map[string]bool{}}
}

func (b *observationBucket[T]) add(organizationKey string, items []T, complete bool) {
	b.overall = append(b.overall, items...)
	b.byOrganization[organizationKey] = append(b.byOrganization[organizationKey], items...)
	if !complete {
		b.overallIncomplete = true
		b.incompleteByOrg[organizationKey] = true
	}
}

// membershipTally accumulates FetchOrgMembership results across every
// configured organization (overall) and per organization.
type membershipTally struct {
	members, owners, withoutTwoFactor int
	complete                          bool
}

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
	featureSignals             observationBucket[RepositoryFeatureSignal]
	attestationSignals         observationBucket[RepositoryAttestationSignal]

	// Phase 4 operational/security/governance additions. Each bucket is
	// populated by the run loop (vertical_slice.go) calling the matching
	// operational_collectors.go/security_collectors.go/enterprise_collectors.go
	// function and folding its result in via the add* method below; populate()
	// then calls the one already-published pure-arithmetic helper per bucket
	// (ActivityMetrics/ActionsMetrics/AlertLifecycleMetrics/MembershipMetrics),
	// never re-deriving that arithmetic here.
	pullRequests       observationBucket[PullRequestObservation]
	actionsRuns        observationBucket[WorkflowRunObservation]
	dependabot         observationBucket[AlertObservation]
	codeScanning       observationBucket[AlertObservation]
	secretScanning     observationBucket[AlertObservation]
	membershipAll      membershipTally
	membershipByOrg    map[string]membershipTally
	membershipObserved bool

	securityConfigCoverageByOrg map[string]MetricValue
	installationsTotal          int
	installationsComplete       bool
	installationsObserved       bool
	customAppsTotal             int
	teamsTotal                  int
	nestedTeamsTotal            int
	hooksTotal, hooksActive     int
	hooksWithoutSecret          []MetricValue
	hookDeliveryFailures        []MetricValue
	hooksInsecureSSLTotal       int
	patGrantsTotal              int
	patPendingTotal             int
	customRoleCountTotal        int
	customRepoRoleCountTotal    int
	securityManagerTeamsTotal   int

	// directOrgRulesetsByOrg/directOrgRulesetsObserved hold the authoritative
	// top-level org.rulesets enumeration (independent of any repository
	// sample); when observed for an organization it takes precedence over
	// the repo-discovered activeOrganizationRulesets proxy for that
	// organization's active_org_rulesets_count.
	directOrgRulesetsByOrg          map[string]int
	directOrgRulesetsOrgSet         map[string]bool
	defaultBranchRulesetActiveByOrg map[string]bool

	// teamGrantedRepositoriesByOrg/teamGrantCountByOrg/teamGrantsIncompleteByOrg/
	// accessByOrg jointly compute team_based_access_pct (COL-027/SEC-017/
	// GOV-017's exact documented formula: team permission grants / (team
	// grants + direct collaborator grants), bots excluded) and
	// repos_with_direct_collaborators_pct. teamGrantCountByOrg is the actual
	// COUNT of (team, repository) permission-grant pairs (not merely whether
	// a repository has at least one team grant); teamGrantedRepositoriesByOrg
	// (the repository-presence set) is retained only for the separate,
	// clearly-labeled supplementary repo-coverage signal, never substituted
	// for the grant-count ratio itself.
	// COUNT of (team, repository) permission-grant pairs (not merely whether
	// a repository has at least one team grant); teamGrantedRepositoriesByOrg
	// (the repository-presence set) is retained only for the separate,
	// clearly-labeled supplementary repo-coverage signal, never substituted
	// for the grant-count ratio itself.
	teamGrantedRepositoriesByOrg map[string]map[string]bool
	teamGrantCountByOrg          map[string]int
	teamGrantsIncompleteByOrg    map[string]bool
	accessByOrg                  map[string][]RepositoryAccessResult

	// commitVerificationByOrg holds GOV-072's verified_commit_ratio_pct raw
	// population: every analyzed repository's default-branch commit
	// verification sample, keyed by RepositoryCommitVerificationResult.
	// Repository (full name). populateRulesetAndCommitMetrics filters this
	// down to each organization's confirmed CRITICAL population only (GOV-072
	// is scoped to critical repositories, never every analyzed repository)
	// using criticalPopulationKnownByOrg/criticalFullNamesByOrg.
	commitVerificationByOrg      map[string][]RepositoryCommitVerificationResult
	criticalPopulationKnownByOrg map[string]bool
	criticalFullNamesByOrg       map[string]map[string]bool

	// contentsProbeByOrg holds SEC-043/SEC-099's repos_with_grouped_version_
	// updates_pct/repos_with_actions_ecosystem_updates_pct raw population:
	// every analyzed repository's parsed .github/dependabot.yml signal,
	// paired with the two independently-determined denominators those
	// metrics are actually scoped to (dependency-eligible repositories for
	// SEC-043, repositories that actually use GitHub Actions for SEC-099) so
	// neither denominator is silently narrowed to "repositories whose
	// dependabot.yml happened to parse".
	contentsProbeByOrg map[string][]contentsProbeRecord

	// defaultRepoPermissionByOrg holds SEC-016's default_repository_permission
	// (a descriptive per-organization text value from the already-collected
	// org.settings response, not a ratio).
	defaultRepoPermissionByOrg map[string]string

	// outsideCollaboratorsByOrg holds SEC-016's outside_collab_ratio_pct and
	// outside_collaborators_without_2fa population.
	outsideCollaboratorsByOrg map[string]OrgOutsideCollaboratorsResult
}

func newMetricAccumulator() *metricAccumulator {
	return &metricAccumulator{
		ruleTypeCoverage: map[string]float64{}, activeOrganizationRulesets: map[string]bool{},
		pullRequests: newObservationBucket[PullRequestObservation](), actionsRuns: newObservationBucket[WorkflowRunObservation](),
		dependabot: newObservationBucket[AlertObservation](), codeScanning: newObservationBucket[AlertObservation](),
		secretScanning: newObservationBucket[AlertObservation](), membershipByOrg: map[string]membershipTally{},
		featureSignals:              newObservationBucket[RepositoryFeatureSignal](),
		attestationSignals:          newObservationBucket[RepositoryAttestationSignal](),
		securityConfigCoverageByOrg: map[string]MetricValue{}, installationsComplete: true,
		directOrgRulesetsByOrg: map[string]int{}, directOrgRulesetsOrgSet: map[string]bool{}, defaultBranchRulesetActiveByOrg: map[string]bool{},
		teamGrantedRepositoriesByOrg: map[string]map[string]bool{}, teamGrantCountByOrg: map[string]int{},
		teamGrantsIncompleteByOrg: map[string]bool{}, accessByOrg: map[string][]RepositoryAccessResult{},
		commitVerificationByOrg:      map[string][]RepositoryCommitVerificationResult{},
		criticalPopulationKnownByOrg: map[string]bool{}, criticalFullNamesByOrg: map[string]map[string]bool{},
		contentsProbeByOrg:         map[string][]contentsProbeRecord{},
		defaultRepoPermissionByOrg: map[string]string{}, outsideCollaboratorsByOrg: map[string]OrgOutsideCollaboratorsResult{},
	}
}

// contentsProbeRecord pairs one repository's parsed .github/dependabot.yml
// signal with the two independently-determined denominators SEC-043/SEC-099
// are actually scoped to.
type contentsProbeRecord struct {
	probe                      RepositoryContentsProbeResult
	dependencyEligible         bool
	dependencyEligibilityKnown bool
	hasWorkflows               bool
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

// addFeatureSignal folds one repository's CodeQL/Dependency eligibility and
// operational signal into both the run-wide pooled bucket and its own
// organization's bucket, so AggregateFeatureCoverage can be called once
// over the full run (Overall) and once per organization (PerOrganization)
// from the identical underlying signals -- never two divergent
// computations for the same metric key.
func (a *metricAccumulator) addFeatureSignal(organizationKey string, signal RepositoryFeatureSignal) {
	a.featureSignals.add(organizationKey, []RepositoryFeatureSignal{signal}, true)
}

// featureSignalsByFullName indexes this organization's already-collected
// RepositoryFeatureSignal values (one per repository analyzeOneRepository
// actually ran for this organization, added via addFeatureSignal before
// analyzeOrganizationOperational runs) by repository full name. Collectors
// that need one specific repository's own CodeQL/dependency eligibility --
// rather than the pooled cohort view AggregateFeatureCoverage already
// computes -- use this instead of a second, divergent eligibility
// determination.
func (a *metricAccumulator) featureSignalsByFullName(organizationKey string) map[string]RepositoryFeatureSignal {
	signals := a.featureSignals.byOrganization[organizationKey]
	indexed := make(map[string]RepositoryFeatureSignal, len(signals))
	for _, signal := range signals {
		indexed[signal.FullName] = signal
	}
	return indexed
}

// addAttestationSignal folds one repository's critical_repos_with_attestations_pct
// pooling signal into both the run-wide pooled bucket and its own
// organization's bucket, mirroring addFeatureSignal's identical
// Overall/PerOrganization pattern.
func (a *metricAccumulator) addAttestationSignal(organizationKey string, signal RepositoryAttestationSignal) {
	a.attestationSignals.add(organizationKey, []RepositoryAttestationSignal{signal}, true)
}

// addPullRequests folds one repository's sampled merged-PR activity into the
// run-wide and organization-scoped pull-request observation buckets.
func (a *metricAccumulator) addPullRequests(organizationKey string, result RepositoryPullRequestResult) {
	a.pullRequests.add(organizationKey, result.Observations, result.Complete)
}

// addActionsRuns folds one repository's sampled workflow-run activity into
// the run-wide and organization-scoped actions-run observation buckets.
func (a *metricAccumulator) addActionsRuns(organizationKey string, result RepositoryActionsRunsResult) {
	a.actionsRuns.add(organizationKey, result.Observations, result.Complete)
}

// addDependabotAlerts/addCodeScanningAlerts/addSecretScanningAlerts fold one
// organization's alert lifecycle collection into the matching bucket.
func (a *metricAccumulator) addDependabotAlerts(organizationKey string, result OrgAlertLifecycleResult) {
	a.dependabot.add(organizationKey, result.Observations, result.Complete)
}

func (a *metricAccumulator) addCodeScanningAlerts(organizationKey string, result OrgAlertLifecycleResult) {
	a.codeScanning.add(organizationKey, result.Observations, result.Complete)
}

func (a *metricAccumulator) addSecretScanningAlerts(organizationKey string, result OrgAlertLifecycleResult) {
	a.secretScanning.add(organizationKey, result.Observations, result.Complete)
}

// addMembership folds one organization's member/owner/2FA population into
// the run-wide and per-organization membership tallies.
func (a *metricAccumulator) addMembership(organizationKey string, result OrgMembershipResult) {
	tally := membershipTally{members: result.Members, owners: result.Owners, withoutTwoFactor: result.WithoutTwoFactor, complete: result.Complete}
	a.membershipByOrg[organizationKey] = tally
	a.membershipAll.members += result.Members
	a.membershipAll.owners += result.Owners
	a.membershipAll.withoutTwoFactor += result.WithoutTwoFactor
	if !a.membershipObserved {
		a.membershipAll.complete = result.Complete
		a.membershipObserved = true
	} else {
		a.membershipAll.complete = a.membershipAll.complete && result.Complete
	}
}

// addSecurityConfigCoverage records one organization's already-pooled code
// security configuration coverage MetricValue. The cross-organization
// "overall" figure is a simple numerator/denominator sum of already-computed
// per-organization results (never a re-run of the underlying configuration-
// matching logic, which is organization-scoped because configuration IDs are
// not guaranteed unique across organizations on the same host).
func (a *metricAccumulator) addSecurityConfigCoverage(organizationKey string, metric MetricValue) {
	a.securityConfigCoverageByOrg[organizationKey] = metric
}

// addGovernanceCounts folds one organization's lightweight governance
// collector totals (installations, teams, PAT grants/requests) and webhook
// configuration/delivery signals into the run-wide tallies. These are
// collection-only totals in this phase beyond the exact profile-key ratios
// computed from them in populate(); no new metric arithmetic is duplicated
// for installations/teams/PAT counts, which are plain sums.
func (a *metricAccumulator) addGovernanceCounts(installations OrgInstallationsResult, installationsComplete bool,
	hooks OrgHooksResult, pat OrgPATGovernanceResult) {
	a.installationsObserved = true
	a.installationsTotal += installations.InstallationCount
	a.customAppsTotal += installations.CustomAppsCount
	a.installationsComplete = a.installationsComplete && installationsComplete
	a.hooksTotal += hooks.HookCount
	a.hooksActive += hooks.ActiveHookCount
	a.hooksWithoutSecret = append(a.hooksWithoutSecret, hooks.HooksWithoutSecretPct)
	a.hooksInsecureSSLTotal += hooks.HooksInsecureSSLCount
	a.hookDeliveryFailures = append(a.hookDeliveryFailures, hooks.DeliveryFailureRatePct)
	a.patGrantsTotal += pat.FineGrainedPATGrantsCount
	a.patPendingTotal += pat.PendingPATRequests
}

// addRoles folds one organization's role catalogue (custom organization
// roles, custom repository roles, security-manager team count) into the
// run-wide tallies.
func (a *metricAccumulator) addRoles(roles OrgRolesResult) {
	a.customRoleCountTotal += roles.CustomRoleCount
	a.customRepoRoleCountTotal += roles.CustomRepoRoleCount
	a.securityManagerTeamsTotal += len(roles.SecurityManagerTeams)
}

// addTeamGrants records the organization's actual team-based repository
// permission GRANT COUNT (COL-027/SEC-017/GOV-017's team_based_access_pct
// numerator: the count of (team, repository) permission-grant pairs, not
// merely whether a repository has at least one team grant), the
// repository-presence set (for the separate supplementary coverage signal
// only) and folds the team roster's nested/total counts into the run-wide
// tallies. A team whose own repository list could not be fully collected
// marks this organization's team-grant count unknown rather than silently
// treating that team as granting zero repositories.
func (a *metricAccumulator) addTeamGrants(organizationKey string, teams []teamSummary) {
	a.teamsTotal += len(teams)
	granted := a.teamGrantedRepositoriesByOrg[organizationKey]
	if granted == nil {
		granted = map[string]bool{}
		a.teamGrantedRepositoriesByOrg[organizationKey] = granted
	}
	for _, team := range teams {
		if team.Nested {
			a.nestedTeamsTotal++
		}
		if !team.ReposComplete {
			a.teamGrantsIncompleteByOrg[organizationKey] = true
			continue
		}
		for _, repo := range team.Repos {
			granted[repo.FullName] = true
			a.teamGrantCountByOrg[organizationKey]++
		}
	}
}

// addRepositoryAccess records one repository's direct/outside collaborator
// inventory for SEC-016's repos_with_direct_collaborators_pct and for
// correlation against addTeamGrants' team-based grant set.
func (a *metricAccumulator) addRepositoryAccess(organizationKey string, access RepositoryAccessResult) {
	a.accessByOrg[organizationKey] = append(a.accessByOrg[organizationKey], access)
}

// setCriticalPopulation records organization's confirmed critical-repository
// population (ComputeCriticalPopulation's result) for GOV-072's
// verified_commit_ratio_pct, which is scoped to critical repositories only.
// A nil result or Method=="unknown" (critical-property schema access
// failed) marks the whole organization's contribution unknown, matching the
// evaluation package's own poolCriticalSignatures contract: an organization
// whose critical population could not be confirmed is never silently
// excluded as if it had zero critical repositories.
func (a *metricAccumulator) setCriticalPopulation(organizationKey string, critical *CriticalPopulationResult) {
	if critical == nil || critical.Method == "unknown" {
		a.criticalPopulationKnownByOrg[organizationKey] = false
		return
	}
	a.criticalPopulationKnownByOrg[organizationKey] = true
	names := make(map[string]bool, len(critical.FullNames))
	for _, name := range critical.FullNames {
		names[name] = true
	}
	a.criticalFullNamesByOrg[organizationKey] = names
}

// addCommitVerification records one repository's default-branch commit
// signature verification sample for GOV-072's verified_commit_ratio_pct.
// Every analyzed repository's sample is recorded here; populateRulesetAndCommitMetrics
// filters to the confirmed critical subset via criticalFullNamesByOrg.
func (a *metricAccumulator) addCommitVerification(organizationKey string, result RepositoryCommitVerificationResult) {
	a.commitVerificationByOrg[organizationKey] = append(a.commitVerificationByOrg[organizationKey], result)
}

// addContentsProbe records one repository's parsed dependabot.yml signal for
// SEC-043/SEC-099, paired with that repository's independently-determined
// dependency-eligibility and Actions-usage signals (the actual denominators
// those two metrics are scoped to).
func (a *metricAccumulator) addContentsProbe(organizationKey string, result RepositoryContentsProbeResult,
	dependencyEligible, dependencyEligibilityKnown, hasWorkflows bool) {
	a.contentsProbeByOrg[organizationKey] = append(a.contentsProbeByOrg[organizationKey], contentsProbeRecord{
		probe: result, dependencyEligible: dependencyEligible, dependencyEligibilityKnown: dependencyEligibilityKnown, hasWorkflows: hasWorkflows,
	})
}

// addDefaultRepositoryPermission records SEC-016's descriptive
// default_repository_permission value from the already-collected org.settings
// response. An empty value (field omitted by the API) is not recorded, since
// omission is unknown, not a confirmed empty setting.
func (a *metricAccumulator) addDefaultRepositoryPermission(organizationKey, value string) {
	if value == "" {
		return
	}
	if a.defaultRepoPermissionByOrg == nil {
		a.defaultRepoPermissionByOrg = map[string]string{}
	}
	a.defaultRepoPermissionByOrg[organizationKey] = value
}

// addOutsideCollaborators records SEC-016's outside-collaborator population.
func (a *metricAccumulator) addOutsideCollaborators(organizationKey string, result OrgOutsideCollaboratorsResult) {
	if a.outsideCollaboratorsByOrg == nil {
		a.outsideCollaboratorsByOrg = map[string]OrgOutsideCollaboratorsResult{}
	}
	a.outsideCollaboratorsByOrg[organizationKey] = result
}

// addDirectOrgRulesets records the organization's authoritative, directly
// enumerated active-ruleset count (GET /orgs/{org}/rulesets) and whether an
// active ruleset targets the organization-wide ~DEFAULT_BRANCH sentinel
// (GOV-070's org_default_branch_rulesets_active), which populate() prefers
// over the repo-discovered proxy (activeOrganizationRulesets) for that
// organization when both are present.
func (a *metricAccumulator) addDirectOrgRulesets(organizationKey string, activeCount int, defaultBranchRulesetActive bool) {
	a.directOrgRulesetsByOrg[organizationKey] = activeCount
	a.directOrgRulesetsOrgSet[organizationKey] = true
	a.defaultBranchRulesetActiveByOrg[organizationKey] = defaultBranchRulesetActive
}

// populate writes every accumulated pooled metric into the run's metrics map.
// lookbackStart/lookbackEnd bound the PR cycle-time and actions-run windows
// (the customer configuration's LookbackDays); alertWindowStart/now bound the
// profile's independent fixed 180-day alert MTTR window.
func (a *metricAccumulator) populate(metrics map[string]Metric, lookbackStart, lookbackEnd, alertWindowStart, now time.Time) error {
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
	totalOrganizationsAnalyzed := len(a.membershipByOrg)
	allOrgsHaveDirectRulesets := totalOrganizationsAnalyzed > 0 && len(a.directOrgRulesetsOrgSet) == totalOrganizationsAnalyzed
	switch {
	case allOrgsHaveDirectRulesets:
		// Every analyzed organization's org.rulesets top-level enumeration
		// succeeded: this authoritative, sample-independent sum replaces the
		// repo-discovered proxy entirely for this run, per the direct
		// top-level inventory's explicit priority over the known subset.
		directTotal := 0.0
		for _, count := range a.directOrgRulesetsByOrg {
			directTotal += float64(count)
		}
		setMetric(metrics, "active_org_rulesets_count", MetricValue{
			Status: MetricKnown, Number: &directTotal, EvidenceRefs: []string{},
			Population: "organizations' directly enumerated active rulesets (GET /orgs/{org}/rulesets), authoritative and independent of any repository sample",
		})
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
			Reason: "a direct top-level org.rulesets enumeration was unavailable for one or more analyzed organizations; " +
				"this figure falls back to the repo-discovered proxy, which can only observe organization rulesets that " +
				"actually applied to at least one analyzed repository's default branch",
		})
	}
	// Per-organization entries always use the authoritative direct
	// enumeration when that organization's org.rulesets call succeeded,
	// regardless of whether every organization in the run did.
	for organizationKey, count := range a.directOrgRulesetsByOrg {
		directCount := float64(count)
		setMetricPerOrganization(metrics, "active_org_rulesets_count", organizationKey, MetricValue{
			Status: MetricKnown, Number: &directCount, EvidenceRefs: []string{},
			Population: "this organization's directly enumerated active rulesets (GET /orgs/{org}/rulesets)",
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

	codeQLCoverage, dependencyCoverage := AggregateFeatureCoverage(a.featureSignals.overall)
	setMetric(metrics, codeQLCoverage.Feature, codeQLCoverage.Metric)
	setMetric(metrics, dependencyCoverage.Feature, dependencyCoverage.Metric)
	// Per-organization values are computed from that organization's own
	// subset of signals, the identical cohort-sensitive AggregateFeatureCoverage
	// mechanism -- an organization whose every repository's eligibility and
	// operational status is confidently known reports its own true value
	// here even when the pooled Overall above is unavailable because of an
	// unresolved repository in a DIFFERENT organization.
	for organizationKey, signals := range a.featureSignals.byOrganization {
		orgCodeQL, orgDependency := AggregateFeatureCoverage(signals)
		setMetricPerOrganization(metrics, codeQLCoverage.Feature, organizationKey, orgCodeQL.Metric)
		setMetricPerOrganization(metrics, dependencyCoverage.Feature, organizationKey, orgDependency.Metric)
	}

	attestationCoverage := AggregateAttestationCoverage(a.attestationSignals.overall)
	setMetric(metrics, attestationCoverage.Feature, attestationCoverage.Metric)
	for organizationKey, signals := range a.attestationSignals.byOrganization {
		orgAttestation := AggregateAttestationCoverage(signals)
		setMetricPerOrganization(metrics, attestationCoverage.Feature, organizationKey, orgAttestation.Metric)
	}

	if err := a.populateActivityMetrics(metrics, lookbackStart, lookbackEnd); err != nil {
		return err
	}
	if err := a.populateActionsMetrics(metrics, lookbackStart, lookbackEnd); err != nil {
		return err
	}
	if err := a.populateAlertMetrics(metrics, alertWindowStart, now); err != nil {
		return err
	}
	if err := a.populateMembershipMetrics(metrics); err != nil {
		return err
	}
	a.populateSecurityConfigCoverage(metrics)
	a.populateGovernanceCounts(metrics)
	a.populateAccessMetrics(metrics)
	a.populateRulesetAndCommitMetrics(metrics)
	a.populateContentsProbeMetrics(metrics)
	a.populateDefaultRepositoryPermission(metrics)
	a.populateOutsideCollaborators(metrics)
	return nil
}

// populateActivityMetrics computes the published ActivityMetrics helper once
// over the run-wide pooled PR sample and once per organization over that
// organization's own sample; it never re-derives the median/coverage
// arithmetic itself.
func (a *metricAccumulator) populateActivityMetrics(metrics map[string]Metric, windowStart, windowEnd time.Time) error {
	overall, err := ActivityMetrics(a.pullRequests.overall, windowStart, windowEnd, !a.pullRequests.overallIncomplete)
	if err != nil {
		return fmt.Errorf("compute pooled pull-request activity metrics: %w", err)
	}
	for key, value := range overall {
		value.Sampled = true
		setMetric(metrics, key, value)
	}
	for organizationKey, observations := range a.pullRequests.byOrganization {
		perOrg, err := ActivityMetrics(observations, windowStart, windowEnd, !a.pullRequests.incompleteByOrg[organizationKey])
		if err != nil {
			return fmt.Errorf("compute pull-request activity metrics for %s: %w", organizationKey, err)
		}
		for key, value := range perOrg {
			value.Sampled = true
			setMetricPerOrganization(metrics, key, organizationKey, value)
		}
	}
	return nil
}

// populateActionsMetrics mirrors populateActivityMetrics for the published
// ActionsMetrics helper over the pooled/organization-scoped workflow-run
// samples.
func (a *metricAccumulator) populateActionsMetrics(metrics map[string]Metric, windowStart, windowEnd time.Time) error {
	overall, err := ActionsMetrics(a.actionsRuns.overall, windowStart, windowEnd, !a.actionsRuns.overallIncomplete)
	if err != nil {
		return fmt.Errorf("compute pooled actions-run metrics: %w", err)
	}
	for key, value := range overall {
		value.Sampled = true
		setMetric(metrics, key, value)
	}
	for organizationKey, observations := range a.actionsRuns.byOrganization {
		perOrg, err := ActionsMetrics(observations, windowStart, windowEnd, !a.actionsRuns.incompleteByOrg[organizationKey])
		if err != nil {
			return fmt.Errorf("compute actions-run metrics for %s: %w", organizationKey, err)
		}
		for key, value := range perOrg {
			value.Sampled = true
			setMetricPerOrganization(metrics, key, organizationKey, value)
		}
	}
	return nil
}

// populateAlertMetrics computes the published AlertLifecycleMetrics helper
// once per alert kind (Dependabot, code scanning, secret scanning), pooled
// and per organization, using the profile's fixed 180-day window. It also
// computes SEC-003/SEC-121's exact declared severity-filtered MTTR keys
// (dependabot_mttr_days_crit_high, mttr_days_crit_high) over the same
// already-published helper restricted to critical/high-severity
// observations, never a separate re-derived MTTR calculation.
func (a *metricAccumulator) populateAlertMetrics(metrics map[string]Metric, windowStart, now time.Time) error {
	kinds := []struct {
		prefix          string
		bucket          *observationBucket[AlertObservation]
		severityMTTRKey string
	}{
		{"dependabot_alerts", &a.dependabot, "dependabot_mttr_days_crit_high"},
		{"code_scanning_alerts", &a.codeScanning, "mttr_days_crit_high"},
		{"secret_scanning_alerts", &a.secretScanning, ""},
	}
	for _, kind := range kinds {
		overall, err := AlertLifecycleMetrics(kind.bucket.overall, windowStart, now, !kind.bucket.overallIncomplete)
		if err != nil {
			return fmt.Errorf("compute pooled %s lifecycle metrics: %w", kind.prefix, err)
		}
		for key, value := range overall {
			setMetric(metrics, kind.prefix+"_"+key, value)
		}
		if kind.severityMTTRKey != "" {
			severityOverall, err := AlertLifecycleMetrics(severityFilter(kind.bucket.overall, "critical", "high"), windowStart, now, !kind.bucket.overallIncomplete)
			if err != nil {
				return fmt.Errorf("compute pooled %s severity-filtered MTTR: %w", kind.prefix, err)
			}
			setMetric(metrics, kind.severityMTTRKey, severityOverall["mttr_days"])
		}
		for organizationKey, observations := range kind.bucket.byOrganization {
			perOrg, err := AlertLifecycleMetrics(observations, windowStart, now, !kind.bucket.incompleteByOrg[organizationKey])
			if err != nil {
				return fmt.Errorf("compute %s lifecycle metrics for %s: %w", kind.prefix, organizationKey, err)
			}
			for key, value := range perOrg {
				setMetricPerOrganization(metrics, kind.prefix+"_"+key, organizationKey, value)
			}
			if kind.severityMTTRKey != "" {
				severityPerOrg, err := AlertLifecycleMetrics(severityFilter(observations, "critical", "high"), windowStart, now, !kind.bucket.incompleteByOrg[organizationKey])
				if err != nil {
					return fmt.Errorf("compute %s severity-filtered MTTR for %s: %w", kind.prefix, organizationKey, err)
				}
				setMetricPerOrganization(metrics, kind.severityMTTRKey, organizationKey, severityPerOrg["mttr_days"])
			}
		}
	}
	return nil
}

// populateMembershipMetrics computes the published MembershipMetrics helper
// over the pooled and per-organization member/owner/2FA tallies, plus
// SEC-016/GOV-061's exact declared raw-count keys (owner_count,
// members_without_2fa) alongside the published percentage keys.
func (a *metricAccumulator) populateMembershipMetrics(metrics map[string]Metric) error {
	if len(a.membershipByOrg) == 0 {
		return nil
	}
	overall, err := MembershipMetrics(a.membershipAll.members, a.membershipAll.owners, a.membershipAll.withoutTwoFactor, a.membershipAll.complete)
	if err != nil {
		return fmt.Errorf("compute pooled membership metrics: %w", err)
	}
	for key, value := range overall {
		setMetric(metrics, key, value)
	}
	setMetric(metrics, "owner_count", knownCountOrUnavailable(float64(a.membershipAll.owners), a.membershipAll.complete, "analyzed organizations' owner-role members"))
	setMetric(metrics, "members_without_2fa", knownCountOrUnavailable(float64(a.membershipAll.withoutTwoFactor), a.membershipAll.complete, "analyzed organizations' members without 2FA"))
	for organizationKey, tally := range a.membershipByOrg {
		perOrg, err := MembershipMetrics(tally.members, tally.owners, tally.withoutTwoFactor, tally.complete)
		if err != nil {
			return fmt.Errorf("compute membership metrics for %s: %w", organizationKey, err)
		}
		for key, value := range perOrg {
			setMetricPerOrganization(metrics, key, organizationKey, value)
		}
		setMetricPerOrganization(metrics, "owner_count", organizationKey,
			knownCountOrUnavailable(float64(tally.owners), tally.complete, "this organization's owner-role members"))
		setMetricPerOrganization(metrics, "members_without_2fa", organizationKey,
			knownCountOrUnavailable(float64(tally.withoutTwoFactor), tally.complete, "this organization's members without 2FA"))
	}
	return nil
}

// populateSecurityConfigCoverage pools every organization's already-computed
// code security configuration coverage MetricValue into one overall figure.
// An organization whose own coverage result is confidently MetricKnown
// contributes its Numerator/Denominator to the pooled sum; one that is
// confidently MetricInapplicable (a confirmed, zero-eligible-repository
// population for that organization) contributes nothing to the sum but does
// NOT itself make the overall figure unknown. Any other status -- the
// organization's own configuration/attachment inventory could not be
// determined at all -- is a genuinely unresolved peer: an unresolved
// organization could itself turn out to contain additional eligible,
// non-compliant repositories, which would change the true pooled result, so
// the overall Status/Number must explicitly become MetricUnavailable rather
// than silently reporting the known subset's sum as if every organization
// had resolved. The confidently-known subset's Numerator/Denominator are
// still retained on the unavailable metric (never erased to nil), matching
// cohortCoverageMetric's identical contract for CodeQL/Dependency/attestation
// coverage -- a caveat string alone does not satisfy this; Status and Number
// must themselves reflect the uncertainty.
func (a *metricAccumulator) populateSecurityConfigCoverage(metrics map[string]Metric) {
	if len(a.securityConfigCoverageByOrg) == 0 {
		return
	}
	numerator, denominator := 0.0, 0.0
	anyUnknown := false
	for _, value := range a.securityConfigCoverageByOrg {
		switch value.Status {
		case MetricKnown:
			if value.Numerator != nil && value.Denominator != nil {
				numerator += *value.Numerator
				denominator += *value.Denominator
			}
		case MetricInapplicable:
			// A confirmed, zero-eligible-repository organization: a
			// genuine 0/0 contribution, not an unresolved peer.
		default:
			anyUnknown = true
		}
	}
	population := "organization-eligible repositories with an attached/enforced configuration enabling every required feature"
	overall, err := securityCoverage(numerator, denominator, population)
	if err != nil {
		overall = MetricValue{Status: MetricUnavailable, Population: population, EvidenceRefs: []string{}}
	}
	if anyUnknown {
		overall.Status = MetricUnavailable
		overall.Number = nil
		overall.Reason = "one or more organizations' code security configuration coverage could not be determined; " +
			"an unresolved organization could change this feature's cohort or result, so the known subset's " +
			"retained counts alone cannot be reported as a confident coverage percentage"
	}
	setMetric(metrics, codeSecurityConfigurationCoveragePopulationKey, overall)
	for organizationKey, value := range a.securityConfigCoverageByOrg {
		setMetricPerOrganization(metrics, codeSecurityConfigurationCoveragePopulationKey, organizationKey, value)
	}
}

// populateGovernanceCounts reports the lightweight, collection-only
// governance totals (installations, teams, PAT grants/requests, webhook
// delivery-failure rate). These are adapter-invented keys, not existing
// automation-profile metric names, and intentionally stay as raw counts
// rather than guessed coverage ratios the collectors cannot yet support.
// populateGovernanceCounts reports the automation profile's exact declared
// PRD-029/ARC-098/ARC-109/SEC-086 metric keys (custom_apps_count,
// hooks_without_secret_pct, hooks_insecure_ssl_count,
// fine_grained_pat_grants_count, pending_pat_requests) and SEC-017/GOV-017/
// SEC-132's exact declared role keys (custom_roles_count,
// security_manager_teams, teams_count), computed from this phase's actual
// observed configuration and inventory data, not adapter-invented names.
func (a *metricAccumulator) populateGovernanceCounts(metrics map[string]Metric) {
	if !a.installationsObserved {
		return
	}
	setMetric(metrics, "custom_apps_count", knownCountOrUnavailable(
		float64(a.customAppsTotal), a.installationsComplete, "analyzed organizations' GitHub App installations classified outside the known-integration catalogue"))
	// custom_integrations_count (ARC-098/ARC-109) is the same observed value
	// as custom_apps_count (PRD-029) under the profile's second declared name
	// for this signal; both keys are emitted rather than guessing which one
	// controls will reference.
	setMetric(metrics, "custom_integrations_count", knownCountOrUnavailable(
		float64(a.customAppsTotal), a.installationsComplete, "analyzed organizations' GitHub App installations classified outside the known-integration catalogue"))
	setMetric(metrics, "teams_count", knownCountOrUnavailable(
		float64(a.teamsTotal), a.installationsComplete, "analyzed organizations' teams"))
	setMetric(metrics, "nested_teams_count", knownCountOrUnavailable(
		float64(a.nestedTeamsTotal), a.installationsComplete, "analyzed organizations' teams with a parent team"))
	setMetric(metrics, "custom_roles_count", knownCountOrUnavailable(
		float64(a.customRoleCountTotal+a.customRepoRoleCountTotal), a.installationsComplete,
		"analyzed organizations' custom organization roles plus custom repository roles"))
	setMetric(metrics, "security_manager_teams", knownCountOrUnavailable(
		float64(a.securityManagerTeamsTotal), a.installationsComplete, "analyzed organizations' security-manager team assignments"))
	setMetric(metrics, "fine_grained_pat_grants_count", knownCountOrUnavailable(
		float64(a.patGrantsTotal), a.installationsComplete, "analyzed organizations' granted fine-grained personal access tokens"))
	setMetric(metrics, "pending_pat_requests", knownCountOrUnavailable(
		float64(a.patPendingTotal), a.installationsComplete, "analyzed organizations' pending fine-grained personal access token requests"))

	hooksWithoutSecretNumerator, hooksWithoutSecretDenominator := 0.0, 0.0
	hooksWithoutSecretKnown := len(a.hooksWithoutSecret) > 0
	for _, value := range a.hooksWithoutSecret {
		if value.Status != MetricKnown || value.Numerator == nil || value.Denominator == nil {
			hooksWithoutSecretKnown = false
			continue
		}
		hooksWithoutSecretNumerator += *value.Numerator
		hooksWithoutSecretDenominator += *value.Denominator
	}
	hooksWithoutSecretPopulation := "analyzed organizations' webhooks"
	hooksWithoutSecretMetric := MetricValue{Status: MetricUnavailable, Population: hooksWithoutSecretPopulation, EvidenceRefs: []string{},
		Reason: "webhook configuration data was unavailable or incomplete for one or more organizations"}
	if hooksWithoutSecretKnown {
		if computed, err := Percentage(hooksWithoutSecretNumerator, hooksWithoutSecretDenominator, hooksWithoutSecretPopulation); err == nil {
			hooksWithoutSecretMetric = computed
		}
	}
	setMetric(metrics, "hooks_without_secret_pct", hooksWithoutSecretMetric)
	setMetric(metrics, "hooks_insecure_ssl_count", knownCountOrUnavailable(
		float64(a.hooksInsecureSSLTotal), a.installationsComplete, "analyzed organizations' webhooks configured with insecure_ssl=1"))

	// org_hook_delivery_failure_rate_pct is adapter-invented supplementary
	// evidence, not a declared automation-profile metric key.
	hookNumerator, hookDenominator := 0.0, 0.0
	hookAllKnown := len(a.hookDeliveryFailures) > 0
	for _, value := range a.hookDeliveryFailures {
		if value.Status != MetricKnown || value.Numerator == nil || value.Denominator == nil {
			hookAllKnown = false
			continue
		}
		hookNumerator += *value.Numerator
		hookDenominator += *value.Denominator
	}
	hookPopulation := "examined webhook deliveries (most recent page per hook, <=100 each; adapter-invented supplementary evidence, not a declared profile metric)"
	hookMetric := MetricValue{Status: MetricUnavailable, Population: hookPopulation, EvidenceRefs: []string{},
		Reason: "webhook delivery data was unavailable or incomplete for one or more organizations"}
	if hookAllKnown {
		if computed, err := Percentage(hookNumerator, hookDenominator, hookPopulation); err == nil {
			hookMetric = computed
		}
	}
	setMetric(metrics, "org_hook_delivery_failure_rate_pct_supplementary", hookMetric)
}

// populateAccessMetrics computes SEC-016's repos_with_direct_collaborators_pct
// and COL-027/SEC-017/GOV-017's team_based_access_pct. team_based_access_pct
// is this package's exact documented formula: team permission GRANTS / (team
// grants + direct collaborator grants), bots excluded -- a ratio of actual
// grant counts, never a repository-presence ratio ("this repository has at
// least one team grant" does not mean 100% of its access is team-based when
// it also has many direct collaborators). A separate, clearly-labeled
// supplementary signal preserves the repository-presence view under its own
// non-profile key rather than silently replacing the documented formula.
func (a *metricAccumulator) populateAccessMetrics(metrics map[string]Metric) {
	if len(a.accessByOrg) == 0 {
		return
	}
	directPopulation := "analyzed repositories with a confidently known direct-collaborator inventory"
	teamPopulation := "organization permission grants (team-based and direct-collaborator, bots excluded)"
	coveragePopulation := "analyzed repositories with a confidently known collaborator inventory"

	setMetric(metrics, "repos_with_direct_collaborators_pct", unavailableObservation("no repository access inventory has been pooled yet", directPopulation))
	setMetric(metrics, "team_based_access_pct", unavailableObservation("no permission-grant data has been pooled yet", teamPopulation))
	setMetric(metrics, "team_based_access_repo_coverage_pct_supplementary",
		unavailableObservation("no repository access inventory has been pooled yet", coveragePopulation))

	var directNumeratorAll, directDenominatorAll float64
	var teamGrantsAll, directGrantsAll float64
	var coverageNumeratorAll, coverageDenominatorAll float64
	directOverallComplete, teamOverallComplete := true, true
	for organizationKey, accessResults := range a.accessByOrg {
		granted := a.teamGrantedRepositoriesByOrg[organizationKey]
		var directNumerator, directDenominator, coverageNumerator, coverageDenominator, directGrants float64
		directComplete := true
		for _, access := range accessResults {
			if !access.Complete {
				directComplete = false
				continue
			}
			directDenominator++
			coverageDenominator++
			directGrants += float64(access.DirectCollaboratorsExclBots)
			if access.DirectCollaboratorsExclBots > 0 {
				directNumerator++
			}
			if granted != nil && granted[access.Repository] {
				coverageNumerator++
			}
		}
		if directMetric, err := Percentage(directNumerator, directDenominator, directPopulation); err == nil {
			if !directComplete {
				directMetric = markCoverageUncertain(directMetric, "one or more repositories' direct-collaborator inventory was incomplete")
				directOverallComplete = false
			}
			setMetricPerOrganization(metrics, "repos_with_direct_collaborators_pct", organizationKey, directMetric)
		}
		if coverageMetric, err := Percentage(coverageNumerator, coverageDenominator, coveragePopulation); err == nil {
			if !directComplete {
				coverageMetric = markCoverageUncertain(coverageMetric, "one or more repositories' direct-collaborator inventory was incomplete")
			}
			setMetricPerOrganization(metrics, "team_based_access_repo_coverage_pct_supplementary", organizationKey, coverageMetric)
		}

		teamGrants := float64(a.teamGrantCountByOrg[organizationKey])
		teamComplete := directComplete && !a.teamGrantsIncompleteByOrg[organizationKey]
		if teamMetric, err := Percentage(teamGrants, teamGrants+directGrants, teamPopulation); err == nil {
			if !teamComplete {
				teamMetric = markCoverageUncertain(teamMetric,
					"one or more teams' repository permission-grant list or one or more repositories' direct-collaborator "+
						"inventory was incomplete; the grant counts below are a lower bound, not a complete ratio")
			}
			setMetricPerOrganization(metrics, "team_based_access_pct", organizationKey, teamMetric)
		}

		if directComplete {
			directNumeratorAll += directNumerator
			directDenominatorAll += directDenominator
			coverageNumeratorAll += coverageNumerator
			coverageDenominatorAll += coverageDenominator
		} else {
			directOverallComplete = false
		}
		if teamComplete {
			teamGrantsAll += teamGrants
			directGrantsAll += directGrants
		} else {
			teamOverallComplete = false
		}
	}
	if directOverallComplete {
		if directMetric, err := Percentage(directNumeratorAll, directDenominatorAll, directPopulation); err == nil {
			setMetricOverall(metrics, "repos_with_direct_collaborators_pct", directMetric)
		}
		if coverageMetric, err := Percentage(coverageNumeratorAll, coverageDenominatorAll, coveragePopulation); err == nil {
			setMetricOverall(metrics, "team_based_access_repo_coverage_pct_supplementary", coverageMetric)
		}
	}
	if teamOverallComplete {
		if teamMetric, err := Percentage(teamGrantsAll, teamGrantsAll+directGrantsAll, teamPopulation); err == nil {
			setMetricOverall(metrics, "team_based_access_pct", teamMetric)
		}
	}
}

// populateRulesetAndCommitMetrics computes GOV-070's
// org_default_branch_rulesets_active (strictly per organization -- never a
// pooled boolean-OR across organizations, since one small compliant
// organization having the ruleset does not represent a separate, larger
// organization's repositories) and GOV-072's verified_commit_ratio_pct
// (scoped to each organization's confirmed CRITICAL repository population
// only, pooled and per organization) from the directly enumerated
// org.rulesets/repo.commits observations.
func (a *metricAccumulator) populateRulesetAndCommitMetrics(metrics map[string]Metric) {
	if len(a.defaultBranchRulesetActiveByOrg) > 0 {
		// This is a per-organization governance control: whether THIS
		// organization has an active, org-wide default-branch ruleset. A
		// single pooled true/false across every analyzed organization would
		// misrepresent coverage, so the "overall" value is deliberately
		// never a boolean OR -- it exists only so the per-organization map
		// is populated, and explicitly documents that each organization's
		// own value must be read independently.
		setMetric(metrics, "org_default_branch_rulesets_active", MetricValue{
			Status: MetricUnavailable, EvidenceRefs: []string{},
			Population: "analyzed organizations' directly enumerated active, branch-target rulesets",
			Reason: "this is a per-organization governance control; a single pooled true/false across multiple organizations " +
				"would misrepresent repository coverage (a small compliant organization cannot stand in for a larger " +
				"non-compliant one) -- read each organization's own value under per_organization instead",
		})
		for organizationKey, active := range a.defaultBranchRulesetActiveByOrg {
			activeValue := active
			setMetricPerOrganization(metrics, "org_default_branch_rulesets_active", organizationKey, MetricValue{
				Status: MetricKnown, Boolean: &activeValue, EvidenceRefs: []string{},
				Population: "this organization's directly enumerated active, branch-target rulesets",
			})
		}
	}

	if len(a.commitVerificationByOrg) == 0 {
		return
	}
	population := "sampled default-branch commits (most recent 100 per repository) from confirmed-critical repositories with a confidently known verification state"
	setMetric(metrics, "verified_commit_ratio_pct", unavailableObservation("no critical-repository commit-verification sample has been pooled yet", population))

	var numeratorAll, denominatorAll float64
	overallComplete := true
	for organizationKey, results := range a.commitVerificationByOrg {
		known := a.criticalPopulationKnownByOrg[organizationKey]
		if !known {
			setMetricPerOrganization(metrics, "verified_commit_ratio_pct", organizationKey,
				unavailableObservation("this organization's critical-repository population could not be confirmed", population))
			overallComplete = false
			continue
		}
		criticalNames := a.criticalFullNamesByOrg[organizationKey]
		var numerator, denominator float64
		complete := true
		for _, result := range results {
			if !criticalNames[result.Repository] {
				// Correctly out of scope (not a critical repository): a
				// non-critical repository's verification sample, however
				// clean, must never dilute or inflate a critical
				// repository's own ratio.
				continue
			}
			if !result.Complete {
				complete = false
				continue
			}
			denominator += float64(result.SampledCommits)
			numerator += float64(result.VerifiedCommits)
		}
		if metric, err := Percentage(numerator, denominator, population); err == nil {
			if !complete {
				metric = markCoverageUncertain(metric, "one or more critical repositories' commit-verification sample was incomplete")
			}
			setMetricPerOrganization(metrics, "verified_commit_ratio_pct", organizationKey, metric)
		}
		if complete {
			numeratorAll += numerator
			denominatorAll += denominator
		} else {
			overallComplete = false
		}
	}
	if overallComplete {
		if metric, err := Percentage(numeratorAll, denominatorAll, population); err == nil {
			setMetricOverall(metrics, "verified_commit_ratio_pct", metric)
		}
	}
}

// populateContentsProbeMetrics computes SEC-043's
// repos_with_grouped_version_updates_pct (denominator: dependency-ELIGIBLE
// repositories) and SEC-099's repos_with_actions_ecosystem_updates_pct
// (denominator: repositories that actually use GitHub Actions, i.e. have at
// least one workflow file) from the parsed dependabot.yml observations.
// Neither denominator is the subset of repositories whose dependabot.yml
// merely happened to parse: a dependency-eligible or Actions-using
// repository with an unparsed/absent dependabot.yml still belongs in its
// metric's denominator as an unknown/incomplete contribution, never quietly
// dropped out, and an eligibility signal that is itself unknown (not
// confirmed false) is also preserved rather than treated as ineligible.
func (a *metricAccumulator) populateContentsProbeMetrics(metrics map[string]Metric) {
	if len(a.contentsProbeByOrg) == 0 {
		return
	}
	groupedPopulation := "dependency-eligible analyzed repositories"
	actionsPopulation := "analyzed repositories that use GitHub Actions (have at least one workflow file)"
	setMetric(metrics, "repos_with_grouped_version_updates_pct", unavailableObservation("no dependency-eligible repository has been pooled yet", groupedPopulation))
	setMetric(metrics, "repos_with_actions_ecosystem_updates_pct", unavailableObservation("no Actions-using repository has been pooled yet", actionsPopulation))

	var groupedNumeratorAll, groupedDenominatorAll, actionsNumeratorAll, actionsDenominatorAll float64
	groupedOverallComplete, actionsOverallComplete := true, true
	for organizationKey, records := range a.contentsProbeByOrg {
		var groupedNumerator, groupedDenominator, actionsNumerator, actionsDenominator float64
		groupedComplete, actionsComplete := true, true
		for _, record := range records {
			// A repository whose dependency eligibility is itself unknown
			// (not confirmed false) must not be silently excluded from
			// SEC-043's denominator: that would understate the population
			// exactly like treating "unknown" as "false" would.
			if !record.dependencyEligibilityKnown {
				groupedComplete = false
			} else if record.dependencyEligible {
				if !record.probe.DependabotConfigKnown {
					groupedComplete = false
				} else {
					groupedDenominator++
					if record.probe.HasGroupedVersionUpdate {
						groupedNumerator++
					}
				}
			}
			if record.hasWorkflows {
				if !record.probe.DependabotConfigKnown {
					actionsComplete = false
				} else {
					actionsDenominator++
					if record.probe.HasActionsEcosystem {
						actionsNumerator++
					}
				}
			}
		}
		if metric, err := Percentage(groupedNumerator, groupedDenominator, groupedPopulation); err == nil {
			if !groupedComplete {
				metric = markCoverageUncertain(metric, "one or more dependency-eligible repositories' dependabot.yml content "+
					"or dependency-eligibility determination was unknown/incomplete")
			}
			setMetricPerOrganization(metrics, "repos_with_grouped_version_updates_pct", organizationKey, metric)
		}
		if metric, err := Percentage(actionsNumerator, actionsDenominator, actionsPopulation); err == nil {
			if !actionsComplete {
				metric = markCoverageUncertain(metric, "one or more Actions-using repositories' dependabot.yml content was unknown/incomplete")
			}
			setMetricPerOrganization(metrics, "repos_with_actions_ecosystem_updates_pct", organizationKey, metric)
		}
		if groupedComplete {
			groupedNumeratorAll += groupedNumerator
			groupedDenominatorAll += groupedDenominator
		} else {
			groupedOverallComplete = false
		}
		if actionsComplete {
			actionsNumeratorAll += actionsNumerator
			actionsDenominatorAll += actionsDenominator
		} else {
			actionsOverallComplete = false
		}
	}
	if groupedOverallComplete {
		if metric, err := Percentage(groupedNumeratorAll, groupedDenominatorAll, groupedPopulation); err == nil {
			setMetricOverall(metrics, "repos_with_grouped_version_updates_pct", metric)
		}
	}
	if actionsOverallComplete {
		if metric, err := Percentage(actionsNumeratorAll, actionsDenominatorAll, actionsPopulation); err == nil {
			setMetricOverall(metrics, "repos_with_actions_ecosystem_updates_pct", metric)
		}
	}
}

func knownCountOrUnavailable(value float64, complete bool, population string) MetricValue {
	if !complete {
		return MetricValue{Status: MetricUnavailable, Population: population, EvidenceRefs: []string{}, Reason: "collection was incomplete for one or more organizations"}
	}
	return MetricValue{Status: MetricKnown, Number: &value, Population: population, EvidenceRefs: []string{}}
}

func setMetric(metrics map[string]Metric, key string, value MetricValue) {
	metrics[key] = Metric{Key: key, Overall: value, PerOrganization: map[string]MetricValue{}}
}

// setMetricOverall replaces an already-populated metric key's Overall value
// in place, preserving any PerOrganization entries already recorded under
// that key. Unlike setMetric (which always resets PerOrganization to a
// fresh empty map), this must be used whenever a metric's final pooled
// Overall value is computed AFTER per-organization values have already been
// written for the same key in the same populate() pass -- calling setMetric
// again at that point would silently wipe every per-organization value just
// recorded.
func setMetricOverall(metrics map[string]Metric, key string, value MetricValue) {
	entry, ok := metrics[key]
	if !ok {
		setMetric(metrics, key, value)
		return
	}
	entry.Overall = value
	metrics[key] = entry
}

// setMetricPerOrganization records one organization-scoped MetricValue under
// an already-populated metric key (setMetric must run first for that key in
// the same populate() call; organization keys are stable Scope.Key() values
// including the GitHub host).
func setMetricPerOrganization(metrics map[string]Metric, key, organizationKey string, value MetricValue) {
	if entry, ok := metrics[key]; ok {
		entry.PerOrganization[organizationKey] = value
	}
}

// populateDefaultRepositoryPermission reports SEC-016's declared
// default_repository_permission from the already-collected org.settings
// response. The overall value is only reported known when every analyzed
// organization agrees; otherwise it is explicitly unavailable (not an
// arbitrary pick) while per-organization values remain known.
func (a *metricAccumulator) populateDefaultRepositoryPermission(metrics map[string]Metric) {
	if len(a.defaultRepoPermissionByOrg) == 0 {
		return
	}
	population := "this organization's org.settings default_repository_permission"
	var first string
	agree := true
	for organizationKey, value := range a.defaultRepoPermissionByOrg {
		valueCopy := value
		setMetricPerOrganization(metrics, "default_repository_permission", organizationKey, MetricValue{
			Status: MetricKnown, Text: &valueCopy, EvidenceRefs: []string{}, Population: population,
		})
		if first == "" {
			first = value
		} else if first != value {
			agree = false
		}
	}
	if agree {
		overall := MetricValue{Status: MetricKnown, Text: &first, EvidenceRefs: []string{},
			Population: "analyzed organizations' org.settings default_repository_permission"}
		setMetric(metrics, "default_repository_permission", overall)
		return
	}
	setMetric(metrics, "default_repository_permission", MetricValue{
		Status: MetricUnavailable, EvidenceRefs: []string{},
		Population: "analyzed organizations' org.settings default_repository_permission",
		Reason:     "analyzed organizations have different default_repository_permission values; see per-organization values",
	})
}

// populateOutsideCollaborators computes SEC-016's outside_collab_ratio_pct
// (outside collaborators as a share of all members) and
// outside_collaborators_without_2fa (a raw count, the profile's declared
// shape) from the org.outside_collaborators/org.members observations.
func (a *metricAccumulator) populateOutsideCollaborators(metrics map[string]Metric) {
	if len(a.outsideCollaboratorsByOrg) == 0 {
		return
	}
	ratioPopulation := "analyzed organizations' members (outside collaborators as a share of all members)"
	var outsideAll, membersAll float64
	ratioKnownAll := true
	for organizationKey, result := range a.outsideCollaboratorsByOrg {
		tally, hasMembers := a.membershipByOrg[organizationKey]
		complete := result.Complete && hasMembers && tally.complete
		setMetricPerOrganization(metrics, "outside_collaborators_without_2fa", organizationKey,
			knownCountOrUnavailable(float64(result.OutsideCollaboratorsWithout2FA), result.Complete, "this organization's outside collaborators without 2FA"))
		if complete {
			if metric, err := Percentage(float64(result.OutsideCollaborators), float64(tally.members), ratioPopulation); err == nil {
				setMetricPerOrganization(metrics, "outside_collab_ratio_pct", organizationKey, metric)
			}
			outsideAll += float64(result.OutsideCollaborators)
			membersAll += float64(tally.members)
		} else {
			ratioKnownAll = false
		}
	}
	withoutTwoFactorTotal, withoutTwoFactorKnown := 0.0, true
	for _, result := range a.outsideCollaboratorsByOrg {
		if !result.Complete {
			withoutTwoFactorKnown = false
			continue
		}
		withoutTwoFactorTotal += float64(result.OutsideCollaboratorsWithout2FA)
	}
	setMetric(metrics, "outside_collaborators_without_2fa", knownCountOrUnavailable(
		withoutTwoFactorTotal, withoutTwoFactorKnown, "analyzed organizations' outside collaborators without 2FA"))
	if ratioKnownAll {
		if metric, err := Percentage(outsideAll, membersAll, ratioPopulation); err == nil {
			setMetric(metrics, "outside_collab_ratio_pct", metric)
		}
	} else {
		setMetric(metrics, "outside_collab_ratio_pct", MetricValue{
			Status: MetricUnavailable, Population: ratioPopulation, EvidenceRefs: []string{},
			Reason: "outside-collaborator or member collection was incomplete for one or more organizations",
		})
	}
}
