// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/google/go-github/v83/github"
)

// RunImplementedCollectorIDs lists the collector catalogue IDs this vertical
// slice run actually calls. It is distinct from the narrower preflight probe
// registry (ImplementedCollectorIDs), which only knows how to probe org.settings
// and ghes.meta before any repository has been discovered: the repository-level
// collectors here require the organization's repository inventory to already be
// known, so they cannot be exercised by a pre-discovery preflight probe.
func RunImplementedCollectorIDs() []string {
	ids := []string{
		"org.settings", "org.repos", "org.properties",
		"repo.details", "repo.rules", "repo.workflows", "repo.languages", "repo.sbom",
	}
	ids = append(ids, OperationalCollectorIDs()...)
	ids = append(ids, SecurityCollectorIDs()...)
	// org.properties is already listed above (repo population/critical-property
	// lookup); this run loop now calls every EnterpriseCollectorIDs() entry,
	// including ent.info/ghes.manage_api (gated by target Enterprise/Deployment).
	ids = append(ids, EnterpriseCollectorIDs()...)
	ids = append(ids, AuditCollectorIDs()...)
	ids = append(ids, RemainingCollectorIDs()...)
	return ids
}

// RepositoryRunResult is one analyzed repository's effective branch protection,
// workflow analysis and feature-eligibility signal.
type RepositoryRunResult struct {
	FullName            string                               `json:"full_name"`
	DefaultBranch       string                               `json:"default_branch"`
	EffectiveProtection *EffectiveBranchProtection           `json:"effective_protection,omitempty"`
	Workflows           *WorkflowAnalysisResult              `json:"workflows,omitempty"`
	Feature             RepositoryFeatureSignal              `json:"feature"`
	PullRequests        *RepositoryPullRequestResult         `json:"pull_requests,omitempty"`
	ActionsRuns         *RepositoryActionsRunsResult         `json:"actions_runs,omitempty"`
	Access              *RepositoryAccessResult              `json:"access,omitempty"`
	ContentsProbe       *RepositoryContentsProbeResult       `json:"contents_probe,omitempty"`
	CommitVerification  *RepositoryCommitVerificationResult  `json:"commit_verification,omitempty"`
	SecretsEnv          *RepositorySecretsEnvResult          `json:"secrets_env,omitempty"`
	Releases            *RepositoryReleasesResult            `json:"releases,omitempty"`
	DiscussionsProjects *RepositoryDiscussionsProjectsResult `json:"discussions_projects,omitempty"`
}

// OrganizationOperationalResult bundles the Phase 4 organization-scoped
// collector outputs (alert lifecycles, code security configuration coverage,
// membership and governance inventories). It is additive to
// OrganizationRunResult's existing Scope/Population/Repositories fields.
type OrganizationOperationalResult struct {
	DependabotAlerts           *OrgAlertLifecycleResult         `json:"dependabot_alerts,omitempty"`
	CodeScanningAlerts         *OrgAlertLifecycleResult         `json:"code_scanning_alerts,omitempty"`
	SecretScanningAlerts       *OrgAlertLifecycleResult         `json:"secret_scanning_alerts,omitempty"`
	CodeSecurityConfigCoverage *MetricValue                     `json:"code_security_configuration_coverage,omitempty"`
	Membership                 *OrgMembershipResult             `json:"membership,omitempty"`
	OutsideCollaborators       *OrgOutsideCollaboratorsResult   `json:"outside_collaborators,omitempty"`
	Teams                      []teamSummary                    `json:"teams,omitempty"`
	Roles                      *OrgRolesResult                  `json:"roles,omitempty"`
	PATGovernance              *OrgPATGovernanceResult          `json:"pat_governance,omitempty"`
	Installations              *OrgInstallationsResult          `json:"installations,omitempty"`
	Hooks                      *OrgHooksResult                  `json:"hooks,omitempty"`
	Rulesets                   *OrgRulesetsResult               `json:"rulesets,omitempty"`
	ActionsPermissions         *OrgActionsPermissionsResult     `json:"actions_permissions,omitempty"`
	Runners                    *OrgRunnersResult                `json:"runners,omitempty"`
	Copilot                    *OrgCopilotResult                `json:"copilot,omitempty"`
	Packages                   *OrgPackagesResult               `json:"packages,omitempty"`
	Projects                   *OrgProjectsResult               `json:"projects,omitempty"`
	AuditLog                   *AuditLogResult                  `json:"audit_log,omitempty"`
	SecretScanningSettings     *OrgSecretScanningSettingsResult `json:"secret_scanning_settings,omitempty"`
	BypassRequests             *OrgBypassRequestsResult         `json:"bypass_requests,omitempty"`
	Campaigns                  *OrgCampaignsResult              `json:"campaigns,omitempty"`
	APIInsights                *OrgAPIInsightsResult            `json:"api_insights,omitempty"`
	Billing                    *BillingUsageResult              `json:"billing,omitempty"`
}

// TargetOperationalResult is one host target's enterprise-/instance-scoped
// (not organization-scoped) Phase 4 collector output: ent.info is scoped to
// the target's declared enterprise slug, ghes.manage_api to its GHES
// instance. Neither is duplicated per organization.
type TargetOperationalResult struct {
	Host                          string                               `json:"host"`
	EnterpriseInfo                *EnterpriseInfo                      `json:"enterprise_info,omitempty"`
	GHESManageBasics              *GHESManageBasicsResult              `json:"ghes_manage_basics,omitempty"`
	EnterpriseActionsPermissions  *EnterpriseActionsPermissionsResult  `json:"enterprise_actions_permissions,omitempty"`
	EnterpriseCodeSecurityConfigs *EnterpriseCodeSecurityConfigsResult `json:"enterprise_code_security_configs,omitempty"`
	EnterpriseAuditLog            *AuditLogResult                      `json:"enterprise_audit_log,omitempty"`
	EnterpriseAuditLogStreams     *EnterpriseAuditLogStreamsResult     `json:"enterprise_audit_log_streams,omitempty"`
	EnterpriseBilling             *BillingUsageResult                  `json:"enterprise_billing,omitempty"`
	EnterpriseCopilot             *EnterpriseCopilotResult             `json:"enterprise_copilot,omitempty"`
	EnterprisePolicies            *EnterprisePoliciesResult            `json:"enterprise_policies,omitempty"`
	EnterpriseSCIMUsers           *EnterpriseSCIMUsersResult           `json:"enterprise_scim_users,omitempty"`
}

// OrganizationRunResult is one organization scope's population and
// per-repository analysis.
type OrganizationRunResult struct {
	Scope        Scope                          `json:"scope"`
	Population   *OrganizationPopulation        `json:"population"`
	Repositories []RepositoryRunResult          `json:"repositories"`
	Operational  *OrganizationOperationalResult `json:"operational,omitempty"`
}

// VerticalSliceReport is the typed, evidence-backed result of `ghqr assess run`.
// It reports measured metrics and raw collection outcomes; it does not produce
// full per-control ControlResult records, which remain a later phase's
// responsibility ("this run emits measured metrics plus raw refs/completeness,
// not guessed states based on pure file presence").
type VerticalSliceReport struct {
	Profile               ProfileSummary            `json:"profile"`
	CollectedAt           time.Time                 `json:"collected_at"`
	ImplementedCollectors []string                  `json:"implemented_collectors"`
	ImplementedEvaluators []string                  `json:"implemented_evaluators"`
	Organizations         []OrganizationRunResult   `json:"organizations"`
	Targets               []TargetOperationalResult `json:"targets,omitempty"`
	Metrics               map[string]Metric         `json:"metrics"`
	Outcomes              []CollectorOutcome        `json:"collector_outcomes"`
	Caveats               []string                  `json:"caveats"`
}

// RunVerticalSlice performs explicitly live-consented collection across every
// configured target: organization inventory and settings, active/eligible/
// critical population determination, effective default-branch rule merging,
// workflow YAML action-reference analysis and feature-eligibility signals. Every
// control outside this scope remains NOT_ASSESSED; this run never fabricates a
// state from mere file presence.
func RunVerticalSlice(ctx context.Context, profile *Profile, config *CustomerConfig) (*VerticalSliceReport, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, err
	}
	budget, err := NewRequestBudget(config.Concurrency)
	if err != nil {
		return nil, err
	}
	clock := SystemClock{}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		return nil, err
	}
	report, runErr := runVerticalSliceWithStore(ctx, profile, config, targets, store, clock,
		func(target Target, source EvidenceSource) (*CollectionClient, error) {
			return NewCollectionClient(target, source, profile, budget, clock)
		})
	closeErr := store.Close()
	if runErr != nil {
		return nil, runErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return report, nil
}

func runVerticalSliceWithStore(ctx context.Context, profile *Profile, config *CustomerConfig, targets []Target,
	store *EvidenceStore, clock Clock, newClient func(Target, EvidenceSource) (*CollectionClient, error)) (*VerticalSliceReport, error) {
	report := &VerticalSliceReport{
		Profile: profile.Summary(), CollectedAt: clock.Now(),
		ImplementedCollectors: RunImplementedCollectorIDs(), ImplementedEvaluators: []string{},
		Organizations: []OrganizationRunResult{}, Targets: []TargetOperationalResult{},
		Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}, Caveats: []string{},
	}
	accumulator := newMetricAccumulator()
	now := clock.Now()
	lookbackStart := now.AddDate(0, 0, -config.LookbackDays)
	alertWindowStart := now.AddDate(0, 0, -alertLifecycleWindowDays)

	for _, target := range targets {
		client, err := newClient(target, RESTEvidence)
		if err != nil {
			return nil, fmt.Errorf("initialize collection client for host %s: %w", target.Host, err)
		}

		targetResult := TargetOperationalResult{Host: target.Host}
		graphQLClient, graphQLErr := newClient(target, GraphQLEvidence)
		if graphQLErr != nil {
			graphQLClient = nil
			report.Caveats = append(report.Caveats, fmt.Sprintf(
				"GraphQL client for %s could not be initialized (%s); org.projects/repo.discussions_projects and, if applicable, "+
					"ent.info were not collected for this target", target.Host, graphQLErr))
		}
		if target.Enterprise != "" {
			if graphQLClient != nil {
				entScope := Scope{Host: target.Host, Kind: EnterpriseScope, Name: target.Enterprise}
				info, infoOutcome, infoErr := FetchEnterpriseInfo(ctx, graphQLClient, store, entScope, target.Enterprise)
				report.Outcomes = append(report.Outcomes, infoOutcome)
				if infoErr == nil {
					targetResult.EnterpriseInfo = info
				}
				policies, policiesOutcome, _ := FetchEnterprisePolicies(ctx, graphQLClient, store, entScope, target.Enterprise)
				report.Outcomes = append(report.Outcomes, policiesOutcome)
				targetResult.EnterprisePolicies = &policies
			}
			entScope := Scope{Host: target.Host, Kind: EnterpriseScope, Name: target.Enterprise}
			actionsPermissions, actionsPermissionsOutcome, actionsPermissionsErr := FetchEnterpriseActionsPermissions(
				ctx, client, store, entScope, target.Enterprise)
			report.Outcomes = append(report.Outcomes, actionsPermissionsOutcome)
			if actionsPermissionsErr == nil {
				targetResult.EnterpriseActionsPermissions = &actionsPermissions
			}
			codeSecurityConfigs, codeSecurityConfigsOutcomes, _ := FetchEnterpriseCodeSecurityConfigurations(
				ctx, client, store, entScope, target.Enterprise)
			report.Outcomes = append(report.Outcomes, codeSecurityConfigsOutcomes...)
			targetResult.EnterpriseCodeSecurityConfigs = &codeSecurityConfigs
			auditLog, auditLogOutcome, _ := FetchEnterpriseAuditLog(ctx, client, store, entScope, target.Enterprise, lookbackStart, now)
			report.Outcomes = append(report.Outcomes, auditLogOutcome)
			targetResult.EnterpriseAuditLog = &auditLog
			auditLogStreams, auditLogStreamsOutcome, _ := FetchEnterpriseAuditLogStreams(ctx, client, store, entScope, target.Enterprise)
			report.Outcomes = append(report.Outcomes, auditLogStreamsOutcome)
			targetResult.EnterpriseAuditLogStreams = &auditLogStreams
			billing, billingOutcomes, _ := FetchEnterpriseBilling(ctx, client, store, entScope, target.Enterprise, target.Deployment)
			report.Outcomes = append(report.Outcomes, billingOutcomes...)
			targetResult.EnterpriseBilling = &billing
			copilot, copilotOutcomes, _ := FetchEnterpriseCopilot(ctx, client, store, entScope, target.Enterprise, target.Deployment, lookbackStart, now)
			report.Outcomes = append(report.Outcomes, copilotOutcomes...)
			targetResult.EnterpriseCopilot = &copilot
		}
		// ent.scim_users is deliberately NOT nested inside the `target.Enterprise
		// != ""` block above: only "emu" mode's endpoint actually requires an
		// enterprise slug (GET /scim/v2/enterprises/{enterprise}/Users). "saml_sso"
		// (Cloud, organization-scoped) and "ghes" (Server, appliance-wide, no
		// enterprise/organization path segment at all) are both legitimate
		// configurations with no enterprise slug configured at all; nesting this
		// call inside the enterprise check silently skipped both of them despite
		// their collector ID being registered as run-wired. A scope with an empty
		// EnterpriseScope name would also fail Scope.Validate() outright, so a
		// host-qualified InstanceScope is used whenever no enterprise slug is
		// configured, falling back to the richer EnterpriseScope only when one is.
		// This is the single call site for every SCIMMode value, including "emu",
		// so there is no risk of double-invoking EMU mode here.
		scimScope := Scope{Host: target.Host, Kind: InstanceScope, Name: target.Host}
		if target.Enterprise != "" {
			scimScope = Scope{Host: target.Host, Kind: EnterpriseScope, Name: target.Enterprise}
		}
		scimUsers, scimOutcomes, _ := FetchEnterpriseSCIMUsers(ctx, client, store, scimScope, target.Enterprise, target.SCIMMode, target.Deployment, target.Organizations)
		report.Outcomes = append(report.Outcomes, scimOutcomes...)
		if target.SCIMMode != "" {
			targetResult.EnterpriseSCIMUsers = &scimUsers
		}
		if target.Deployment == Server {
			managementClient, managementErr := newClient(target, ManagementEvidence)
			if managementErr != nil {
				report.Caveats = append(report.Caveats, fmt.Sprintf(
					"ghes.manage_api client for %s could not be initialized (%s); GHES management basics were not collected", target.Host, managementErr))
			} else {
				instanceScope := Scope{Host: target.Host, Kind: InstanceScope, Name: target.Host}
				basics, basicsOutcomes, _ := FetchGHESManageBasics(ctx, managementClient, store, instanceScope)
				report.Outcomes = append(report.Outcomes, basicsOutcomes...)
				targetResult.GHESManageBasics = &basics
			}
		}
		if targetResult.EnterpriseInfo != nil || targetResult.GHESManageBasics != nil ||
			targetResult.EnterpriseActionsPermissions != nil || targetResult.EnterpriseCodeSecurityConfigs != nil ||
			targetResult.EnterpriseAuditLog != nil || targetResult.EnterpriseAuditLogStreams != nil ||
			targetResult.EnterpriseBilling != nil || targetResult.EnterpriseCopilot != nil ||
			targetResult.EnterprisePolicies != nil || targetResult.EnterpriseSCIMUsers != nil {
			report.Targets = append(report.Targets, targetResult)
		}

		for _, organization := range target.Organizations {
			orgScope := Scope{Host: target.Host, Kind: OrganizationScope, Name: organization}
			settings, settingsOutcome, settingsErr := collectJSONObject[github.Organization](ctx, client, store, orgScope,
				"org.settings", "settings", "orgs/"+url.PathEscape(organization))
			report.Outcomes = append(report.Outcomes, settingsOutcome)
			if settingsErr != nil {
				report.Caveats = append(report.Caveats, fmt.Sprintf(
					"organization settings probe for %s was incomplete (%s); repository inventory collection proceeded regardless",
					orgScope.Key(), settingsOutcome.Availability))
			} else if settings != nil {
				accumulator.addDefaultRepositoryPermission(orgScope.Key(), settings.GetDefaultRepoPermission())
			}

			population, eligible, populationOutcomes, err := BuildOrganizationPopulation(ctx, client, store, orgScope, organization, config, clock.Now())
			report.Outcomes = append(report.Outcomes, populationOutcomes...)
			if err != nil {
				return nil, fmt.Errorf("build repository population for %s: %w", orgScope.Key(), err)
			}
			// GOV-072's verified_commit_ratio_pct is scoped to this
			// organization's confirmed CRITICAL repository population only
			// (never every analyzed repository); recording it here, before
			// any repository is analyzed, matches the same critical-
			// population contract the evaluator's own pooling already
			// depends on (an unresolved critical population makes the whole
			// organization's contribution unknown, never silently zero).
			accumulator.setCriticalPopulation(orgScope.Key(), population.Critical)

			orgResult := OrganizationRunResult{Scope: orgScope, Population: population, Repositories: []RepositoryRunResult{}}
			for _, repo := range eligible {
				fullName := repo.GetFullName()
				owner, name := splitOwnerRepo(fullName)
				repoScope := Scope{Host: target.Host, Kind: RepositoryScope, Name: fullName}
				repoResult := analyzeOneRepository(ctx, client, graphQLClient, store, orgScope, repoScope, organization, owner, name, repo,
					lookbackStart, report, accumulator)
				orgResult.Repositories = append(orgResult.Repositories, repoResult)
			}
			orgResult.Operational = analyzeOrganizationOperational(ctx, client, graphQLClient, store, orgScope, organization,
				population.EligibleFullNames, target.Deployment, lookbackStart, now, report, accumulator)
			report.Organizations = append(report.Organizations, orgResult)
		}
	}

	if err := accumulator.populate(report.Metrics, lookbackStart, now, alertWindowStart, now); err != nil {
		return nil, fmt.Errorf("compute Phase 4 operational/security/governance metrics: %w", err)
	}
	report.Caveats = append(report.Caveats,
		"this run computes metrics and raw collection outcomes only; it does not produce full per-control "+
			"ControlResult records or IMPLEMENTED/PARTIAL/NOT_IMPLEMENTED decisions, which remain a later phase's responsibility",
		"the automation profile's shared \"eligible_repos_count\" metric key is overloaded across SEC-001 (dependency-scanning "+
			"eligibility) and SEC-004 (code-scanning eligibility); this run reports each feature's population under a distinct "+
			"key instead of writing that ambiguous shared key",
		"repo.prs activity metrics (review_coverage_pct, median_pr_cycle_time_h, median_time_to_first_review_h) are computed "+
			"over a capped sample of each repository's most recently merged pull requests (<=100), not its exhaustive merged-PR "+
			"history; the resulting Metric values are marked Sampled",
		"org.teams/org.roles/org.pat_governance/org.installations/org.hooks/org.actions_permissions/org.runners/org.copilot/"+
			"org.packages/org.projects/ent.actions_permissions/ent.code_security_configs/repo.secrets_env/"+
			"repo.releases_packages/repo.discussions_projects/org.audit_log/ent.audit_log/ent.audit_log_streams/"+
			"org.secret_scanning_settings/org.bypass_requests/org.campaigns are collection-only in this phase: their evidence "+
			"and raw counts are reported per organization/repository/target, but no coverage/compliance ratio or ControlResult "+
			"is derived from them in the pooled Metrics map yet (ent.code_security_configs in particular has no enterprise-wide "+
			"eligible-repository population available in this run loop, so configuration_coverage_pct is left uncomputed at "+
			"that scope)",
		"org.audit_log/ent.audit_log classify every retrieved event locally into the profile's documented phrase categories "+
			"from one single, full, date-bounded pull (not one live query per phrase); Git-category events are retained by "+
			"GitHub for only 7 days regardless of the requested lookback, so a longer configured window cannot be claimed as "+
			"fully achieved for Git events specifically (web events are retained 180 days) -- AuditLogResult.EarliestEntryAt "+
			"discloses what was actually observed rather than assuming the requested window was satisfied",
		"ent.scim_users remains fully unimplemented this phase: the EMU-vs-SAML-SSO routing decision and PII handling were "+
			"not resolved with enough confidence to implement without risking a misleading partial result")

	if err := store.WriteReport("run.json", report); err != nil {
		return nil, err
	}
	if err := store.WriteReport("runs/run-"+clock.Now().Format("20060102T150405.000000000Z")+".json", report); err != nil {
		return nil, err
	}
	return report, nil
}

// analyzeOrganizationOperational runs the organization-scoped Phase 4
// collectors (alert lifecycles, code security configuration coverage,
// membership and lightweight governance inventories) once per organization
// (not per repository) and folds their contribution into the run-wide
// metric accumulator.
func analyzeOrganizationOperational(ctx context.Context, client, graphQLClient *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string, eligibleRepositoryFullNames []string, deployment Deployment, lookbackStart, now time.Time,
	report *VerticalSliceReport, accumulator *metricAccumulator) *OrganizationOperationalResult {
	organizationKey := orgScope.Key()
	result := &OrganizationOperationalResult{}

	dependabot, dependabotOutcomes, _ := FetchOrgDependabotAlerts(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, dependabotOutcomes...)
	result.DependabotAlerts = &dependabot
	accumulator.addDependabotAlerts(organizationKey, dependabot)

	codeScanning, codeScanningOutcomes, _ := FetchOrgCodeScanningAlerts(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, codeScanningOutcomes...)
	result.CodeScanningAlerts = &codeScanning
	accumulator.addCodeScanningAlerts(organizationKey, codeScanning)

	secretScanning, secretScanningOutcomes, _ := FetchOrgSecretScanningAlerts(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, secretScanningOutcomes...)
	result.SecretScanningAlerts = &secretScanning
	accumulator.addSecretScanningAlerts(organizationKey, secretScanning)

	configCoverage, configOutcomes, configErr := FetchOrgCodeSecurityConfigurations(ctx, client, store, orgScope, organization, eligibleRepositoryFullNames)
	report.Outcomes = append(report.Outcomes, configOutcomes...)
	if configErr == nil {
		result.CodeSecurityConfigCoverage = &configCoverage
		accumulator.addSecurityConfigCoverage(organizationKey, configCoverage)
	}

	membership, membershipOutcomes, _ := FetchOrgMembership(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, membershipOutcomes...)
	result.Membership = &membership
	accumulator.addMembership(organizationKey, membership)

	outsideCollaborators, outsideCollaboratorsOutcomes, _ := FetchOrgOutsideCollaborators(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, outsideCollaboratorsOutcomes...)
	result.OutsideCollaborators = &outsideCollaborators
	accumulator.addOutsideCollaborators(organizationKey, outsideCollaborators)

	teams, teamsOutcomes, _ := FetchOrgTeams(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, teamsOutcomes...)
	result.Teams = teams
	accumulator.addTeamGrants(organizationKey, teams)

	roles, rolesOutcomes, _ := FetchOrgRoles(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, rolesOutcomes...)
	result.Roles = &roles
	accumulator.addRoles(roles)

	pat, patOutcomes, _ := FetchOrgPATGovernance(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, patOutcomes...)
	result.PATGovernance = &pat

	installations, installationsOutcome, installationsErr := FetchOrgInstallations(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, installationsOutcome)
	result.Installations = &installations

	hooks, hooksOutcomes, _ := FetchOrgHooks(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, hooksOutcomes...)
	result.Hooks = &hooks

	rulesets, rulesetsOutcome, rulesetsErr := FetchOrgRulesets(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, rulesetsOutcome)
	if rulesetsErr == nil {
		result.Rulesets = rulesets
		accumulator.addDirectOrgRulesets(organizationKey, rulesets.ActiveCount, rulesets.DefaultBranchRulesetActive)
	}

	actionsPermissions, actionsPermissionsOutcome, actionsPermissionsErr := FetchOrgActionsPermissions(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, actionsPermissionsOutcome)
	if actionsPermissionsErr == nil {
		result.ActionsPermissions = &actionsPermissions
	}

	runners, runnersOutcomes, _ := FetchOrgRunners(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, runnersOutcomes...)
	result.Runners = &runners

	copilot, copilotOutcome, _ := FetchOrgCopilot(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, copilotOutcome)
	result.Copilot = &copilot

	packages, packagesOutcomes, _ := FetchOrgPackages(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, packagesOutcomes...)
	result.Packages = &packages

	projects, projectsOutcome, projectsErr := FetchOrgProjects(ctx, graphQLClient, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, projectsOutcome)
	if projectsErr == nil {
		result.Projects = &projects
	}

	auditLog, auditLogOutcome, _ := FetchOrgAuditLog(ctx, client, store, orgScope, organization, lookbackStart, now)
	report.Outcomes = append(report.Outcomes, auditLogOutcome)
	result.AuditLog = &auditLog

	secretScanningSettings, secretScanningSettingsOutcome, secretScanningSettingsErr := FetchOrgSecretScanningSettings(
		ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, secretScanningSettingsOutcome)
	if secretScanningSettingsErr == nil {
		result.SecretScanningSettings = &secretScanningSettings
	}

	bypassRequests, bypassRequestsOutcomes, _ := FetchOrgBypassRequests(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, bypassRequestsOutcomes...)
	result.BypassRequests = &bypassRequests

	campaigns, campaignsOutcomes, _ := FetchOrgCampaigns(ctx, client, store, orgScope, organization)
	report.Outcomes = append(report.Outcomes, campaignsOutcomes...)
	result.Campaigns = &campaigns

	apiInsights, apiInsightsOutcomes, _ := FetchOrgAPIInsights(ctx, client, store, orgScope, organization, deployment, lookbackStart, now)
	report.Outcomes = append(report.Outcomes, apiInsightsOutcomes...)
	result.APIInsights = &apiInsights

	billing, billingOutcomes, _ := FetchOrgBilling(ctx, client, store, orgScope, organization, deployment)
	report.Outcomes = append(report.Outcomes, billingOutcomes...)
	result.Billing = &billing

	accumulator.addGovernanceCounts(installations, installationsErr == nil, hooks, pat)
	return result
}

// analyzeOneRepository runs effective-rules, workflow and feature-eligibility
// analysis for one repository and folds its contribution into the run-wide
// metric accumulator.
func analyzeOneRepository(ctx context.Context, client, graphQLClient *CollectionClient, store *EvidenceStore, orgScope, repoScope Scope,
	organization, owner, name string, repo *github.Repository, lookbackStart time.Time,
	report *VerticalSliceReport, accumulator *metricAccumulator) RepositoryRunResult {
	details, detailsOutcome, detailsErr := FetchRepositoryDetails(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, detailsOutcome)
	defaultBranch := repo.GetDefaultBranch()
	if detailsErr == nil && details != nil && details.GetDefaultBranch() != "" {
		defaultBranch = details.GetDefaultBranch()
	}
	result := RepositoryRunResult{
		FullName: repo.GetFullName(), DefaultBranch: defaultBranch,
		Feature: RepositoryFeatureSignal{FullName: repo.GetFullName()},
	}

	if defaultBranch != "" {
		effective, ruleOutcomes, ruleErr := ComputeEffectiveBranchProtection(ctx, client, store, orgScope, repoScope,
			organization, owner, name, defaultBranch)
		report.Outcomes = append(report.Outcomes, ruleOutcomes...)
		if ruleErr == nil && effective != nil {
			result.EffectiveProtection = effective
			accumulator.addEffectiveProtection(effective)
		}
	}

	workflows, workflowOutcomes, workflowErr := AnalyzeRepositoryWorkflows(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, workflowOutcomes...)
	if workflowErr == nil && workflows != nil {
		result.Workflows = workflows
		accumulator.addReferences(workflows.References)
		result.Feature.CodeQLOperational = workflows.CodeQLOperational
	}

	// GitHub's native code-scanning default setup is a distinct enablement
	// mechanism from a custom `github/codeql-action` workflow step; either one
	// makes code scanning operationally active for this repository.
	defaultSetupConfigured, defaultSetupOutcome, _ := FetchRepositoryCodeScanningDefaultSetup(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, defaultSetupOutcome)
	if defaultSetupConfigured != nil && *defaultSetupConfigured {
		result.Feature.CodeQLOperational = true
	}

	organizationKey := orgScope.Key()
	pullRequests, pullRequestOutcomes, _ := FetchRepositoryPullRequests(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, pullRequestOutcomes...)
	result.PullRequests = &pullRequests
	accumulator.addPullRequests(organizationKey, pullRequests)

	actionsRuns, actionsRunOutcomes, _ := FetchRepositoryActionsRuns(ctx, client, store, repoScope, owner, name, lookbackStart)
	report.Outcomes = append(report.Outcomes, actionsRunOutcomes...)
	result.ActionsRuns = &actionsRuns
	accumulator.addActionsRuns(organizationKey, actionsRuns)

	languages, languagesOutcome, _ := FetchRepositoryLanguages(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, languagesOutcome)
	result.Feature.CodeQLEligible = HasPositiveCodeQLSupportedLanguageBytes(languages)

	// repo.contents_probe inventories actual dependency manifest files
	// (recursive default-branch tree, falling back to root-only when
	// truncated/unavailable) and repo.sbom's package list (excluding the
	// SPDX document's own "describes" package) feeds the published
	// DependencyEligibility helper directly, replacing the Phase 3 "SBOM
	// endpoint returned 200" boolean proxy with the actual observed
	// manifest/package population it was always meant to represent.
	contentsProbe, contentsProbeOutcomes, _ := FetchRepositoryContentsProbe(ctx, client, store, repoScope, owner, name, defaultBranch)
	report.Outcomes = append(report.Outcomes, contentsProbeOutcomes...)
	result.ContentsProbe = &contentsProbe
	dependencyPackages, sbomOutcome, _ := FetchRepositorySBOMPackageCount(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, sbomOutcome)
	var supportedManifests *int
	if contentsProbe.Complete {
		count := contentsProbe.SupportedManifestCount
		supportedManifests = &count
	}
	dependencyEligibility, eligibilityErr := DependencyEligibility(supportedManifests, dependencyPackages, true)
	dependencyEligibilityKnown := eligibilityErr == nil && dependencyEligibility.Status == MetricKnown
	if dependencyEligibilityKnown {
		result.Feature.DependencyEligible = dependencyEligibility.Boolean != nil && *dependencyEligibility.Boolean
	}
	if result.Feature.DependencyEligible && detailsErr == nil && details != nil {
		if analysis := details.GetSecurityAndAnalysis(); analysis != nil {
			if updates := analysis.GetDependabotSecurityUpdates(); updates != nil {
				result.Feature.DependencyOperational = updates.GetStatus() == "enabled"
			}
		}
	}
	// SEC-043's grouping denominator is dependency-ELIGIBLE repositories
	// (never the subset whose dependabot.yml merely happened to parse) and
	// SEC-099's actions-ecosystem denominator is repositories that actually
	// use GitHub Actions (have at least one workflow file), not a parsed-
	// config subset either; both independently-determined flags are folded
	// in alongside the raw probe so neither metric's population is silently
	// narrowed by this collector.
	hasWorkflows := workflowErr == nil && workflows != nil && workflows.WorkflowCount > 0
	accumulator.addContentsProbe(organizationKey, contentsProbe, result.Feature.DependencyEligible, dependencyEligibilityKnown, hasWorkflows)

	access, accessOutcomes, _ := FetchRepositoryAccess(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, accessOutcomes...)
	result.Access = &access
	accumulator.addRepositoryAccess(organizationKey, access)

	commitVerification, commitOutcome, _ := FetchRepositoryCommitVerification(ctx, client, store, repoScope, owner, name, defaultBranch)
	report.Outcomes = append(report.Outcomes, commitOutcome)
	result.CommitVerification = &commitVerification
	accumulator.addCommitVerification(organizationKey, commitVerification)

	secretsEnv, secretsEnvOutcomes, _ := FetchRepositorySecretsAndEnvironments(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, secretsEnvOutcomes...)
	result.SecretsEnv = &secretsEnv

	releases, releasesOutcome, _ := FetchRepositoryReleases(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, releasesOutcome)
	result.Releases = &releases

	discussionsProjects, discussionsProjectsOutcome, discussionsProjectsErr := FetchRepositoryDiscussionsProjects(ctx, graphQLClient, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, discussionsProjectsOutcome)
	if discussionsProjectsErr == nil {
		result.DiscussionsProjects = &discussionsProjects
	}

	accumulator.addFeatureSignal(result.Feature)
	return result
}
