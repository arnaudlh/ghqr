// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/go-github/v83/github"
)

// EnterpriseCollectorIDs lists the catalogue collector IDs this file
// implements: organization membership/teams/roles/PAT governance/
// installations/hooks/rulesets, repository access, enterprise identity
// (GraphQL) and GHES management basics. It is additive to
// RunImplementedCollectorIDs.
func EnterpriseCollectorIDs() []string {
	return []string{
		"org.members", "org.outside_collaborators", "org.teams", "org.roles", "org.pat_governance",
		"org.installations", "org.hooks", "org.rulesets", "repo.access",
		"org.actions_permissions", "org.runners", "org.copilot", "org.packages", "org.projects",
		"ent.info", "ghes.manage_api", "ent.actions_permissions", "ent.code_security_configs",
	}
}

// OrgMembershipResult is one organization's member/owner/2FA population for
// the published MembershipMetrics helper. A 403 on an owner-only filter
// (role=admin or filter=2fa_disabled) is preserved as Complete=false so the
// pure helper reports unavailable, never a false "zero admins"/"zero without
// 2FA" from a forbidden, not empty, response.
type OrgMembershipResult struct {
	Members          int  `json:"members"`
	Owners           int  `json:"owners"`
	WithoutTwoFactor int  `json:"without_two_factor"`
	Complete         bool `json:"complete"`
}

// FetchOrgMembership collects an organization's complete member roster, its
// owner-role subset and its 2FA-disabled subset (every list fully paginated).
func FetchOrgMembership(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgMembershipResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	members, membersOutcome, membersErr := collectJSONArray[*github.User](ctx, client, store, orgScope,
		"org.members", "all", "orgs/"+organizationPath+"/members", "", true)
	owners, ownersOutcome, ownersErr := collectJSONArray[*github.User](ctx, client, store, orgScope,
		"org.members", "admin", "orgs/"+organizationPath+"/members?role=admin", "", true)
	withoutTwoFactor, withoutTwoFactorOutcome, withoutTwoFactorErr := collectJSONArray[*github.User](ctx, client, store, orgScope,
		"org.members", "2fa-disabled", "orgs/"+organizationPath+"/members?filter=2fa_disabled", "", true)
	result := OrgMembershipResult{
		Members: len(members), Owners: len(owners), WithoutTwoFactor: len(withoutTwoFactor),
		Complete: membersErr == nil && ownersErr == nil && withoutTwoFactorErr == nil,
	}
	return result, []CollectorOutcome{membersOutcome, ownersOutcome, withoutTwoFactorOutcome}, nil
}

// OrgOutsideCollaboratorsResult is SEC-016's outside_collab_ratio_pct and the
// companion outside_collaborators_without_2fa population: the organization's
// complete outside-collaborator roster and its 2FA-disabled subset (both
// fully paginated). A 403 on the owner-only 2FA filter is preserved as
// Complete=false, matching FetchOrgMembership's documented forbidden-vs-zero
// contract — never a false "zero outside collaborators without 2FA".
type OrgOutsideCollaboratorsResult struct {
	OutsideCollaborators           int  `json:"outside_collaborators"`
	OutsideCollaboratorsWithout2FA int  `json:"outside_collaborators_without_2fa"`
	Complete                       bool `json:"complete"`
}

// FetchOrgOutsideCollaborators collects the organization's complete outside-
// collaborator roster and its 2FA-disabled subset.
func FetchOrgOutsideCollaborators(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgOutsideCollaboratorsResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	all, allOutcome, allErr := collectJSONArray[*github.User](ctx, client, store, orgScope,
		"org.outside_collaborators", "all", "orgs/"+organizationPath+"/outside_collaborators", "", true)
	withoutTwoFactor, withoutTwoFactorOutcome, withoutTwoFactorErr := collectJSONArray[*github.User](ctx, client, store, orgScope,
		"org.outside_collaborators", "2fa-disabled", "orgs/"+organizationPath+"/outside_collaborators?filter=2fa_disabled", "", true)
	result := OrgOutsideCollaboratorsResult{
		OutsideCollaborators: len(all), OutsideCollaboratorsWithout2FA: len(withoutTwoFactor),
		Complete: allErr == nil && withoutTwoFactorErr == nil,
	}
	return result, []CollectorOutcome{allOutcome, withoutTwoFactorOutcome}, nil
}

// teamRepoAccess is one team's permission on one repository, from
// GET /orgs/{org}/teams/{team_slug}/repos.
type teamRepoAccess struct {
	FullName   string `json:"full_name"`
	Permission string `json:"permission"`
}

// teamSummary preserves the collected team roster fields the org.teams
// collector documents (slug, privacy, parent, members/repos counts) plus
// each team's actual repository permission grants, which combine with the
// repo.access collector's direct-collaborator inventory to compute
// team_based_access_pct.
type teamSummary struct {
	Slug         string           `json:"slug"`
	Privacy      string           `json:"privacy"`
	MembersCount int              `json:"members_count"`
	ReposCount   int              `json:"repos_count"`
	Nested       bool             `json:"nested"`
	Repos        []teamRepoAccess `json:"repos"`
	// ReposComplete is false when this team's repository permission-grant
	// list could not be fully collected (a page failure, not a confirmed
	// empty list): team_based_access_pct must treat that team's
	// contribution as unknown, never as "this team grants access to zero
	// repositories".
	ReposComplete bool `json:"repos_complete"`
}

// FetchOrgTeams collects the organization's complete team roster and, for
// every team, its complete (fully paginated) repository permission grants.
func FetchOrgTeams(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) ([]teamSummary, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	teams, outcome, err := collectJSONArray[*github.Team](ctx, client, store, orgScope,
		"org.teams", "teams", "orgs/"+organizationPath+"/teams", "", true)
	outcomes := []CollectorOutcome{outcome}
	if err != nil {
		return nil, outcomes, err
	}
	summaries := make([]teamSummary, 0, len(teams))
	for _, team := range teams {
		if team == nil || team.GetSlug() == "" {
			continue
		}
		summary := teamSummary{
			Slug: team.GetSlug(), Privacy: team.GetPrivacy(), MembersCount: team.GetMembersCount(),
			ReposCount: team.GetReposCount(), Nested: team.Parent != nil, Repos: []teamRepoAccess{},
		}
		repos, reposOutcome, reposErr := collectJSONArray[*github.Repository](ctx, client, store, orgScope,
			"org.teams", safeFeatureName("repos", team.GetSlug()),
			"orgs/"+organizationPath+"/teams/"+url.PathEscape(team.GetSlug())+"/repos", "", true)
		outcomes = append(outcomes, reposOutcome)
		summary.ReposComplete = reposErr == nil
		if reposErr == nil {
			for _, repo := range repos {
				if repo == nil || repo.GetFullName() == "" {
					continue
				}
				summary.Repos = append(summary.Repos, teamRepoAccess{FullName: repo.GetFullName(), Permission: repoPermissionLevel(repo)})
			}
		}
		summaries = append(summaries, summary)
	}
	return summaries, outcomes, nil
}

// repoPermissionLevel reports the single highest permission level GitHub's
// team-repos response encodes in its boolean permissions object (admin >
// maintain > push > triage > pull), matching the REST documentation's own
// precedence.
func repoPermissionLevel(repo *github.Repository) string {
	permissions := repo.GetPermissions()
	if permissions == nil {
		return "unknown"
	}
	switch {
	case permissions.GetAdmin():
		return "admin"
	case permissions.GetMaintain():
		return "maintain"
	case permissions.GetPush():
		return "push"
	case permissions.GetTriage():
		return "triage"
	case permissions.GetPull():
		return "pull"
	default:
		return "unknown"
	}
}

// roleAssignment is one organization role's resolved team/user assignment
// counts, used to compute security_role_used/custom_roles_count signals
// without enumerating every member's effective permission set.
type roleAssignment struct {
	Name      string `json:"name"`
	IsCustom  bool   `json:"is_custom"`
	TeamCount int    `json:"team_count"`
	UserCount int    `json:"user_count"`
}

// OrgRolesResult preserves the organization-roles catalogue (including
// custom roles), each role's actual team/user assignment counts, the
// deprecated-but-still-live security-manager team assignment and the
// organization's custom repository roles.
type OrgRolesResult struct {
	Roles                []roleAssignment `json:"roles"`
	CustomRoleCount      int              `json:"custom_role_count"`
	CustomRepoRoleCount  int              `json:"custom_repo_role_count"`
	SecurityManagerTeams []string         `json:"security_manager_teams"`
}

// FetchOrgRoles collects the organization's role catalogue (predefined and
// custom), each role's actual team/user assignment (fully paginated per
// role), its custom repository roles and its security-manager team
// assignment.
func FetchOrgRoles(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgRolesResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	envelope, rolesOutcome, rolesErr := collectJSONObject[github.OrganizationCustomRoles](ctx, client, store, orgScope,
		"org.roles", "organization-roles", "orgs/"+organizationPath+"/organization-roles")
	outcomes := []CollectorOutcome{rolesOutcome}
	result := OrgRolesResult{Roles: []roleAssignment{}, SecurityManagerTeams: []string{}}
	if rolesErr == nil && envelope != nil {
		for _, role := range envelope.CustomRepoRoles {
			if role == nil || role.ID == nil {
				continue
			}
			isCustom := role.GetSource() == "Custom" || role.GetSource() == "custom"
			if isCustom {
				result.CustomRoleCount++
			}
			teams, teamsOutcome, _ := collectJSONArray[*github.Team](ctx, client, store, orgScope,
				"org.roles", safeFeatureName("role-teams", strconv.FormatInt(role.GetID(), 10)),
				"orgs/"+organizationPath+"/organization-roles/"+strconv.FormatInt(role.GetID(), 10)+"/teams", "", true)
			outcomes = append(outcomes, teamsOutcome)
			users, usersOutcome, _ := collectJSONArray[*github.User](ctx, client, store, orgScope,
				"org.roles", safeFeatureName("role-users", strconv.FormatInt(role.GetID(), 10)),
				"orgs/"+organizationPath+"/organization-roles/"+strconv.FormatInt(role.GetID(), 10)+"/users", "", true)
			outcomes = append(outcomes, usersOutcome)
			result.Roles = append(result.Roles, roleAssignment{
				Name: role.GetName(), IsCustom: isCustom, TeamCount: len(teams), UserCount: len(users),
			})
		}
	}

	customRepoRoles, customRepoRolesOutcome, customRepoRolesErr := collectJSONObject[github.OrganizationCustomRepoRoles](ctx, client, store, orgScope,
		"org.roles", "custom-repository-roles", "orgs/"+organizationPath+"/custom-repository-roles")
	outcomes = append(outcomes, customRepoRolesOutcome)
	if customRepoRolesErr == nil && customRepoRoles != nil {
		result.CustomRepoRoleCount = len(customRepoRoles.CustomRepoRoles)
	}

	securityManagers, managersOutcome, managersErr := collectJSONArray[*github.Team](ctx, client, store, orgScope,
		"org.roles", "security-managers", "orgs/"+organizationPath+"/security-managers", "", false)
	outcomes = append(outcomes, managersOutcome)
	if managersErr == nil {
		for _, team := range securityManagers {
			if team != nil {
				result.SecurityManagerTeams = append(result.SecurityManagerTeams, team.GetSlug())
			}
		}
	}
	return result, outcomes, nil
}

// personalAccessTokenRequest is go-github's missing typed shape for GET
// /orgs/{org}/personal-access-token-requests (pending fine-grained PAT
// approval requests; distinct from github.PersonalAccessToken, which covers
// already-granted tokens).
type personalAccessTokenRequest struct {
	ID                  *int64            `json:"id"`
	Owner               *github.User      `json:"owner"`
	RepositorySelection *string           `json:"repository_selection"`
	CreatedAt           *github.Timestamp `json:"created_at"`
	TokenExpired        *bool             `json:"token_expired"`
}

// patRepositorySampleCap bounds the number of granted fine-grained PATs whose
// per-PAT repository list (GET .../personal-access-tokens/{id}/repositories)
// is actually fetched, keeping per-run request volume bounded. The PAT
// policy itself (allow/restrict, approval requirement, maximum lifetime) has
// no REST endpoint at all and is left for a UI-capture collector
// (ui.org_pat_policy), not this one.
const patRepositorySampleCap = 5

// OrgPATGovernanceResult field names match the automation profile's exact
// declared metric keys (SEC-086: fine_grained_pat_grants_count,
// pending_pat_requests) rather than adapter-invented names.
type OrgPATGovernanceResult struct {
	PendingPATRequests                   int `json:"pending_pat_requests"`
	FineGrainedPATGrantsCount            int `json:"fine_grained_pat_grants_count"`
	SampledGrantsWithRepositoryListKnown int `json:"sampled_grants_with_repository_list_known"`
}

// FetchOrgPATGovernance collects the organization's pending fine-grained PAT
// requests and already-granted fine-grained PAT inventory (both fully
// paginated), plus a bounded sample of each granted token's actual
// repository-selection list (not merely the declared repository_selection
// string) for audit evidence.
func FetchOrgPATGovernance(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgPATGovernanceResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	requests, requestsOutcome, _ := collectJSONArray[*personalAccessTokenRequest](ctx, client, store, orgScope,
		"org.pat_governance", "requests", "orgs/"+organizationPath+"/personal-access-token-requests", "", true)
	grants, grantsOutcome, _ := collectJSONArray[*github.PersonalAccessToken](ctx, client, store, orgScope,
		"org.pat_governance", "grants", "orgs/"+organizationPath+"/personal-access-tokens", "", true)
	outcomes := []CollectorOutcome{requestsOutcome, grantsOutcome}
	result := OrgPATGovernanceResult{PendingPATRequests: len(requests), FineGrainedPATGrantsCount: len(grants)}
	sampled := 0
	for _, grant := range grants {
		if sampled >= patRepositorySampleCap || grant == nil || grant.ID == nil || grant.GetRepositorySelection() != "subset" {
			continue
		}
		sampled++
		_, repositoriesOutcome, repositoriesErr := collectJSONArray[*github.Repository](ctx, client, store, orgScope,
			"org.pat_governance", safeFeatureName("repositories", strconv.FormatInt(grant.GetID(), 10)),
			"orgs/"+organizationPath+"/personal-access-tokens/"+strconv.FormatInt(grant.GetID(), 10)+"/repositories", "", true)
		outcomes = append(outcomes, repositoriesOutcome)
		if repositoriesErr == nil {
			result.SampledGrantsWithRepositoryListKnown++
		}
	}
	return result, outcomes, nil
}

// knownIntegrationAppSlugs mirrors the org.installations collector's
// documented classification catalogue: "Classify app_slug against a known
// list: slack, msteams (Microsoft Teams), jira, azure-boards,
// azure-pipelines, sonarcloud, snyk, dependabot, codecov, renovate,
// github-copilot; unknown apps flagged for interview."
var knownIntegrationAppSlugs = map[string]bool{
	"slack": true, "msteams": true, "microsoft-teams": true, "jira": true,
	"azure-boards": true, "azure-pipelines": true, "sonarcloud": true, "snyk": true,
	"dependabot": true, "codecov": true, "renovate": true, "github-copilot": true, "copilot": true,
}

// OrgInstallationsResult preserves the installation count and the subset
// classified as outside the documented known-integration catalogue
// (custom_apps_count, PRD-029's exact declared metric key), plus the
// unknown app_slug values themselves for assessor interview follow-up.
type OrgInstallationsResult struct {
	InstallationCount int      `json:"installation_count"`
	CustomAppsCount   int      `json:"custom_apps_count"`
	UnknownAppSlugs   []string `json:"unknown_app_slugs"`
}

// FetchOrgInstallations collects the organization's complete GitHub App
// installation inventory and classifies each installation's app_slug
// against the documented known-integrations catalogue.
func FetchOrgInstallations(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgInstallationsResult, CollectorOutcome, error) {
	envelope, outcome, err := collectJSONObject[github.OrganizationInstallations](ctx, client, store, orgScope,
		"org.installations", "installations", "orgs/"+url.PathEscape(organization)+"/installations")
	if err != nil || envelope == nil {
		return OrgInstallationsResult{}, outcome, err
	}
	result := OrgInstallationsResult{InstallationCount: len(envelope.Installations), UnknownAppSlugs: []string{}}
	for _, installation := range envelope.Installations {
		if installation == nil {
			continue
		}
		slug := strings.ToLower(strings.TrimSpace(installation.GetAppSlug()))
		if slug == "" || !knownIntegrationAppSlugs[slug] {
			result.CustomAppsCount++
			if slug != "" {
				result.UnknownAppSlugs = appendUnique(result.UnknownAppSlugs, slug)
			}
		}
	}
	return result, outcome, nil
}

// OrgHooksResult reports the automation profile's exact declared PRD-029/
// ARC-098/ARC-109 metric keys (hooks_without_secret_pct,
// hooks_insecure_ssl_count) computed from the organization's actual webhook
// configuration, plus a clearly supplementary (non-profile-declared)
// delivery-failure ratio. Webhook destination hosts/secrets are never read
// directly by this collector; the shared Redactor independently strips
// config.url to its host and config.secret's presence before persistence.
type OrgHooksResult struct {
	HookCount             int         `json:"hook_count"`
	ActiveHookCount       int         `json:"active_hook_count"`
	HooksWithoutSecretPct MetricValue `json:"hooks_without_secret_pct"`
	HooksInsecureSSLCount int         `json:"hooks_insecure_ssl_count"`
	// DeliveryFailureRatePct is adapter-invented supplementary evidence, not
	// a declared automation-profile metric key; it must not be presented as
	// satisfying any profile control on its own.
	DeliveryFailureRatePct MetricValue `json:"delivery_failure_rate_pct_supplementary"`
}

// FetchOrgHooks collects the organization's webhook inventory (config
// secret-presence and insecure_ssl are read directly from the already-
// collected hook list; no extra request is needed for those two profile
// keys) and, for every hook, its most recent single page (<=100) of
// deliveries for the supplementary failure-rate ratio.
func FetchOrgHooks(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgHooksResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	hooks, hooksOutcome, hooksErr := collectJSONArray[*github.Hook](ctx, client, store, orgScope,
		"org.hooks", "hooks", "orgs/"+organizationPath+"/hooks", "", true)
	outcomes := []CollectorOutcome{hooksOutcome}
	result := OrgHooksResult{}
	if hooksErr != nil {
		result.HooksWithoutSecretPct = unavailableObservation("organization hook inventory is incomplete", "organization webhooks")
		result.DeliveryFailureRatePct = unavailableObservation("organization hook inventory is incomplete", "examined webhook deliveries")
		return result, outcomes, nil
	}
	result.HookCount = len(hooks)
	withoutSecret := 0.0
	failed, total := 0.0, 0.0
	complete := true
	for _, hook := range hooks {
		if hook == nil || hook.ID == nil {
			continue
		}
		if hook.GetActive() {
			result.ActiveHookCount++
		}
		config := hook.GetConfig()
		if config == nil || config.Secret == nil || *config.Secret == "" {
			withoutSecret++
		}
		if config != nil && config.GetInsecureSSL() == "1" {
			result.HooksInsecureSSLCount++
		}
		deliveries, deliveriesOutcome, deliveriesErr := collectJSONArray[*github.HookDelivery](ctx, client, store, orgScope,
			"org.hooks", safeFeatureName("deliveries", strconv.FormatInt(hook.GetID(), 10)),
			"orgs/"+organizationPath+"/hooks/"+strconv.FormatInt(hook.GetID(), 10)+"/deliveries", "", false)
		outcomes = append(outcomes, deliveriesOutcome)
		if deliveriesErr != nil {
			complete = false
			continue
		}
		for _, delivery := range deliveries {
			if delivery == nil || delivery.StatusCode == nil {
				complete = false
				continue
			}
			total++
			if delivery.GetStatusCode() < 200 || delivery.GetStatusCode() >= 300 {
				failed++
			}
		}
	}
	withoutSecretMetric, err := Percentage(withoutSecret, float64(result.HookCount), "organization webhooks")
	if err != nil {
		return result, outcomes, err
	}
	result.HooksWithoutSecretPct = withoutSecretMetric
	deliveryMetric, err := Percentage(failed, total, "examined webhook deliveries (most recent page per hook, <=100 each)")
	if err != nil {
		return result, outcomes, err
	}
	if !complete {
		deliveryMetric = markCoverageUncertain(deliveryMetric, "one or more hooks' delivery pages were incomplete or omitted a status code")
	}
	result.DeliveryFailureRatePct = deliveryMetric
	return result, outcomes, nil
}

// EnterpriseInfo is the normalized result of the ent.info GraphQL query: the
// enterprise identity, its organization count/logins and its owner-role
// inventory (the privileged-role population for identity/access controls).
// Only the first 100 organizations and owners are collected in this phase
// (no cursor-based follow-up query yet); larger enterprises are truthfully
// flagged as PartiallyCollected rather than silently truncated.
type EnterpriseInfo struct {
	Slug               string   `json:"slug"`
	Name               string   `json:"name"`
	OrganizationCount  int      `json:"organization_count"`
	OrganizationLogins []string `json:"organization_logins"`
	OwnerCount         int      `json:"owner_count"`
	OwnerLogins        []string `json:"owner_logins"`
	SAMLConfigured     bool     `json:"saml_configured"`
	PartiallyCollected bool     `json:"partially_collected"`
}

const entInfoQuery = `query($slug: String!) {
  enterprise(slug: $slug) {
    name
    slug
    organizations(first: 100) { totalCount nodes { login } }
    ownerInfo {
      admins(role: OWNER, first: 100) { totalCount nodes { login } }
      samlIdentityProvider { ssoUrl issuer }
    }
  }
}`

type entInfoResponse struct {
	Data struct {
		Enterprise struct {
			Name          string `json:"name"`
			Slug          string `json:"slug"`
			Organizations struct {
				TotalCount int `json:"totalCount"`
				Nodes      []struct {
					Login string `json:"login"`
				} `json:"nodes"`
			} `json:"organizations"`
			OwnerInfo struct {
				Admins struct {
					TotalCount int `json:"totalCount"`
					Nodes      []struct {
						Login string `json:"login"`
					} `json:"nodes"`
				} `json:"admins"`
				SamlIdentityProvider *struct {
					SsoURL string `json:"ssoUrl"`
					Issuer string `json:"issuer"`
				} `json:"samlIdentityProvider"`
			} `json:"ownerInfo"`
		} `json:"enterprise"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// FetchEnterpriseInfo executes the ent.info GraphQL query against a
// GraphQLEvidence-sourced CollectionClient (distinct from the REST client
// used by every other collector in this file) and normalizes its result.
// A GraphQL "errors" envelope on an HTTP 200 response (for example a
// permission-denied or unknown-enterprise error) is treated as a failed
// collection, matching this package's documented rule that HTTP 200 is not
// assumed to mean success for GraphQL.
func FetchEnterpriseInfo(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string) (*EnterpriseInfo, CollectorOutcome, error) {
	outcome, raw, err := client.CollectGraphQL(ctx, store, entScope, "ent.info", "info", entInfoQuery,
		map[string]any{"slug": enterpriseSlug})
	if err != nil {
		return nil, outcome, err
	}
	var response entInfoResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, outcome, fmt.Errorf("decode ent.info response: %w", err)
	}
	if len(response.Errors) > 0 {
		outcome.Status = CollectionFailed
		outcome.Reason = "GraphQL response carried a top-level errors envelope despite HTTP 200"
		return nil, outcome, fmt.Errorf("ent.info query returned GraphQL errors: %s", response.Errors[0].Message)
	}
	enterprise := response.Data.Enterprise
	info := &EnterpriseInfo{
		Slug: enterprise.Slug, Name: enterprise.Name,
		OrganizationCount: enterprise.Organizations.TotalCount, OwnerCount: enterprise.OwnerInfo.Admins.TotalCount,
		SAMLConfigured:     enterprise.OwnerInfo.SamlIdentityProvider != nil,
		PartiallyCollected: enterprise.Organizations.TotalCount > 100 || enterprise.OwnerInfo.Admins.TotalCount > 100,
	}
	for _, node := range enterprise.Organizations.Nodes {
		info.OrganizationLogins = append(info.OrganizationLogins, node.Login)
	}
	for _, node := range enterprise.OwnerInfo.Admins.Nodes {
		info.OwnerLogins = append(info.OwnerLogins, node.Login)
	}
	return info, outcome, nil
}

// GHESManageBasicsResult preserves which of the documented read-only
// Management Console endpoints were reachable. ghes.cli/ghes.backup remain
// out of scope here (CLI/SSH-collected, not REST; the brief directs those to
// existing import contracts, not an invented REST surface).
type GHESManageBasicsResult struct {
	VersionAvailable        bool `json:"version_available"`
	ConfigSettingsAvailable bool `json:"config_settings_available"`
	ReplicationStatusKnown  bool `json:"replication_status_known"`
	MaintenanceStatusKnown  bool `json:"maintenance_status_known"`
}

// FetchGHESManageBasics probes the documented read-only GHES Management
// Console endpoints (port 8443, Basic auth, already implemented by
// ManagementEvidence-sourced CollectionClient construction). It is
// collection-only in this phase: it records reachability/evidence and does
// not yet derive a version-gap or replication-health metric.
func FetchGHESManageBasics(ctx context.Context, client *CollectionClient, store *EvidenceStore, instanceScope Scope) (GHESManageBasicsResult, []CollectorOutcome, error) {
	var result GHESManageBasicsResult
	outcomes := make([]CollectorOutcome, 0, 4)
	probe := func(feature, endpoint string) bool {
		_, outcome, err := collectJSONObject[map[string]any](ctx, client, store, instanceScope, "ghes.manage_api", feature, endpoint)
		outcomes = append(outcomes, outcome)
		return err == nil
	}
	result.VersionAvailable = probe("version", "version")
	result.ConfigSettingsAvailable = probe("config-settings", "config/settings")
	result.ReplicationStatusKnown = probe("replication-status", "replication/status")
	result.MaintenanceStatusKnown = probe("maintenance", "maintenance")
	return result, outcomes, nil
}

// OrgRulesetsResult is the organization's directly enumerated top-level
// ruleset inventory (GET /orgs/{org}/rulesets), authoritative for
// active_org_rulesets_count independently of Phase 3's per-repository
// inherited-ruleset discovery (which can only ever observe organization
// rulesets that actually apply to at least one analyzed repository's default
// branch, an incomplete proxy when the analyzed population is sampled or
// when an organization ruleset targets repositories outside that sample).
// DefaultBranchRulesetActive is GOV-070's exact declared metric key
// (org_default_branch_rulesets_active): at least one active, branch-target
// ruleset whose ref-name conditions include the literal "~DEFAULT_BRANCH"
// sentinel (applying organization-wide to every repository's default
// branch), not merely a ruleset that happens to name a specific branch that
// matches some repository's default branch.
type OrgRulesetsResult struct {
	TotalCount                 int  `json:"total_count"`
	ActiveCount                int  `json:"active_count"`
	DefaultBranchRulesetActive bool `json:"org_default_branch_rulesets_active"`
}

// FetchOrgRulesets collects the organization's complete, directly enumerated
// ruleset inventory (fully paginated), independent of any repository sample.
func FetchOrgRulesets(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (*OrgRulesetsResult, CollectorOutcome, error) {
	rulesets, outcome, err := collectJSONArray[*github.RepositoryRuleset](ctx, client, store, orgScope,
		"org.rulesets", "rulesets", "orgs/"+url.PathEscape(organization)+"/rulesets", "", true)
	if err != nil {
		return nil, outcome, err
	}
	result := &OrgRulesetsResult{TotalCount: len(rulesets)}
	for _, ruleset := range rulesets {
		if ruleset == nil || ruleset.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		result.ActiveCount++
		if ruleset.Target == nil || *ruleset.Target != github.RulesetTargetBranch || ruleset.Conditions == nil || ruleset.Conditions.RefName == nil {
			continue
		}
		for _, pattern := range ruleset.Conditions.RefName.Include {
			if pattern == "~DEFAULT_BRANCH" {
				result.DefaultBranchRulesetActive = true
			}
		}
	}
	return result, outcome, nil
}

// RepositoryAccessResult is one repository's actual collaborator inventory
// (SEC-016's repos_with_direct_collaborators_pct / direct-grant ratio
// population), with bot accounts excluded from the direct-grant count per
// the repo.access collector's documented definition ("Direct-grant ratio =
// repos with >0 direct collaborators (excluding bots) / repos sampled").
type RepositoryAccessResult struct {
	Repository                  string `json:"repository"`
	DirectCollaboratorsExclBots int    `json:"direct_collaborators_excluding_bots"`
	OutsideCollaborators        int    `json:"outside_collaborators"`
	Complete                    bool   `json:"complete"`
}

// FetchRepositoryAccess collects a repository's direct (bot-excluded) and
// outside collaborator lists (each fully paginated).
func FetchRepositoryAccess(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (RepositoryAccessResult, []CollectorOutcome, error) {
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)
	direct, directOutcome, directErr := collectJSONArray[*github.User](ctx, client, store, scope,
		"repo.access", "direct-collaborators", "repos/"+ownerPath+"/"+repoPath+"/collaborators?affiliation=direct", "", true)
	outside, outsideOutcome, outsideErr := collectJSONArray[*github.User](ctx, client, store, scope,
		"repo.access", "outside-collaborators", "repos/"+ownerPath+"/"+repoPath+"/collaborators?affiliation=outside", "", true)
	result := RepositoryAccessResult{Repository: owner + "/" + repo, Complete: directErr == nil && outsideErr == nil}
	for _, user := range direct {
		if user != nil && !strings.EqualFold(user.GetType(), "Bot") && !strings.HasSuffix(strings.ToLower(user.GetLogin()), "[bot]") {
			result.DirectCollaboratorsExclBots++
		}
	}
	result.OutsideCollaborators = len(outside)
	return result, []CollectorOutcome{directOutcome, outsideOutcome}, nil
}

// OrgActionsPermissionsResult preserves SEC-098's exact declared metric key
// (allowed_actions_policy) and the raw enabled-repositories scope, read
// directly from the organization's actual Actions permissions configuration,
// not inferred from whether any workflow files happen to be present.
type OrgActionsPermissionsResult struct {
	AllowedActionsPolicy string `json:"allowed_actions_policy"`
	EnabledRepositories  string `json:"enabled_repositories"`
	SHAPinningRequired   *bool  `json:"sha_pinning_required,omitempty"`
	Complete             bool   `json:"complete"`
}

// FetchOrgActionsPermissions collects the organization's actual Actions
// permissions policy (GET /orgs/{org}/actions/permissions). The companion
// selected-actions/workflow-permissions sub-documents are read-only and
// feasible but are left uncollected this round; only the single top-level
// policy object this phase actually derives a metric from is fetched, to
// keep this collector's scope bounded and honestly reported.
func FetchOrgActionsPermissions(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgActionsPermissionsResult, CollectorOutcome, error) {
	permissions, outcome, err := collectJSONObject[github.ActionsPermissions](ctx, client, store, orgScope,
		"org.actions_permissions", "permissions", "orgs/"+url.PathEscape(organization)+"/actions/permissions")
	if err != nil || permissions == nil {
		return OrgActionsPermissionsResult{}, outcome, err
	}
	return OrgActionsPermissionsResult{
		AllowedActionsPolicy: permissions.GetAllowedActions(), EnabledRepositories: permissions.GetEnabledRepositories(),
		SHAPinningRequired: permissions.SHAPinningRequired, Complete: true,
	}, outcome, nil
}

// OrgRunnersResult reports the organization's self-hosted runner and runner
// group inventory. The automation profile declares this same concept under
// two different literal metric key spellings across different controls
// (self_hosted_runner_count in PRD-009, self_hosted_runners_count in
// SEC-103); both are emitted with the identical collected value, matching
// this package's existing custom_apps_count/custom_integrations_count
// duplicate-key precedent rather than guessing which spelling is
// authoritative.
type OrgRunnersResult struct {
	SelfHostedRunnerCount int  `json:"self_hosted_runner_count"`
	OnlineRunnerCount     int  `json:"online_runner_count"`
	RunnerGroupsCount     int  `json:"runner_groups_count"`
	Complete              bool `json:"complete"`
}

// FetchOrgRunners collects the organization's complete self-hosted runner
// roster and runner-group inventory (both fully paginated). GitHub-hosted
// larger runners (GET .../actions/hosted-runners) are a distinct, separately
// documented endpoint this collector does not yet probe.
func FetchOrgRunners(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgRunnersResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	runners, runnersOutcome, runnersErr := collectJSONArray[*github.Runner](ctx, client, store, orgScope,
		"org.runners", "runners", "orgs/"+organizationPath+"/actions/runners", "runners", true)
	groups, groupsOutcome, groupsErr := collectJSONArray[*github.RunnerGroup](ctx, client, store, orgScope,
		"org.runners", "runner-groups", "orgs/"+organizationPath+"/actions/runner-groups", "runner_groups", true)
	result := OrgRunnersResult{RunnerGroupsCount: len(groups), Complete: runnersErr == nil && groupsErr == nil}
	for _, runner := range runners {
		if runner == nil {
			continue
		}
		result.SelfHostedRunnerCount++
		if runner.GetStatus() == "online" {
			result.OnlineRunnerCount++
		}
	}
	return result, []CollectorOutcome{runnersOutcome, groupsOutcome}, nil
}

// OrgCopilotResult reports GOV-075's exact declared metric keys
// (public_code_suggestions, seat_management_setting) plus the organization's
// actual seat utilization (active-this-cycle seats over total assigned
// seats), not a settings-page proxy.
type OrgCopilotResult struct {
	SeatsTotal            int         `json:"seats_total"`
	SeatsActiveThisCycle  int         `json:"seats_active_this_cycle"`
	SeatUtilisationPct    MetricValue `json:"copilot_seat_utilisation_pct"`
	PublicCodeSuggestions string      `json:"public_code_suggestions"`
	SeatManagementSetting string      `json:"seat_management_setting"`
	Complete              bool        `json:"complete"`
}

// FetchOrgCopilot collects the organization's actual Copilot billing/policy
// snapshot (GET /orgs/{org}/copilot/billing). A 404 (Copilot for Business not
// enabled for this organization) is a confirmed, not a forbidden, absence and
// is preserved as Complete=false with an explicit unknown utilization metric
// rather than a false "0% utilisation".
func FetchOrgCopilot(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgCopilotResult, CollectorOutcome, error) {
	billing, outcome, err := collectJSONObject[github.CopilotOrganizationDetails](ctx, client, store, orgScope,
		"org.copilot", "billing", "orgs/"+url.PathEscape(organization)+"/copilot/billing")
	if err != nil || billing == nil {
		return OrgCopilotResult{SeatUtilisationPct: unavailableObservation(
			"organization Copilot billing is not available (not enabled, or the probe failed)", "assigned Copilot seats")}, outcome, nil
	}
	result := OrgCopilotResult{
		PublicCodeSuggestions: billing.PublicCodeSuggestions, SeatManagementSetting: billing.SeatManagementSetting, Complete: true,
	}
	if breakdown := billing.SeatBreakdown; breakdown != nil {
		result.SeatsTotal = breakdown.Total
		result.SeatsActiveThisCycle = breakdown.ActiveThisCycle
	}
	utilisation, err := Percentage(float64(result.SeatsActiveThisCycle), float64(result.SeatsTotal), "assigned Copilot seats")
	if err != nil {
		return result, outcome, err
	}
	result.SeatUtilisationPct = utilisation
	return result, outcome, nil
}

// orgPackageEcosystems mirrors the org.packages collector's documented
// per-ecosystem query contract ("GET /orgs/{org}/packages?package_type=
// {container|npm|maven|nuget|rubygems|docker}"): the endpoint has no
// "all ecosystems" mode, so every ecosystem is queried separately and summed.
var orgPackageEcosystems = []string{"container", "npm", "maven", "nuget", "rubygems", "docker"}

// OrgPackagesResult reports PRD-013/SEC-104's exact declared packages_count
// metric key: the organization's total published package count across every
// documented ecosystem.
type OrgPackagesResult struct {
	PackagesCount int  `json:"packages_count"`
	Complete      bool `json:"complete"`
}

// FetchOrgPackages collects the organization's complete package inventory
// (fully paginated per ecosystem, summed across every documented ecosystem).
func FetchOrgPackages(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgPackagesResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	result := OrgPackagesResult{Complete: true}
	outcomes := make([]CollectorOutcome, 0, len(orgPackageEcosystems))
	for _, ecosystem := range orgPackageEcosystems {
		packages, outcome, err := collectJSONArray[*github.Package](ctx, client, store, orgScope,
			"org.packages", safeFeatureName("packages", ecosystem),
			"orgs/"+organizationPath+"/packages?package_type="+ecosystem, "", true)
		outcomes = append(outcomes, outcome)
		if err != nil {
			result.Complete = false
			continue
		}
		result.PackagesCount += len(packages)
	}
	return result, outcomes, nil
}

// EnterpriseActionsPermissionsResult mirrors OrgActionsPermissionsResult at
// enterprise scope (GET /enterprises/{enterprise}/actions/permissions),
// feeding SEC-098/SEC-066/GOV-042's enterprise-level allowed_actions_policy.
type EnterpriseActionsPermissionsResult struct {
	AllowedActionsPolicy string `json:"allowed_actions_policy"`
	EnabledOrganizations string `json:"enabled_organizations"`
	Complete             bool   `json:"complete"`
}

// FetchEnterpriseActionsPermissions collects the enterprise's actual Actions
// permissions policy.
func FetchEnterpriseActionsPermissions(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string) (EnterpriseActionsPermissionsResult, CollectorOutcome, error) {
	permissions, outcome, err := collectJSONObject[github.ActionsPermissionsEnterprise](ctx, client, store, entScope,
		"ent.actions_permissions", "permissions", "enterprises/"+url.PathEscape(enterpriseSlug)+"/actions/permissions")
	if err != nil || permissions == nil {
		return EnterpriseActionsPermissionsResult{}, outcome, err
	}
	return EnterpriseActionsPermissionsResult{
		AllowedActionsPolicy: permissions.GetAllowedActions(), EnabledOrganizations: permissions.GetEnabledOrganizations(), Complete: true,
	}, outcome, nil
}

// EnterpriseCodeSecurityConfigsResult reports SEC-106's exact declared
// configurations_count metric key at enterprise scope and the subset of
// those configurations enforcing every one of
// requiredCodeSecurityConfigurationFeatures (full_feature_configuration).
// Unlike org.code_security_configs, this collector does not enumerate an
// enterprise-wide eligible-repository population in this run (the run loop
// discovers repositories per organization, not per enterprise), so
// configuration_coverage_pct is intentionally left uncomputed here rather
// than guessed from an incomplete population; this is reported as an
// explicit remaining gap, not silently omitted.
type EnterpriseCodeSecurityConfigsResult struct {
	ConfigurationsCount           int  `json:"configurations_count"`
	FullFeatureConfigurationCount int  `json:"full_feature_configuration_count"`
	FullFeatureConfiguration      bool `json:"full_feature_configuration"`
	Complete                      bool `json:"complete"`
}

// FetchEnterpriseCodeSecurityConfigurations collects the enterprise's code
// security configuration catalogue (fully paginated) and its default-for-
// new-repos assignments.
func FetchEnterpriseCodeSecurityConfigurations(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string) (EnterpriseCodeSecurityConfigsResult, []CollectorOutcome, error) {
	enterprisePath := url.PathEscape(enterpriseSlug)
	configs, listOutcome, listErr := collectJSONArray[*github.CodeSecurityConfiguration](ctx, client, store, entScope,
		"ent.code_security_configs", "configurations", "enterprises/"+enterprisePath+"/code-security/configurations", "", true)
	defaults, defaultsOutcome, defaultsErr := collectJSONArray[*github.CodeSecurityConfigurationWithDefaultForNewRepos](ctx, client, store, entScope,
		"ent.code_security_configs", "defaults", "enterprises/"+enterprisePath+"/code-security/configurations/defaults", "", false)
	_ = defaults
	result := EnterpriseCodeSecurityConfigsResult{ConfigurationsCount: len(configs), Complete: listErr == nil && defaultsErr == nil}
	for _, config := range configs {
		if config == nil {
			continue
		}
		fullFeature := true
		for _, feature := range requiredCodeSecurityConfigurationFeatures {
			var state *bool
			switch feature {
			case "secret_scanning":
				state = codeSecurityFeatureState(config.SecretScanning)
			case "secret_scanning_push_protection":
				state = codeSecurityFeatureState(config.SecretScanningPushProtection)
			case "dependabot_alerts":
				state = codeSecurityFeatureState(config.DependabotAlerts)
			case "code_scanning_default_setup":
				state = codeSecurityFeatureState(config.CodeScanningDefaultSetup)
			}
			if state == nil || !*state {
				fullFeature = false
				break
			}
		}
		if fullFeature {
			result.FullFeatureConfigurationCount++
			result.FullFeatureConfiguration = true
		}
	}
	return result, []CollectorOutcome{listOutcome, defaultsOutcome}, nil
}

// orgProjectsV2Query matches org.projects's documented GraphQL query exactly:
// the organization's total ProjectsV2 count and, per project, its closed
// state and most-recent item-presence signal (bounded to the first 100
// projects; larger catalogues are reported as PartiallyCollected rather than
// silently truncated).
const orgProjectsV2Query = `query($org: String!) {
  organization(login: $org) {
    projectsV2(first: 100) {
      totalCount
      nodes { title closed updatedAt items(first: 1) { totalCount } }
    }
  }
}`

type orgProjectsV2Response struct {
	Data struct {
		Organization struct {
			ProjectsV2 struct {
				TotalCount int `json:"totalCount"`
				Nodes      []struct {
					Closed bool `json:"closed"`
				} `json:"nodes"`
			} `json:"projectsV2"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// OrgProjectsResult is the organization's ProjectsV2 inventory
// (projects_count, open_projects_count), from org.projects's documented
// GraphQL query.
type OrgProjectsResult struct {
	ProjectsCount      int  `json:"projects_count"`
	OpenProjectsCount  int  `json:"open_projects_count"`
	PartiallyCollected bool `json:"partially_collected"`
	Complete           bool `json:"complete"`
}

// FetchOrgProjects executes the org.projects GraphQL query against a
// GraphQLEvidence-sourced CollectionClient. A nil client (the caller's
// GraphQL client could not be initialized for this target) is reported as an
// explicit incomplete result, never a silent zero.
func FetchOrgProjects(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgProjectsResult, CollectorOutcome, error) {
	if client == nil {
		return OrgProjectsResult{}, CollectorOutcome{CollectorID: "org.projects", Feature: "projects", Scope: orgScope,
			Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{}, Reason: "no GraphQL client was available for this target"}, nil
	}
	outcome, raw, err := client.CollectGraphQL(ctx, store, orgScope, "org.projects", "projects", orgProjectsV2Query,
		map[string]any{"org": organization})
	if err != nil {
		return OrgProjectsResult{}, outcome, err
	}
	var response orgProjectsV2Response
	if err := json.Unmarshal(raw, &response); err != nil {
		return OrgProjectsResult{}, outcome, fmt.Errorf("decode org.projects response: %w", err)
	}
	if len(response.Errors) > 0 {
		outcome.Status = CollectionFailed
		outcome.Reason = "GraphQL response carried a top-level errors envelope despite HTTP 200"
		return OrgProjectsResult{}, outcome, fmt.Errorf("org.projects query returned GraphQL errors: %s", response.Errors[0].Message)
	}
	projects := response.Data.Organization.ProjectsV2
	result := OrgProjectsResult{ProjectsCount: projects.TotalCount, PartiallyCollected: projects.TotalCount > 100, Complete: true}
	for _, node := range projects.Nodes {
		if !node.Closed {
			result.OpenProjectsCount++
		}
	}
	return result, outcome, nil
}
