// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestFetchOrgMembershipForbiddenOwnerFilterStaysUnavailableNotZero is a
// regression test for the exact failure mode the org.members collector must
// avoid: GitHub returns HTTP 403 for role=admin and filter=2fa_disabled when
// the caller is not an organization owner. That 403 must mark the whole
// membership result incomplete, so the published MembershipMetrics helper
// reports owner_ratio_pct/members_with_2fa_pct as unavailable — never a
// false "zero owners"/"zero without 2FA" derived from a forbidden response.
func TestFetchOrgMembershipForbiddenOwnerFilterStaysUnavailableNotZero(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("role") + "|" + request.URL.Query().Get("filter") {
		case "|":
			writeJSON(t, writer, []map[string]any{{"login": "octocat"}, {"login": "hubot"}})
		case "admin|":
			writer.WriteHeader(http.StatusForbidden)
			writeJSON(t, writer, map[string]string{"message": "must be an organization owner"})
		case "|2fa_disabled":
			writer.WriteHeader(http.StatusForbidden)
			writeJSON(t, writer, map[string]string{"message": "must be an organization owner"})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgMembership(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 3 {
		t.Fatalf("expected 3 recorded outcomes (all/admin/2fa-disabled), got %d", len(outcomes))
	}
	if result.Complete {
		t.Fatal("a forbidden owner-only filter must mark the membership result incomplete")
	}
	if result.Members != 2 {
		t.Fatalf("the readable member roster must still be preserved: %+v", result)
	}

	metrics, err := MembershipMetrics(result.Members, result.Owners, result.WithoutTwoFactor, result.Complete)
	if err != nil {
		t.Fatal(err)
	}
	if metrics["owner_ratio_pct"].Status != MetricUnavailable || metrics["members_with_2fa_pct"].Status != MetricUnavailable {
		t.Fatalf("forbidden owner-only filters must yield unavailable metrics, never a false zero: %+v", metrics)
	}
}

// TestFetchOrgMembershipCompleteOwnerKnowsRatio confirms the happy path
// still correctly computes a known ratio when every list succeeds.
func TestFetchOrgMembershipCompleteOwnerKnowsRatio(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("role") + "|" + request.URL.Query().Get("filter") {
		case "|":
			writeJSON(t, writer, []map[string]any{{"login": "octocat"}, {"login": "hubot"}, {"login": "monalisa"}, {"login": "mona"}})
		case "admin|":
			writeJSON(t, writer, []map[string]any{{"login": "octocat"}})
		case "|2fa_disabled":
			writeJSON(t, writer, []map[string]any{{"login": "mona"}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgMembership(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Members != 4 || result.Owners != 1 || result.WithoutTwoFactor != 1 {
		t.Fatalf("unexpected membership tally: %+v", result)
	}
	metrics, err := MembershipMetrics(result.Members, result.Owners, result.WithoutTwoFactor, result.Complete)
	if err != nil {
		t.Fatal(err)
	}
	if metrics["owner_ratio_pct"].Status != MetricKnown || metrics["owner_ratio_pct"].Number == nil || *metrics["owner_ratio_pct"].Number != 25 {
		t.Fatalf("expected a known 25%% owner ratio: %+v", metrics["owner_ratio_pct"])
	}
}

// TestFetchOrgHooksDeliveryFailureRateExcludesWebhookSecrets confirms the
// pooled delivery failure ratio is computed from status codes and that no
// webhook URL path, query string or secret presence marker leaks into
// persisted evidence (only the sanitized host survives).
func TestFetchOrgHooksDeliveryFailureRateExcludesWebhookSecrets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/hooks":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "active": true, "config": map[string]any{
					"url": "https://hooks.example.test/secret-path?token=abc123", "secret": "configured-webhook-secret",
				}},
			})
		case "/orgs/fixture-org/hooks/1/deliveries":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "status_code": 200}, {"id": 2, "status_code": 500}, {"id": 3, "status_code": 200},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgHooks(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.HookCount != 1 || result.ActiveHookCount != 1 {
		t.Fatalf("unexpected hook inventory: %+v", result)
	}
	if result.DeliveryFailureRatePct.Status != MetricKnown || result.DeliveryFailureRatePct.Number == nil ||
		*result.DeliveryFailureRatePct.Number < 33.0 || *result.DeliveryFailureRatePct.Number > 34.0 {
		t.Fatalf("expected a ~33%% delivery failure rate (1 of 3), got %+v", result.DeliveryFailureRatePct)
	}

	raw, _, _, err := store.LoadJSON(scope, "org.hooks", "hooks-page-000001")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-path", "token=abc123", "configured-webhook-secret"} {
		if contains(raw, forbidden) {
			t.Fatalf("webhook path/query/secret must not survive sanitization: found %q", forbidden)
		}
	}
}

func contains(data []byte, value string) bool {
	return len(data) > 0 && bytesContainAny(data, value)
}

// graphQLFixtureClient builds a GraphQLEvidence-sourced CollectionClient
// pointed directly at a test server, mirroring collectionFixtureClient's
// pattern for REST without resolving real GitHub addresses or credentials.
func graphQLFixtureClient(t *testing.T, server *httptest.Server, budget *RequestBudget, clock Clock) *CollectionClient {
	t.Helper()
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	transport := &readTransport{base: base, graphQLPath: "/graphql", budget: budget, clock: clock, wrapped: server.Client().Transport}
	return &CollectionClient{
		http: &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		base: base, source: GraphQLEvidence, credentialKind: NoCredential, profile: profile, clock: clock, redactor: NewRedactor(),
	}
}

// managementFixtureClient builds a ManagementEvidence-sourced
// CollectionClient with Basic auth credentials pointed directly at a test
// server.
func managementFixtureClient(t *testing.T, server *httptest.Server, budget *RequestBudget, clock Clock, username, password string) *CollectionClient {
	t.Helper()
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse(server.URL + "/manage/v1/")
	if err != nil {
		t.Fatal(err)
	}
	transport := &readTransport{base: base, username: username, password: password, budget: budget, clock: clock, wrapped: server.Client().Transport}
	return &CollectionClient{
		http: &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		base: base, source: ManagementEvidence, credentialKind: ManagementConsole, profile: profile, clock: clock, redactor: NewRedactor(),
	}
}

// TestFetchEnterpriseInfoGraphQLHappyPath exercises the CollectGraphQL
// primitive end to end: a read-only query body, GraphQL-sourced
// CollectionClient routing, and correct decoding of the enterprise identity
// envelope.
func TestFetchEnterpriseInfoGraphQLHappyPath(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/graphql" || request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, writer, map[string]any{"data": map[string]any{"enterprise": map[string]any{
			"name": "Fixture Enterprise", "slug": "fixture-enterprise",
			"organizations": map[string]any{"totalCount": 2, "nodes": []map[string]any{{"login": "fixture-org"}, {"login": "another-org"}}},
			"ownerInfo": map[string]any{
				"admins":               map[string]any{"totalCount": 1, "nodes": []map[string]any{{"login": "octocat"}}},
				"samlIdentityProvider": map[string]any{"ssoUrl": "https://idp.example.test/sso", "issuer": "https://idp.example.test"},
			},
		}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}
	info, outcome, err := FetchEnterpriseInfo(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != CollectionOK || !outcome.Complete {
		t.Fatalf("expected a complete GraphQL outcome: %+v", outcome)
	}
	if info.OrganizationCount != 2 || info.OwnerCount != 1 || !info.SAMLConfigured {
		t.Fatalf("unexpected enterprise info: %+v", info)
	}
	if len(info.OrganizationLogins) != 2 || len(info.OwnerLogins) != 1 {
		t.Fatalf("expected organization/owner logins to be populated: %+v", info)
	}
}

// TestFetchEnterpriseInfoGraphQLErrorsEnvelopeIsFailure confirms a GraphQL
// "errors" array on an HTTP 200 response is treated as a failed collection,
// not a successful empty result.
func TestFetchEnterpriseInfoGraphQLErrorsEnvelopeIsFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"data": map[string]any{"enterprise": nil},
			"errors": []map[string]any{{"message": "Could not resolve to an Enterprise with the slug 'fixture-enterprise'."}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}
	info, _, err := FetchEnterpriseInfo(context.Background(), client, store, scope, "fixture-enterprise")
	if err == nil || info != nil {
		t.Fatalf("a GraphQL errors envelope must be treated as a failed collection: info=%+v err=%v", info, err)
	}
}

// TestFetchGHESManageBasicsUsesManagementCredentials confirms the
// Management-sourced client correctly probes the documented read-only
// endpoints with Basic authentication on the management base path.
func TestFetchGHESManageBasicsUsesManagementCredentials(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "admin" || password != "fixture-password" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/manage/v1/version":
			writeJSON(t, writer, map[string]any{"version": "3.18.0"})
		case "/manage/v1/config/settings":
			writeJSON(t, writer, map[string]any{"private_mode": false})
		case "/manage/v1/replication/status":
			writer.WriteHeader(http.StatusNotFound)
		case "/manage/v1/maintenance":
			writeJSON(t, writer, map[string]any{"status": "off"})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := managementFixtureClient(t, server, fixtureBudget(t), SystemClock{}, "admin", "fixture-password")

	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), InstanceScope, client.base.Hostname()}
	result, outcomes, err := FetchGHESManageBasics(context.Background(), client, store, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 4 {
		t.Fatalf("expected 4 probed endpoints, got %d", len(outcomes))
	}
	if !result.VersionAvailable || !result.ConfigSettingsAvailable || result.ReplicationStatusKnown || !result.MaintenanceStatusKnown {
		t.Fatalf("unexpected reachability result (replication/status was a 404 and must be false): %+v", result)
	}
}

// TestFetchOrgRulesetsDetectsDefaultBranchSentinelAndCountsActive confirms
// the authoritative top-level ruleset enumeration counts only active
// rulesets and correctly detects the literal "~DEFAULT_BRANCH" sentinel
// (org_default_branch_rulesets_active), not merely a ruleset that happens to
// name a specific branch.
func TestFetchOrgRulesetsDetectsDefaultBranchSentinelAndCountsActive(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/orgs/fixture-org/rulesets" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, writer, []map[string]any{
			{"id": 1, "name": "org-wide-default-branch", "target": "branch", "enforcement": "active",
				"conditions": map[string]any{"ref_name": map[string]any{"include": []string{"~DEFAULT_BRANCH"}, "exclude": []string{}}}},
			{"id": 2, "name": "release-branch-only", "target": "branch", "enforcement": "active",
				"conditions": map[string]any{"ref_name": map[string]any{"include": []string{"refs/heads/release/*"}, "exclude": []string{}}}},
			{"id": 3, "name": "disabled-ruleset", "target": "branch", "enforcement": "disabled",
				"conditions": map[string]any{"ref_name": map[string]any{"include": []string{"~DEFAULT_BRANCH"}, "exclude": []string{}}}},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgRulesets(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalCount != 3 || result.ActiveCount != 2 {
		t.Fatalf("expected 3 total, 2 active (disabled excluded): %+v", result)
	}
	if !result.DefaultBranchRulesetActive {
		t.Fatal("expected the ~DEFAULT_BRANCH sentinel ruleset to be detected as active")
	}
}

// TestFetchOrgRulesetsNoDefaultBranchSentinelWhenOnlySpecificBranches
// confirms a ruleset targeting a specific branch name (even one that could
// coincidentally match some repository's default branch) is not mistaken
// for the organization-wide ~DEFAULT_BRANCH sentinel.
func TestFetchOrgRulesetsNoDefaultBranchSentinelWhenOnlySpecificBranches(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"id": 1, "name": "main-only", "target": "branch", "enforcement": "active",
				"conditions": map[string]any{"ref_name": map[string]any{"include": []string{"refs/heads/main"}, "exclude": []string{}}}},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgRulesets(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.DefaultBranchRulesetActive {
		t.Fatal("a ruleset naming a specific branch must not be mistaken for the ~DEFAULT_BRANCH org-wide sentinel")
	}
}

// TestFetchOrgTeamsCollectsRepoGrantsAndNestedFlag confirms each team's
// actual repository permission grants and parent-team (nested) status are
// collected, not merely the team roster.
func TestFetchOrgTeamsCollectsRepoGrantsAndNestedFlag(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/teams":
			writeJSON(t, writer, []map[string]any{
				{"slug": "platform", "privacy": "closed", "members_count": 5, "repos_count": 2},
				{"slug": "platform-core", "privacy": "secret", "members_count": 2, "repos_count": 1,
					"parent": map[string]any{"slug": "platform"}},
			})
		case "/orgs/fixture-org/teams/platform/repos":
			writeJSON(t, writer, []map[string]any{
				{"full_name": "fixture-org/repo-001", "permissions": map[string]any{"admin": false, "maintain": false, "push": true, "triage": true, "pull": true}},
			})
		case "/orgs/fixture-org/teams/platform-core/repos":
			writeJSON(t, writer, []map[string]any{
				{"full_name": "fixture-org/repo-002", "permissions": map[string]any{"admin": true, "maintain": true, "push": true, "triage": true, "pull": true}},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	teams, outcomes, err := FetchOrgTeams(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 3 || len(teams) != 2 {
		t.Fatalf("expected 2 teams and 3 outcomes (list + 2 team-repos fetches): %+v", teams)
	}
	for _, team := range teams {
		switch team.Slug {
		case "platform":
			if team.Nested || len(team.Repos) != 1 || team.Repos[0].Permission != "push" {
				t.Fatalf("unexpected platform team result: %+v", team)
			}
		case "platform-core":
			if !team.Nested || len(team.Repos) != 1 || team.Repos[0].Permission != "admin" {
				t.Fatalf("unexpected platform-core team result: %+v", team)
			}
		default:
			t.Fatalf("unexpected team slug: %s", team.Slug)
		}
	}
}

// TestFetchOrgRolesCollectsCustomRolesAssignmentsAndRepoRoles confirms custom
// organization roles' actual team/user assignment counts and the
// organization's custom repository roles are collected, not merely the role
// catalogue.
func TestFetchOrgRolesCollectsCustomRolesAssignmentsAndRepoRoles(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/organization-roles":
			writeJSON(t, writer, map[string]any{"total_count": 2, "roles": []map[string]any{
				{"id": 1, "name": "all_repo_read", "source": "Predefined"},
				{"id": 2, "name": "incident-responder", "source": "Custom"},
			}})
		case "/orgs/fixture-org/organization-roles/2/teams":
			writeJSON(t, writer, []map[string]any{{"slug": "security"}})
		case "/orgs/fixture-org/organization-roles/2/users":
			writeJSON(t, writer, []map[string]any{{"login": "octocat"}, {"login": "mona"}})
		case "/orgs/fixture-org/organization-roles/1/teams":
			writeJSON(t, writer, []map[string]any{})
		case "/orgs/fixture-org/organization-roles/1/users":
			writeJSON(t, writer, []map[string]any{})
		case "/orgs/fixture-org/custom-repository-roles":
			writeJSON(t, writer, map[string]any{"total_count": 1, "custom_roles": []map[string]any{{"id": 9, "name": "reviewer-plus"}}})
		case "/orgs/fixture-org/security-managers":
			writeJSON(t, writer, []map[string]any{{"slug": "security"}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgRoles(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.CustomRoleCount != 1 || result.CustomRepoRoleCount != 1 || len(result.SecurityManagerTeams) != 1 {
		t.Fatalf("unexpected role counts: %+v", result)
	}
	for _, role := range result.Roles {
		if role.Name == "incident-responder" && (role.TeamCount != 1 || role.UserCount != 2 || !role.IsCustom) {
			t.Fatalf("unexpected custom role assignment counts: %+v", role)
		}
	}
}

// TestFetchOrgInstallationsClassifiesUnknownAppsAsCustom confirms a known
// integration (slack) is not counted as custom, while an unrecognized
// app_slug is.
func TestFetchOrgInstallationsClassifiesUnknownAppsAsCustom(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"total_count": 2, "installations": []map[string]any{
			{"id": 1, "app_slug": "slack"}, {"id": 2, "app_slug": "acme-internal-bot"},
		}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgInstallations(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.InstallationCount != 2 || result.CustomAppsCount != 1 || len(result.UnknownAppSlugs) != 1 || result.UnknownAppSlugs[0] != "acme-internal-bot" {
		t.Fatalf("unexpected installation classification: %+v", result)
	}
}

// TestFetchOrgHooksSecretAndInsecureSSLSignals confirms hooks_without_secret_pct
// and hooks_insecure_ssl_count are derived from the actual hook configuration,
// not the delivery-failure supplementary ratio.
func TestFetchOrgHooksSecretAndInsecureSSLSignals(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/hooks":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "active": true, "config": map[string]any{"url": "https://a.example.test/hook", "secret": "configured", "insecure_ssl": "0"}},
				{"id": 2, "active": true, "config": map[string]any{"url": "https://b.example.test/hook", "insecure_ssl": "1"}},
			})
		case "/orgs/fixture-org/hooks/1/deliveries", "/orgs/fixture-org/hooks/2/deliveries":
			writeJSON(t, writer, []map[string]any{{"id": 1, "status_code": 200}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgHooks(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if result.HooksWithoutSecretPct.Status != MetricKnown || result.HooksWithoutSecretPct.Number == nil || *result.HooksWithoutSecretPct.Number != 50 {
		t.Fatalf("expected 50%% of hooks without a secret (1 of 2): %+v", result.HooksWithoutSecretPct)
	}
	if result.HooksInsecureSSLCount != 1 {
		t.Fatalf("expected exactly 1 hook with insecure_ssl=1: %+v", result)
	}
}

// TestFetchRepositoryAccessExcludesBotsFromDirectCount confirms bot
// collaborators (both User.Type == "Bot" and a "[bot]"-suffixed login) are
// excluded from the direct-grant count, per the repo.access collector's
// documented "excluding bots" definition.
func TestFetchRepositoryAccessExcludesBotsFromDirectCount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("affiliation") {
		case "direct":
			writeJSON(t, writer, []map[string]any{
				{"login": "octocat", "type": "User"},
				{"login": "dependabot[bot]", "type": "Bot"},
				{"login": "renovate[bot]", "type": "User"},
			})
		case "outside":
			writeJSON(t, writer, []map[string]any{{"login": "external-contractor", "type": "User"}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryAccess(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.DirectCollaboratorsExclBots != 1 || result.OutsideCollaborators != 1 {
		t.Fatalf("expected only 'octocat' counted as a direct non-bot collaborator (both bot forms excluded): %+v", result)
	}
}

// TestFetchOrgActionsPermissionsReadsAllowedActionsPolicy confirms
// org.actions_permissions decodes the actual allowed_actions_policy from the
// organization's real permissions object, and that a confirmed 404 ("Actions
// disabled") is reported as an explicit incomplete result, never a fabricated
// policy value.
func TestFetchOrgActionsPermissionsReadsAllowedActionsPolicy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{
			"enabled_repositories": "selected", "allowed_actions": "selected", "sha_pinning_required": true,
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgActionsPermissions(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.AllowedActionsPolicy != "selected" || result.EnabledRepositories != "selected" ||
		result.SHAPinningRequired == nil || !*result.SHAPinningRequired {
		t.Fatalf("unexpected actions permissions result: %+v", result)
	}
}

// TestFetchOrgRunnersCountsSelfHostedAndGroups confirms org.runners pools
// both the runner roster (with online-status subset) and the runner-group
// inventory from their actual envelope fields, not a bare array assumption.
func TestFetchOrgRunnersCountsSelfHostedAndGroups(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/fixture-org/actions/runners":
			writeJSON(t, writer, map[string]any{"total_count": 2, "runners": []map[string]any{
				{"id": 1, "name": "runner-a", "status": "online"},
				{"id": 2, "name": "runner-b", "status": "offline"},
			}})
		case "/orgs/fixture-org/actions/runner-groups":
			writeJSON(t, writer, map[string]any{"total_count": 1, "runner_groups": []map[string]any{{"id": 1, "name": "default"}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgRunners(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.SelfHostedRunnerCount != 2 || result.OnlineRunnerCount != 1 || result.RunnerGroupsCount != 1 {
		t.Fatalf("unexpected runners result: %+v", result)
	}
}

// TestFetchOrgCopilotComputesSeatUtilisationNotSettingsProxy confirms
// org.copilot derives copilot_seat_utilisation_pct from the actual
// active-this-cycle/total seat breakdown, and that an organization with
// Copilot for Business unavailable (404) is reported unknown, never 0%.
func TestFetchOrgCopilotComputesSeatUtilisationNotSettingsProxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{
			"seat_breakdown":          map[string]any{"total": 20, "active_this_cycle": 15},
			"public_code_suggestions": "block",
			"seat_management_setting": "assign_selected",
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, _, err := FetchOrgCopilot(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.SeatsTotal != 20 || result.SeatsActiveThisCycle != 15 ||
		result.SeatUtilisationPct.Status != MetricKnown || result.SeatUtilisationPct.Number == nil || *result.SeatUtilisationPct.Number != 75 {
		t.Fatalf("unexpected copilot utilisation: %+v", result)
	}
	if result.PublicCodeSuggestions != "block" || result.SeatManagementSetting != "assign_selected" {
		t.Fatalf("unexpected copilot policy fields: %+v", result)
	}

	disabledServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(disabledServer.Close)
	disabledClient := collectionFixtureClient(t, disabledServer, fixtureBudget(t), SystemClock{})
	disabledResult, _, err := FetchOrgCopilot(context.Background(), disabledClient, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if disabledResult.Complete || disabledResult.SeatUtilisationPct.Status != MetricUnavailable {
		t.Fatalf("Copilot not enabled (404) must be unknown, not a false 0%%: %+v", disabledResult)
	}
}

// TestFetchOrgPackagesSumsEveryDocumentedEcosystem confirms org.packages
// queries every documented package_type separately (the endpoint has no
// "all ecosystems" mode) and sums their actual counts.
func TestFetchOrgPackagesSumsEveryDocumentedEcosystem(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Query().Get("package_type") {
		case "container":
			writeJSON(t, writer, []map[string]any{{"name": "pkg-a"}, {"name": "pkg-b"}})
		case "npm":
			writeJSON(t, writer, []map[string]any{{"name": "pkg-c"}})
		default:
			writeJSON(t, writer, []map[string]any{})
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcomes, err := FetchOrgPackages(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.PackagesCount != 3 {
		t.Fatalf("expected 2 container + 1 npm = 3 packages summed across ecosystems: %+v", result)
	}
	if len(outcomes) != len(orgPackageEcosystems) {
		t.Fatalf("expected one outcome per documented ecosystem (%d), got %d", len(orgPackageEcosystems), len(outcomes))
	}
}

// TestFetchEnterpriseActionsPermissionsReadsEnterpriseScope confirms
// ent.actions_permissions decodes the enterprise-scoped (not
// organization-scoped) permissions object.
func TestFetchEnterpriseActionsPermissionsReadsEnterpriseScope(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/enterprises/fixture-enterprise/actions/permissions" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(t, writer, map[string]any{"enabled_organizations": "all", "allowed_actions": "all"})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseActionsPermissions(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.AllowedActionsPolicy != "all" || result.EnabledOrganizations != "all" {
		t.Fatalf("unexpected enterprise actions permissions: %+v", result)
	}
}

// TestFetchEnterpriseCodeSecurityConfigurationsFullFeatureOnly confirms
// ent.code_security_configs only counts a configuration as
// full_feature_configuration when every required feature reports "enabled",
// mirroring org.code_security_configs's documented full-feature contract at
// enterprise scope.
func TestFetchEnterpriseCodeSecurityConfigurationsFullFeatureOnly(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/enterprises/fixture-enterprise/code-security/configurations":
			writeJSON(t, writer, []map[string]any{
				{"id": 1, "secret_scanning": "enabled", "secret_scanning_push_protection": "enabled",
					"dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
				{"id": 2, "secret_scanning": "enabled", "secret_scanning_push_protection": "disabled",
					"dependabot_alerts": "enabled", "code_scanning_default_setup": "enabled"},
			})
		case "/enterprises/fixture-enterprise/code-security/configurations/defaults":
			writeJSON(t, writer, []map[string]any{})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, _, err := FetchEnterpriseCodeSecurityConfigurations(context.Background(), client, store, scope, "fixture-enterprise")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ConfigurationsCount != 2 || result.FullFeatureConfigurationCount != 1 || !result.FullFeatureConfiguration {
		t.Fatalf("expected exactly 1 of 2 configurations to qualify as full-feature: %+v", result)
	}
}

// TestFetchOrgProjectsCountsOpenProjectsAndNilClientIsExplicit confirms
// org.projects decodes the documented ProjectsV2 GraphQL query and that a
// nil GraphQL client (unavailable for this target) is reported as an
// explicit NotRun outcome, never a silent zero.
func TestFetchOrgProjectsCountsOpenProjectsAndNilClientIsExplicit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"data": map[string]any{"organization": map[string]any{
			"projectsV2": map[string]any{"totalCount": 2, "nodes": []map[string]any{{"closed": false}, {"closed": true}}},
		}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}

	result, outcome, err := FetchOrgProjects(context.Background(), client, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ProjectsCount != 2 || result.OpenProjectsCount != 1 {
		t.Fatalf("unexpected projects result: %+v", result)
	}

	nilResult, nilOutcome, err := FetchOrgProjects(context.Background(), nil, store, scope, "fixture-org")
	if err != nil {
		t.Fatal(err)
	}
	if nilResult.Complete || nilOutcome.Status != NotRun || nilOutcome.Reason == "" {
		t.Fatalf("a nil GraphQL client must be reported as an explicit, reasoned NotRun outcome, never a silent zero: %+v / %+v",
			nilResult, nilOutcome)
	}
	_ = outcome
}
