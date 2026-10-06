// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMetricAccumulatorIncompleteRepositoryMarksPooledMetricsUnavailable is a
// regression test for silently excluding an incompletely assessed repository
// from both the numerator and the denominator of the pooled effective-
// protection metrics, which let the remaining confidently assessed subset look
// like a complete, clean coverage figure. One incomplete repository among the
// analyzed population must make every pooled metric derived from this data
// explicitly unavailable, while still preserving the confidently known
// subset's numerator/denominator for audit.
func TestMetricAccumulatorIncompleteRepositoryMarksPooledMetricsUnavailable(t *testing.T) {
	accumulator := newMetricAccumulator()
	complete := &EffectiveBranchProtection{
		Completeness: CollectionOK, Source: "ruleset",
		PullRequestRequired: true, MinApprovals: 1, StatusChecks: []string{"ci"},
		BlockForcePush: true, BlockDeletion: true,
		ApplicableRulesets: []RulesetReference{{ID: 1, SourceType: "Organization", Source: "fixture-org"}},
	}
	incomplete := &EffectiveBranchProtection{Completeness: CollectionPartial, Source: "unknown"}
	accumulator.addEffectiveProtection(complete)
	accumulator.addEffectiveProtection(incomplete)

	metrics := map[string]Metric{}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	if err := accumulator.populate(metrics, now.AddDate(0, 0, -90), now, now.AddDate(0, 0, -180), now); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"repos_with_default_branch_protection_pct", "repos_fully_protected_pct", "rule_type_coverage", "active_org_rulesets_count"} {
		metric, ok := metrics[key]
		if !ok {
			t.Fatalf("metric %s was not populated", key)
		}
		if metric.Overall.Status != MetricUnavailable {
			t.Fatalf("metric %s silently reported a clean known result despite one incomplete analyzed repository: %+v", key, metric.Overall)
		}
		if metric.Overall.Reason == "" || !strings.Contains(metric.Overall.Reason, "1 of 2") {
			t.Fatalf("metric %s did not disclose the incomplete/total repository count: %+v", key, metric.Overall)
		}
	}

	protected := metrics["repos_with_default_branch_protection_pct"].Overall
	if protected.Numerator == nil || *protected.Numerator != 1 || protected.Denominator == nil || *protected.Denominator != 1 {
		t.Fatalf("the confidently known subset's numerator/denominator must be preserved for audit, not discarded: %+v", protected)
	}
}

// TestMetricAccumulatorFullyProtectedDoesNotRequireSignatures is a regression
// test: GOV-070's "fully protected" criterion is pull_request (>=1 approval),
// required_status_checks (>=1 context), non_fast_forward and deletion
// protection. Required signatures are GOV-072's separate criterion. An
// otherwise fully protected but unsigned repository must still count toward
// GOV-070's fully-protected numerator.
func TestMetricAccumulatorFullyProtectedDoesNotRequireSignatures(t *testing.T) {
	accumulator := newMetricAccumulator()
	unsignedButFullyProtected := &EffectiveBranchProtection{
		Completeness: CollectionOK, Source: "ruleset",
		PullRequestRequired: true, MinApprovals: 1, StatusChecks: []string{"ci"},
		BlockForcePush: true, BlockDeletion: true, Signatures: false,
	}
	accumulator.addEffectiveProtection(unsignedButFullyProtected)

	metrics := map[string]Metric{}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	if err := accumulator.populate(metrics, now.AddDate(0, 0, -90), now, now.AddDate(0, 0, -180), now); err != nil {
		t.Fatal(err)
	}

	fullyProtected := metrics["repos_fully_protected_pct"].Overall
	if fullyProtected.Status != MetricKnown || fullyProtected.Number == nil || *fullyProtected.Number != 100 {
		t.Fatalf("an unsigned but otherwise fully protected repository must count toward GOV-070: %+v", fullyProtected)
	}

	ruleTypes := metrics["rule_type_coverage"].Overall
	if ruleTypes.Status != MetricKnown || ruleTypes.Dictionary == nil {
		t.Fatalf("rule_type_coverage was not populated: %+v", ruleTypes)
	}
	if _, present := (*ruleTypes.Dictionary)["required_signatures"]; present {
		t.Fatal("required_signatures must not appear for a repository that does not require signatures")
	}
	if _, present := (*ruleTypes.Dictionary)["pull_request"]; !present {
		t.Fatal("signature separation must not remove the other observed rule types")
	}
}

// TestMetricAccumulatorActiveOrgRulesetsCountUnavailableWhenNoObservations is a
// regression test: an empty accumulator (no repository's effective-rules
// evidence was ever observed) must never report active_org_rulesets_count as a
// known zero, which would falsely claim an inventory was taken.
func TestMetricAccumulatorActiveOrgRulesetsCountUnavailableWhenNoObservations(t *testing.T) {
	accumulator := newMetricAccumulator()
	metrics := map[string]Metric{}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	if err := accumulator.populate(metrics, now.AddDate(0, 0, -90), now, now.AddDate(0, 0, -180), now); err != nil {
		t.Fatal(err)
	}
	count := metrics["active_org_rulesets_count"].Overall
	if count.Status != MetricUnavailable || count.Number != nil {
		t.Fatalf("active_org_rulesets_count falsely reported a known zero with no observed evidence: %+v", count)
	}
}

// TestEffectiveBranchProtectionBypassDataCompleteFalseWhenRulesetDetailMissing
// is a regression test: a missing ruleset detail (for an applicable ruleset)
// must not silently present bypass_actor_count as a confirmed zero while the
// primary effective-rules endpoint still marks overall Completeness as
// CollectionOK. Effective-rule completeness (rule types) and bypass/detail
// completeness are separate signals.
func TestEffectiveBranchProtectionBypassDataCompleteFalseWhenRulesetDetailMissing(t *testing.T) {
	branchRules := []map[string]any{
		{"type": "pull_request", "ruleset_source_type": "Organization", "ruleset_source": "fixture-org", "ruleset_id": 1,
			"parameters": map[string]any{"required_approving_review_count": 2, "require_code_owner_review": true, "dismiss_stale_reviews_on_push": false}},
	}
	summaries := []map[string]any{
		{"id": 1, "name": "org-default-branch-protection", "target": "branch", "source_type": "Organization", "source": "fixture-org", "enforcement": "active"},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/rules/branches/main":
			writeJSON(t, writer, branchRules)
		case "/repos/fixture-org/widget/rulesets":
			writeJSON(t, writer, summaries)
		case "/orgs/fixture-org/rulesets/1":
			// The ruleset's full detail (bypass_actors, conditions) is forbidden,
			// even though the repository and its branch-rules are readable.
			writer.WriteHeader(http.StatusForbidden)
			writeJSON(t, writer, map[string]string{"message": "must have admin rights"})
		case "/repos/fixture-org/widget/branches/main/protection":
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	orgScope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	repoScope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	effective, _, err := ComputeEffectiveBranchProtection(context.Background(), client, store, orgScope, repoScope,
		"fixture-org", "fixture-org", "widget", "main")
	if err != nil {
		t.Fatal(err)
	}
	if effective.Completeness != CollectionOK {
		t.Fatalf("effective-rule (rule-type) completeness should remain known from the primary endpoint: %+v", effective)
	}
	if effective.BypassDataComplete {
		t.Fatalf("bypass completeness must be false when an applicable ruleset's detail could not be fetched: %+v", effective)
	}
	if effective.BypassActorCount != 0 || len(effective.BypassActors) != 0 {
		t.Fatalf("with no detail available, bypass actors must stay empty (a lower bound), not fabricated: %+v", effective.BypassActors)
	}
	foundNote := false
	for _, note := range effective.Notes {
		if strings.Contains(note, "bypass_data_complete") {
			foundNote = true
		}
	}
	if !foundNote {
		t.Fatal("missing ruleset detail must be disclosed via a note referencing bypass_data_complete")
	}
}

// TestPopulateRulesetAndCommitMetricsGOV070NeverPoolsBooleanORAcrossOrgs is a
// regression test: a pooled "any organization has the ruleset" boolean OR
// across multiple organizations is actively misleading (a small compliant
// organization cannot stand in for a separate, much larger non-compliant
// one). The overall value must never be a clean known boolean; each
// organization's own value must remain independently correct.
func TestPopulateRulesetAndCommitMetricsGOV070NeverPoolsBooleanORAcrossOrgs(t *testing.T) {
	accumulator := newMetricAccumulator()
	accumulator.addDirectOrgRulesets("github.com/organization/small-compliant", 1, true)
	accumulator.addDirectOrgRulesets("github.com/organization/large-noncompliant", 0, false)

	metrics := map[string]Metric{}
	if err := accumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}

	metric := metrics["org_default_branch_rulesets_active"]
	if metric.Overall.Status != MetricUnavailable {
		t.Fatalf("org_default_branch_rulesets_active overall must never be a pooled boolean OR across organizations: %+v", metric.Overall)
	}
	compliant := metric.PerOrganization["github.com/organization/small-compliant"]
	if compliant.Status != MetricKnown || compliant.Boolean == nil || !*compliant.Boolean {
		t.Fatalf("the small compliant organization's own value must remain known true: %+v", compliant)
	}
	nonCompliant := metric.PerOrganization["github.com/organization/large-noncompliant"]
	if nonCompliant.Status != MetricKnown || nonCompliant.Boolean == nil || *nonCompliant.Boolean {
		t.Fatalf("the large non-compliant organization's own value must remain known false, never upgraded by the other organization: %+v",
			nonCompliant)
	}
}

// TestPopulateRulesetAndCommitMetricsGOV072ScopedToConfirmedCriticalPopulationOnly
// is a regression test for pooling GOV-072's verified_commit_ratio_pct over
// every analyzed repository instead of each organization's confirmed
// CRITICAL population only. One organization has exactly 1 critical
// repository (0/1 commits verified) and 100 non-critical repositories
// (100/100 commits verified each): the correct pooled/per-organization ratio
// is exactly 0% (the critical repository alone), never ~99.0% (the critical
// repository silently diluted by the much larger non-critical sample). A
// second organization's unresolved critical population (Method=="unknown")
// must make its own contribution unavailable, never silently zero, and must
// not corrupt the first organization's correct figure.
func TestPopulateRulesetAndCommitMetricsGOV072ScopedToConfirmedCriticalPopulationOnly(t *testing.T) {
	const orgA = "github.com/organization/acme"
	const orgB = "github.com/organization/unknown-critical"
	accumulator := newMetricAccumulator()
	accumulator.setCriticalPopulation(orgA, &CriticalPopulationResult{Method: "custom-property", FullNames: []string{"acme/critical-repo"}})
	accumulator.addCommitVerification(orgA, RepositoryCommitVerificationResult{
		Repository: "acme/critical-repo", SampledCommits: 1, VerifiedCommits: 0, Complete: true,
	})
	for i := 0; i < 100; i++ {
		accumulator.addCommitVerification(orgA, RepositoryCommitVerificationResult{
			Repository: fmt.Sprintf("acme/noncritical-repo-%d", i), SampledCommits: 1, VerifiedCommits: 1, Complete: true,
		})
	}
	accumulator.setCriticalPopulation(orgB, &CriticalPopulationResult{Method: "unknown", Reason: "schema access failed"})
	accumulator.addCommitVerification(orgB, RepositoryCommitVerificationResult{Repository: "other/repo", SampledCommits: 1, VerifiedCommits: 1, Complete: true})

	metrics := map[string]Metric{}
	if err := accumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}

	metric := metrics["verified_commit_ratio_pct"]
	orgAValue := metric.PerOrganization[orgA]
	if orgAValue.Status != MetricKnown || orgAValue.Number == nil || *orgAValue.Number != 0 {
		t.Fatalf("organization A's verified_commit_ratio_pct must be exactly 0%% from its 1 critical repository alone, "+
			"never diluted by 100 non-critical repositories' clean samples: %+v", orgAValue)
	}
	if orgAValue.Denominator == nil || *orgAValue.Denominator != 1 {
		t.Fatalf("organization A's denominator must be exactly 1 (the critical repository's own sampled commits), not 101: %+v", orgAValue)
	}
	orgBValue := metric.PerOrganization[orgB]
	if orgBValue.Status != MetricUnavailable {
		t.Fatalf("organization B's unresolved critical population must make its own value unavailable, never a silent clean figure: %+v",
			orgBValue)
	}
	// The pooled overall must also be unavailable: organization B's unknown
	// critical population must not be silently excluded from the pooled
	// figure as if it had zero critical repositories.
	if metric.Overall.Status != MetricUnavailable {
		t.Fatalf("the pooled overall verified_commit_ratio_pct must be unavailable when any organization's critical "+
			"population is unresolved: %+v", metric.Overall)
	}
}

// TestPopulateRulesetAndCommitMetricsGOV072IncompleteCriticalRepoDoesNotInflate
// confirms an incomplete commit-verification sample on a CONFIRMED critical
// repository marks that organization's ratio uncertain (a lower bound, never
// a falsely clean percentage silently computed over only the complete
// subset).
func TestPopulateRulesetAndCommitMetricsGOV072IncompleteCriticalRepoDoesNotInflate(t *testing.T) {
	const org = "github.com/organization/acme"
	accumulator := newMetricAccumulator()
	accumulator.setCriticalPopulation(org, &CriticalPopulationResult{Method: "custom-property", FullNames: []string{"acme/a", "acme/b"}})
	accumulator.addCommitVerification(org, RepositoryCommitVerificationResult{Repository: "acme/a", SampledCommits: 1, VerifiedCommits: 1, Complete: true})
	accumulator.addCommitVerification(org, RepositoryCommitVerificationResult{Repository: "acme/b", Complete: false})

	metrics := map[string]Metric{}
	if err := accumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	value := metrics["verified_commit_ratio_pct"].PerOrganization[org]
	if value.Status != MetricUnavailable {
		t.Fatalf("one incomplete critical repository must make the organization's ratio unavailable, not a clean 100%% "+
			"silently computed over the one complete repository: %+v", value)
	}
}

// TestPopulateContentsProbeMetricsDenominatorsAreEligibilityAndWorkflowScoped
// is a regression test: SEC-043's repos_with_grouped_version_updates_pct
// denominator must be dependency-ELIGIBLE repositories (never "repositories
// whose dependabot.yml happened to parse"), and SEC-099's
// repos_with_actions_ecosystem_updates_pct denominator must be repositories
// that actually use GitHub Actions (have at least one workflow file), not
// the dependabot.yml-parsed subset either. A repository that is not
// dependency-eligible/has no workflows must be excluded entirely (not
// counted, not marked uncertain); a repository whose eligibility is itself
// unknown, or whose eligible/Actions-using dependabot.yml could not be
// parsed, must mark the ratio uncertain rather than silently shrinking the
// denominator.
func TestPopulateContentsProbeMetricsDenominatorsAreEligibilityAndWorkflowScoped(t *testing.T) {
	const org = "github.com/organization/acme"
	accumulator := newMetricAccumulator()
	// Dependency-eligible, grouped updates configured: counts in SEC-043's
	// numerator and denominator.
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/eligible-grouped", DependabotConfigKnown: true, HasGroupedVersionUpdate: true,
	}, true, true, false)
	// Dependency-eligible, no groups configured: counts only in SEC-043's
	// denominator.
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/eligible-no-groups", DependabotConfigKnown: true, HasGroupedVersionUpdate: false,
	}, true, true, false)
	// Not dependency-eligible: must be entirely excluded from SEC-043 (not
	// counted as a non-grouped repository, not marked uncertain).
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/not-eligible", DependabotConfigKnown: true, HasGroupedVersionUpdate: true,
	}, false, true, false)
	// Dependency eligibility itself unknown: must NOT be silently treated as
	// ineligible-and-excluded; it must mark the ratio uncertain.
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/eligibility-unknown", DependabotConfigKnown: true,
	}, false, false, false)
	// Has workflows, Actions-ecosystem update configured: counts in SEC-099's
	// numerator and denominator.
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/workflows-actions-update", DependabotConfigKnown: true, HasActionsEcosystem: true,
	}, false, true, true)
	// No workflows at all: must be entirely excluded from SEC-099.
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/no-workflows", DependabotConfigKnown: true, HasActionsEcosystem: true,
	}, false, true, false)
	// Has workflows but dependabot.yml could not be parsed: must mark
	// SEC-099's ratio uncertain, not silently excluded.
	accumulator.addContentsProbe(org, RepositoryContentsProbeResult{
		Repository: "acme/workflows-unknown-config", DependabotConfigKnown: false,
	}, false, true, true)

	metrics := map[string]Metric{}
	if err := accumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}

	grouped := metrics["repos_with_grouped_version_updates_pct"].PerOrganization[org]
	if grouped.Status != MetricUnavailable {
		t.Fatalf("an unknown dependency-eligibility determination must mark the ratio uncertain, not a falsely clean figure: %+v", grouped)
	}
	if grouped.Denominator == nil || *grouped.Denominator != 2 || grouped.Numerator == nil || *grouped.Numerator != 1 {
		t.Fatalf("the confidently known dependency-eligible subset (2 repositories, 1 grouped) must still be preserved for audit: %+v", grouped)
	}

	actions := metrics["repos_with_actions_ecosystem_updates_pct"].PerOrganization[org]
	if actions.Status != MetricUnavailable {
		t.Fatalf("an Actions-using repository with an unparsed dependabot.yml must mark the ratio uncertain: %+v", actions)
	}
	if actions.Denominator == nil || *actions.Denominator != 1 || actions.Numerator == nil || *actions.Numerator != 1 {
		t.Fatalf("the confidently known Actions-using subset (1 repository, 1 with the ecosystem update) must still be preserved for audit: %+v",
			actions)
	}
}

// TestPopulateAccessMetricsTeamBasedAccessPctIsGrantCountRatioNotRepoPresence
// is a regression test for the exact documented formula (section 6):
// team_based_access_pct = team permission GRANTS / (team grants + direct
// collaborator grants), bots excluded. A repository that merely has at
// least one team grant alongside a much larger number of direct
// collaborator grants must not be reported as "100% team-based access"; the
// metric must reflect actual grant counts. Covers: 1 team grant + 99 direct
// grants (expect 1%, not 100%), bot exclusion (via the already bot-excluded
// DirectCollaboratorsExclBots field), an incomplete contributor (team repo
// list or access inventory), a zero-grant organization, and multi-organization
// pooling.
func TestPopulateAccessMetricsTeamBasedAccessPctIsGrantCountRatioNotRepoPresence(t *testing.T) {
	const orgA = "github.com/organization/acme"
	accumulator := newMetricAccumulator()
	accumulator.addTeamGrants(orgA, []teamSummary{
		{Slug: "platform", ReposComplete: true, Repos: []teamRepoAccess{{FullName: "acme/widget", Permission: "push"}}},
	})
	accumulator.addRepositoryAccess(orgA, RepositoryAccessResult{Repository: "acme/widget", DirectCollaboratorsExclBots: 99, Complete: true})

	metricsA := map[string]Metric{}
	if err := accumulator.populate(metricsA, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	teamMetric := metricsA["team_based_access_pct"].PerOrganization[orgA]
	if teamMetric.Status != MetricKnown || teamMetric.Number == nil || *teamMetric.Number != 1 {
		t.Fatalf("1 team grant among 100 total grants (1 team + 99 direct) must be exactly 1%%, never 100%% from "+
			"repository presence alone: %+v", teamMetric)
	}
	if teamMetric.Numerator == nil || *teamMetric.Numerator != 1 || teamMetric.Denominator == nil || *teamMetric.Denominator != 100 {
		t.Fatalf("expected the actual grant-count numerator/denominator (1/100), not a repository-presence count: %+v", teamMetric)
	}
	// Overall must agree with the single organization's own figure.
	if overall := metricsA["team_based_access_pct"].Overall; overall.Status != MetricKnown || overall.Number == nil || *overall.Number != 1 {
		t.Fatalf("the pooled overall must match the single organization's 1%%: %+v", overall)
	}

	t.Run("incomplete_team_repo_list_marks_uncertain_not_clean", func(t *testing.T) {
		incompleteAccumulator := newMetricAccumulator()
		incompleteAccumulator.addTeamGrants("github.com/organization/incomplete", []teamSummary{
			{Slug: "platform", ReposComplete: false},
		})
		incompleteAccumulator.addRepositoryAccess("github.com/organization/incomplete",
			RepositoryAccessResult{Repository: "incomplete/widget", DirectCollaboratorsExclBots: 5, Complete: true})
		metrics := map[string]Metric{}
		if err := incompleteAccumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		value := metrics["team_based_access_pct"].PerOrganization["github.com/organization/incomplete"]
		if value.Status != MetricUnavailable {
			t.Fatalf("a team whose own repository grant list failed to collect must make this organization's ratio "+
				"unavailable, never silently treated as granting zero repositories: %+v", value)
		}
	})

	t.Run("incomplete_direct_access_marks_uncertain_not_clean", func(t *testing.T) {
		incompleteAccumulator := newMetricAccumulator()
		incompleteAccumulator.addTeamGrants("github.com/organization/incomplete-access", []teamSummary{
			{Slug: "platform", ReposComplete: true, Repos: []teamRepoAccess{{FullName: "incomplete-access/widget"}}},
		})
		incompleteAccumulator.addRepositoryAccess("github.com/organization/incomplete-access",
			RepositoryAccessResult{Repository: "incomplete-access/widget", Complete: false})
		metrics := map[string]Metric{}
		if err := incompleteAccumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		value := metrics["team_based_access_pct"].PerOrganization["github.com/organization/incomplete-access"]
		if value.Status != MetricUnavailable {
			t.Fatalf("an incomplete direct-collaborator inventory must also make team_based_access_pct unavailable: %+v", value)
		}
	})

	t.Run("zero_grants_is_unavailable_not_a_fake_percentage", func(t *testing.T) {
		zeroAccumulator := newMetricAccumulator()
		zeroAccumulator.addTeamGrants("github.com/organization/zero", nil)
		zeroAccumulator.addRepositoryAccess("github.com/organization/zero",
			RepositoryAccessResult{Repository: "zero/widget", DirectCollaboratorsExclBots: 0, Complete: true})
		metrics := map[string]Metric{}
		if err := zeroAccumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		value := metrics["team_based_access_pct"].PerOrganization["github.com/organization/zero"]
		if value.Status != MetricUnavailable {
			t.Fatalf("zero team and zero direct grants must report unavailable (zero eligible observations), never a fake 0%% or 100%%: %+v", value)
		}
	})

	t.Run("multi_organization_pool_sums_actual_grant_counts", func(t *testing.T) {
		poolAccumulator := newMetricAccumulator()
		poolAccumulator.addTeamGrants("github.com/organization/pool-a", []teamSummary{
			{Slug: "platform", ReposComplete: true, Repos: []teamRepoAccess{{FullName: "pool-a/widget"}}},
		})
		poolAccumulator.addRepositoryAccess("github.com/organization/pool-a",
			RepositoryAccessResult{Repository: "pool-a/widget", DirectCollaboratorsExclBots: 9, Complete: true})
		poolAccumulator.addTeamGrants("github.com/organization/pool-b", []teamSummary{
			{Slug: "security", ReposComplete: true, Repos: []teamRepoAccess{
				{FullName: "pool-b/widget"}, {FullName: "pool-b/gadget"},
			}},
		})
		poolAccumulator.addRepositoryAccess("github.com/organization/pool-b",
			RepositoryAccessResult{Repository: "pool-b/widget", DirectCollaboratorsExclBots: 0, Complete: true})
		poolAccumulator.addRepositoryAccess("github.com/organization/pool-b",
			RepositoryAccessResult{Repository: "pool-b/gadget", DirectCollaboratorsExclBots: 8, Complete: true})
		metrics := map[string]Metric{}
		if err := poolAccumulator.populate(metrics, time.Time{}, time.Time{}, time.Time{}, time.Time{}); err != nil {
			t.Fatal(err)
		}
		// pool-a: 1 team grant, 9 direct grants (1/10 = 10%).
		poolA := metrics["team_based_access_pct"].PerOrganization["github.com/organization/pool-a"]
		if poolA.Number == nil || *poolA.Number != 10 {
			t.Fatalf("pool-a expected 10%% (1 team grant / 10 total grants): %+v", poolA)
		}
		// pool-b: 2 team grants, 8 direct grants (2/10 = 20%).
		poolB := metrics["team_based_access_pct"].PerOrganization["github.com/organization/pool-b"]
		if poolB.Number == nil || *poolB.Number != 20 {
			t.Fatalf("pool-b expected 20%% (2 team grants / 10 total grants): %+v", poolB)
		}
		// Pooled overall: 3 team grants, 17 direct grants out of 20 total = 15%.
		overall := metrics["team_based_access_pct"].Overall
		if overall.Number == nil || *overall.Number != 15 {
			t.Fatalf("the pooled overall across both organizations must sum actual grant counts (3 team + 17 direct = "+
				"3/20 = 15%%), not average the two organizations' percentages ((10+20)/2=15 coincidentally matches here, "+
				"but must come from summed counts): %+v", overall)
		}
	})
}

// TestPopulateSecurityConfigCoverageUnknownOrganizationCannotProduceKnownSubset
// is a regression test: the pooled code_security_configuration_full_coverage_pct
// previously treated ANY non-MetricKnown organization result (including a
// genuinely unresolved one) by simply excluding it from the numerator/
// denominator sum, while separately forcing the overall Status to
// MetricUnavailable with Number/Numerator/Denominator all erased to nil --
// collapsing the confidently-known subset's own retained counts entirely,
// the same "unknown peer silently excluded" defect this package's
// cohortCoverageMetric helper already exists to prevent for CodeQL/
// Dependency/attestation coverage. One organization whose own coverage is
// confidently known (1/2) alongside one whose coverage could not be
// determined at all must report the pooled Overall as MetricUnavailable
// with Number:nil, while still retaining the known organization's own 1/2
// counts on the pooled Numerator/Denominator (never silently reporting a
// confident 50%, and never erasing the retained counts either).
func TestPopulateSecurityConfigCoverageUnknownOrganizationCannotProduceKnownSubset(t *testing.T) {
	numerator, denominator := 1.0, 2.0
	accumulator := newMetricAccumulator()
	accumulator.addSecurityConfigCoverage("github.com/organization/known", MetricValue{
		Status: MetricKnown, Number: floatPointer(50), Numerator: &numerator, Denominator: &denominator,
		Population: "configuration-eligible repositories", EvidenceRefs: []string{},
	})
	accumulator.addSecurityConfigCoverage("github.com/organization/unresolved", MetricValue{
		Status: MetricUnavailable, Population: "configuration-eligible repositories", EvidenceRefs: []string{},
		Reason: "configuration or attachment inventory is incomplete",
	})

	metrics := map[string]Metric{}
	accumulator.populateSecurityConfigCoverage(metrics)

	overall := metrics["code_security_configuration_full_coverage_pct"].Overall
	if overall.Status != MetricUnavailable {
		t.Fatalf("one genuinely unresolved organization must make the pooled overall unavailable, never a silently "+
			"computed subset percentage: %+v", overall)
	}
	if overall.Number != nil {
		t.Fatalf("an unavailable pooled metric must not carry a Number: %+v", overall)
	}
	if overall.Numerator == nil || overall.Denominator == nil || *overall.Numerator != 1 || *overall.Denominator != 2 {
		t.Fatalf("the confidently-known organization's own 1/2 counts must still be retained on the pooled metric, "+
			"not erased to nil: %+v", overall)
	}
	if overall.Reason == "" {
		t.Fatal("expected an explicit disclosed Reason for the unavailable pooled metric")
	}
	known := metrics["code_security_configuration_full_coverage_pct"].PerOrganization["github.com/organization/known"]
	if known.Status != MetricKnown || known.Number == nil || *known.Number != 50 {
		t.Fatalf("the resolved organization's own per-organization value must remain its true known 50%%, "+
			"unaffected by the unresolved peer: %+v", known)
	}
}

// TestPopulateSecurityConfigCoverageConfirmedEmptyOrganizationDoesNotForceUnavailable
// is the sibling confirming a confirmed, zero-eligible-repository
// organization (MetricInapplicable -- a genuine, resolved "nothing to
// measure here", not an unresolved peer) does not, on its own, force the
// pooled overall unavailable: pooled with one other organization whose own
// coverage is fully known, the overall must report that organization's
// true known percentage.
func TestPopulateSecurityConfigCoverageConfirmedEmptyOrganizationDoesNotForceUnavailable(t *testing.T) {
	numerator, denominator := 1.0, 1.0
	accumulator := newMetricAccumulator()
	accumulator.addSecurityConfigCoverage("github.com/organization/known", MetricValue{
		Status: MetricKnown, Number: floatPointer(100), Numerator: &numerator, Denominator: &denominator,
		Population: "configuration-eligible repositories", EvidenceRefs: []string{},
	})
	accumulator.addSecurityConfigCoverage("github.com/organization/empty", MetricValue{
		Status: MetricInapplicable, Population: "configuration-eligible repositories", EvidenceRefs: []string{},
		Reason: "complete population contains no eligible repositories",
	})

	metrics := map[string]Metric{}
	accumulator.populateSecurityConfigCoverage(metrics)

	overall := metrics["code_security_configuration_full_coverage_pct"].Overall
	if overall.Status != MetricKnown || overall.Number == nil || *overall.Number != 100 {
		t.Fatalf("a confirmed-empty peer organization must not force the pooled overall unavailable, nor dilute "+
			"the other organization's true known 100%%: %+v", overall)
	}
}

func floatPointer(value float64) *float64 {
	return &value
}
