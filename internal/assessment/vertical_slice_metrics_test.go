// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	accumulator.populate(metrics)

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
	accumulator.populate(metrics)

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
	accumulator.populate(metrics)
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
