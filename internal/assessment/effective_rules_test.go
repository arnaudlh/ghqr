// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v83/github"
)

func TestRefConditionMatchesSentinelsAndGlobPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		branch  string
		want    bool
	}{
		{"all sentinel matches any branch", "~ALL", "release/1.0", true},
		{"default branch sentinel always matches", "~DEFAULT_BRANCH", "main", true},
		{"literal branch name matches itself", "main", "main", true},
		{"literal branch name does not match a different branch", "main", "develop", false},
		{"refs/heads prefix is stripped before matching", "refs/heads/main", "main", true},
		{"single star matches one path segment", "release/*", "release/1.0", true},
		{"single star does not cross a path segment boundary", "release/*", "release/1.0/hotfix", false},
		{"double star matches across path segment boundaries", "release/**", "release/1.0/hotfix", true},
		{"unrelated pattern does not match", "release/*", "main", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refConditionMatches(tt.pattern, tt.branch); got != tt.want {
				t.Fatalf("refConditionMatches(%q, %q) = %v, want %v", tt.pattern, tt.branch, got, tt.want)
			}
		})
	}
}

func TestRulesetAppliesToBranchRequiresActiveBranchTargetAndMatchingConditions(t *testing.T) {
	branch := github.RulesetTargetBranch
	tag := github.RulesetTargetTag
	active := github.RulesetEnforcementActive
	evaluate := github.RulesetEnforcementEvaluate
	defaultConditions := &github.RepositoryRulesetConditions{RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~DEFAULT_BRANCH"}}}
	tests := []struct {
		name    string
		ruleset *github.RepositoryRuleset
		want    bool
	}{
		{"nil ruleset never applies", nil, false},
		{"tag target never applies to a branch", &github.RepositoryRuleset{Target: &tag, Enforcement: active, Conditions: defaultConditions}, false},
		{"evaluate-mode ruleset is not active protection", &github.RepositoryRuleset{Target: &branch, Enforcement: evaluate, Conditions: defaultConditions}, false},
		{"missing ref_name conditions never applies", &github.RepositoryRuleset{Target: &branch, Enforcement: active}, false},
		{"excluded branch overrides an included default branch", &github.RepositoryRuleset{Target: &branch, Enforcement: active, Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"~ALL"}, Exclude: []string{"main"}},
		}}, false},
		{"default branch sentinel applies", &github.RepositoryRuleset{Target: &branch, Enforcement: active, Conditions: defaultConditions}, true},
		{"unrelated release glob does not apply to the default branch", &github.RepositoryRuleset{Target: &branch, Enforcement: active, Conditions: &github.RepositoryRulesetConditions{
			RefName: &github.RepositoryRulesetRefConditionParameters{Include: []string{"release/*"}},
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rulesetAppliesToBranch(tt.ruleset, "main"); got != tt.want {
				t.Fatalf("rulesetAppliesToBranch(..., %q) = %v, want %v", "main", got, tt.want)
			}
		})
	}
}

// newEffectiveRulesFixtureServer serves a synthetic repository with one
// organization-sourced ruleset that actively protects the default branch, one
// active repository-sourced ruleset that targets an unrelated release branch
// pattern and must never contribute to default-branch protection or bypass
// counts, and 99 filler tag-target rulesets so the repository ruleset listing
// exceeds 100 entries and must be followed across two pages.
func newEffectiveRulesFixtureServer(t *testing.T, legacyStatus int, legacyBody map[string]any) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var sawLastFiller atomic.Bool
	branchRules := []map[string]any{
		{"type": "pull_request", "ruleset_source_type": "Organization", "ruleset_source": "fixture-org", "ruleset_id": 1,
			"parameters": map[string]any{"required_approving_review_count": 2, "require_code_owner_review": true, "dismiss_stale_reviews_on_push": false}},
		{"type": "required_status_checks", "ruleset_source_type": "Organization", "ruleset_source": "fixture-org", "ruleset_id": 1,
			"parameters": map[string]any{"required_status_checks": []map[string]any{{"context": "ci"}}, "strict_required_status_checks_policy": true}},
		{"type": "non_fast_forward", "ruleset_source_type": "Organization", "ruleset_source": "fixture-org", "ruleset_id": 1, "parameters": map[string]any{}},
	}
	summaries := make([]map[string]any, 0, 101)
	summaries = append(summaries,
		map[string]any{"id": 1, "name": "org-default-branch-protection", "target": "branch", "source_type": "Organization", "source": "fixture-org", "enforcement": "active"},
		map[string]any{"id": 2, "name": "unrelated-release-branch-ruleset", "target": "branch", "source_type": "Repository", "source": "fixture-org/widget", "enforcement": "active"},
	)
	for i := 3; i <= 101; i++ {
		summaries = append(summaries, map[string]any{
			"id": i, "name": fmt.Sprintf("filler-%d", i), "target": "tag", "source_type": "Repository", "source": "fixture-org/widget", "enforcement": "active",
		})
	}
	details := map[string]map[string]any{
		"1": {
			"id": 1, "name": "org-default-branch-protection", "target": "branch", "source_type": "Organization", "source": "fixture-org", "enforcement": "active",
			"conditions":    map[string]any{"ref_name": map[string]any{"include": []string{"~DEFAULT_BRANCH"}, "exclude": []string{}}},
			"bypass_actors": []map[string]any{{"actor_type": "Team", "actor_id": 55, "bypass_mode": "pull_request"}},
		},
		"2": {
			"id": 2, "name": "unrelated-release-branch-ruleset", "target": "branch", "source_type": "Repository", "source": "fixture-org/widget", "enforcement": "active",
			"conditions":    map[string]any{"ref_name": map[string]any{"include": []string{"release/*"}, "exclude": []string{}}},
			"bypass_actors": []map[string]any{{"actor_type": "RepositoryRole", "bypass_mode": "always"}},
		},
	}

	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/fixture-org/widget/rules/branches/main":
			writeJSON(t, writer, branchRules)
		case request.URL.Path == "/repos/fixture-org/widget/rulesets":
			page := request.URL.Query().Get("page")
			const pageSize = 100
			start, end := 0, min(pageSize, len(summaries))
			if page == "2" {
				start, end = pageSize, len(summaries)
			} else if end < len(summaries) {
				next := *request.URL
				query := next.Query()
				query.Set("page", "2")
				next.RawQuery = query.Encode()
				writer.Header().Set("Link", "<"+server.URL+next.RequestURI()+">; rel=\"next\"")
			}
			writeJSON(t, writer, summaries[start:end])
		case strings.HasPrefix(request.URL.Path, "/repos/fixture-org/widget/rulesets/"):
			id := strings.TrimPrefix(request.URL.Path, "/repos/fixture-org/widget/rulesets/")
			if id == "101" {
				sawLastFiller.Store(true)
			}
			respondRulesetDetail(t, writer, id, details)
		case strings.HasPrefix(request.URL.Path, "/orgs/fixture-org/rulesets/"):
			id := strings.TrimPrefix(request.URL.Path, "/orgs/fixture-org/rulesets/")
			respondRulesetDetail(t, writer, id, details)
		case request.URL.Path == "/repos/fixture-org/widget/branches/main/protection":
			writer.WriteHeader(legacyStatus)
			if legacyBody != nil {
				writeJSON(t, writer, legacyBody)
			} else {
				writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
			}
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	return server, &sawLastFiller
}

func respondRulesetDetail(t *testing.T, writer http.ResponseWriter, id string, details map[string]map[string]any) {
	t.Helper()
	if detail, ok := details[id]; ok {
		writeJSON(t, writer, detail)
		return
	}
	numericID, err := strconv.Atoi(id)
	if err != nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writeJSON(t, writer, map[string]any{
		"id": numericID, "name": fmt.Sprintf("filler-%d", numericID), "target": "tag",
		"source_type": "Repository", "source": "fixture-org/widget", "enforcement": "active",
	})
}

func TestComputeEffectiveBranchProtectionMergesInheritedRulesetsAndLegacyWithBypassAndPagination(t *testing.T) {
	legacyBody := map[string]any{
		"enforce_admins":                map[string]any{"enabled": true},
		"allow_force_pushes":            map[string]any{"enabled": false},
		"allow_deletions":               map[string]any{"enabled": false},
		"required_pull_request_reviews": map[string]any{"required_approving_review_count": 1, "require_code_owner_reviews": false, "dismiss_stale_reviews": true},
	}
	server, sawLastFiller := newEffectiveRulesFixtureServer(t, http.StatusOK, legacyBody)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	orgScope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
	repoScope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	effective, outcomes, err := ComputeEffectiveBranchProtection(context.Background(), client, store, orgScope, repoScope,
		"fixture-org", "fixture-org", "widget", "main")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) == 0 {
		t.Fatal("effective branch protection recorded no collector outcomes")
	}
	if effective.Source != "ruleset+legacy" || effective.Completeness != CollectionOK || effective.Unprotected {
		t.Fatalf("merge source/completeness incorrect: %+v", effective)
	}
	if !effective.PullRequestRequired || effective.MinApprovals != 2 || !effective.CodeOwnerReview {
		t.Fatalf("ruleset pull_request parameters not applied: %+v", effective)
	}
	if !effective.StaleDismiss {
		t.Fatal("legacy dismiss_stale_reviews did not merge into the effective record")
	}
	if !effective.Strict || len(effective.StatusChecks) != 1 || effective.StatusChecks[0] != "ci" {
		t.Fatalf("required_status_checks parameters not applied: %+v", effective)
	}
	if !effective.BlockForcePush || !effective.BlockDeletion {
		t.Fatalf("force-push/deletion protection not merged from ruleset and legacy: %+v", effective)
	}
	if effective.EnforceAdmins == nil || !*effective.EnforceAdmins {
		t.Fatalf("legacy enforce_admins was not preserved: %+v", effective)
	}
	if len(effective.ApplicableRulesets) != 1 || effective.ApplicableRulesets[0].ID != 1 {
		t.Fatalf("an active unrelated-branch ruleset incorrectly protected the default branch: %+v", effective.ApplicableRulesets)
	}
	if effective.BypassActorCount != 1 || len(effective.BypassActors) != 1 || effective.BypassActors[0].RulesetID != 1 {
		t.Fatalf("bypass actors leaked from an unrelated-branch ruleset, or the applicable ruleset's bypass actor was lost: %+v", effective.BypassActors)
	}
	if !sawLastFiller.Load() {
		t.Fatal("the repository ruleset listing was not fully paginated past 100 entries; the 101st ruleset was never fetched")
	}
}

func TestLegacyProtection404IsConfirmedAbsenceNot403ConcealedAsUnprotected(t *testing.T) {
	t.Run("404 with no ruleset signal is a confirmed absence", func(t *testing.T) {
		server := newEffectiveRulesFixtureServerNoRulesets(t, http.StatusNotFound, nil)
		client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		orgScope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
		repoScope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/empty"}

		effective, _, err := ComputeEffectiveBranchProtection(context.Background(), client, store, orgScope, repoScope,
			"fixture-org", "fixture-org", "empty", "main")
		if err != nil {
			t.Fatal(err)
		}
		if effective.Source != "none" || !effective.Unprotected || effective.Completeness != CollectionOK {
			t.Fatalf("a confirmed 404 on a readable repository was not treated as a true absence: %+v", effective)
		}
	})
	t.Run("403 is unknown, never collapsed into unprotected", func(t *testing.T) {
		server := newEffectiveRulesFixtureServerNoRulesets(t, http.StatusForbidden, map[string]any{"message": "must have admin rights"})
		client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		orgScope := Scope{client.base.Hostname(), OrganizationScope, "fixture-org"}
		repoScope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/empty"}

		effective, _, err := ComputeEffectiveBranchProtection(context.Background(), client, store, orgScope, repoScope,
			"fixture-org", "fixture-org", "empty", "main")
		if err != nil {
			t.Fatal(err)
		}
		if effective.Unprotected {
			t.Fatalf("a 403 (missing permission) was incorrectly collapsed into \"unprotected\": %+v", effective)
		}
		if effective.Source == "none" {
			t.Fatalf("a 403 must never be reported as a confirmed absence of protection: %+v", effective)
		}
	})
}

// newEffectiveRulesFixtureServerNoRulesets serves a repository with no
// applicable ruleset-based protection (an empty effective-rules response and an
// empty ruleset listing), isolating the legacy-protection 404-vs-403 behavior.
func newEffectiveRulesFixtureServerNoRulesets(t *testing.T, legacyStatus int, legacyBody map[string]any) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/empty/rules/branches/main":
			writeJSON(t, writer, []map[string]any{})
		case "/repos/fixture-org/empty/rulesets":
			writeJSON(t, writer, []map[string]any{})
		case "/repos/fixture-org/empty/branches/main/protection":
			writer.WriteHeader(legacyStatus)
			if legacyBody != nil {
				writeJSON(t, writer, legacyBody)
			} else {
				writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
			}
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	return server
}
