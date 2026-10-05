// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-github/v83/github"
)

// RulesetReference preserves which ruleset(s) contributed to an effective
// default-branch protection decision, independently of its rule content.
type RulesetReference struct {
	ID         int64  `json:"id"`
	Name       string `json:"name,omitempty"`
	SourceType string `json:"source_type"`
	Source     string `json:"source"`
}

// RulesetBypassActorRef is one bypass actor from one ruleset that was confirmed to
// apply to the repository's default branch.
type RulesetBypassActorRef struct {
	RulesetID  int64  `json:"ruleset_id"`
	ActorType  string `json:"actor_type"`
	ActorID    *int64 `json:"actor_id,omitempty"`
	BypassMode string `json:"bypass_mode"`
}

// EffectiveBranchProtection is the normalized merge of ruleset-based and legacy
// branch protection for one repository's default branch, matching the shape the
// repo.rules collector documents: "effective protection" with pr_required,
// min_approvals, code_owner_review, stale_dismiss, status_checks, strict,
// signatures, block_force_push, block_deletion, linear_history,
// required_workflows, code_scanning_gate and source.
type EffectiveBranchProtection struct {
	Repository          string                  `json:"repository"`
	DefaultBranch       string                  `json:"default_branch"`
	PullRequestRequired bool                    `json:"pr_required"`
	MinApprovals        int                     `json:"min_approvals"`
	CodeOwnerReview     bool                    `json:"code_owner_review"`
	StaleDismiss        bool                    `json:"stale_dismiss"`
	StatusChecks        []string                `json:"status_checks"`
	Strict              bool                    `json:"strict"`
	Signatures          bool                    `json:"signatures"`
	BlockForcePush      bool                    `json:"block_force_push"`
	BlockDeletion       bool                    `json:"block_deletion"`
	LinearHistory       bool                    `json:"linear_history"`
	RequiredWorkflows   []string                `json:"required_workflows"`
	CodeScanningGate    bool                    `json:"code_scanning_gate"`
	EnforceAdmins       *bool                   `json:"enforce_admins,omitempty"`
	Source              string                  `json:"source"`
	ApplicableRulesets  []RulesetReference      `json:"applicable_rulesets"`
	BypassActorCount    int                     `json:"bypass_actor_count"`
	BypassActors        []RulesetBypassActorRef `json:"bypass_actors"`
	BypassDataComplete  bool                    `json:"bypass_data_complete"`
	RulesetSignal       Availability            `json:"ruleset_signal"`
	LegacySignal        Availability            `json:"legacy_signal"`
	Completeness        OutcomeStatus           `json:"completeness"`
	Unprotected         bool                    `json:"unprotected"`
	Notes               []string                `json:"notes"`
}

// ComputeEffectiveBranchProtection merges GitHub's dedicated effective-rules
// endpoint (authoritative for ruleset applicability, but silent on legacy branch
// protection and bypass actors), the repository's full ruleset listing and detail
// (for provenance and bypass actors), and legacy branch protection into one
// normalized record. A 403 on legacy protection is preserved as unknown, never
// collapsed into "unprotected"; only a confirmed 404 on that documented endpoint
// is treated as a true absence.
func ComputeEffectiveBranchProtection(ctx context.Context, client *CollectionClient, store *EvidenceStore,
	orgScope, repoScope Scope, organization, owner, repo, defaultBranch string) (*EffectiveBranchProtection, []CollectorOutcome, error) {
	effective := &EffectiveBranchProtection{
		Repository: owner + "/" + repo, DefaultBranch: defaultBranch,
		StatusChecks: []string{}, RequiredWorkflows: []string{},
		ApplicableRulesets: []RulesetReference{}, BypassActors: []RulesetBypassActorRef{}, Notes: []string{},
	}
	outcomes := []CollectorOutcome{}
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)

	branchRules, rulesOutcome, rulesErr := collectJSONObject[github.BranchRules](ctx, client, store, repoScope,
		"repo.rules", "branch-rules", "repos/"+ownerPath+"/"+repoPath+"/rules/branches/"+url.PathEscape(defaultBranch))
	outcomes = append(outcomes, rulesOutcome)
	effective.RulesetSignal = rulesOutcome.Availability

	summaries, listOutcome, listErr := collectJSONArray[*github.RepositoryRuleset](ctx, client, store, repoScope,
		"repo.rules", "rulesets", "repos/"+ownerPath+"/"+repoPath+"/rulesets?includes_parents=true", "", true)
	outcomes = append(outcomes, listOutcome)

	details := make(map[int64]*github.RepositoryRuleset, len(summaries))
	detailFailures := 0
	for _, summary := range summaries {
		if summary == nil || summary.ID == nil {
			continue
		}
		branchTargetActive := summary.Target != nil && *summary.Target == github.RulesetTargetBranch &&
			summary.Enforcement == github.RulesetEnforcementActive
		endpoint := "repos/" + ownerPath + "/" + repoPath + "/rulesets/" + strconv.FormatInt(*summary.ID, 10)
		detailScope := repoScope
		if summary.SourceType != nil && *summary.SourceType == github.RulesetSourceTypeOrganization {
			detailScope = orgScope
			endpoint = "orgs/" + url.PathEscape(organization) + "/rulesets/" + strconv.FormatInt(*summary.ID, 10)
		}
		detail, detailOutcome, detailErr := collectJSONObject[github.RepositoryRuleset](ctx, client, store, detailScope,
			"repo.rules", fmt.Sprintf("ruleset-%d", *summary.ID), endpoint)
		outcomes = append(outcomes, detailOutcome)
		if detailErr != nil || detail == nil {
			if branchTargetActive {
				detailFailures++
			}
			effective.Notes = append(effective.Notes, fmt.Sprintf(
				"ruleset %d detail unavailable (%s); its conditions and bypass actors are incomplete", *summary.ID, detailOutcome.Availability))
			continue
		}
		details[*summary.ID] = detail
	}

	primaryKnown := rulesErr == nil && branchRules != nil
	authoritative := map[int64]bool{}
	if primaryKnown {
		collectBranchRuleIDs(branchRules, authoritative)
	}
	locallyMatched := map[int64]bool{}
	for id, detail := range details {
		if rulesetAppliesToBranch(detail, defaultBranch) {
			locallyMatched[id] = true
		}
	}
	applicable := authoritative
	if primaryKnown {
		for id := range authoritative {
			if !locallyMatched[id] {
				effective.Notes = append(effective.Notes, fmt.Sprintf(
					"ruleset %d contributed to the default branch per GitHub's effective-rules endpoint but did not match local ref-name conditions", id))
			}
		}
		for id := range locallyMatched {
			if !authoritative[id] {
				effective.Notes = append(effective.Notes, fmt.Sprintf(
					"ruleset %d matched local ref-name conditions but GitHub's effective-rules endpoint did not report it as contributing; it was excluded", id))
			}
		}
	} else {
		applicable = locallyMatched
		effective.Notes = append(effective.Notes, "the dedicated effective-rules endpoint was unavailable; "+
			"ruleset applicability was computed locally by matching ref-name conditions against the default branch")
	}

	bypassDataComplete := true
	for id := range applicable {
		reference := RulesetReference{ID: id, SourceType: "Repository", Source: owner + "/" + repo}
		detail, ok := details[id]
		if !ok {
			// A missing ruleset detail means its bypass_actors are unknown, not
			// zero: this applicable ruleset's bypass contribution must not be
			// silently presented as "no bypass actors" while the overall
			// effective-rule completeness (rule types, from the primary
			// endpoint or local ref matching) remains confidently known.
			bypassDataComplete = false
		}
		if ok {
			if detail.SourceType != nil {
				reference.SourceType = string(*detail.SourceType)
			}
			reference.Source = detail.Source
			reference.Name = detail.Name
			for _, actor := range detail.BypassActors {
				if actor == nil {
					continue
				}
				ref := RulesetBypassActorRef{RulesetID: id, ActorID: actor.ActorID}
				if actor.ActorType != nil {
					ref.ActorType = string(*actor.ActorType)
				}
				if actor.BypassMode != nil {
					ref.BypassMode = string(*actor.BypassMode)
				}
				effective.BypassActors = append(effective.BypassActors, ref)
			}
		}
		effective.ApplicableRulesets = append(effective.ApplicableRulesets, reference)
	}
	sort.Slice(effective.ApplicableRulesets, func(i, j int) bool { return effective.ApplicableRulesets[i].ID < effective.ApplicableRulesets[j].ID })
	sort.Slice(effective.BypassActors, func(i, j int) bool {
		if effective.BypassActors[i].RulesetID != effective.BypassActors[j].RulesetID {
			return effective.BypassActors[i].RulesetID < effective.BypassActors[j].RulesetID
		}
		return effective.BypassActors[i].ActorType < effective.BypassActors[j].ActorType
	})
	effective.BypassActorCount = len(effective.BypassActors)
	effective.BypassDataComplete = bypassDataComplete
	if !bypassDataComplete {
		effective.Notes = append(effective.Notes,
			"one or more applicable rulesets' detail could not be fetched; bypass_actor_count/bypass_actors is a known "+
				"lower bound, not a confirmed complete count (bypass_data_complete is false)")
	}

	if primaryKnown {
		applyBranchRules(effective, branchRules)
	} else {
		for id := range applicable {
			if detail, ok := details[id]; ok && detail.Rules != nil {
				applyRulesetRules(effective, detail.Rules)
			}
		}
	}
	rulesetKnown := primaryKnown || (listErr == nil && detailFailures == 0)

	legacy, legacyOutcome, legacyErr := collectJSONObject[github.Protection](ctx, client, store, repoScope,
		"repo.rules", "protection", "repos/"+ownerPath+"/"+repoPath+"/branches/"+url.PathEscape(defaultBranch)+"/protection")
	outcomes = append(outcomes, legacyOutcome)
	effective.LegacySignal = legacyOutcome.Availability
	legacyKnownPresent, legacyKnownAbsent := false, false
	switch {
	case legacyErr == nil && legacy != nil:
		applyLegacyProtection(effective, legacy)
		legacyKnownPresent = true
	case legacyOutcome.HTTPStatus != nil && *legacyOutcome.HTTPStatus == 404:
		// Per GitHub's documented contract for this endpoint, 404 on a readable branch
		// confirms no legacy branch protection, distinct from a concealed 403.
		legacyKnownAbsent = true
	case legacyOutcome.Availability == MissingPermission:
		effective.Notes = append(effective.Notes, "legacy branch protection could not be read due to missing permission; its contribution is unknown, not assumed absent")
	default:
		if legacyErr != nil {
			effective.Notes = append(effective.Notes, "legacy branch protection could not be read; its contribution is unknown, not assumed absent")
		}
	}

	finalizeEffectiveBranchProtection(effective, rulesetKnown, legacyKnownPresent, legacyKnownAbsent)
	return effective, outcomes, nil
}

func finalizeEffectiveBranchProtection(effective *EffectiveBranchProtection, rulesetKnown, legacyKnownPresent, legacyKnownAbsent bool) {
	switch {
	case len(effective.ApplicableRulesets) > 0 && legacyKnownPresent:
		effective.Source = "ruleset+legacy"
	case len(effective.ApplicableRulesets) > 0:
		effective.Source = "ruleset"
	case legacyKnownPresent:
		effective.Source = "legacy"
	case rulesetKnown && legacyKnownAbsent:
		effective.Source = "none"
	default:
		effective.Source = "unknown"
	}
	effective.Unprotected = effective.Source == "none"
	switch {
	case (rulesetKnown || len(effective.ApplicableRulesets) > 0) && (legacyKnownPresent || legacyKnownAbsent):
		effective.Completeness = CollectionOK
	case rulesetKnown || legacyKnownPresent || legacyKnownAbsent || len(effective.ApplicableRulesets) > 0:
		effective.Completeness = CollectionPartial
	default:
		effective.Completeness = CollectionFailed
	}
}

func applyBranchRules(effective *EffectiveBranchProtection, rules *github.BranchRules) {
	for _, rule := range rules.PullRequest {
		if rule == nil {
			continue
		}
		effective.PullRequestRequired = true
		if rule.Parameters.RequiredApprovingReviewCount > effective.MinApprovals {
			effective.MinApprovals = rule.Parameters.RequiredApprovingReviewCount
		}
		effective.CodeOwnerReview = effective.CodeOwnerReview || rule.Parameters.RequireCodeOwnerReview
		effective.StaleDismiss = effective.StaleDismiss || rule.Parameters.DismissStaleReviewsOnPush
	}
	for _, rule := range rules.RequiredStatusChecks {
		if rule == nil {
			continue
		}
		for _, check := range rule.Parameters.RequiredStatusChecks {
			if check != nil {
				effective.StatusChecks = appendUnique(effective.StatusChecks, check.Context)
			}
		}
		effective.Strict = effective.Strict || rule.Parameters.StrictRequiredStatusChecksPolicy
	}
	effective.Signatures = effective.Signatures || len(rules.RequiredSignatures) > 0
	effective.BlockDeletion = effective.BlockDeletion || len(rules.Deletion) > 0
	effective.BlockForcePush = effective.BlockForcePush || len(rules.NonFastForward) > 0
	effective.LinearHistory = effective.LinearHistory || len(rules.RequiredLinearHistory) > 0
	for _, rule := range rules.Workflows {
		if rule == nil {
			continue
		}
		for _, workflow := range rule.Parameters.Workflows {
			if workflow != nil {
				effective.RequiredWorkflows = appendUnique(effective.RequiredWorkflows, workflow.Path)
			}
		}
	}
	effective.CodeScanningGate = effective.CodeScanningGate || len(rules.CodeScanning) > 0
}

func collectBranchRuleIDs(rules *github.BranchRules, ids map[int64]bool) {
	for _, rule := range rules.Creation {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.Update {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.Deletion {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.RequiredLinearHistory {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.RequiredSignatures {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.PullRequest {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.RequiredStatusChecks {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.Workflows {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
	for _, rule := range rules.CodeScanning {
		if rule != nil {
			ids[rule.RulesetID] = true
		}
	}
}

func applyRulesetRules(effective *EffectiveBranchProtection, rules *github.RepositoryRulesetRules) {
	if rules.PullRequest != nil {
		effective.PullRequestRequired = true
		if rules.PullRequest.RequiredApprovingReviewCount > effective.MinApprovals {
			effective.MinApprovals = rules.PullRequest.RequiredApprovingReviewCount
		}
		effective.CodeOwnerReview = effective.CodeOwnerReview || rules.PullRequest.RequireCodeOwnerReview
		effective.StaleDismiss = effective.StaleDismiss || rules.PullRequest.DismissStaleReviewsOnPush
	}
	if rules.RequiredStatusChecks != nil {
		for _, check := range rules.RequiredStatusChecks.RequiredStatusChecks {
			if check != nil {
				effective.StatusChecks = appendUnique(effective.StatusChecks, check.Context)
			}
		}
		effective.Strict = effective.Strict || rules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy
	}
	effective.Signatures = effective.Signatures || rules.RequiredSignatures != nil
	effective.BlockDeletion = effective.BlockDeletion || rules.Deletion != nil
	effective.BlockForcePush = effective.BlockForcePush || rules.NonFastForward != nil
	effective.LinearHistory = effective.LinearHistory || rules.RequiredLinearHistory != nil
	if rules.Workflows != nil {
		for _, workflow := range rules.Workflows.Workflows {
			if workflow != nil {
				effective.RequiredWorkflows = appendUnique(effective.RequiredWorkflows, workflow.Path)
			}
		}
	}
	effective.CodeScanningGate = effective.CodeScanningGate || rules.CodeScanning != nil
}

func applyLegacyProtection(effective *EffectiveBranchProtection, protection *github.Protection) {
	if reviews := protection.RequiredPullRequestReviews; reviews != nil {
		effective.PullRequestRequired = true
		if reviews.RequiredApprovingReviewCount > effective.MinApprovals {
			effective.MinApprovals = reviews.RequiredApprovingReviewCount
		}
		effective.CodeOwnerReview = effective.CodeOwnerReview || reviews.RequireCodeOwnerReviews
		effective.StaleDismiss = effective.StaleDismiss || reviews.DismissStaleReviews
	}
	if checks := protection.RequiredStatusChecks; checks != nil {
		effective.Strict = effective.Strict || checks.Strict
		if checks.Contexts != nil {
			for _, context := range *checks.Contexts {
				effective.StatusChecks = appendUnique(effective.StatusChecks, context)
			}
		}
		if checks.Checks != nil {
			for _, check := range *checks.Checks {
				if check != nil {
					effective.StatusChecks = appendUnique(effective.StatusChecks, check.Context)
				}
			}
		}
	}
	// Admin-only subfields (enforce_admins, allow_force_pushes, allow_deletions,
	// required_signatures) are omitted by GitHub for a non-admin reader. A nil
	// sub-object here means unknown, not "feature disabled": the caller's overall
	// completeness, not this boolean, carries that distinction.
	if protection.EnforceAdmins != nil {
		enabled := protection.EnforceAdmins.Enabled
		effective.EnforceAdmins = &enabled
	}
	if protection.AllowForcePushes != nil && !protection.AllowForcePushes.Enabled {
		effective.BlockForcePush = true
	}
	if protection.AllowDeletions != nil && !protection.AllowDeletions.Enabled {
		effective.BlockDeletion = true
	}
	if protection.RequiredSignatures != nil && protection.RequiredSignatures.Enabled != nil && *protection.RequiredSignatures.Enabled {
		effective.Signatures = true
	}
}

// rulesetAppliesToBranch independently evaluates whether an active, branch-target
// ruleset's ref_name conditions match the given branch. It is used both as the
// sole applicability signal when GitHub's effective-rules endpoint is unavailable,
// and as a cross-check against that endpoint's authoritative contributing-ruleset
// list otherwise.
func rulesetAppliesToBranch(ruleset *github.RepositoryRuleset, branch string) bool {
	if ruleset == nil || ruleset.Target == nil || *ruleset.Target != github.RulesetTargetBranch {
		return false
	}
	if ruleset.Enforcement != github.RulesetEnforcementActive {
		return false
	}
	conditions := ruleset.Conditions
	if conditions == nil || conditions.RefName == nil {
		return false
	}
	included := false
	for _, pattern := range conditions.RefName.Include {
		if refConditionMatches(pattern, branch) {
			included = true
			break
		}
	}
	if !included {
		return false
	}
	for _, pattern := range conditions.RefName.Exclude {
		if refConditionMatches(pattern, branch) {
			return false
		}
	}
	return true
}

// refConditionMatches implements the ruleset condition vocabulary this run
// understands: the "~ALL" and "~DEFAULT_BRANCH" sentinels (this function is only
// ever evaluated against a repository's actual default branch, so both match by
// definition) and fnmatch-style "*"/"**" glob patterns, optionally prefixed with
// "refs/heads/".
func refConditionMatches(pattern, branch string) bool {
	switch pattern {
	case "~ALL", "~DEFAULT_BRANCH":
		return true
	}
	return refGlobMatch(strings.TrimPrefix(pattern, "refs/heads/"), branch)
}

const refGlobDoubleStarPlaceholder = "\x00DOUBLE-STAR\x00"

func refGlobMatch(pattern, value string) bool {
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*\*`, refGlobDoubleStarPlaceholder)
	quoted = strings.ReplaceAll(quoted, `\*`, `[^/]*`)
	quoted = strings.ReplaceAll(quoted, refGlobDoubleStarPlaceholder, `.*`)
	matched, err := regexp.MatchString("^"+quoted+"$", value)
	return err == nil && matched
}

// effectiveRuleTypesPresent lists the profile's documented effective-rule type
// names observed in one confidently assessed EffectiveBranchProtection, for the
// rule_type_coverage dictionary metric.
func effectiveRuleTypesPresent(effective *EffectiveBranchProtection) []string {
	var types []string
	if effective.PullRequestRequired {
		types = append(types, "pull_request")
	}
	if len(effective.StatusChecks) > 0 {
		types = append(types, "required_status_checks")
	}
	if effective.Signatures {
		types = append(types, "required_signatures")
	}
	if effective.BlockDeletion {
		types = append(types, "deletion")
	}
	if effective.BlockForcePush {
		types = append(types, "non_fast_forward")
	}
	if effective.LinearHistory {
		types = append(types, "required_linear_history")
	}
	if len(effective.RequiredWorkflows) > 0 {
		types = append(types, "workflows")
	}
	if effective.CodeScanningGate {
		types = append(types, "code_scanning")
	}
	return types
}
