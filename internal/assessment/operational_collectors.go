// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v83/github"
)

// OperationalCollectorIDs lists the catalogue collector IDs this file
// implements: repo.prs (merged pull request lifecycle and review sampling),
// repo.actions_runs (workflow run success/duration/queue-time sampling),
// repo.commits (default-branch commit signature verification sampling),
// repo.secrets_env (environment/secret/variable inventory),
// repo.releases_packages (release inventory) and repo.discussions_projects
// (Discussions/Wiki/Projects/open-issues enablement via GraphQL). It is
// additive to RunImplementedCollectorIDs, not a replacement for it.
func OperationalCollectorIDs() []string {
	return []string{
		"repo.prs", "repo.actions_runs", "repo.commits",
		"repo.secrets_env", "repo.releases_packages", "repo.discussions_projects",
	}
}

// mergedPullRequestSampleCap mirrors the repo.prs collector's documented
// "last 100 merged PRs is the sample" contract. Review coverage and cycle-time
// metrics computed from this sample are marked Sampled, not exhaustive.
const mergedPullRequestSampleCap = 100

// actionsRunSampleCap mirrors the repo.actions_runs collector's documented
// "cap 1,000 runs per repository (most recent)" contract.
const actionsRunSampleCap = 1000

// RepositoryPullRequestResult is one repository's sampled merged pull-request
// activity evidence plus completeness/sampling provenance for the run adapter.
type RepositoryPullRequestResult struct {
	Repository      string                   `json:"repository"`
	Observations    []PullRequestObservation `json:"observations"`
	Complete        bool                     `json:"complete"`
	Sampled         bool                     `json:"sampled"`
	TotalClosedSeen int                      `json:"total_closed_seen"`
	TotalMergedSeen int                      `json:"total_merged_seen"`
}

// FetchRepositoryPullRequests collects the repository's closed pull-request
// history (fully, nestedly paginated: the closed-PR list itself follows every
// Link "next" page, and so does each sampled pull request's review list) and,
// for the most recently merged mergedPullRequestSampleCap pull requests, each
// pull request's complete review history. The closed-PR listing endpoint
// cannot filter server-side for "merged only", so every closed PR is
// collected and then the merged subset is selected and capped to the
// documented sample size; this keeps the review-fetch request count bounded
// (closer to the <=1,000-node-equivalent collection budget) without silently
// claiming an exhaustive review history. A list-page failure marks the whole
// result incomplete; an individual pull request's incomplete review
// pagination is preserved per-PR via PullRequestObservation.ReviewsComplete,
// which the existing ActivityMetrics helper already treats as invalidating
// review-coverage/first-review metrics rather than presenting a clean PR.
func FetchRepositoryPullRequests(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (RepositoryPullRequestResult, []CollectorOutcome, error) {
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)
	endpoint := "repos/" + ownerPath + "/" + repoPath + "/pulls?state=closed&sort=updated&direction=desc"
	closed, listOutcome, listErr := collectJSONArray[*github.PullRequest](ctx, client, store, scope,
		"repo.prs", "closed", endpoint, "", true)
	outcomes := []CollectorOutcome{listOutcome}
	result := RepositoryPullRequestResult{Repository: owner + "/" + repo, Observations: []PullRequestObservation{}, TotalClosedSeen: len(closed)}
	if listErr != nil {
		result.Complete = false
		return result, outcomes, nil
	}

	merged := make([]*github.PullRequest, 0, len(closed))
	for _, pr := range closed {
		if pr != nil && pr.MergedAt != nil {
			merged = append(merged, pr)
		}
	}
	result.TotalMergedSeen = len(merged)
	sort.Slice(merged, func(i, j int) bool { return merged[i].GetMergedAt().After(merged[j].GetMergedAt().Time) })
	if len(merged) > mergedPullRequestSampleCap {
		merged = merged[:mergedPullRequestSampleCap]
		result.Sampled = true
	}

	for _, pr := range merged {
		createdAt := pr.GetCreatedAt().Time
		mergedAtValue := pr.GetMergedAt().Time
		observation := PullRequestObservation{
			Author: pr.GetUser().GetLogin(), CreatedAt: createdAt, MergedAt: &mergedAtValue, Reviews: []ReviewObservation{},
		}
		reviews, reviewOutcome, reviewErr := collectJSONArray[*github.PullRequestReview](ctx, client, store, scope,
			"repo.prs", fmt.Sprintf("reviews-%d", pr.GetNumber()),
			"repos/"+ownerPath+"/"+repoPath+"/pulls/"+strconv.Itoa(pr.GetNumber())+"/reviews", "", true)
		outcomes = append(outcomes, reviewOutcome)
		observation.ReviewsComplete = reviewErr == nil
		for _, review := range reviews {
			if review == nil {
				continue
			}
			observation.Reviews = append(observation.Reviews, ReviewObservation{
				Author: review.GetUser().GetLogin(), SubmittedAt: review.GetSubmittedAt().Time, State: review.GetState(),
			})
		}
		result.Observations = append(result.Observations, observation)
	}
	result.Complete = true
	return result, outcomes, nil
}

// RepositoryActionsRunsResult is one repository's sampled workflow-run
// activity evidence plus completeness/sampling provenance for the run
// adapter.
type RepositoryActionsRunsResult struct {
	Repository   string                   `json:"repository"`
	Observations []WorkflowRunObservation `json:"observations"`
	Complete     bool                     `json:"complete"`
	Sampled      bool                     `json:"sampled"`
	TotalSeen    int                      `json:"total_seen"`
}

// FetchRepositoryActionsRuns collects workflow runs created on or after since
// (fully paginated, capped to the documented 1,000-most-recent sample) and,
// for every run whose status has reached a conclusion, that run's actual job
// completion data (fully paginated) to compute a verified completion
// timestamp. The run list response itself never includes a `completed_at`
// field (only `created_at`, `updated_at` and `run_started_at`); using
// `updated_at` as a stand-in for completion time would silently conflate
// "last metadata change" with "actual finish time" (for example a later
// re-run attempt or label edit bumps `updated_at` without the run having
// re-completed), so completion is instead derived from the maximum
// `completed_at` across that run's actual jobs, leaving it unknown when no
// job carries a completion timestamp rather than guessing from `updated_at`.
func FetchRepositoryActionsRuns(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string, since time.Time) (RepositoryActionsRunsResult, []CollectorOutcome, error) {
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)
	endpoint := "repos/" + ownerPath + "/" + repoPath + "/actions/runs?created=>=" + since.UTC().Format("2006-01-02")
	runs, listOutcome, listErr := collectJSONArray[*github.WorkflowRun](ctx, client, store, scope,
		"repo.actions_runs", "runs", endpoint, "workflow_runs", true)
	outcomes := []CollectorOutcome{listOutcome}
	result := RepositoryActionsRunsResult{Repository: owner + "/" + repo, Observations: []WorkflowRunObservation{}, TotalSeen: len(runs)}
	if listErr != nil {
		result.Complete = false
		return result, outcomes, nil
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].GetCreatedAt().After(runs[j].GetCreatedAt().Time) })
	if len(runs) > actionsRunSampleCap {
		runs = runs[:actionsRunSampleCap]
		result.Sampled = true
	}

	for _, run := range runs {
		if run == nil {
			continue
		}
		observation := WorkflowRunObservation{CreatedAt: run.GetCreatedAt().Time}
		if run.RunStartedAt != nil {
			startedAt := run.GetRunStartedAt().Time
			observation.StartedAt = &startedAt
		}
		if run.Conclusion != nil {
			conclusion := run.GetConclusion()
			observation.Conclusion = &conclusion
			completedAt, jobsOutcome, _ := fetchWorkflowRunCompletion(ctx, client, store, scope, ownerPath, repoPath, run.GetID())
			outcomes = append(outcomes, jobsOutcome)
			observation.CompletedAt = completedAt
		}
		result.Observations = append(result.Observations, observation)
	}
	result.Complete = true
	return result, outcomes, nil
}

// fetchWorkflowRunCompletion collects one workflow run's actual jobs and
// returns the latest confirmed job completion timestamp, or nil when no job
// carries one (collection failure, no jobs, or every job still incomplete).
func fetchWorkflowRunCompletion(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	ownerPath, repoPath string, runID int64) (*time.Time, CollectorOutcome, error) {
	jobs, outcome, err := collectJSONArray[*github.WorkflowJob](ctx, client, store, scope,
		"repo.actions_runs", fmt.Sprintf("jobs-%d", runID),
		"repos/"+ownerPath+"/"+repoPath+"/actions/runs/"+strconv.FormatInt(runID, 10)+"/jobs", "jobs", true)
	if err != nil {
		return nil, outcome, err
	}
	var latest *time.Time
	for _, job := range jobs {
		if job == nil || job.CompletedAt == nil {
			continue
		}
		completed := job.GetCompletedAt().Time
		if latest == nil || completed.After(*latest) {
			latest = &completed
		}
	}
	return latest, outcome, nil
}

// commitVerificationSampleSize mirrors the repo.commits collector's
// documented "One page of 100 commits" contract: the most recent 100
// default-branch commits, not the repository's exhaustive commit history.
const commitVerificationSampleSize = 100

// RepositoryCommitVerificationResult is GOV-072's verified_commit_ratio_pct
// population: the most recent 100 default-branch commits' signature
// verification status. A commit whose verification state could not be
// confidently observed is excluded from both the numerator and denominator
// (unknown, not unsigned).
type RepositoryCommitVerificationResult struct {
	Repository      string `json:"repository"`
	SampledCommits  int    `json:"sampled_commits"`
	VerifiedCommits int    `json:"verified_commits"`
	Complete        bool   `json:"complete"`
}

// FetchRepositoryCommitVerification collects the most recent single page
// (<=100) of default-branch commits and counts how many carry a confirmed
// verified signature.
func FetchRepositoryCommitVerification(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo, defaultBranch string) (RepositoryCommitVerificationResult, CollectorOutcome, error) {
	result := RepositoryCommitVerificationResult{Repository: owner + "/" + repo}
	if defaultBranch == "" {
		return result, CollectorOutcome{CollectorID: "repo.commits", Feature: "commits", Scope: scope,
			Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{}, Reason: "default branch is unknown"}, nil
	}
	commits, outcome, err := collectJSONArray[*github.RepositoryCommit](ctx, client, store, scope,
		"repo.commits", "commits",
		"repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/commits?sha="+url.QueryEscape(defaultBranch)+
			"&per_page="+strconv.Itoa(commitVerificationSampleSize), "", false)
	if err != nil {
		result.Complete = false
		return result, outcome, nil
	}
	result.Complete = true
	for _, commit := range commits {
		if commit == nil || commit.GetCommit() == nil || commit.GetCommit().Verification == nil {
			continue
		}
		result.SampledCommits++
		if commit.GetCommit().GetVerification().GetVerified() {
			result.VerifiedCommits++
		}
	}
	return result, outcome, nil
}

// repositoryProductionEnvironmentNames are the case-insensitive environment
// name patterns SEC-105/SEC-137 treat as "production" for the
// prod_environments_count/prod_environments_with_reviewers_pct population;
// this is an adapter convention (the profile does not enumerate exact
// names), documented here rather than left implicit.
var repositoryProductionEnvironmentNames = map[string]bool{"production": true, "prod": true}

// RepositorySecretsEnvResult reports repo.secrets_env's actual environment
// and Actions secret/variable inventory: environment counts (including the
// production subset and its reviewer/branch-policy configuration) and
// secret/variable NAME counts only — no secret or variable value is ever
// read into this result (Secrets carries no value field at all; Variables
// values are deliberately never copied out of the decoded response here,
// though the shared Redactor still independently scans every stored raw
// evidence page regardless of which field a credential-shaped string
// appears in).
type RepositorySecretsEnvResult struct {
	EnvironmentsCount                   int  `json:"environments_count"`
	ProductionEnvironmentsCount         int  `json:"prod_environments_count"`
	ProductionEnvironmentsWithReviewers int  `json:"prod_environments_with_reviewers_count"`
	ActionsSecretsCount                 int  `json:"actions_secrets_count"`
	ActionsVariablesCount               int  `json:"actions_variables_count"`
	Complete                            bool `json:"complete"`
}

// FetchRepositorySecretsAndEnvironments collects the repository's complete
// environment inventory (fully paginated) and its complete Actions secret
// and variable NAME inventories (fully paginated). Deployment-branch-policy
// detail and org-visible secrets are left uncollected this round
// (documented as a remaining gap), keeping this collector's actual request
// surface bounded to what prod_environments_count/
// prod_environments_with_reviewers_pct/actions_secrets_count need.
func FetchRepositorySecretsAndEnvironments(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (RepositorySecretsEnvResult, []CollectorOutcome, error) {
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)
	environments, environmentsOutcome, environmentsErr := collectJSONArray[*github.Environment](ctx, client, store, scope,
		"repo.secrets_env", "environments", "repos/"+ownerPath+"/"+repoPath+"/environments", "environments", true)
	secrets, secretsOutcome, secretsErr := collectJSONArray[*github.Secret](ctx, client, store, scope,
		"repo.secrets_env", "secrets", "repos/"+ownerPath+"/"+repoPath+"/actions/secrets", "secrets", true)
	variables, variablesOutcome, variablesErr := collectJSONArray[*github.ActionsVariable](ctx, client, store, scope,
		"repo.secrets_env", "variables", "repos/"+ownerPath+"/"+repoPath+"/actions/variables", "variables", true)
	result := RepositorySecretsEnvResult{
		EnvironmentsCount: len(environments), ActionsSecretsCount: len(secrets), ActionsVariablesCount: len(variables),
		Complete: environmentsErr == nil && secretsErr == nil && variablesErr == nil,
	}
	for _, environment := range environments {
		if environment == nil || !repositoryProductionEnvironmentNames[strings.ToLower(environment.GetName())] {
			continue
		}
		result.ProductionEnvironmentsCount++
		if len(environment.Reviewers) > 0 {
			result.ProductionEnvironmentsWithReviewers++
		}
	}
	return result, []CollectorOutcome{environmentsOutcome, secretsOutcome, variablesOutcome}, nil
}

// RepositoryReleasesResult reports the repository's actual release
// inventory (releases_count) from repo.releases_packages.
// critical_repos_with_attestations_pct (see
// FetchRepositoryAttestationCoverage) collects its own latest-release
// lookup separately, since the two features have different pagination and
// "latest" semantics.
type RepositoryReleasesResult struct {
	ReleasesCount    int  `json:"releases_count"`
	PrereleasesCount int  `json:"prereleases_count"`
	Complete         bool `json:"complete"`
}

// FetchRepositoryReleases collects the repository's complete release
// inventory (fully paginated).
func FetchRepositoryReleases(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (RepositoryReleasesResult, CollectorOutcome, error) {
	releases, outcome, err := collectJSONArray[*github.RepositoryRelease](ctx, client, store, scope,
		"repo.releases_packages", "releases", "repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/releases", "", true)
	result := RepositoryReleasesResult{ReleasesCount: len(releases), Complete: err == nil}
	for _, release := range releases {
		if release != nil && release.GetPrerelease() {
			result.PrereleasesCount++
		}
	}
	return result, outcome, nil
}

// repositoryDiscussionsProjectsQuery matches repo.discussions_projects's
// documented GraphQL query exactly.
const repositoryDiscussionsProjectsQuery = `query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    hasDiscussionsEnabled
    hasWikiEnabled
    discussions(first: 1) { totalCount }
    projectsV2(first: 1) { totalCount }
    issues(states: OPEN) { totalCount }
  }
}`

type repositoryDiscussionsProjectsResponse struct {
	Data struct {
		Repository struct {
			HasDiscussionsEnabled bool `json:"hasDiscussionsEnabled"`
			HasWikiEnabled        bool `json:"hasWikiEnabled"`
			Discussions           struct {
				TotalCount int `json:"totalCount"`
			} `json:"discussions"`
			ProjectsV2 struct {
				TotalCount int `json:"totalCount"`
			} `json:"projectsV2"`
			Issues struct {
				TotalCount int `json:"totalCount"`
			} `json:"issues"`
		} `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// RepositoryDiscussionsProjectsResult is the repository's actual
// Discussions/Wiki/Projects/open-issues enablement signal from
// repo.discussions_projects's documented GraphQL query.
type RepositoryDiscussionsProjectsResult struct {
	HasDiscussionsEnabled bool `json:"has_discussions_enabled"`
	HasWikiEnabled        bool `json:"has_wiki_enabled"`
	DiscussionsCount      int  `json:"discussions_count"`
	ProjectsCount         int  `json:"projects_count"`
	OpenIssuesCount       int  `json:"open_issues_count"`
	Complete              bool `json:"complete"`
}

// FetchRepositoryDiscussionsProjects executes repo.discussions_projects'
// GraphQL query against a GraphQLEvidence-sourced CollectionClient. A nil
// client (no GraphQL client was available for this target) is reported as
// an explicit incomplete result, never a silent zero.
func FetchRepositoryDiscussionsProjects(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (RepositoryDiscussionsProjectsResult, CollectorOutcome, error) {
	if client == nil {
		return RepositoryDiscussionsProjectsResult{}, CollectorOutcome{CollectorID: "repo.discussions_projects", Feature: "discussions-projects",
			Scope: scope, Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{},
			Reason: "no GraphQL client was available for this target"}, nil
	}
	outcome, raw, err := client.CollectGraphQL(ctx, store, scope, "repo.discussions_projects", "discussions-projects",
		repositoryDiscussionsProjectsQuery, map[string]any{"owner": owner, "name": repo})
	if err != nil {
		return RepositoryDiscussionsProjectsResult{}, outcome, err
	}
	var response repositoryDiscussionsProjectsResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return RepositoryDiscussionsProjectsResult{}, outcome, fmt.Errorf("decode repo.discussions_projects response: %w", err)
	}
	if len(response.Errors) > 0 {
		outcome.Status = CollectionFailed
		outcome.Reason = "GraphQL response carried a top-level errors envelope despite HTTP 200"
		return RepositoryDiscussionsProjectsResult{}, outcome, fmt.Errorf(
			"repo.discussions_projects query returned GraphQL errors: %s", response.Errors[0].Message)
	}
	fetched := response.Data.Repository
	return RepositoryDiscussionsProjectsResult{
		HasDiscussionsEnabled: fetched.HasDiscussionsEnabled, HasWikiEnabled: fetched.HasWikiEnabled,
		DiscussionsCount: fetched.Discussions.TotalCount, ProjectsCount: fetched.ProjectsV2.TotalCount,
		OpenIssuesCount: fetched.Issues.TotalCount, Complete: true,
	}, outcome, nil
}
