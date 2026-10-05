// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFetchRepositoryPullRequestsSamplesMergedPRsAndCollectsNestedReviews
// exercises nested pagination at both levels: the closed-PR list itself
// spans two pages (>100 total closed PRs across the fixture), and one
// sampled pull request's own review list also spans two pages. Review
// authors include both a human and a bot login to confirm neither is
// specially excluded (only same-author self-reviews are excluded, per the
// already-published ActivityMetrics helper).
func TestFetchRepositoryPullRequestsSamplesMergedPRsAndCollectsNestedReviews(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	const totalMerged = 120
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/fixture-org/widget/pulls":
			page := request.URL.Query().Get("page")
			var prs []map[string]any
			start, end := 1, 100
			if page == "2" {
				start, end = 101, totalMerged
			} else {
				writer.Header().Set("Link", "<"+server.URL+`/repos/fixture-org/widget/pulls?state=closed&sort=updated&direction=desc&per_page=100&page=2>; rel="next"`)
			}
			for number := start; number <= end; number++ {
				merged := base.Add(time.Duration(number) * time.Hour)
				prs = append(prs, map[string]any{
					"number": number, "state": "closed", "user": map[string]any{"login": "octocat"},
					"created_at": merged.Add(-2 * time.Hour).Format(time.RFC3339), "merged_at": merged.Format(time.RFC3339),
				})
			}
			writeJSON(t, writer, prs)
		case request.URL.Path == "/repos/fixture-org/widget/pulls/120/reviews":
			if request.URL.Query().Get("page") == "2" {
				writeJSON(t, writer, []map[string]any{
					{"user": map[string]any{"login": "dependabot[bot]"}, "state": "APPROVED", "submitted_at": base.Format(time.RFC3339)},
				})
				return
			}
			writer.Header().Set("Link", "<"+server.URL+`/repos/fixture-org/widget/pulls/120/reviews?per_page=100&page=2>; rel="next"`)
			writeJSON(t, writer, []map[string]any{
				{"user": map[string]any{"login": "reviewer-human"}, "state": "APPROVED", "submitted_at": base.Add(time.Hour).Format(time.RFC3339)},
			})
		case len(request.URL.Path) > len("/repos/fixture-org/widget/pulls/") && request.URL.Path[:len("/repos/fixture-org/widget/pulls/")] == "/repos/fixture-org/widget/pulls/":
			// Every other sampled PR's reviews: a single empty page.
			writeJSON(t, writer, []map[string]any{})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, outcomes, err := FetchRepositoryPullRequests(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) == 0 {
		t.Fatal("expected collector outcomes to be recorded")
	}
	if !result.Complete {
		t.Fatalf("expected a complete result: %+v", result)
	}
	if result.TotalMergedSeen != totalMerged {
		t.Fatalf("expected to observe all %d merged PRs before sampling, got %d", totalMerged, result.TotalMergedSeen)
	}
	if !result.Sampled || len(result.Observations) != mergedPullRequestSampleCap {
		t.Fatalf("expected the sample to be capped at %d, got %d (sampled=%v)", mergedPullRequestSampleCap, len(result.Observations), result.Sampled)
	}
	// The most recently merged PR (number 120, since merged_at increases with
	// number) must be present in the capped sample with both nested review
	// pages collected.
	found := false
	for _, observation := range result.Observations {
		if observation.MergedAt == nil || !observation.MergedAt.Equal(base.Add(120*time.Hour)) {
			continue
		}
		found = true
		if !observation.ReviewsComplete {
			t.Fatal("expected PR 120's nested review pagination to be complete")
		}
		if len(observation.Reviews) != 2 {
			t.Fatalf("expected both nested review pages for PR 120 to be collected, got %d reviews", len(observation.Reviews))
		}
		authors := map[string]bool{}
		for _, review := range observation.Reviews {
			authors[review.Author] = true
		}
		if !authors["reviewer-human"] || !authors["dependabot[bot]"] {
			t.Fatalf("expected both human and bot review authors to be preserved, got %+v", authors)
		}
	}
	if !found {
		t.Fatal("expected the most recently merged PR to be part of the capped sample")
	}
}

// TestFetchRepositoryPullRequestsIncompleteOnListFailure confirms a failed
// closed-PR list page marks the whole repository result incomplete rather
// than silently reporting zero merged PRs.
func TestFetchRepositoryPullRequestsIncompleteOnListFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		writeJSON(t, writer, map[string]string{"message": "forbidden"})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryPullRequests(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatal("a failed closed-PR list page must mark the result incomplete, not silently clean")
	}
}

// TestFetchRepositoryActionsRunsUsesVerifiedJobCompletionNotUpdatedAt is a
// regression test: the run list response has no completed_at field at all
// (only created_at/updated_at/run_started_at); a stale updated_at timestamp
// (for example from a later unrelated metadata edit) must never be used as a
// stand-in for actual completion. Duration must come from the maximum
// verified job completion time instead.
func TestFetchRepositoryActionsRunsUsesVerifiedJobCompletionNotUpdatedAt(t *testing.T) {
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	started := created.Add(2 * time.Minute)
	staleUpdatedAt := created.Add(30 * 24 * time.Hour) // a much later, unrelated metadata edit
	actualJobCompletion := created.Add(10 * time.Minute)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/actions/runs":
			writeJSON(t, writer, map[string]any{"total_count": 1, "workflow_runs": []map[string]any{
				{
					"id": 1, "status": "completed", "conclusion": "success",
					"created_at": created.Format(time.RFC3339), "updated_at": staleUpdatedAt.Format(time.RFC3339),
					"run_started_at": started.Format(time.RFC3339),
				},
			}})
		case "/repos/fixture-org/widget/actions/runs/1/jobs":
			writeJSON(t, writer, map[string]any{"total_count": 1, "jobs": []map[string]any{
				{"id": 1, "status": "completed", "conclusion": "success", "completed_at": actualJobCompletion.Format(time.RFC3339)},
			}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryActionsRuns(context.Background(), client, store, scope, "fixture-org", "widget", created.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Observations) != 1 {
		t.Fatalf("expected one complete workflow run observation: %+v", result)
	}
	observation := result.Observations[0]
	if observation.CompletedAt == nil {
		t.Fatal("expected a verified job-derived completion timestamp")
	}
	if !observation.CompletedAt.Equal(actualJobCompletion) {
		t.Fatalf("completion must come from verified job data (%s), not the stale updated_at (%s): got %s",
			actualJobCompletion, staleUpdatedAt, observation.CompletedAt)
	}
	if observation.StartedAt == nil || !observation.StartedAt.Equal(started) {
		t.Fatalf("expected run_started_at to be preserved for queue time: %+v", observation.StartedAt)
	}
}

// TestFetchRepositoryActionsRunsMissingJobCompletionStaysUnknown confirms a
// completed run whose jobs never report a completion timestamp leaves
// CompletedAt nil (unknown), never fabricated from updated_at or left as a
// false zero duration.
func TestFetchRepositoryActionsRunsMissingJobCompletionStaysUnknown(t *testing.T) {
	created := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/actions/runs":
			writeJSON(t, writer, map[string]any{"total_count": 1, "workflow_runs": []map[string]any{
				{"id": 2, "status": "completed", "conclusion": "failure", "created_at": created.Format(time.RFC3339)},
			}})
		case "/repos/fixture-org/widget/actions/runs/2/jobs":
			// A job without a completed_at (still mid-flight in some edge case,
			// or the API omitted it) must not synthesize a duration.
			writeJSON(t, writer, map[string]any{"total_count": 1, "jobs": []map[string]any{
				{"id": 2, "status": "in_progress"},
			}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryActionsRuns(context.Background(), client, store, scope, "fixture-org", "widget", created.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 1 || result.Observations[0].CompletedAt != nil || result.Observations[0].StartedAt != nil {
		t.Fatalf("expected an unknown completion/start, not a fabricated value: %+v", result.Observations)
	}
	if result.Observations[0].Conclusion == nil || *result.Observations[0].Conclusion != "failure" {
		t.Fatalf("expected the observed conclusion to be preserved: %+v", result.Observations[0])
	}
}

// TestFetchRepositoryActionsRunsEmptyPopulationStaysUnavailable confirms a
// repository with no workflow runs in the lookback window feeds the
// published ActionsMetrics helper a complete-but-empty population, which it
// reports as unavailable rather than a false zero/100%.
func TestFetchRepositoryActionsRunsEmptyPopulationStaysUnavailable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(t, writer, map[string]any{"total_count": 0, "workflow_runs": []map[string]any{}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)

	result, _, err := FetchRepositoryActionsRuns(context.Background(), client, store, scope, "fixture-org", "widget", now.AddDate(0, 0, -90))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || len(result.Observations) != 0 {
		t.Fatalf("expected a complete, empty population: %+v", result)
	}
	metrics, err := ActionsMetrics(result.Observations, now.AddDate(0, 0, -90), now, result.Complete)
	if err != nil {
		t.Fatal(err)
	}
	if metrics["ci_success_rate_90d"].Status != MetricUnavailable {
		t.Fatalf("a zero-run denominator must report unavailable, not a false rate: %+v", metrics["ci_success_rate_90d"])
	}
}

// TestFetchRepositoryCommitVerificationCountsVerifiedCommits confirms the
// collector counts verified/unverified commits from the single bounded page
// (<=100) of default-branch commits and excludes commits whose verification
// state is entirely absent from both the numerator and denominator.
func TestFetchRepositoryCommitVerificationCountsVerifiedCommits(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/fixture-org/widget/commits" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.URL.Query().Get("sha") != "main" || request.URL.Query().Get("per_page") != "100" {
			t.Errorf("expected sha=main&per_page=100, got %s", request.URL.RawQuery)
		}
		writeJSON(t, writer, []map[string]any{
			{"sha": "a1", "commit": map[string]any{"verification": map[string]any{"verified": true}}},
			{"sha": "a2", "commit": map[string]any{"verification": map[string]any{"verified": false, "reason": "unsigned"}}},
			{"sha": "a3", "commit": map[string]any{}},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryCommitVerification(context.Background(), client, store, scope, "fixture-org", "widget", "main")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.SampledCommits != 2 || result.VerifiedCommits != 1 {
		t.Fatalf("expected 2 known-verification commits (1 verified), a commit with no verification object excluded: %+v", result)
	}
}

// TestFetchRepositoryCommitVerificationUnknownDefaultBranchDoesNotRun
// confirms an unknown default branch produces a not-run outcome rather than
// an arbitrary/incorrect request.
func TestFetchRepositoryCommitVerificationUnknownDefaultBranchDoesNotRun(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, outcome, err := FetchRepositoryCommitVerification(context.Background(), client, store, scope, "fixture-org", "widget", "")
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != NotRun || result.Complete {
		t.Fatalf("expected a not-run outcome for an unknown default branch: %+v %+v", result, outcome)
	}
}

// TestFetchRepositorySecretsAndEnvironmentsCountsProductionReviewersAndNames
// confirms repo.secrets_env counts the production-environment subset (and
// its reviewer configuration) plus Actions secret/variable NAME counts
// only, never a secret or variable value.
func TestFetchRepositorySecretsAndEnvironmentsCountsProductionReviewersAndNames(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/environments":
			writeJSON(t, writer, map[string]any{"total_count": 2, "environments": []map[string]any{
				{"name": "production", "reviewers": []map[string]any{{"type": "User", "reviewer": map[string]any{"login": "octocat"}}}},
				{"name": "staging"},
			}})
		case "/repos/fixture-org/widget/actions/secrets":
			writeJSON(t, writer, map[string]any{"total_count": 1, "secrets": []map[string]any{
				{"name": "DEPLOY_TOKEN", "created_at": "2026-08-01T00:00:00Z", "updated_at": "2026-08-01T00:00:00Z"},
			}})
		case "/repos/fixture-org/widget/actions/variables":
			writeJSON(t, writer, map[string]any{"total_count": 1, "variables": []map[string]any{
				{"name": "BUILD_ENV", "value": "production"},
			}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositorySecretsAndEnvironments(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.EnvironmentsCount != 2 || result.ProductionEnvironmentsCount != 1 ||
		result.ProductionEnvironmentsWithReviewers != 1 || result.ActionsSecretsCount != 1 || result.ActionsVariablesCount != 1 {
		t.Fatalf("unexpected secrets/environments result: %+v", result)
	}
}

// TestFetchRepositoryReleasesCountsPrereleases confirms repo.releases_packages
// collects the full paginated release inventory and its prerelease subset.
func TestFetchRepositoryReleasesCountsPrereleases(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, []map[string]any{
			{"id": 1, "tag_name": "v1.0.0", "prerelease": false},
			{"id": 2, "tag_name": "v1.1.0-rc1", "prerelease": true},
		})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryReleases(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ReleasesCount != 2 || result.PrereleasesCount != 1 {
		t.Fatalf("unexpected releases result: %+v", result)
	}
}

// TestFetchRepositoryDiscussionsProjectsDecodesEnablementSignalAndNilClient
// confirms repo.discussions_projects decodes the documented GraphQL query
// and that a nil GraphQL client is reported as an explicit NotRun outcome.
func TestFetchRepositoryDiscussionsProjectsDecodesEnablementSignalAndNilClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"data": map[string]any{"repository": map[string]any{
			"hasDiscussionsEnabled": true, "hasWikiEnabled": false,
			"discussions": map[string]any{"totalCount": 5}, "projectsV2": map[string]any{"totalCount": 1},
			"issues": map[string]any{"totalCount": 12},
		}}})
	}))
	t.Cleanup(server.Close)
	client := graphQLFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, _, err := FetchRepositoryDiscussionsProjects(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || !result.HasDiscussionsEnabled || result.HasWikiEnabled ||
		result.DiscussionsCount != 5 || result.ProjectsCount != 1 || result.OpenIssuesCount != 12 {
		t.Fatalf("unexpected discussions/projects result: %+v", result)
	}

	nilResult, nilOutcome, err := FetchRepositoryDiscussionsProjects(context.Background(), nil, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if nilResult.Complete || nilOutcome.Status != NotRun || nilOutcome.Reason == "" {
		t.Fatalf("a nil GraphQL client must be an explicit, reasoned NotRun outcome: %+v / %+v", nilResult, nilOutcome)
	}
}
