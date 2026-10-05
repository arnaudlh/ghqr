// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"testing"
	"time"
)

func TestActualReviewCoverageExcludesAuthorsAndMissingPages(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(90 * 24 * time.Hour)
	created := start.Add(time.Hour)
	merged := created.Add(10 * time.Hour)
	prs := []PullRequestObservation{
		{Author: "author", CreatedAt: created, MergedAt: &merged, ReviewsComplete: true,
			Reviews: []ReviewObservation{{Author: "author", SubmittedAt: created.Add(time.Hour), State: "APPROVED"}}},
		{Author: "author", CreatedAt: created, MergedAt: &merged, ReviewsComplete: true,
			Reviews: []ReviewObservation{{Author: "reviewer", SubmittedAt: created.Add(2 * time.Hour), State: "COMMENTED"}}},
	}
	metrics, err := ActivityMetrics(prs, start, end, true)
	if err != nil || metrics["review_coverage_pct"].Number == nil || *metrics["review_coverage_pct"].Number != 50 ||
		*metrics["median_pr_cycle_time_h"].Number != 10 || *metrics["median_time_to_first_review_h"].Number != 2 {
		t.Fatalf("actual review/lifecycle metrics incorrect: %+v %v", metrics, err)
	}
	prs[1].ReviewsComplete = false
	metrics, err = ActivityMetrics(prs, start, end, true)
	if err != nil || metrics["review_coverage_pct"].Status != MetricUnavailable {
		t.Fatal("missing nested pages looked like complete review coverage")
	}
	metrics, err = ActivityMetrics(nil, start, end, true)
	if err != nil || metrics["review_coverage_pct"].Status != MetricUnavailable {
		t.Fatal("zero merged PR population became known coverage")
	}
}

func TestActionsUsesStartedAndCompletedTimestampsAndExplicitDenominator(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(90 * 24 * time.Hour)
	created := start.Add(time.Hour)
	started := created.Add(2 * time.Minute)
	completed := started.Add(10 * time.Minute)
	success, failure, cancelled := "success", "failure", "cancelled"
	runs := []WorkflowRunObservation{
		{CreatedAt: created, StartedAt: &started, CompletedAt: &completed, Conclusion: &success},
		{CreatedAt: created, StartedAt: &started, CompletedAt: &completed, Conclusion: &failure},
		{CreatedAt: created, StartedAt: &started, CompletedAt: &completed, Conclusion: &cancelled},
	}
	metrics, err := ActionsMetrics(runs, start, end, true)
	if err != nil || *metrics["ci_success_rate_90d"].Number != 50 || *metrics["ci_success_rate_90d"].Denominator != 2 ||
		*metrics["median_queue_time_min"].Number != 2 || *metrics["median_run_duration_min"].Number != 10 {
		t.Fatalf("run timing/conclusion metrics incorrect: %+v %v", metrics, err)
	}
	runs[0].CompletedAt = nil
	metrics, err = ActionsMetrics(runs, start, end, true)
	if err != nil || metrics["median_run_duration_min"].Status != MetricUnavailable {
		t.Fatal("omitted completion timestamps were treated as successful duration data")
	}
}

func TestAlertsIncludeOpenAgeAndOnlyRecentFixedLifecycleMTTR(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	window := now.Add(-180 * 24 * time.Hour)
	fixed := now.Add(-time.Hour)
	oldFixed := window.Add(-time.Hour)
	alerts := []AlertObservation{
		{Number: 1, State: "open", CreatedAt: now.Add(-20 * 24 * time.Hour)},
		{Number: 2, State: "fixed", CreatedAt: fixed.Add(-4 * 24 * time.Hour), FixedAt: &fixed},
		{Number: 3, State: "dismissed", CreatedAt: now.Add(-100 * 24 * time.Hour)},
		{Number: 4, State: "fixed", CreatedAt: oldFixed.Add(-40 * 24 * time.Hour), FixedAt: &oldFixed},
	}
	metrics, err := AlertLifecycleMetrics(alerts, window, now, true)
	if err != nil || *metrics["median_open_alert_age_days"].Number != 20 || *metrics["mttr_days"].Number != 4 {
		t.Fatalf("alert ageing/MTTR incorrect: %+v %v", metrics, err)
	}
	metrics, err = AlertLifecycleMetrics(alerts, window, now, false)
	if err != nil || metrics["mttr_days"].Status != MetricUnavailable {
		t.Fatal("incomplete alert pages appeared complete")
	}
}

func TestMembershipUsesCompletePopulationAndDoesNotGuess2FA(t *testing.T) {
	metrics, err := MembershipMetrics(100, 2, 10, true)
	if err != nil || *metrics["owner_ratio_pct"].Number != 2 || *metrics["members_with_2fa_pct"].Number != 90 {
		t.Fatalf("membership ratios incorrect: %+v %v", metrics, err)
	}
	metrics, err = MembershipMetrics(100, 2, 0, false)
	if err != nil || metrics["members_with_2fa_pct"].Status != MetricUnavailable {
		t.Fatal("forbidden 2FA population became compliant")
	}
	metrics, err = MembershipMetrics(0, 0, 0, true)
	if err != nil || metrics["owner_ratio_pct"].Status != MetricUnavailable {
		t.Fatal("empty member population became known ratio")
	}
}
