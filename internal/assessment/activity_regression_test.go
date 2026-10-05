// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"testing"
	"time"
)

func TestCompletedRunWithoutStartAlsoInvalidatesDuration(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(90 * 24 * time.Hour)
	created, began, completed := start.Add(time.Hour), start.Add(2*time.Hour), start.Add(3*time.Hour)
	success := "success"
	metrics, err := ActionsMetrics([]WorkflowRunObservation{
		{CreatedAt: created, StartedAt: &began, CompletedAt: &completed, Conclusion: &success},
		{CreatedAt: created, CompletedAt: &completed, Conclusion: &success},
	}, start, end, true)
	if err != nil || metrics["median_queue_time_min"].Status != MetricUnavailable ||
		metrics["median_run_duration_min"].Status != MetricUnavailable {
		t.Fatal("completed run missing start silently disappeared from duration")
	}
}

func TestMalformedCreationAndReviewObservationsCannotLookClean(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(90 * 24 * time.Hour)
	if _, err := ActionsMetrics([]WorkflowRunObservation{{}}, start, end, true); err == nil {
		t.Fatal("zero run creation silently filtered outside lookback")
	}
	if _, err := ActivityMetrics([]PullRequestObservation{{}}, start, end, true); err == nil {
		t.Fatal("zero PR creation silently filtered outside lookback")
	}
	created, merged := start.Add(time.Hour), start.Add(2*time.Hour)
	metrics, err := ActivityMetrics([]PullRequestObservation{
		{Author: "author", CreatedAt: created, MergedAt: &merged, ReviewsComplete: true,
			Reviews: []ReviewObservation{{Author: "reviewer", State: "APPROVED"}}},
	}, start, end, true)
	if err != nil || metrics["review_coverage_pct"].Status != MetricUnavailable {
		t.Fatal("malformed review timestamp was discarded as a clean denominator")
	}
}

func TestSecretAlertDismissalResolutionsDoNotCountAsRemediation(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	window := now.Add(-180 * 24 * time.Hour)
	closed := now.Add(-time.Hour)
	alerts := []AlertObservation{
		{State: "resolved", Resolution: "false_positive", CreatedAt: closed.Add(-100 * 24 * time.Hour), ClosedAt: &closed},
		{State: "resolved", Resolution: "wont_fix", CreatedAt: closed.Add(-80 * 24 * time.Hour), ClosedAt: &closed},
		{State: "resolved", Resolution: "used_in_tests", CreatedAt: closed.Add(-60 * 24 * time.Hour), ClosedAt: &closed},
		{State: "resolved", Resolution: "revoked", CreatedAt: closed.Add(-2 * 24 * time.Hour), ClosedAt: &closed},
	}
	metrics, err := AlertLifecycleMetrics(alerts, window, now, true)
	if err != nil || metrics["mttr_days"].Number == nil || *metrics["mttr_days"].Number != 2 {
		t.Fatal("dismissed secret alerts distorted fixed-alert MTTR")
	}
	alerts = append(alerts, AlertObservation{State: "resolved", CreatedAt: closed.Add(-time.Hour), ClosedAt: &closed})
	metrics, err = AlertLifecycleMetrics(alerts, window, now, true)
	if err != nil || metrics["mttr_days"].Status != MetricUnavailable {
		t.Fatal("unknown secret-alert resolution was guessed as fixed")
	}
}
