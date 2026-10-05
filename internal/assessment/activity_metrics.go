// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReviewObservation describes an actual PR review, not repository review settings.
type ReviewObservation struct {
	Author      string    `json:"author"`
	SubmittedAt time.Time `json:"submitted_at"`
	State       string    `json:"state"`
}

// PullRequestObservation preserves the lifecycle and actual review history of a merged PR.
type PullRequestObservation struct {
	Author          string              `json:"author"`
	CreatedAt       time.Time           `json:"created_at"`
	MergedAt        *time.Time          `json:"merged_at"`
	Reviews         []ReviewObservation `json:"reviews"`
	ReviewsComplete bool                `json:"reviews_complete"`
}

// WorkflowRunObservation distinguishes lifecycle timestamps and conclusion states.
type WorkflowRunObservation struct {
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Conclusion  *string    `json:"conclusion"`
}

// AlertObservation supports open ageing and fixed-alert MTTR without guessing closed timestamps.
type AlertObservation struct {
	Number     int        `json:"number"`
	State      string     `json:"state"`
	Severity   string     `json:"severity"`
	Resolution string     `json:"resolution"`
	CreatedAt  time.Time  `json:"created_at"`
	FixedAt    *time.Time `json:"fixed_at"`
	ClosedAt   *time.Time `json:"closed_at"`
}

// ActivityMetrics computes actual merged-PR review coverage and lifecycle medians.
// Missing nested review pages invalidate coverage instead of creating clean PRs.
func ActivityMetrics(prs []PullRequestObservation, windowStart, windowEnd time.Time, complete bool) (map[string]MetricValue, error) {
	result := map[string]MetricValue{}
	keys := []string{"review_coverage_pct", "median_pr_cycle_time_h", "median_time_to_first_review_h"}
	if !complete {
		for _, key := range keys {
			result[key] = unavailableObservation("merged PR collection is incomplete", "merged PRs in the lookback window")
		}
		return result, nil
	}
	cycles, firstReviews := []float64{}, []float64{}
	merged, reviewed := 0.0, 0.0
	reviewsComplete := true
	for _, pr := range prs {
		if pr.CreatedAt.IsZero() {
			return nil, fmt.Errorf("PR creation timestamp is invalid")
		}
		if pr.MergedAt == nil || pr.MergedAt.Before(windowStart) || pr.MergedAt.After(windowEnd) {
			continue
		}
		if pr.MergedAt.Before(pr.CreatedAt) {
			return nil, fmt.Errorf("merged PR lifecycle timestamps are invalid")
		}
		merged++
		cycles = append(cycles, pr.MergedAt.Sub(pr.CreatedAt).Hours())
		if !pr.ReviewsComplete {
			reviewsComplete = false
		}
		var first *time.Time
		for _, review := range pr.Reviews {
			if review.State == "PENDING" {
				continue
			}
			if review.Author == "" || review.SubmittedAt.IsZero() || review.SubmittedAt.Before(pr.CreatedAt) {
				reviewsComplete = false
				continue
			}
			if strings.EqualFold(review.Author, pr.Author) || review.SubmittedAt.After(*pr.MergedAt) {
				continue
			}
			if first == nil || review.SubmittedAt.Before(*first) {
				value := review.SubmittedAt
				first = &value
			}
		}
		if first != nil {
			reviewed++
			firstReviews = append(firstReviews, first.Sub(pr.CreatedAt).Hours())
		}
	}
	if reviewsComplete {
		coverage, err := Percentage(reviewed, merged, "merged PRs with complete non-author review history")
		if err != nil {
			return nil, err
		}
		result["review_coverage_pct"] = coverage
		result["median_time_to_first_review_h"] = medianObservation(firstReviews, "merged PRs with at least one non-author review")
	} else {
		result["review_coverage_pct"] = unavailableObservation("nested PR review pagination is incomplete", "merged PRs")
		result["median_time_to_first_review_h"] = unavailableObservation("nested PR review pagination is incomplete", "reviewed merged PRs")
	}
	result["median_pr_cycle_time_h"] = medianObservation(cycles, "merged PRs in the lookback window")
	return result, nil
}

// ActionsMetrics excludes cancellations/skips from the explicit success/failure denominator.
func ActionsMetrics(runs []WorkflowRunObservation, windowStart, windowEnd time.Time, complete bool) (map[string]MetricValue, error) {
	result := map[string]MetricValue{}
	if !complete {
		for _, key := range []string{"ci_success_rate_90d", "median_run_duration_min", "median_queue_time_min"} {
			result[key] = unavailableObservation("workflow run collection is incomplete", "runs created in lookback window")
		}
		return result, nil
	}
	successes, failures := 0.0, 0.0
	durations, queues := []float64{}, []float64{}
	missingDuration, missingQueue := false, false
	for _, run := range runs {
		if run.CreatedAt.IsZero() {
			return nil, fmt.Errorf("workflow run creation timestamp is invalid")
		}
		if run.CreatedAt.Before(windowStart) || run.CreatedAt.After(windowEnd) {
			continue
		}
		if run.Conclusion != nil {
			switch *run.Conclusion {
			case "success":
				successes++
			case "failure":
				failures++
			}
		}
		if run.StartedAt == nil {
			missingQueue = true
			if run.Conclusion != nil {
				missingDuration = true
			}
			continue
		}
		if run.StartedAt.Before(run.CreatedAt) {
			return nil, fmt.Errorf("workflow run started before creation")
		}
		queues = append(queues, run.StartedAt.Sub(run.CreatedAt).Minutes())
		if run.Conclusion == nil {
			continue
		}
		if run.CompletedAt == nil {
			missingDuration = true
			continue
		}
		if run.CompletedAt.Before(*run.StartedAt) {
			return nil, fmt.Errorf("workflow run completed before starting")
		}
		durations = append(durations, run.CompletedAt.Sub(*run.StartedAt).Minutes())
	}
	rate, err := Percentage(successes, successes+failures, "completed success or failure runs")
	if err != nil {
		return nil, err
	}
	result["ci_success_rate_90d"] = rate
	result["median_run_duration_min"] = medianObservation(durations, "completed workflow runs")
	result["median_queue_time_min"] = medianObservation(queues, "started workflow runs")
	if missingDuration {
		result["median_run_duration_min"] = unavailableObservation("completed run timestamps are omitted", "completed workflow runs")
	}
	if missingQueue {
		result["median_queue_time_min"] = unavailableObservation("run start timestamps are omitted", "lookback workflow runs")
	}
	return result, nil
}

// AlertLifecycleMetrics uses fixed—not dismissed—alerts closed in the specified window for MTTR.
func AlertLifecycleMetrics(alerts []AlertObservation, windowStart, now time.Time, complete bool) (map[string]MetricValue, error) {
	if !complete {
		return map[string]MetricValue{
			"median_open_alert_age_days": unavailableObservation("alert collection is incomplete", "open alerts"),
			"mttr_days":                  unavailableObservation("alert collection is incomplete", "fixed alerts in the lifecycle window"),
		}, nil
	}
	ages, mttr := []float64{}, []float64{}
	missingFix := false
	for _, alert := range alerts {
		if alert.CreatedAt.IsZero() || alert.CreatedAt.After(now) {
			return nil, fmt.Errorf("alert creation timestamp is invalid")
		}
		if alert.State == "open" {
			ages = append(ages, now.Sub(alert.CreatedAt).Hours()/24)
			continue
		}
		if alert.State != "fixed" && alert.State != "resolved" {
			continue
		}
		if alert.State == "resolved" && alert.Resolution != "revoked" {
			switch alert.Resolution {
			case "false_positive", "wont_fix", "used_in_tests":
				continue
			default:
				missingFix = true
				continue
			}
		}
		fixedAt := alert.FixedAt
		if alert.State == "resolved" && fixedAt == nil {
			fixedAt = alert.ClosedAt
		}
		if fixedAt == nil {
			missingFix = true
			continue
		}
		if fixedAt.Before(alert.CreatedAt) || fixedAt.After(now) {
			return nil, fmt.Errorf("alert fix timestamp is invalid")
		}
		if !fixedAt.Before(windowStart) {
			mttr = append(mttr, fixedAt.Sub(alert.CreatedAt).Hours()/24)
		}
	}
	result := map[string]MetricValue{
		"median_open_alert_age_days": medianObservation(ages, "currently open alerts"),
		"mttr_days":                  medianObservation(mttr, "fixed alerts closed in the configured lifecycle window"),
	}
	if missingFix {
		result["mttr_days"] = unavailableObservation("fixed alert timestamp is omitted", "fixed alerts")
	}
	return result, nil
}

// MembershipMetrics rejects incomplete member/admin/2FA populations and impossible subset counts.
func MembershipMetrics(members, owners, withoutTwoFactor int, complete bool) (map[string]MetricValue, error) {
	if !complete {
		return map[string]MetricValue{
			"owner_ratio_pct":      unavailableObservation("member/admin pagination is incomplete", "organization members"),
			"members_with_2fa_pct": unavailableObservation("2FA population unavailable or incomplete", "organization members"),
		}, nil
	}
	ownerRatio, err := Percentage(float64(owners), float64(members), "all organization members")
	if err != nil {
		return nil, err
	}
	twoFactor, err := Percentage(float64(members-withoutTwoFactor), float64(members), "all organization members with 2FA observation")
	if err != nil {
		return nil, err
	}
	return map[string]MetricValue{"owner_ratio_pct": ownerRatio, "members_with_2fa_pct": twoFactor}, nil
}

func unavailableObservation(reason, population string) MetricValue {
	return MetricValue{Status: MetricUnavailable, Reason: reason, Population: population, EvidenceRefs: []string{}}
}

func medianObservation(values []float64, population string) MetricValue {
	if len(values) == 0 {
		return unavailableObservation("population has no eligible observations", population)
	}
	copyValues := append([]float64{}, values...)
	sort.Float64s(copyValues)
	middle := len(copyValues) / 2
	value := copyValues[middle]
	if len(copyValues)%2 == 0 {
		value = (copyValues[middle-1] + copyValues[middle]) / 2
	}
	return MetricValue{Status: MetricKnown, Number: &value, Population: population, EvidenceRefs: []string{}}
}
