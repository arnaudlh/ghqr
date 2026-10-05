// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v83/github"
)

// RemainingCollectorIDs lists the catalogue's final six collector IDs this
// file implements, closing out the 67-entry catalogue: organization API
// request insights, organization and enterprise enhanced-billing usage,
// enterprise Copilot seats/metrics, enterprise-wide policy settings
// (GraphQL) and enterprise/organization SCIM-provisioned user inventories.
// It is additive to RunImplementedCollectorIDs.
func RemainingCollectorIDs() []string {
	return []string{
		"org.api_insights", "org.billing", "ent.billing", "ent.copilot", "ent.policies", "ent.scim_users",
	}
}

// deploymentGateOutcome reports a collector feature as deliberately not
// attempted because its REST surface only exists for a specific GitHub
// Deployment (GitHub Enterprise Cloud XOR GitHub Enterprise Server, never
// both): calling the wrong host for it would not produce a meaningful
// "confirmed absence" signal (a 404 there would reflect the wrong
// deployment never having implemented the path at all, not anything about
// whether the feature itself is configured), so no request is made. The
// gate itself keys off the caller-supplied Deployment value (exactly like
// vertical_slice.go's own `if target.Deployment == Server` branch for
// ghes.manage_api), never a host-string guess. Readiness stays Ready (the
// adapter genuinely exists and runs for its supported deployment);
// Availability is the documented Inapplicable value, and Status is NotRun,
// matching every other "not attempted" branch in this package (for example
// FetchOrgProjects's nil-GraphQL-client guard).
func deploymentGateOutcome(collectorID, feature string, scope Scope, reason string) CollectorOutcome {
	return CollectorOutcome{
		CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: Ready,
		Availability: Inapplicable, Status: NotRun, EvidenceRefs: []string{}, Reason: reason,
	}
}

// notConfiguredOutcome reports a collector feature as not attempted because
// required explicit operator configuration (never inferred automatically)
// is absent.
func notConfiguredOutcome(collectorID, feature string, scope Scope, reason string) CollectorOutcome {
	return CollectorOutcome{
		CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: Ready,
		Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{}, Reason: reason,
	}
}

// isoTimestamp formats t as the ISO 8601 UTC instant GitHub's documented API
// Insights min_timestamp/max_timestamp parameters require exactly
// (YYYY-MM-DDTHH:MM:SSZ).
func isoTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// validateCollectionWindow rejects a zero or inverted [since, until] window
// before any request is attempted, matching audit_collectors.go's own
// fetchAuditLog bounds check.
func validateCollectionWindow(collectorID string, since, until time.Time) error {
	if since.IsZero() || until.IsZero() || since.After(until) {
		return fmt.Errorf("%s: requested window is zero or inverted (since=%s, until=%s)", collectorID, since, until)
	}
	return nil
}

// ===== org.api_insights =====

// apiInsightsSummaryStats is GET .../insights/api/summary-stats' (and its
// users/{user_id} and {actor_type}/{actor_id} variants') documented object
// response shape. Pointers distinguish an absent field (the response was
// not the documented shape; unknown) from a confirmed zero count.
type apiInsightsSummaryStats struct {
	TotalRequestCount       *int64 `json:"total_request_count"`
	RateLimitedRequestCount *int64 `json:"rate_limited_request_count"`
}

// apiInsightsTimeStat is one GET .../insights/api/time-stats array entry.
type apiInsightsTimeStat struct {
	Timestamp               *string `json:"timestamp"`
	TotalRequestCount       *int64  `json:"total_request_count"`
	RateLimitedRequestCount *int64  `json:"rate_limited_request_count"`
}

// apiInsightsSubjectStat is one GET .../insights/api/subject-stats array
// entry (a user or GitHub App making API requests within the organization).
type apiInsightsSubjectStat struct {
	SubjectType             *string `json:"subject_type"`
	SubjectName             *string `json:"subject_name"`
	TotalRequestCount       *int64  `json:"total_request_count"`
	RateLimitedRequestCount *int64  `json:"rate_limited_request_count"`
}

// OrgAPIInsightsResult reports org.api_insights' organization-wide request
// volume (summary-stats), its time-bucketed breakdown (time-stats) and its
// per-subject breakdown (subject-stats); it does not attempt the
// documented per-user (summary-stats/users/{user_id}, user-stats/{user_id})
// or per-actor (route-stats/{actor_type}/{actor_id},
// summary-stats/{actor_type}/{actor_id}, time-stats/{actor_type}/{actor_id})
// drill-down variants, each of which requires a caller-supplied specific
// user or actor ID this run does not already enumerate from any other
// collector; implementing them would mean guessing which IDs to query,
// which this package does not do. RequestedMinTimestamp/RequestedMaxTimestamp
// disclose the exact, explicit instants requested (GitHub's own
// documentation describes max_timestamp's default as "30 days ago" but does
// not commit to that default being precise or stable, so this collector
// always supplies both parameters explicitly rather than relying on it).
type OrgAPIInsightsResult struct {
	TotalRequestCount       *int64    `json:"total_request_count"`
	RateLimitedRequestCount *int64    `json:"rate_limited_request_count"`
	TimeStatsBucketsCount   int       `json:"time_stats_buckets_count"`
	SubjectsObservedCount   int       `json:"subjects_observed_count"`
	RequestedMinTimestamp   time.Time `json:"requested_min_timestamp"`
	RequestedMaxTimestamp   time.Time `json:"requested_max_timestamp"`
	DataLagCaveat           string    `json:"data_lag_caveat"`
	Complete                bool      `json:"complete"`
}

// apiInsightsDataLagCaveat is GitHub's own documented processing lag for
// every API Insights endpoint ("Under normal conditions, you can expect API
// data to appear within 4-6 hours after making a request... During
// incidents... it may take longer").
const apiInsightsDataLagCaveat = "API Insights data typically appears 4-6 hours after the underlying request was made " +
	"(longer during incidents); very recent activity within that lag window may be legitimately absent from this " +
	"result, not necessarily zero"

// FetchOrgAPIInsights collects the organization's complete (fully paginated)
// API Insights summary, time-bucketed and per-subject request statistics
// for the exact [since, until] window (GitHub's GHEC-only API Insights
// feature: GET /orgs/{org}/insights/api/summary-stats, .../time-stats and
// .../subject-stats).
func FetchOrgAPIInsights(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string, deployment Deployment, since, until time.Time) (OrgAPIInsightsResult, []CollectorOutcome, error) {
	if err := validateCollectionWindow("org.api_insights", since, until); err != nil {
		return OrgAPIInsightsResult{}, nil, err
	}
	if deployment != Cloud {
		return OrgAPIInsightsResult{}, []CollectorOutcome{deploymentGateOutcome("org.api_insights", "summary", orgScope,
			"API Insights is a GitHub Enterprise Cloud-only REST surface; it is not reachable on this GitHub Enterprise Server host")}, nil
	}
	organizationPath := url.PathEscape(organization)
	window := "min_timestamp=" + url.QueryEscape(isoTimestamp(since)) + "&max_timestamp=" + url.QueryEscape(isoTimestamp(until))

	summary, summaryOutcome, summaryErr := collectJSONObject[apiInsightsSummaryStats](ctx, client, store, orgScope,
		"org.api_insights", "summary", "orgs/"+organizationPath+"/insights/api/summary-stats?"+window)
	timeStats, timeStatsOutcome, timeStatsErr := collectJSONArray[*apiInsightsTimeStat](ctx, client, store, orgScope,
		"org.api_insights", "time", "orgs/"+organizationPath+"/insights/api/time-stats?"+window+"&timestamp_increment=1d", "", true)
	subjects, subjectsOutcome, subjectsErr := collectJSONArray[*apiInsightsSubjectStat](ctx, client, store, orgScope,
		"org.api_insights", "subjects", "orgs/"+organizationPath+"/insights/api/subject-stats?"+window, "", true)

	result := OrgAPIInsightsResult{
		RequestedMinTimestamp: since, RequestedMaxTimestamp: until, DataLagCaveat: apiInsightsDataLagCaveat,
		Complete: summaryErr == nil && timeStatsErr == nil && subjectsErr == nil,
	}
	if summaryErr == nil && summary != nil {
		result.TotalRequestCount = summary.TotalRequestCount
		result.RateLimitedRequestCount = summary.RateLimitedRequestCount
		if !apiInsightsCountValid(summary.TotalRequestCount) || !apiInsightsCountValid(summary.RateLimitedRequestCount) {
			result.Complete = false
			summaryOutcome = markOutcomeIncomplete(summaryOutcome,
				"summary-stats response was missing its documented total_request_count/rate_limited_request_count field, or carried a negative count")
		}
	}
	// Every time-stats/subject-stats array entry is independently validated,
	// not merely counted via len(): an array containing [null] or [{}] (both
	// decode without a JSON error, since every field below is a pointer) must
	// not inflate the observed-bucket/subject counts or be reported
	// Complete=true, and a prior, separately-validated summary result must
	// never be treated as if it vouches for these arrays' own completeness.
	validTimeStats, invalidTimeStats := 0, 0
	for _, entry := range timeStats {
		if entry == nil || entry.Timestamp == nil || *entry.Timestamp == "" ||
			!apiInsightsCountValid(entry.TotalRequestCount) || !apiInsightsCountValid(entry.RateLimitedRequestCount) {
			invalidTimeStats++
			continue
		}
		validTimeStats++
	}
	result.TimeStatsBucketsCount = validTimeStats
	if invalidTimeStats > 0 {
		result.Complete = false
		timeStatsOutcome = markOutcomeIncomplete(timeStatsOutcome, fmt.Sprintf(
			"%d of %d time-stats entries were missing a required field or carried a negative count", invalidTimeStats, len(timeStats)))
	}
	validSubjects, invalidSubjects := 0, 0
	for _, entry := range subjects {
		if entry == nil || entry.SubjectType == nil || *entry.SubjectType == "" || entry.SubjectName == nil || *entry.SubjectName == "" ||
			!apiInsightsCountValid(entry.TotalRequestCount) || !apiInsightsCountValid(entry.RateLimitedRequestCount) {
			invalidSubjects++
			continue
		}
		validSubjects++
	}
	result.SubjectsObservedCount = validSubjects
	if invalidSubjects > 0 {
		result.Complete = false
		subjectsOutcome = markOutcomeIncomplete(subjectsOutcome, fmt.Sprintf(
			"%d of %d subject-stats entries were missing a required field or carried a negative count", invalidSubjects, len(subjects)))
	}
	return result, []CollectorOutcome{summaryOutcome, timeStatsOutcome, subjectsOutcome}, nil
}

// apiInsightsCountValid reports whether a documented API Insights request
// count was actually present (not nil, i.e. not omitted from the response)
// and not a negative, sanity-failing value. A negative or missing count is
// never silently treated as zero.
func apiInsightsCountValid(count *int64) bool {
	return count != nil && *count >= 0
}

// ===== org.billing / ent.billing =====

// legacyBillingGapDisclosure explains why this collector does not call the
// classic per-category GET .../settings/billing/actions, .../packages or
// .../shared-storage endpoints that an earlier profile revision documented:
// go-github's own maintainers note these endpoints "appear to have
// disappeared from the official GitHub v3 API documentation website", and a
// live doc fetch during this phase confirmed the current billing
// documentation page no longer lists them (only advanced-security and the
// enhanced-billing-platform usage/summary endpoints remain current). Calling
// an unverified, possibly retired endpoint and treating its response (or
// absence) as a confident metric would risk exactly the "fabricated legacy
// field" outcome this phase was asked to avoid; this is an explicit,
// disclosed scope reduction, not a silent omission.
const legacyBillingGapDisclosure = "classic per-category GitHub Actions minutes/Packages/shared-storage billing endpoints " +
	"are not queried: they are absent from GitHub's current billing documentation and are not confirmed still current"

// BillingUsageResult is org.billing's and ent.billing's shared enhanced-
// billing-platform usage/GHAS-committer snapshot. UsageItemsCount/
// UsageNetAmountTotal summarize GET .../settings/billing/usage's usageItems
// array (date/product/sku/quantity/unitType/pricePerUnit/grossAmount/
// discountAmount/netAmount, exactly as documented); a nil UsageItemsCount
// (as opposed to zero) means the usageItems key itself was absent from the
// response, not a confirmed empty billing period. UsageNetAmountTotal sums
// only the items whose documented netAmount field was actually present
// (UsageItemsWithUnknownAmountCount discloses how many were excluded from
// that sum, which is reported as a known partial total over a known
// subset, never silently padded with a fabricated 0 for the rest). Advanced
// Security committer fields are *int because GitHub's own documented
// response marks them optional (omitted when GitHub Advanced Security was
// never purchased), never a confirmed zero.
type BillingUsageResult struct {
	TotalAdvancedSecurityCommitters     *int    `json:"total_advanced_security_committers"`
	MaximumAdvancedSecurityCommitters   *int    `json:"maximum_advanced_security_committers"`
	PurchasedAdvancedSecurityCommitters *int    `json:"purchased_advanced_security_committers"`
	UsageItemsCount                     *int    `json:"usage_items_count"`
	UsageItemsWithUnknownAmountCount    int     `json:"usage_items_with_unknown_amount_count"`
	UsageNetAmountTotal                 float64 `json:"usage_net_amount_total"`
	LegacyBillingGapDisclosure          string  `json:"legacy_billing_gap_disclosure"`
	Complete                            bool    `json:"complete"`
}

// billingUsageItem mirrors GET .../settings/billing/usage's documented
// usageItems array entry with every amount/identity field as a pointer.
// go-github's own typed github.UsageItem uses plain (non-pointer) numeric
// fields, which cannot distinguish a genuinely observed 0 from a field the
// response omitted entirely -- exactly the silent "missing netAmount
// collapses into a 0.0 contribution" failure this collector must avoid, so
// a dedicated, fully nullable type is used here instead of reusing the SDK
// type for this one decode.
type billingUsageItem struct {
	NetAmount *float64 `json:"netAmount"`
}

// billingUsageReport mirrors GET .../settings/billing/usage's documented
// top-level response shape. A nil UsageItems means the usageItems key
// itself was absent from the response, distinct from a present, confirmed-
// empty [].
type billingUsageReport struct {
	UsageItems []*billingUsageItem `json:"usageItems"`
}

// FetchOrgBilling collects the organization's GitHub Advanced Security
// active-committer snapshot (GET /orgs/{org}/settings/billing/advanced-
// security) and its enhanced-billing-platform usage report (GET
// /organizations/{org}/settings/billing/usage); both are documented as
// current GHEC-only surfaces.
func FetchOrgBilling(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string, deployment Deployment) (BillingUsageResult, []CollectorOutcome, error) {
	if deployment != Cloud {
		return BillingUsageResult{LegacyBillingGapDisclosure: legacyBillingGapDisclosure}, []CollectorOutcome{deploymentGateOutcome(
			"org.billing", "advanced-security", orgScope,
			"the enhanced billing platform and GHAS committer billing REST surfaces are GitHub Enterprise Cloud-only and are "+
				"not reachable on this GitHub Enterprise Server host")}, nil
	}
	organizationPath := url.PathEscape(organization)
	committers, committersOutcome, committersErr := collectJSONObject[github.ActiveCommitters](ctx, client, store, orgScope,
		"org.billing", "advanced-security", "orgs/"+organizationPath+"/settings/billing/advanced-security")
	usage, usageOutcome, usageErr := collectJSONObject[billingUsageReport](ctx, client, store, orgScope,
		"org.billing", "usage", "organizations/"+organizationPath+"/settings/billing/usage")
	result, usageOutcome := newBillingUsageResult(committers, committersErr, usage, usageErr, usageOutcome)
	return result, []CollectorOutcome{committersOutcome, usageOutcome}, nil
}

// FetchEnterpriseBilling collects the enterprise's enhanced-billing-platform
// usage report (GET /enterprises/{enterprise}/settings/billing/usage).
// GitHub's own documentation addresses this endpoint only via
// api.github.com (curl examples never substitute a GitHub Enterprise Server
// appliance host), and no currently documented enterprise-wide equivalent of
// the organization-level advanced-security committers endpoint was
// confirmed during this phase, so only the usage report is collected here.
// This is a distinct scope from FetchOrgBilling (an enterprise's own usage
// vs. one member organization's usage): neither caller sums the two
// together anywhere in this package, so there is no double-counting risk
// between them.
func FetchEnterpriseBilling(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string, deployment Deployment) (BillingUsageResult, []CollectorOutcome, error) {
	if deployment != Cloud {
		return BillingUsageResult{LegacyBillingGapDisclosure: legacyBillingGapDisclosure}, []CollectorOutcome{deploymentGateOutcome(
			"ent.billing", "usage", entScope,
			"the enhanced billing platform is reachable only via api.github.com; this target's REST client is bound to its "+
				"GitHub Enterprise Server appliance host and cannot reach it")}, nil
	}
	usage, usageOutcome, usageErr := collectJSONObject[billingUsageReport](ctx, client, store, entScope,
		"ent.billing", "usage", "enterprises/"+url.PathEscape(enterpriseSlug)+"/settings/billing/usage")
	result, usageOutcome := newBillingUsageResult(nil, nil, usage, usageErr, usageOutcome)
	return result, []CollectorOutcome{usageOutcome}, nil
}

func newBillingUsageResult(committers *github.ActiveCommitters, committersErr error, usage *billingUsageReport, usageErr error,
	usageOutcome CollectorOutcome) (BillingUsageResult, CollectorOutcome) {
	result := BillingUsageResult{LegacyBillingGapDisclosure: legacyBillingGapDisclosure, Complete: usageErr == nil}
	if committers != nil {
		result.Complete = result.Complete && committersErr == nil
		result.TotalAdvancedSecurityCommitters = committers.TotalAdvancedSecurityCommitters
		result.MaximumAdvancedSecurityCommitters = committers.MaximumAdvancedSecurityCommitters
		result.PurchasedAdvancedSecurityCommitters = committers.PurchasedAdvancedSecurityCommitters
	} else if committersErr != nil {
		result.Complete = false
	}
	if usageErr == nil && usage != nil {
		if usage.UsageItems == nil {
			result.Complete = false
			usageOutcome = markOutcomeIncomplete(usageOutcome, "the usageItems array key was absent from the response, not a confirmed empty billing period")
		} else {
			count := len(usage.UsageItems)
			result.UsageItemsCount = &count
			unknownAmount := 0
			for _, item := range usage.UsageItems {
				if item == nil || item.NetAmount == nil {
					unknownAmount++
					continue
				}
				result.UsageNetAmountTotal += *item.NetAmount
			}
			result.UsageItemsWithUnknownAmountCount = unknownAmount
			if unknownAmount > 0 {
				result.Complete = false
				usageOutcome = markOutcomeIncomplete(usageOutcome, fmt.Sprintf(
					"%d of %d usage items were missing their documented netAmount field; the reported total sums only the "+
						"%d items with a known amount, never a fabricated 0 for the rest", unknownAmount, count, count-unknownAmount))
			}
		}
	}
	return result, usageOutcome
}

// ===== ent.copilot =====

// entCopilotMetricsObservedWindowDays/entCopilotMetricsWindowLimitation
// disclose Copilot's well-documented metrics retention limit (the metrics
// API only ever returns data for roughly the trailing 28 days, regardless
// of how far back `since` is set).
const (
	entCopilotMetricsObservedWindowDays = 28
	entCopilotMetricsWindowLimitation   = "GitHub's Copilot metrics endpoints only retain roughly the trailing 28 days of " +
		"daily usage data regardless of the requested since date; a longer configured lookback cannot be satisfied by this endpoint"
)

// EnterpriseCopilotResult reports ent.copilot's enterprise-wide Copilot seat
// inventory (GET /enterprises/{enterprise}/copilot/billing/seats, fully
// paginated) and its most recent daily usage metrics snapshot (GET
// /enterprises/{enterprise}/copilot/metrics). SeatsReportedTotal is the
// envelope's own documented total_seats scalar (nil if that page could not
// be re-read), kept separate from SeatsReturnedCount (the number of seat
// objects this collector actually paginated through) so a caller can detect
// the two disagreeing -- a real pagination inconsistency, never silently
// resolved. MetricsTotalActiveUsersLatestDay/MetricsTotalEngagedUsersLatestDay
// are pointers: GitHub's documented response marks them optional (omitted
// once a day's results are no longer available), never a confirmed zero.
type EnterpriseCopilotResult struct {
	SeatsReportedTotal                *int64    `json:"seats_reported_total"`
	SeatsReturnedCount                int       `json:"seats_returned_count"`
	SeatsWithRecentActivityCount      int       `json:"seats_with_recent_activity_count"`
	RecentActivityCutoff              time.Time `json:"recent_activity_cutoff"`
	MetricsDaysObserved               int       `json:"metrics_days_observed"`
	MetricsLatestDay                  string    `json:"metrics_latest_day"`
	MetricsTotalActiveUsersLatestDay  *int      `json:"metrics_total_active_users_latest_day"`
	MetricsTotalEngagedUsersLatestDay *int      `json:"metrics_total_engaged_users_latest_day"`
	ObservedWindowDays                int       `json:"observed_window_days"`
	WindowLimitationReason            string    `json:"window_limitation_reason"`
	Complete                          bool      `json:"complete"`
}

// entCopilotSeatsEnvelope decodes only the envelope-level total_seats
// scalar from a seats response page, re-read from page 1's already-
// persisted evidence (collectJSONArray's arrayField unwrapping discards
// every envelope field besides the array itself, so this is a second,
// zero-network read of evidence already on disk, not an extra request).
type entCopilotSeatsEnvelope struct {
	TotalSeats *int64 `json:"total_seats"`
}

// FetchEnterpriseCopilot collects the enterprise's complete Copilot seat
// roster and its daily usage metrics since the later of since or GitHub's
// own ~28-day metrics retention limit, whichever is more recent. now is the
// caller-supplied clock reading (never time.Now() read directly here): a
// replay of previously collected evidence must recompute the exact same
// metrics window/recency cutoff it used at original collection time, not a
// window that keeps drifting forward every time the same evidence is
// re-analyzed.
func FetchEnterpriseCopilot(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string, deployment Deployment, since, now time.Time) (EnterpriseCopilotResult, []CollectorOutcome, error) {
	if deployment != Cloud {
		return EnterpriseCopilotResult{ObservedWindowDays: entCopilotMetricsObservedWindowDays, WindowLimitationReason: entCopilotMetricsWindowLimitation},
			[]CollectorOutcome{deploymentGateOutcome("ent.copilot", "seats", entScope,
				"Copilot for Business seats/metrics are a GitHub Enterprise Cloud feature; a GitHub Enterprise Server appliance "+
					"with Copilot enabled surfaces it through its organizations' own github.com-hosted endpoints, which this "+
					"enterprise-scoped collector does not call")}, nil
	}
	enterprisePath := url.PathEscape(enterpriseSlug)
	seats, seatsOutcome, seatsErr := collectJSONArray[*github.CopilotSeatDetails](ctx, client, store, entScope,
		"ent.copilot", "seats", "enterprises/"+enterprisePath+"/copilot/billing/seats", "seats", true)

	var seatsReportedTotal *int64
	if seatsOutcome.Pages > 0 {
		if raw, _, _, loadErr := store.LoadJSON(entScope, "ent.copilot", pageFeatureName("seats", 1)); loadErr == nil {
			var envelope entCopilotSeatsEnvelope
			if json.Unmarshal(raw, &envelope) == nil {
				seatsReportedTotal = envelope.TotalSeats
			}
		}
	}

	cutoff := now.AddDate(0, 0, -(entCopilotMetricsObservedWindowDays - 1))
	clampedSince := since
	if clampedSince.Before(cutoff) {
		clampedSince = cutoff
	}
	metrics, metricsOutcome, metricsErr := collectJSONArray[*github.CopilotMetrics](ctx, client, store, entScope,
		"ent.copilot", "metrics", "enterprises/"+enterprisePath+"/copilot/metrics?since="+clampedSince.UTC().Format("2006-01-02"), "", true)

	result := EnterpriseCopilotResult{
		SeatsReturnedCount: len(seats), RecentActivityCutoff: since,
		MetricsDaysObserved: len(metrics),
		ObservedWindowDays:  entCopilotMetricsObservedWindowDays, WindowLimitationReason: entCopilotMetricsWindowLimitation,
		Complete: seatsErr == nil && metricsErr == nil,
	}
	if seatsReportedTotal != nil {
		result.SeatsReportedTotal = seatsReportedTotal
		if *seatsReportedTotal != int64(len(seats)) {
			result.Complete = false
			seatsOutcome = markOutcomeIncomplete(seatsOutcome, fmt.Sprintf(
				"the envelope's own total_seats (%d) disagrees with the %d seat objects actually paginated through", *seatsReportedTotal, len(seats)))
		}
	} else {
		result.Complete = false
		seatsOutcome = markOutcomeIncomplete(seatsOutcome, "the seats response envelope's total_seats field could not be re-read")
	}
	// A seat counts as recently active only when its documented
	// last_activity_at falls within the caller's own requested [since, now]
	// window -- any lifetime activity timestamp, however old, previously
	// satisfied this count, which conflated "has ever used Copilot at all"
	// with "is active within the window this run is actually reporting on".
	for _, seat := range seats {
		if seat == nil || seat.LastActivityAt == nil {
			continue
		}
		activityTime := seat.LastActivityAt.Time
		if !activityTime.Before(since) && !activityTime.After(now) {
			result.SeatsWithRecentActivityCount++
		}
	}
	// The metrics array's own ordering is not documented as sorted, and
	// Link-header-paginated pages are concatenated in whatever order they
	// were fetched: this must not assume the LAST array element is the most
	// recent day. Every entry's own documented date is parsed and the
	// greatest valid one wins; an entry with a missing or unparseable date
	// is excluded from the latest-day determination and downgrades
	// Complete, never silently treated as the most recent (or as clean).
	var latestDate time.Time
	invalidDates := 0
	for _, entry := range metrics {
		if entry == nil || entry.Date == "" {
			invalidDates++
			continue
		}
		parsed, err := time.Parse("2006-01-02", entry.Date)
		if err != nil {
			invalidDates++
			continue
		}
		if latestDate.IsZero() || parsed.After(latestDate) {
			latestDate = parsed
			result.MetricsLatestDay = entry.Date
			result.MetricsTotalActiveUsersLatestDay = entry.TotalActiveUsers
			result.MetricsTotalEngagedUsersLatestDay = entry.TotalEngagedUsers
		}
	}
	if invalidDates > 0 {
		result.Complete = false
		metricsOutcome = markOutcomeIncomplete(metricsOutcome, fmt.Sprintf(
			"%d of %d metrics entries had a missing or unparseable date and were excluded from the latest-day determination",
			invalidDates, len(metrics)))
	}
	return result, []CollectorOutcome{seatsOutcome, metricsOutcome}, nil
}

// ===== ent.policies =====

// entPoliciesQuery matches the profile's documented GraphQL query exactly:
// every EnterpriseOwnerInfo policy field it names was independently
// reverified against a schema-generated GraphQL client model during this
// phase (field names/types are current: most are the three-state
// EnterpriseEnabledDisabledSettingValue enum ENABLED/DISABLED/NO_POLICY;
// membersCanCreateRepositoriesSetting, defaultRepositoryPermissionSetting,
// twoFactorRequiredSetting, ipAllowListEnabledSetting,
// ipAllowListForInstalledAppsEnabledSetting,
// notificationDeliveryRestrictionEnabledSetting and
// allowPrivateRepositoryForkingSettingPolicyValue each use their own
// distinct enum; membersCanCreateInternalRepositoriesSetting,
// membersCanCreatePrivateRepositoriesSetting and
// membersCanCreatePublicRepositoriesSetting are plain nullable booleans,
// not enums). This collector does not assume any one encoding: every value
// is decoded generically and reported as its own literal observed string,
// never coerced into a shared true/false policy judgement. If GitHub's
// schema has since renamed or removed a field, the query fails cleanly as a
// whole with a descriptive GraphQL "errors" envelope (handled identically
// to ent.info/org.projects), never a silently wrong value.
const entPoliciesQuery = `query($slug: String!) {
  enterprise(slug: $slug) {
    ownerInfo {
      defaultRepositoryPermissionSetting
      membersCanCreateRepositoriesSetting
      membersCanCreatePublicRepositoriesSetting
      membersCanCreatePrivateRepositoriesSetting
      membersCanCreateInternalRepositoriesSetting
      membersCanChangeRepositoryVisibilitySetting
      membersCanDeleteRepositoriesSetting
      membersCanDeleteIssuesSetting
      membersCanInviteCollaboratorsSetting
      membersCanUpdateProtectedBranchesSetting
      allowPrivateRepositoryForkingSetting
      allowPrivateRepositoryForkingSettingPolicyValue
      twoFactorRequiredSetting
      ipAllowListEnabledSetting
      ipAllowListForInstalledAppsEnabledSetting
      notificationDeliveryRestrictionEnabledSetting
      membersCanViewDependencyInsightsSetting
      organizationProjectsSetting
      repositoryProjectsSetting
      teamDiscussionsSetting
    }
  }
}`

type entPoliciesResponse struct {
	Data struct {
		Enterprise struct {
			OwnerInfo map[string]json.RawMessage `json:"ownerInfo"`
		} `json:"enterprise"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// EnterprisePoliciesResult reports every EnterpriseOwnerInfo policy field
// ent.policies' documented query names, each as its literal observed value
// (an enum string such as "ENABLED"/"DISABLED"/"NO_POLICY", "true"/"false"
// for the plain-boolean fields, or "" when the field was null/absent --
// never coerced into a shared pass/fail judgement). Actions and Copilot
// enterprise policies are not exposed by this GraphQL query at all (the
// profile's own documented gap): they remain covered only by the existing
// ent.actions_permissions REST collector and the ui.ent_policies import
// contract.
type EnterprisePoliciesResult struct {
	Policies map[string]string `json:"policies"`
	Complete bool              `json:"complete"`
}

// entPoliciesFields is the exact set of EnterpriseOwnerInfo fields
// entPoliciesQuery requests, used to validate every requested field was
// actually present in the decoded response (an entirely missing field,
// as opposed to an explicit null, means the query's shape did not match
// what this collector expects and the result cannot be trusted as
// complete).
var entPoliciesFields = []string{
	"defaultRepositoryPermissionSetting", "membersCanCreateRepositoriesSetting",
	"membersCanCreatePublicRepositoriesSetting", "membersCanCreatePrivateRepositoriesSetting",
	"membersCanCreateInternalRepositoriesSetting", "membersCanChangeRepositoryVisibilitySetting",
	"membersCanDeleteRepositoriesSetting", "membersCanDeleteIssuesSetting",
	"membersCanInviteCollaboratorsSetting", "membersCanUpdateProtectedBranchesSetting",
	"allowPrivateRepositoryForkingSetting", "allowPrivateRepositoryForkingSettingPolicyValue",
	"twoFactorRequiredSetting", "ipAllowListEnabledSetting", "ipAllowListForInstalledAppsEnabledSetting",
	"notificationDeliveryRestrictionEnabledSetting", "membersCanViewDependencyInsightsSetting",
	"organizationProjectsSetting", "repositoryProjectsSetting", "teamDiscussionsSetting",
}

// FetchEnterprisePolicies executes ent.policies' GraphQL query against a
// GraphQLEvidence-sourced CollectionClient and normalizes its result. A nil
// client, a GraphQL errors envelope on an HTTP 200 response, or a response
// missing one of entPoliciesFields each leave the result incomplete, never
// silently coerced into a known value.
func FetchEnterprisePolicies(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string) (EnterprisePoliciesResult, CollectorOutcome, error) {
	if client == nil {
		return EnterprisePoliciesResult{}, CollectorOutcome{CollectorID: "ent.policies", Feature: "policies", Scope: entScope,
			Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{}, Reason: "no GraphQL client was available for this target"}, nil
	}
	outcome, raw, err := client.CollectGraphQL(ctx, store, entScope, "ent.policies", "policies", entPoliciesQuery,
		map[string]any{"slug": enterpriseSlug})
	if err != nil {
		return EnterprisePoliciesResult{}, outcome, err
	}
	var response entPoliciesResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return EnterprisePoliciesResult{}, outcome, fmt.Errorf("decode ent.policies response: %w", err)
	}
	if len(response.Errors) > 0 {
		outcome.Status = CollectionFailed
		outcome.Reason = "GraphQL response carried a top-level errors envelope despite HTTP 200"
		return EnterprisePoliciesResult{}, outcome, fmt.Errorf("ent.policies query returned GraphQL errors: %s", response.Errors[0].Message)
	}
	result := EnterprisePoliciesResult{Policies: map[string]string{}, Complete: true}
	missingFields, unsupportedFields := 0, 0
	for _, field := range entPoliciesFields {
		raw, present := response.Data.Enterprise.OwnerInfo[field]
		if !present {
			result.Complete = false
			missingFields++
			continue
		}
		value, ok := decodeEnterprisePolicyValue(raw)
		if !ok {
			result.Complete = false
			unsupportedFields++
			continue
		}
		result.Policies[field] = value
	}
	if !result.Complete {
		reason := ""
		if missingFields > 0 {
			reason = fmt.Sprintf("%d documented ownerInfo policy field(s) were absent from the response shape", missingFields)
		}
		if unsupportedFields > 0 {
			if reason != "" {
				reason += "; "
			}
			reason += fmt.Sprintf("%d field(s) carried a JSON type that is neither a string, boolean, nor null (unsupported, reported unavailable rather "+
				"than a guessed value)", unsupportedFields)
		}
		outcome = markOutcomeIncomplete(outcome, reason)
	}
	return result, outcome, nil
}

// decodeEnterprisePolicyValue normalizes one EnterpriseOwnerInfo policy
// field's raw JSON value into its literal observed string, tolerating both
// the common three-state enum encoding (a JSON string) and the handful of
// plain-boolean fields (a JSON boolean), without assuming which one
// applies. A JSON null is an explicitly observed, legitimate value for some
// fields and decodes to the empty string with ok=true, matching this
// package's existing "empty means a deliberate null" convention. Any other
// JSON type (number, array, object) is not a value this schema is ever
// documented to produce for these fields; ok=false reports it as
// unavailable rather than silently folding it into the same empty-string
// bucket as a legitimate null.
func decodeEnterprisePolicyValue(raw json.RawMessage) (value string, ok bool) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", true
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text, true
	}
	var flag bool
	if json.Unmarshal(raw, &flag) == nil {
		return strconv.FormatBool(flag), true
	}
	return "", false
}

// ===== ent.scim_users =====

// scimUsersPage is the shared SCIM ListResponse envelope every routing mode
// returns (confirmed identical in go-github's SCIMEnterpriseUsers/
// SCIMProvisionedIdentities types): schemas, totalResults, itemsPerPage,
// startIndex and a Resources array. Decoding generically here lets one
// pagination loop serve every routing mode.
type scimUsersPage struct {
	TotalResults *int              `json:"totalResults"`
	ItemsPerPage *int              `json:"itemsPerPage"`
	StartIndex   *int              `json:"startIndex"`
	Resources    []json.RawMessage `json:"Resources"`
}

// scimUserRecord decodes only the fields this collector's own counting,
// cross-page deduplication and consistency checks need from one SCIM user
// resource: its documented id (server-assigned and, per GitHub's SCIM
// schema, always present on every returned resource -- used to detect and
// exclude an accidental duplicate returned across two pages, since SCIM has
// no Link header and a server that mis-honors startIndex could otherwise
// silently double-count) and active flag. A resource missing either is
// treated identically: malformed, excluded, and downgrading.
type scimUserRecord struct {
	ID     *string `json:"id"`
	Active *bool   `json:"active"`
}

// scimUsersPageSize is this collector's own chosen page size for the SCIM
// startIndex/count pagination parameters (GitHub's SCIM endpoints do not
// send an RFC 5988 Link header the way most other REST list endpoints do,
// so this package drives pagination itself using the response's own
// totalResults/itemsPerPage/startIndex fields rather than relying on
// CollectGET's generic Link-header follower).
const scimUsersPageSize = 100

// scimUsersMaxPages bounds the manual pagination loop defensively; at 100
// users/page this covers 100,000 provisioned identities, far beyond any
// real enterprise's SCIM-provisioned population.
const scimUsersMaxPages = 1000

// fetchSCIMUsersAllPages drives one SCIM Users endpoint's full
// startIndex/count pagination to completion against the server's OWN
// validated response (never a fixed page-size assumption, which would skip
// or double-count identities the moment a real server returns a short or
// irregular page): pagination advances by exactly the number of resources
// the server actually returned, cross-page duplicates are detected and
// excluded via each resource's documented id, and every termination path is
// classified explicitly rather than defaulting to Complete=true:
//   - a page whose own startIndex/totalResults disagrees with what this
//     walk requested or previously observed,
//   - an empty page reached before the server's own disclosed totalResults
//     was actually walked (a premature end),
//   - the server never disclosing totalResults at all (an empty {} or a
//     response missing the field entirely means this walk can never prove
//     the roster is exhausted, even if every individual page decoded fine),
//   - hitting scimUsersMaxPages without confirming exhaustion,
//   - a page request failing outright,
//
// each downgrades Complete and records a specific, human-readable reason on
// every outcome returned from this walk (so a caller inspecting any single
// page's outcome still sees the walk's true completeness). Complete=true
// with a zero count is reported only when the server's own typed
// totalResults is explicitly present and equal to 0 -- never inferred from
// an empty or malformed response alone.
func fetchSCIMUsersAllPages(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	collectorID, featurePrefix, basePath string) (totalResults *int, resourcesSeen, active, inactive int, complete bool, outcomes []CollectorOutcome) {
	complete = true
	nextStartIndex := 1
	totalWalked := 0
	seenIDs := map[string]bool{}
	var reasons []string
	note := func(reason string) {
		complete = false
		reasons = append(reasons, reason)
	}

	page := 1
	for ; page <= scimUsersMaxPages; page++ {
		endpoint := basePath + "?startIndex=" + strconv.Itoa(nextStartIndex) + "&count=" + strconv.Itoa(scimUsersPageSize)
		result, outcome, err := collectJSONObject[scimUsersPage](ctx, client, store, scope, collectorID, pageFeatureName(featurePrefix, page), endpoint)
		outcomes = append(outcomes, outcome)
		if err != nil || result == nil {
			note(fmt.Sprintf("page %d could not be collected", page))
			break
		}
		if result.StartIndex != nil && *result.StartIndex != nextStartIndex {
			note(fmt.Sprintf("page %d reported startIndex %d, this walk requested %d", page, *result.StartIndex, nextStartIndex))
		}
		if result.ItemsPerPage != nil && *result.ItemsPerPage != len(result.Resources) {
			note(fmt.Sprintf("page %d reported itemsPerPage %d, but its Resources array actually contained %d entries",
				page, *result.ItemsPerPage, len(result.Resources)))
		}
		if result.TotalResults != nil {
			if totalResults != nil && *totalResults != *result.TotalResults {
				note(fmt.Sprintf("page %d reported totalResults %d, an earlier page reported %d", page, *result.TotalResults, *totalResults))
			}
			totalResults = result.TotalResults
		}
		pageNewlyCounted := 0
		for _, raw := range result.Resources {
			var record scimUserRecord
			if json.Unmarshal(raw, &record) != nil || record.Active == nil || record.ID == nil || *record.ID == "" {
				note(fmt.Sprintf("page %d contained a resource missing its documented id or active field", page))
				continue
			}
			if seenIDs[*record.ID] {
				note(fmt.Sprintf("page %d repeated a resource (id %s) already counted on an earlier page", page, *record.ID))
				continue
			}
			seenIDs[*record.ID] = true
			resourcesSeen++
			pageNewlyCounted++
			if *record.Active {
				active++
			} else {
				inactive++
			}
		}
		totalWalked += len(result.Resources)
		if len(result.Resources) == 0 {
			if totalResults == nil {
				note(fmt.Sprintf("page %d was empty and no totalResults was ever disclosed to confirm the roster is genuinely exhausted", page))
			} else if *totalResults != totalWalked {
				note(fmt.Sprintf("page %d was empty before the disclosed totalResults (%d) matched the %d resources actually walked", page, *totalResults, totalWalked))
			}
			break
		}
		if totalResults != nil && totalWalked >= *totalResults {
			if totalWalked != *totalResults {
				note(fmt.Sprintf("walked %d resources, overshooting the disclosed totalResults of %d", totalWalked, *totalResults))
			}
			break
		}
		if pageNewlyCounted == 0 {
			// A non-empty page that contributed zero genuinely new,
			// validly-counted resources (every entry was a duplicate of an
			// earlier page, or malformed) means this walk cannot make
			// further progress: a server that keeps repeating the same
			// page (or only ever sends malformed entries) without ever
			// disclosing totalResults must not be chased all the way to
			// scimUsersMaxPages real requests.
			note(fmt.Sprintf("page %d contributed no new, validly-counted resources; this walk cannot confirm further progress is possible", page))
			break
		}
		// Advance by the page's actual, validated resource count -- never a
		// fixed scimUsersPageSize assumption, which would skip identities
		// the moment a real server returns a short (or irregular) page.
		nextStartIndex += len(result.Resources)
	}
	if page > scimUsersMaxPages {
		note(fmt.Sprintf("pagination cap of %d pages was reached before the roster was confirmed exhausted", scimUsersMaxPages))
	}
	if totalResults == nil {
		note("the server never disclosed a typed totalResults; this walk cannot prove the roster is complete, even if every individual page decoded cleanly")
	}
	if len(reasons) > 0 {
		reason := strings.Join(reasons, "; ")
		for i := range outcomes {
			outcomes[i] = markOutcomeIncomplete(outcomes[i], reason)
		}
	}
	return totalResults, resourcesSeen, active, inactive, complete, outcomes
}

// EnterpriseSCIMUsersResult reports ent.scim_users' provisioned-identity
// inventory under whichever routing mode was explicitly configured.
// TotalResultsReported is the SCIM server's own disclosed totalResults
// (summed across organizations in "saml_sso" mode, and only ever populated
// when EVERY queried organization disclosed its own total -- a partial sum
// over a subset of organizations is never reported as if it were the
// complete enterprise total); a caller can compare it against org.members'
// member count to detect users outside SCIM provisioning, matching the
// profile's documented intent.
type EnterpriseSCIMUsersResult struct {
	Mode                   string `json:"mode"`
	TotalResultsReported   *int   `json:"total_results_reported"`
	ResourcesReturnedCount int    `json:"resources_returned_count"`
	ActiveCount            int    `json:"active_count"`
	InactiveCount          int    `json:"inactive_count"`
	Complete               bool   `json:"complete"`
}

// FetchEnterpriseSCIMUsers collects the provisioned SCIM user inventory
// under exactly one of three mutually exclusive, explicitly configured
// routing modes -- never inferred from SAML presence, membership counts, or
// any other runtime signal:
//   - "emu": the enterprise-wide Enterprise Managed Users endpoint (GET
//     /scim/v2/enterprises/{enterprise}/Users), GitHub Enterprise Cloud only.
//   - "saml_sso": each configured organization's own SCIM endpoint (GET
//     /scim/v2/organizations/{org}/Users), also GitHub Enterprise Cloud only
//     (a non-EMU Cloud enterprise's member organizations each provision
//     independently).
//   - "ghes": the GitHub Enterprise Server appliance-wide endpoint (GET
//     /scim/v2/Users against the appliance's own host), GitHub Enterprise
//     Server only. Confirmed via the official GHES SCIM documentation,
//     which explicitly directs callers to root every request at
//     HOST/api/v3/scim/v2/ and NOT include an "enterprises/{enterprise}/"
//     (or organization) path segment -- GHES SCIM is not enterprise- or
//     organization-scoped the way the two Cloud routes are.
//
// An empty mode (the default, no explicit Target.SCIMMode configured)
// reports an explicit NotRun outcome and makes no request. A mode
// configured for the wrong Deployment (validateTarget in config.go already
// rejects this combination at configuration time; this is a runtime
// defense-in-depth guard for callers that construct a Target directly,
// bypassing config validation) also makes no request. GitHub's SCIM
// surfaces additionally require a specific credential: every documented
// SCIM auth flow (Cloud EMU's setup-user classic PAT and the admin:enterprise
// read fallback; GHES's classic-PAT-only, fine-grained-PAT-and-App-tokens-
// explicitly-unsupported requirement) specifies a classic personal access
// token; a credential kind other than ClassicPAT is already known unable to
// succeed and no request is attempted. This same, single check also governs
// a replay of already-collected evidence: a replay-mode client's credential
// kind is derived from the original target's genuinely configured
// credential (not forced to a different value for replay), so a genuine
// prior ClassicPAT collection replays cleanly through this unmodified
// check, with no separate replay-specific exemption needed.
func FetchEnterpriseSCIMUsers(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug, mode string, deployment Deployment, organizations []string) (EnterpriseSCIMUsersResult, []CollectorOutcome, error) {
	switch mode {
	case "":
		return EnterpriseSCIMUsersResult{}, []CollectorOutcome{notConfiguredOutcome("ent.scim_users", "routing", entScope,
			"no explicit SCIM routing mode is configured for this target (scim_mode); EMU-vs-SAML-SSO-vs-GHES status is never inferred automatically")}, nil
	case "emu":
		if deployment != Cloud {
			return EnterpriseSCIMUsersResult{Mode: mode}, []CollectorOutcome{deploymentGateOutcome("ent.scim_users", "users", entScope,
				"Enterprise Managed Users SCIM provisioning is a GitHub Enterprise Cloud-only feature; this target is not a cloud deployment")}, nil
		}
	case "saml_sso":
		if deployment != Cloud {
			return EnterpriseSCIMUsersResult{Mode: mode}, []CollectorOutcome{deploymentGateOutcome("ent.scim_users", "users", entScope,
				"non-EMU SAML-SSO organization SCIM provisioning is a GitHub Enterprise Cloud-only feature; use scim_mode "+
					"\"ghes\" for a GitHub Enterprise Server deployment, not \"saml_sso\"")}, nil
		}
		if len(organizations) == 0 {
			return EnterpriseSCIMUsersResult{Mode: mode}, []CollectorOutcome{notConfiguredOutcome("ent.scim_users", "users", entScope,
				"scim_mode \"saml_sso\" has no configured organizations to query; validateTarget already requires at least one, "+
					"so this is a defense-in-depth guard for a Target constructed directly")}, nil
		}
	case "ghes":
		if deployment != Server {
			return EnterpriseSCIMUsersResult{Mode: mode}, []CollectorOutcome{deploymentGateOutcome("ent.scim_users", "users", entScope,
				"scim_mode \"ghes\" is only valid for a GitHub Enterprise Server deployment")}, nil
		}
	default:
		return EnterpriseSCIMUsersResult{}, []CollectorOutcome{notConfiguredOutcome("ent.scim_users", "routing", entScope,
			fmt.Sprintf("unrecognized SCIM routing mode %q", mode))}, fmt.Errorf("ent.scim_users: unrecognized SCIM routing mode %q", mode)
	}
	if client.credentialKind != ClassicPAT {
		return EnterpriseSCIMUsersResult{Mode: mode}, []CollectorOutcome{notConfiguredOutcome("ent.scim_users", "users", entScope,
			"no classic personal access token is configured for this target; GitHub's SCIM endpoints document only classic-PAT "+
				"authentication (fine-grained PATs and GitHub App installation tokens are explicitly unsupported) and are never "+
				"attempted with any other credential kind")}, nil
	}

	switch mode {
	case "emu":
		totalResults, resourcesSeen, active, inactive, complete, outcomes := fetchSCIMUsersAllPages(ctx, client, store, entScope,
			"ent.scim_users", "users", "scim/v2/enterprises/"+url.PathEscape(enterpriseSlug)+"/Users")
		return EnterpriseSCIMUsersResult{
			Mode: mode, TotalResultsReported: totalResults, ResourcesReturnedCount: resourcesSeen,
			ActiveCount: active, InactiveCount: inactive, Complete: complete,
		}, outcomes, nil
	case "ghes":
		// Confirmed via docs.github.com/en/enterprise-server@3.17/rest/enterprise-admin/scim:
		// "Do not include the enterprises/{enterprise}/ portion of the URLs
		// provided in the endpoint documentation below. This part of the
		// path is not applicable to GitHub Enterprise Server." The relative
		// path below resolves against this REST client's own GHES-appliance
		// base (https://HOST/api/v3/), giving the documented
		// https://HOST/api/v3/scim/v2/Users root exactly.
		totalResults, resourcesSeen, active, inactive, complete, outcomes := fetchSCIMUsersAllPages(ctx, client, store, entScope,
			"ent.scim_users", "users", "scim/v2/Users")
		return EnterpriseSCIMUsersResult{
			Mode: mode, TotalResultsReported: totalResults, ResourcesReturnedCount: resourcesSeen,
			ActiveCount: active, InactiveCount: inactive, Complete: complete,
		}, outcomes, nil
	default: // "saml_sso"
		result := EnterpriseSCIMUsersResult{Mode: mode, Complete: true}
		var outcomes []CollectorOutcome
		total := 0
		everyOrganizationDisclosedTotal := len(organizations) > 0
		for _, organization := range organizations {
			orgTotal, resourcesSeen, active, inactive, complete, orgOutcomes := fetchSCIMUsersAllPages(ctx, client, store, entScope,
				"ent.scim_users", safeFeatureName("users", organization), "scim/v2/organizations/"+url.PathEscape(organization)+"/Users")
			outcomes = append(outcomes, orgOutcomes...)
			result.ResourcesReturnedCount += resourcesSeen
			result.ActiveCount += active
			result.InactiveCount += inactive
			if !complete {
				result.Complete = false
			}
			if orgTotal != nil {
				total += *orgTotal
			} else {
				// A single organization's undisclosed total makes the
				// cross-organization SUM unverifiable as a complete
				// enterprise-wide figure, even if every other organization
				// disclosed its own total cleanly: reporting a sum over
				// only the known subset as if it were the whole enterprise
				// would be exactly the "known subset total" overclaim this
				// field must avoid.
				everyOrganizationDisclosedTotal = false
			}
		}
		if everyOrganizationDisclosedTotal {
			result.TotalResultsReported = &total
		}
		return result, outcomes, nil
	}
}
