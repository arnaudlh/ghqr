// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-github/v83/github"
)

// markOutcomeIncomplete downgrades a transport-successful CollectorOutcome
// (HTTP succeeded, body decoded -- CollectionOK/Complete=true) to explicitly
// reflect a SEMANTIC collection failure this package's own result
// validation detected (a documented required field was missing, null, or
// carried an unrecognized value). The raw outcome alone would otherwise
// look like a clean success to anything reading report.Outcomes or the
// feasibility log, even though the typed Result fed from the same call is
// Complete=false for a specific, disclosed reason. Underlying HTTP-
// transport metadata (HTTPStatus, Pages, CredentialKind, EvidenceRefs) is
// preserved verbatim; only Status/Complete/Reason are overwritten (reasons
// are appended, never silently replaced, if the outcome already carried
// one).
func markOutcomeIncomplete(outcome CollectorOutcome, reason string) CollectorOutcome {
	outcome.Status = CollectionPartial
	outcome.Complete = false
	if outcome.Reason == "" {
		outcome.Reason = reason
	} else {
		outcome.Reason = outcome.Reason + "; " + reason
	}
	return outcome
}

// AuditCollectorIDs lists the catalogue collector IDs this file implements:
// enterprise/organization audit logs, enterprise audit-log streaming
// destinations, organization secret-scanning pattern settings, organization
// secret-scanning/push-ruleset bypass requests and organization security
// campaigns. It is additive to RunImplementedCollectorIDs.
func AuditCollectorIDs() []string {
	return []string{
		"ent.audit_log", "org.audit_log", "ent.audit_log_streams",
		"org.secret_scanning_settings", "org.bypass_requests", "org.campaigns",
	}
}

// auditLogWebRetentionDays/auditLogGitRetentionDays are GitHub's documented,
// fixed retention windows for the audit log ("Using the audit log API for
// your enterprise": web events kept 180 days, Git events kept 7 days). A
// customer's configured lookback can exceed 7 days; this package never
// claims Git-event completeness beyond what GitHub actually retains, and
// reports the achieved coverage explicitly rather than a silent clean zero.
const (
	auditLogWebRetentionDays = 180
	auditLogGitRetentionDays = 7
)

// auditLogActionCategories maps this package's locally classified category
// names to the AuditEntry.Action literal (exact match) or prefix (trailing
// ".", prefix match) that identifies it. These mirror the ent.audit_log/
// org.audit_log collectors' documented phrase list ("phrases used:
// action:org.update_member ; action:org.add_member ; ..."), but are applied
// as a LOCAL classification over one single, full, date-bounded pull rather
// than one live query per phrase: querying this endpoint once per phrase
// would cost up to 13x the request budget against its documented 1,750
// queries/hour enterprise limit, and an event whose action text happens to
// satisfy more than one phrase would be double-counted across separate
// phrase-filtered result sets. A single pull with local classification by
// construction counts every event exactly once.
var auditLogActionCategories = map[string]string{
	"org.update_member":                      "org.update_member",
	"org.add_member":                         "org.add_member",
	"org.remove_member":                      "org.remove_member",
	"repo.access":                            "repo.access",
	"repo.destroy":                           "repo.destroy",
	"repo.transfer":                          "repo.transfer",
	"protected_branch.policy_override":       "protected_branch.policy_override",
	"repository_ruleset.":                    "repository_ruleset",
	"secret_scanning_push_protection.bypass": "secret_scanning_push_protection.bypass",
	"personal_access_token.":                 "personal_access_token",
	"business.update_member_repository_creation_permission": "business.update_member_repository_creation_permission",
	"workflows.":                         "workflows",
	"copilot.":                           "copilot",
	"org.disable_two_factor_requirement": "org.disable_two_factor_requirement",
}

// classifyAuditLogAction reports this package's locally classified category
// name for one audit-log action string, or "" when it matches none of the
// documented phrase categories (most audit-log traffic is routine and
// outside this profile's named security-relevant phrase list).
func classifyAuditLogAction(action string) string {
	if category, exact := auditLogActionCategories[action]; exact {
		return category
	}
	for prefix, category := range auditLogActionCategories {
		if strings.HasSuffix(prefix, ".") && strings.HasPrefix(action, prefix) {
			return category
		}
	}
	return ""
}

// AuditLogResult is the normalized result of one ent.audit_log/org.audit_log
// collection: every retrieved event (deduplicated by the API's own
// `_document_id`, defense in depth against any pagination-boundary repeat),
// classified locally into the documented phrase categories, plus the
// earliest event timestamp actually observed (so a caller can compare the
// achieved coverage against the requested lookback window and GitHub's
// fixed retention limits, rather than assuming the requested window was
// fully satisfied). An entry missing its documented required fields
// (`_document_id`, `action`, a usable timestamp) cannot be classified or
// deduplicated with confidence; it is counted under UnclassifiableEntries
// and downgrades the whole result to Complete=false -- it must never be
// silently excluded while the rest of the result still claims a clean,
// complete category inventory.
type AuditLogResult struct {
	TotalEntries            int            `json:"total_entries"`
	CategoryCounts          map[string]int `json:"category_counts"`
	UnclassifiableEntries   int            `json:"unclassifiable_entries"`
	EarliestEntryAt         *time.Time     `json:"earliest_entry_at,omitempty"`
	RequestedSince          time.Time      `json:"requested_since"`
	RequestedUntil          time.Time      `json:"requested_until"`
	WebRetentionLimitedDays int            `json:"web_retention_limited_days"`
	GitRetentionLimitedDays int            `json:"git_retention_limited_days"`
	Complete                bool           `json:"complete"`
}

// auditEntryTimestamp prefers AuditEntry's documented authoritative event
// time, `@timestamp` (UTC epoch milliseconds; go-github's Timestamp decoder
// already disambiguates seconds vs milliseconds), over the secondary
// `created_at` field, which official GitHub documentation does not
// guarantee is always present. Returns the zero time when neither field
// decoded to a usable value, never a fabricated "now".
func auditEntryTimestamp(entry *github.AuditEntry) time.Time {
	if entry.Timestamp != nil {
		if value := entry.GetTimestamp().Time; !value.IsZero() {
			return value
		}
	}
	if entry.CreatedAt != nil {
		if value := entry.GetCreatedAt().Time; !value.IsZero() {
			return value
		}
	}
	return time.Time{}
}

// fetchAuditLog is the shared implementation for ent.audit_log/org.audit_log:
// one full, cursor-paginated SOURCE pull covering every audit-log event
// GitHub's documented `created:YYYY-MM-DD..YYYY-MM-DD` inclusive, day-only
// range phrase can express for [since, until] -- GitHub's audit-log search
// has no finer-than-day granularity, so the source query can overfetch by
// up to 24h on the since side AND up to 24h on the until side (up to 48h
// combined widening versus the literal requested instants). This package
// never presents that widened source fetch as the actual result: every
// decoded entry's own classified timestamp is filtered back down to the
// exact [since, until] instant range before it is counted, and an entry
// timestamped after until is excluded from CI/security-window metrics just
// as strictly as one before since. include=all covers both web and
// Git-category events; Git events remain subject to GitHub's fixed 7-day
// retention regardless of this parameter or the requested since/until -- a
// wider requested window must never be presented as achieved Git-event
// coverage. Results are ordered oldest-first so pagination cursors remain
// stable as the log continues to grow. A zero or inverted (since after
// until) window is rejected before any request is attempted.
func fetchAuditLog(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	collectorID, basePath string, since, until time.Time) (AuditLogResult, CollectorOutcome, error) {
	if since.IsZero() || until.IsZero() || since.After(until) {
		return AuditLogResult{}, CollectorOutcome{}, fmt.Errorf(
			"%s: requested audit-log window is zero or inverted (since=%s, until=%s)", collectorID, since, until)
	}
	sinceDay, untilDay := since.UTC().Format("2006-01-02"), until.UTC().Format("2006-01-02")
	endpoint := basePath + "?include=all&order=asc&phrase=" + url.QueryEscape("created:"+sinceDay+".."+untilDay)
	entries, outcome, err := collectJSONArray[*github.AuditEntry](ctx, client, store, scope, collectorID, "events", endpoint, "", true)
	result := AuditLogResult{
		CategoryCounts: map[string]int{}, Complete: err == nil,
		RequestedSince:          since,
		RequestedUntil:          until,
		WebRetentionLimitedDays: auditLogWebRetentionDays, GitRetentionLimitedDays: auditLogGitRetentionDays,
	}
	malformedEntries := 0
	seenDocumentIDs := map[string]bool{}
	for _, entry := range entries {
		if entry == nil {
			result.Complete = false
			result.UnclassifiableEntries++
			malformedEntries++
			continue
		}
		documentID := entry.GetDocumentID()
		if documentID == "" {
			// GitHub's documented schema always includes _document_id;
			// its absence is an unexpected response shape this package
			// cannot safely deduplicate against, so the result is
			// downgraded rather than risking a silent undetected repeat.
			result.Complete = false
			malformedEntries++
		} else if seenDocumentIDs[documentID] {
			continue
		} else {
			seenDocumentIDs[documentID] = true
		}
		action := entry.GetAction()
		eventTime := auditEntryTimestamp(entry)
		if action == "" || eventTime.IsZero() {
			result.UnclassifiableEntries++
			result.Complete = false
			malformedEntries++
			continue
		}
		// Trim the day-granular source query's over-fetched edges back to
		// the exact requested instants: an entry outside [since, until]
		// must never be silently folded into a result that claims to
		// reflect that exact window.
		if eventTime.Before(since) || eventTime.After(until) {
			continue
		}
		result.TotalEntries++
		if category := classifyAuditLogAction(action); category != "" {
			result.CategoryCounts[category]++
		}
		if result.EarliestEntryAt == nil || eventTime.Before(*result.EarliestEntryAt) {
			result.EarliestEntryAt = &eventTime
		}
	}
	if malformedEntries > 0 {
		outcome = markOutcomeIncomplete(outcome, fmt.Sprintf(
			"%d of %d retrieved audit-log entries were missing a required _document_id/action/timestamp field",
			malformedEntries, len(entries)))
	}
	return result, outcome, nil
}

// FetchOrgAuditLog collects an organization's audit log (GET
// /orgs/{org}/audit-log, read:audit_log scope or organization-owner
// credentials; documented 1,750 queries/hour rate limit applies to this
// endpoint specifically).
func FetchOrgAuditLog(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string, since, until time.Time) (AuditLogResult, CollectorOutcome, error) {
	return fetchAuditLog(ctx, client, store, orgScope, "org.audit_log", "orgs/"+url.PathEscape(organization)+"/audit-log", since, until)
}

// FetchEnterpriseAuditLog collects an enterprise's audit log (GET
// /enterprises/{enterprise}/audit-log, read:audit_log scope or enterprise
// owner/classic PAT credentials).
func FetchEnterpriseAuditLog(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string, since, until time.Time) (AuditLogResult, CollectorOutcome, error) {
	return fetchAuditLog(ctx, client, store, entScope, "ent.audit_log",
		"enterprises/"+url.PathEscape(enterpriseSlug)+"/audit-log", since, until)
}

// auditLogStream is go-github's missing typed shape for GET
// /enterprises/{enterprise}/audit-log/streams (confirmed against the
// documented response: id, stream_type, enabled, paused_at). The profile's
// own notes use "paused" informally; the actual API field is paused_at (a
// nullable timestamp, not a boolean), which this type preserves verbatim
// rather than guessing an equivalent boolean. Enabled is a pointer so an
// omitted value (a malformed or unexpected response shape, since the
// documented schema always includes it) is distinguishable from a
// genuinely observed `false`.
type auditLogStream struct {
	ID         *int64            `json:"id"`
	StreamType *string           `json:"stream_type"`
	Enabled    *bool             `json:"enabled"`
	PausedAt   *github.Timestamp `json:"paused_at"`
}

// EnterpriseAuditLogStreamsResult is ent.audit_log_streams' actual streaming
// destination inventory: how many are configured, enabled and currently
// paused (paused_at is non-nil), from the real API response rather than a
// guessed "paused" boolean. A stream missing its documented id/enabled
// fields cannot be counted with confidence and downgrades the whole result
// to Complete=false rather than silently counting it as disabled.
type EnterpriseAuditLogStreamsResult struct {
	StreamsCount int  `json:"streams_count"`
	EnabledCount int  `json:"enabled_count"`
	PausedCount  int  `json:"paused_count"`
	Complete     bool `json:"complete"`
}

// FetchEnterpriseAuditLogStreams collects the enterprise's complete
// audit-log streaming destination inventory (GET
// /enterprises/{enterprise}/audit-log/streams). The companion GET
// .../streams/{stream_id} single-stream detail endpoint is not separately
// probed: the list response already carries every field this result reports.
func FetchEnterpriseAuditLogStreams(ctx context.Context, client *CollectionClient, store *EvidenceStore, entScope Scope,
	enterpriseSlug string) (EnterpriseAuditLogStreamsResult, CollectorOutcome, error) {
	streams, outcome, err := collectJSONArray[*auditLogStream](ctx, client, store, entScope,
		"ent.audit_log_streams", "streams", "enterprises/"+url.PathEscape(enterpriseSlug)+"/audit-log/streams", "", false)
	result := EnterpriseAuditLogStreamsResult{StreamsCount: len(streams), Complete: err == nil}
	malformed := 0
	for _, stream := range streams {
		if stream == nil || stream.ID == nil || stream.Enabled == nil {
			result.Complete = false
			malformed++
			continue
		}
		if *stream.Enabled {
			result.EnabledCount++
		}
		if stream.PausedAt != nil {
			result.PausedCount++
		}
	}
	if malformed > 0 {
		outcome = markOutcomeIncomplete(outcome, fmt.Sprintf(
			"%d of %d audit-log streams were missing a required id/enabled field", malformed, result.StreamsCount))
	}
	return result, outcome, nil
}

// secretScanningPatternSetting enumerates the documented push-protection
// setting values (GET /orgs/{org}/secret-scanning/pattern-configurations):
// `setting` is one of not-set/disabled/enabled, `default_setting` is one of
// disabled/enabled (it never reports "not-set" itself), and
// `enterprise_setting` is one of not-set/disabled/enabled or JSON null.
func validSecretScanningSetting(value string, allowNotSet bool) bool {
	switch value {
	case "disabled", "enabled":
		return true
	case "not-set":
		return allowNotSet
	default:
		return false
	}
}

// secretScanningPatternOverride is one entry from GET
// /orgs/{org}/secret-scanning/pattern-configurations' provider_pattern_overrides
// or custom_pattern_overrides array (confirmed against the documented
// response shape). EnterpriseSetting is a pointer: the documented schema
// allows it to be JSON null (no enterprise-level constraint configured),
// which is a legitimate known value, distinct from the field being entirely
// absent from a malformed response.
type secretScanningPatternOverride struct {
	TokenType         string  `json:"token_type"`
	Slug              string  `json:"slug"`
	DisplayName       string  `json:"display_name"`
	Setting           string  `json:"setting"`
	DefaultSetting    string  `json:"default_setting"`
	EnterpriseSetting *string `json:"enterprise_setting"`
}

// secretScanningPatternConfiguration is GET
// /orgs/{org}/secret-scanning/pattern-configurations' envelope. The override
// slices are left as their natural Go zero value (nil) when the
// corresponding JSON key is entirely absent, which this package
// distinguishes from an explicitly returned empty array -- GitHub's
// documented schema declares both arrays always present, so their absence
// indicates a response shape this package does not trust as a confirmed
// empty configuration.
type secretScanningPatternConfiguration struct {
	PatternConfigVersion     string                          `json:"pattern_config_version"`
	ProviderPatternOverrides []secretScanningPatternOverride `json:"provider_pattern_overrides"`
	CustomPatternOverrides   []secretScanningPatternOverride `json:"custom_pattern_overrides"`
}

// OrgSecretScanningSettingsResult is org.secret_scanning_settings' actual
// per-pattern override inventory. These are EXPLICIT override tallies only
// (the literal `setting` value this organization has configured), never an
// "effective"/"operational" enablement figure: a pattern reporting
// "not-set" inherits its enablement from default_setting (itself
// potentially further constrained by a non-null enterprise_setting), and
// this package does not derive that combined effective value without a
// fully documented precedence specification it does not currently have --
// deriving one here would risk silently mislabeling an inherited-enabled
// pattern as disabled, or vice versa. Custom-pattern DEFINITION content (the
// regular expression itself) has no public REST list endpoint at all per
// the profile's own notes; only the override/enablement state this
// endpoint actually returns is reported here.
type OrgSecretScanningSettingsResult struct {
	ProviderPatternOverridesCount          int  `json:"provider_pattern_overrides_count"`
	ProviderPatternsExplicitlyEnabledCount int  `json:"provider_patterns_explicitly_enabled_count"`
	CustomPatternOverridesCount            int  `json:"custom_pattern_overrides_count"`
	CustomPatternsExplicitlyEnabledCount   int  `json:"custom_patterns_explicitly_enabled_count"`
	Complete                               bool `json:"complete"`
}

// FetchOrgSecretScanningSettings collects the organization's actual
// secret-scanning pattern enablement overrides (GET
// /orgs/{org}/secret-scanning/pattern-configurations). This endpoint's 404
// semantics (a confirmed "no overrides configured" versus GHAS not enabled
// for the organization versus a permission gap) are not independently
// verified against official documentation, so any non-2xx or decode failure
// is preserved as Complete=false/unknown here. A decoded response whose
// override arrays are both entirely absent (not merely empty), or whose
// enum fields carry an unrecognized value, is also Complete=false: it is
// never silently treated as a confirmed empty/clean configuration.
func FetchOrgSecretScanningSettings(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgSecretScanningSettingsResult, CollectorOutcome, error) {
	configuration, outcome, err := collectJSONObject[secretScanningPatternConfiguration](ctx, client, store, orgScope,
		"org.secret_scanning_settings", "pattern-configurations",
		"orgs/"+url.PathEscape(organization)+"/secret-scanning/pattern-configurations")
	if err != nil || configuration == nil {
		return OrgSecretScanningSettingsResult{}, outcome, err
	}
	if configuration.ProviderPatternOverrides == nil || configuration.CustomPatternOverrides == nil {
		outcome = markOutcomeIncomplete(outcome,
			"provider_pattern_overrides/custom_pattern_overrides were entirely absent from the response, not confirmed empty")
		return OrgSecretScanningSettingsResult{}, outcome, nil
	}
	result := OrgSecretScanningSettingsResult{
		ProviderPatternOverridesCount: len(configuration.ProviderPatternOverrides),
		CustomPatternOverridesCount:   len(configuration.CustomPatternOverrides),
		Complete:                      true,
	}
	invalidOverrides := 0
	countOverrides := func(overrides []secretScanningPatternOverride) int {
		explicitlyEnabled := 0
		for _, override := range overrides {
			if !validSecretScanningSetting(override.Setting, true) || !validSecretScanningSetting(override.DefaultSetting, false) ||
				(override.EnterpriseSetting != nil && !validSecretScanningSetting(*override.EnterpriseSetting, true)) {
				result.Complete = false
				invalidOverrides++
				continue
			}
			if override.Setting == "enabled" {
				explicitlyEnabled++
			}
		}
		return explicitlyEnabled
	}
	result.ProviderPatternsExplicitlyEnabledCount = countOverrides(configuration.ProviderPatternOverrides)
	result.CustomPatternsExplicitlyEnabledCount = countOverrides(configuration.CustomPatternOverrides)
	if invalidOverrides > 0 {
		outcome = markOutcomeIncomplete(outcome, fmt.Sprintf(
			"%d pattern overrides carried an unrecognized setting/default_setting/enterprise_setting value", invalidOverrides))
	}
	return result, outcome, nil
}

// orgBypassRequestStatus is the full documented status enum across both
// GET /orgs/{org}/bypass-requests/secret-scanning and GET
// /orgs/{org}/bypass-requests/push-rules response entries (the push-rules
// endpoint's own documented response schema lists `pending` as a possible
// status alongside the request_status *filter*'s narrower enum, which omits
// it -- the filter enum and the actual response enum are not identical).
var orgBypassRequestStatuses = map[string]bool{
	"pending": true, "open": true, "approved": true, "denied": true,
	"completed": true, "cancelled": true, "expired": true, "deleted": true,
}

// orgBypassRequestTimePeriod is the widest window the documented
// time_period filter accepts (hour/day/week/month; default day = the past
// 24 hours only). "month" is this endpoint's actual maximum -- it can never
// be used to claim a full 90-day (or longer) bypass-request inventory
// matching a customer's configured lookback; only the achieved ~1-month
// window is ever reported.
const orgBypassRequestTimePeriod = "month"

// orgBypassRequestObservedWindowDays is the approximate number of days the
// documented time_period=month filter actually covers. This is an explicit
// field on OrgBypassRequestsResult (not merely a code comment) so a
// consumer comparing it against a longer configured customer lookback (for
// example 90 days) can programmatically detect the gap rather than having
// to read source comments.
const orgBypassRequestObservedWindowDays = 30

// orgBypassRequestWindowLimitation is OrgBypassRequestsResult's explicit,
// always-populated disclosure that this collector's achieved window is
// capped at the bypass-requests API's own maximum, independent of whatever
// lookback window the customer configured for the rest of this run.
const orgBypassRequestWindowLimitation = "the bypass-requests API's time_period filter maxes out at \"month\" " +
	"(~30 days); it cannot reflect a longer configured customer lookback (for example 90 days)"

// orgBypassRequest is the shared shape for both GET
// /orgs/{org}/bypass-requests/secret-scanning and GET
// /orgs/{org}/bypass-requests/push-rules list responses (id, status).
type orgBypassRequest struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

// OrgBypassRequestsResult is org.bypass_requests' actual secret-scanning and
// push-ruleset bypass-request inventory, bounded to the documented
// time_period=month maximum window (counts only; the request's underlying
// commit/file content is not read by this collector). ObservedWindowDays/
// WindowLimitationReason make that cap an explicit, always-present field
// rather than only a source-code comment. PendingCount is tracked distinctly
// from OpenCount per the documented response status enum. A request
// missing/carrying an unrecognized status cannot be classified and
// downgrades the whole result to Complete=false.
type OrgBypassRequestsResult struct {
	SecretScanningRequestsCount int    `json:"secret_scanning_bypass_requests_count"`
	SecretScanningOpenCount     int    `json:"secret_scanning_bypass_requests_open_count"`
	SecretScanningPendingCount  int    `json:"secret_scanning_bypass_requests_pending_count"`
	PushRulesRequestsCount      int    `json:"push_rules_bypass_requests_count"`
	PushRulesOpenCount          int    `json:"push_rules_bypass_requests_open_count"`
	PushRulesPendingCount       int    `json:"push_rules_bypass_requests_pending_count"`
	ObservedWindowDays          int    `json:"observed_window_days"`
	WindowLimitationReason      string `json:"window_limitation_reason"`
	Complete                    bool   `json:"complete"`
}

// FetchOrgBypassRequests collects the organization's complete (paginated)
// secret-scanning and push-ruleset bypass-request inventories, each bounded
// to the documented time_period=month maximum (the default is day, the past
// 24 hours only, if this parameter is omitted).
func FetchOrgBypassRequests(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgBypassRequestsResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	secretScanning, secretScanningOutcome, secretScanningErr := collectJSONArray[*orgBypassRequest](ctx, client, store, orgScope,
		"org.bypass_requests", "secret-scanning",
		"orgs/"+organizationPath+"/bypass-requests/secret-scanning?time_period="+orgBypassRequestTimePeriod, "", true)
	pushRules, pushRulesOutcome, pushRulesErr := collectJSONArray[*orgBypassRequest](ctx, client, store, orgScope,
		"org.bypass_requests", "push-rules",
		"orgs/"+organizationPath+"/bypass-requests/push-rules?time_period="+orgBypassRequestTimePeriod, "", true)
	result := OrgBypassRequestsResult{
		SecretScanningRequestsCount: len(secretScanning), PushRulesRequestsCount: len(pushRules),
		ObservedWindowDays: orgBypassRequestObservedWindowDays, WindowLimitationReason: orgBypassRequestWindowLimitation,
		Complete: secretScanningErr == nil && pushRulesErr == nil,
	}
	secretScanningInvalid := 0
	for _, request := range secretScanning {
		if request == nil || !orgBypassRequestStatuses[request.Status] {
			result.Complete = false
			secretScanningInvalid++
			continue
		}
		switch request.Status {
		case "open":
			result.SecretScanningOpenCount++
		case "pending":
			result.SecretScanningPendingCount++
		}
	}
	if secretScanningInvalid > 0 {
		secretScanningOutcome = markOutcomeIncomplete(secretScanningOutcome, fmt.Sprintf(
			"%d of %d secret-scanning bypass requests were missing or had an unrecognized status",
			secretScanningInvalid, result.SecretScanningRequestsCount))
	}
	pushRulesInvalid := 0
	for _, request := range pushRules {
		if request == nil || !orgBypassRequestStatuses[request.Status] {
			result.Complete = false
			pushRulesInvalid++
			continue
		}
		switch request.Status {
		case "open":
			result.PushRulesOpenCount++
		case "pending":
			result.PushRulesPendingCount++
		}
	}
	if pushRulesInvalid > 0 {
		pushRulesOutcome = markOutcomeIncomplete(pushRulesOutcome, fmt.Sprintf(
			"%d of %d push-rule bypass requests were missing or had an unrecognized status",
			pushRulesInvalid, result.PushRulesRequestsCount))
	}
	return result, []CollectorOutcome{secretScanningOutcome, pushRulesOutcome}, nil
}

// orgCampaignStates is the documented state enum for GET
// /orgs/{org}/campaigns.
var orgCampaignStates = map[string]bool{"open": true, "closed": true}

// orgCampaign is GET /orgs/{org}/campaigns' per-entry shape (number, name,
// state, ends_at; confirmed against the documented response).
type orgCampaign struct {
	Number int               `json:"number"`
	Name   string            `json:"name"`
	State  string            `json:"state"`
	EndsAt *github.Timestamp `json:"ends_at"`
}

// OrgCampaignsResult is org.campaigns' actual open/closed security-campaign
// inventory. A campaign missing its documented number or carrying an
// unrecognized state cannot be classified and downgrades the whole result
// to Complete=false.
type OrgCampaignsResult struct {
	OpenCount   int  `json:"open_campaigns_count"`
	ClosedCount int  `json:"closed_campaigns_count"`
	Complete    bool `json:"complete"`
}

// FetchOrgCampaigns collects the organization's complete (paginated) open
// and closed security-campaign inventories (the endpoint has no "all states"
// mode, so both are queried separately and summed, matching the profile's
// own documented two-call contract).
func FetchOrgCampaigns(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgCampaignsResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	open, openOutcome, openErr := collectJSONArray[*orgCampaign](ctx, client, store, orgScope,
		"org.campaigns", "open", "orgs/"+organizationPath+"/campaigns?state=open", "", true)
	closed, closedOutcome, closedErr := collectJSONArray[*orgCampaign](ctx, client, store, orgScope,
		"org.campaigns", "closed", "orgs/"+organizationPath+"/campaigns?state=closed", "", true)
	result := OrgCampaignsResult{Complete: openErr == nil && closedErr == nil}
	classify := func(campaigns []*orgCampaign, expectedState string) int {
		invalid := 0
		for _, campaign := range campaigns {
			if campaign == nil || campaign.Number == 0 || campaign.State != expectedState || !orgCampaignStates[campaign.State] {
				result.Complete = false
				invalid++
				continue
			}
			switch campaign.State {
			case "open":
				result.OpenCount++
			case "closed":
				result.ClosedCount++
			}
		}
		return invalid
	}
	if invalid := classify(open, "open"); invalid > 0 {
		openOutcome = markOutcomeIncomplete(openOutcome, fmt.Sprintf(
			"%d of %d open-state campaigns were missing number/state or carried an unrecognized state", invalid, len(open)))
	}
	if invalid := classify(closed, "closed"); invalid > 0 {
		closedOutcome = markOutcomeIncomplete(closedOutcome, fmt.Sprintf(
			"%d of %d closed-state campaigns were missing number/state or carried an unrecognized state", invalid, len(closed)))
	}
	return result, []CollectorOutcome{openOutcome, closedOutcome}, nil
}
