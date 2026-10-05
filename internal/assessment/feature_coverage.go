// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// FeatureCoverage is a pooled, feature-scoped coverage ratio: an explicit
// numerator and denominator over an explicit population, not an average of
// per-repository percentages. Each feature keeps its own denominator so one
// feature's eligibility count is never silently reused, or overwritten, by a
// different feature (the automation profile's shared "eligible_repos_count" key
// is overloaded across SEC-001's dependency-scanning eligibility and SEC-004's
// code-scanning eligibility; this run reports each feature's population under a
// distinct name instead of writing that ambiguous shared key).
type FeatureCoverage struct {
	Feature     string      `json:"feature"`
	Numerator   int         `json:"numerator"`
	Denominator int         `json:"denominator"`
	Metric      MetricValue `json:"metric"`
	Notes       string      `json:"notes,omitempty"`
	// UnknownEligibilityCount is the number of analyzed repositories whose
	// eligibility for this feature could not be determined at all (for
	// example the languages probe returned a concealed/failed response).
	// These repositories are excluded from BOTH Numerator and Denominator
	// -- never silently counted as confirmed-ineligible -- so Denominator
	// never implies "every analyzed repository was checked and found
	// ineligible" when some genuinely could not be checked at all.
	UnknownEligibilityCount int `json:"unknown_eligibility_count,omitempty"`
	// UnknownOperationalCount is the number of Denominator-eligible
	// repositories whose operational status could not be determined (the
	// operational probe itself was concealed, failed, or returned
	// malformed data with no positive evidence found elsewhere). These
	// repositories are excluded from Numerator only -- never silently
	// counted as confirmed-non-operational.
	UnknownOperationalCount int `json:"unknown_operational_count,omitempty"`
}

// codeQLSupportedLanguages mirrors the repo.languages collector's documented
// CodeQL-supported language set.
var codeQLSupportedLanguages = map[string]bool{
	"c": true, "c++": true, "c#": true, "go": true, "java": true, "kotlin": true,
	"javascript": true, "typescript": true, "python": true, "ruby": true, "swift": true, "rust": true,
}

// FetchRepositoryLanguages collects the language-name-to-byte-count map used to
// determine CodeQL eligibility.
func FetchRepositoryLanguages(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (map[string]int64, CollectorOutcome, error) {
	languages, outcome, err := collectJSONObject[map[string]int64](ctx, client, store, scope,
		"repo.languages", "languages", "repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/languages")
	if err != nil || languages == nil {
		return nil, outcome, err
	}
	return *languages, outcome, nil
}

// HasPositiveCodeQLSupportedLanguageBytes reports whether at least one
// CodeQL-supported language has a positive byte count, the profile's documented
// eligibility signal for CodeQL coverage.
func HasPositiveCodeQLSupportedLanguageBytes(languages map[string]int64) bool {
	for language, bytes := range languages {
		if bytes > 0 && codeQLSupportedLanguages[strings.ToLower(language)] {
			return true
		}
	}
	return false
}

// ProbeDependencyGraphSBOM reports whether the dependency-graph SBOM endpoint
// returned a successful response, the available proxy signal for "a supported
// manifest is present and the dependency graph is enabled" (the collector notes
// that 404 cannot, by itself, distinguish a disabled dependency graph from a
// genuinely unsupported manifest).
func ProbeDependencyGraphSBOM(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (bool, CollectorOutcome, error) {
	_, outcome, err := collectJSONObject[map[string]any](ctx, client, store, scope,
		"repo.sbom", "sbom", "repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/dependency-graph/sbom")
	if err != nil {
		return false, outcome, nil
	}
	return true, outcome, nil
}

// RepositoryFeatureSignal is one analyzed repository's feature-specific
// eligibility and operational status, kept distinct per feature so eligibility
// denominators never collide across features.
//
// CodeQLOperational/CodeQLOperationalKnown is this package's authoritative
// signal: it is derived ONLY from the repository's own recorded code-scanning
// analysis history actually including a successful (non-error) CodeQL entry
// on the default branch within the analyzed window
// (FetchRepositoryCodeScanningAnalyses) -- never from a workflow file's mere
// reference to the github/codeql-action step, and never from native default
// setup merely being "configured" (enablement, not evidence a scan has ever
// completed). CodeQLOperational is only meaningful when
// CodeQLOperationalKnown is true; a concealed/failed/malformed probe with no
// positive evidence found elsewhere leaves CodeQLOperationalKnown false so
// AggregateFeatureCoverage never mistakes "could not be determined" for a
// confirmed non-operational repository. CodeQLEligible/CodeQLEligibleKnown
// follows the identical contract for the languages-probe-derived eligibility
// signal.
//
// CodeQLWorkflowReferenced and CodeQLDefaultSetupConfigured(Known) are
// diagnostic-only signals, kept separate from the authoritative
// CodeQLOperational determination above: a workflow can reference the
// codeql-action step, or default setup can be "configured", while never
// having produced a genuine completed analysis yet (a broken trigger, a
// failing step, a disabled workflow, or a first scheduled scan still
// pending all leave either diagnostic signal true without
// CodeQLOperational necessarily following).
//
// DependencyEligible/DependencyEligibleKnown and DependencyOperational/
// DependencyOperationalKnown follow the identical known/unknown contract,
// applied by AggregateFeatureCoverage through the same cohort-sensitive
// mechanism as the CodeQL fields above -- not a separate, divergent
// implementation for the same class of bug.
type RepositoryFeatureSignal struct {
	FullName string `json:"full_name"`

	CodeQLEligible      bool `json:"codeql_eligible"`
	CodeQLEligibleKnown bool `json:"codeql_eligible_known"`

	CodeQLOperational      bool `json:"codeql_operational"`
	CodeQLOperationalKnown bool `json:"codeql_operational_known"`

	CodeQLWorkflowReferenced          bool `json:"codeql_workflow_referenced"`
	CodeQLDefaultSetupConfigured      bool `json:"codeql_default_setup_configured"`
	CodeQLDefaultSetupConfiguredKnown bool `json:"codeql_default_setup_configured_known"`

	DependencyEligible      bool `json:"dependency_eligible"`
	DependencyEligibleKnown bool `json:"dependency_eligible_known"`

	DependencyOperational      bool `json:"dependency_operational"`
	DependencyOperationalKnown bool `json:"dependency_operational_known"`
}

// cohortCoverageMetric builds a MetricValue for a pooled feature-coverage
// ratio whose denominator is itself an observed subset, never the full
// analyzed population. The confidently-known numerator/denominator are
// always retained in the returned MetricValue (Numerator/Denominator are
// never erased), but whenever any peer's eligibility or operational status
// could not be determined at all (unknownEligible or unknownOperational >
// 0), an unresolved peer could change this feature's true cohort or result
// -- the known subset alone can never be presented as a confident coverage
// percentage in that case. Status/Number/Reason are explicitly overridden
// to MetricUnavailable/nil/a disclosed reason, not merely a caveat buried in
// free-text Population that a Status/Number-only consumer would never see.
// A repository with CONFIRMED (known) ineligibility is correctly excluded
// from the denominator as always intended; only genuine UNKNOWN eligibility
// or operational status triggers this override.
func cohortCoverageMetric(numerator, denominator, unknownEligible, unknownOperational, totalSignals int, population string) MetricValue {
	metric, _ := Percentage(float64(numerator), float64(denominator), population)
	if unknownEligible > 0 || unknownOperational > 0 {
		metric.Status = MetricUnavailable
		metric.Number = nil
		metric.Reason = fmt.Sprintf("%d of %d analyzed repositories' eligibility could not be determined and/or "+
			"%d known-eligible repositories' operational status could not be determined; an unresolved peer could "+
			"change this feature's cohort or result, so the %d/%d known subset alone cannot be reported as a "+
			"confident coverage percentage", unknownEligible, totalSignals, unknownOperational, numerator, denominator)
	}
	return metric
}

// AggregateFeatureCoverage pools per-repository feature signals into
// explicit, feature-scoped numerator/denominator coverage metrics, for both
// CodeQL and Dependency features, through the identical cohort-sensitive
// mechanism (cohortCoverageMetric): a repository whose eligibility could
// not be determined at all is excluded from both the numerator and
// denominator -- never silently folded into "confirmed ineligible" -- and
// among known-eligible repositories, one whose operational status could
// not be determined is excluded from the numerator only -- never silently
// folded into "confirmed non-operational". Either case forces the
// returned MetricValue to MetricUnavailable (Number nil, explicit Reason),
// since an unresolved peer could change the true cohort/result; the
// confidently-known numerator/denominator are still retained on the
// returned FeatureCoverage/MetricValue for audit, never erased.
func AggregateFeatureCoverage(signals []RepositoryFeatureSignal) (codeQL, dependency FeatureCoverage) {
	var codeQLNumerator, codeQLDenominator, codeQLUnknownEligibility, codeQLUnknownOperational int
	var dependencyNumerator, dependencyDenominator, dependencyUnknownEligibility, dependencyUnknownOperational int
	for _, signal := range signals {
		if !signal.CodeQLEligibleKnown {
			codeQLUnknownEligibility++
		} else if signal.CodeQLEligible {
			codeQLDenominator++
			switch {
			case !signal.CodeQLOperationalKnown:
				codeQLUnknownOperational++
			case signal.CodeQLOperational:
				codeQLNumerator++
			}
		}
		if !signal.DependencyEligibleKnown {
			dependencyUnknownEligibility++
		} else if signal.DependencyEligible {
			dependencyDenominator++
			switch {
			case !signal.DependencyOperationalKnown:
				dependencyUnknownOperational++
			case signal.DependencyOperational:
				dependencyNumerator++
			}
		}
	}
	codeQLMetric := cohortCoverageMetric(codeQLNumerator, codeQLDenominator, codeQLUnknownEligibility, codeQLUnknownOperational, len(signals),
		"analyzed repositories with at least one CodeQL-supported language reporting positive bytes, "+
			"excluding repositories whose eligibility could not be determined")
	dependencyMetric := cohortCoverageMetric(dependencyNumerator, dependencyDenominator, dependencyUnknownEligibility, dependencyUnknownOperational, len(signals),
		"analyzed repositories where the dependency-graph SBOM endpoint confirmed a supported manifest, "+
			"excluding repositories whose eligibility could not be determined")
	codeQLNotes := "Phase3-invented key (not an existing automation profile metric name); numerator requires the " +
		"repository's own recorded code-scanning analysis history actually including a successful CodeQL entry on " +
		"its default branch within the analyzed window -- real observed activity, never a workflow file merely " +
		"referencing the github/codeql-action step, and never native default setup merely being \"configured\" " +
		"(see RepositoryFeatureSignal.CodeQLWorkflowReferenced/CodeQLDefaultSetupConfigured for those separate, " +
		"diagnostic-only caveats)"
	codeQL = FeatureCoverage{
		Feature: "codeql_operational_coverage_pct", Numerator: codeQLNumerator, Denominator: codeQLDenominator, Metric: codeQLMetric,
		Notes: codeQLNotes, UnknownEligibilityCount: codeQLUnknownEligibility, UnknownOperationalCount: codeQLUnknownOperational,
	}
	dependency = FeatureCoverage{
		Feature: "dependabot_security_updates_pct", Numerator: dependencyNumerator, Denominator: dependencyDenominator, Metric: dependencyMetric,
		Notes: "denominator is the SBOM-endpoint-available proxy for \"supported manifest\" from the repo.sbom collector " +
			"notes; it cannot yet separate a disabled dependency graph from a genuinely absent manifest",
		UnknownEligibilityCount: dependencyUnknownEligibility, UnknownOperationalCount: dependencyUnknownOperational,
	}
	return codeQL, dependency
}
