// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
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
type RepositoryFeatureSignal struct {
	FullName              string `json:"full_name"`
	CodeQLEligible        bool   `json:"codeql_eligible"`
	CodeQLOperational     bool   `json:"codeql_operational"`
	DependencyEligible    bool   `json:"dependency_eligible"`
	DependencyOperational bool   `json:"dependency_operational"`
}

// AggregateFeatureCoverage pools per-repository feature signals into explicit,
// feature-scoped numerator/denominator coverage metrics.
func AggregateFeatureCoverage(signals []RepositoryFeatureSignal) (codeQL, dependency FeatureCoverage) {
	var codeQLNumerator, codeQLDenominator, dependencyNumerator, dependencyDenominator int
	for _, signal := range signals {
		if signal.CodeQLEligible {
			codeQLDenominator++
			if signal.CodeQLOperational {
				codeQLNumerator++
			}
		}
		if signal.DependencyEligible {
			dependencyDenominator++
			if signal.DependencyOperational {
				dependencyNumerator++
			}
		}
	}
	codeQLMetric, _ := Percentage(float64(codeQLNumerator), float64(codeQLDenominator),
		"analyzed repositories with at least one CodeQL-supported language reporting positive bytes")
	dependencyMetric, _ := Percentage(float64(dependencyNumerator), float64(dependencyDenominator),
		"analyzed repositories where the dependency-graph SBOM endpoint confirmed a supported manifest")
	codeQL = FeatureCoverage{
		Feature: "codeql_operational_coverage_pct", Numerator: codeQLNumerator, Denominator: codeQLDenominator, Metric: codeQLMetric,
		Notes: "Phase3-invented key (not an existing automation profile metric name); numerator requires an active " +
			"workflow with a github/codeql-action step, not mere file presence",
	}
	dependency = FeatureCoverage{
		Feature: "dependabot_security_updates_pct", Numerator: dependencyNumerator, Denominator: dependencyDenominator, Metric: dependencyMetric,
		Notes: "denominator is the SBOM-endpoint-available proxy for \"supported manifest\" from the repo.sbom collector " +
			"notes; it cannot yet separate a disabled dependency graph from a genuinely absent manifest",
	}
	return codeQL, dependency
}
