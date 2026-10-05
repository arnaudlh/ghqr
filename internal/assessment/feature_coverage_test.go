// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import "testing"

// TestAggregateFeatureCoverageUnknownEligibilityCannotProduceKnownSubsetCoverage
// migrates the exact reproduction scenario confirmed against this package:
// one genuinely known, eligible and operational repository alongside one
// repository whose eligibility was never determined at all (a zero-value
// RepositoryFeatureSignal -- CodeQLEligibleKnown false) must NOT be
// reported as a confident "100% of known subset" coverage. The unresolved
// peer could itself turn out eligible (and non-operational), which would
// change the true cohort/result; a caveat string alone is not sufficient,
// Status/Number must explicitly become unavailable.
func TestAggregateFeatureCoverageUnknownEligibilityCannotProduceKnownSubsetCoverage(t *testing.T) {
	codeQL, _ := AggregateFeatureCoverage([]RepositoryFeatureSignal{
		{FullName: "fixture/known", CodeQLEligible: true, CodeQLEligibleKnown: true,
			CodeQLOperational: true, CodeQLOperationalKnown: true},
		{FullName: "fixture/unknown"},
	})
	if codeQL.Metric.Status == MetricKnown {
		t.Fatalf("an unknown-eligibility peer must not shrink the cohort into a known clean subset coverage: %+v", codeQL.Metric)
	}
	if codeQL.Metric.Number != nil {
		t.Fatalf("an unavailable metric must not carry a Number: %+v", codeQL.Metric)
	}
	if codeQL.Metric.Reason == "" {
		t.Fatalf("expected an explicit disclosed Reason: %+v", codeQL.Metric)
	}
	if codeQL.Metric.Numerator == nil || codeQL.Metric.Denominator == nil || *codeQL.Metric.Numerator != 1 || *codeQL.Metric.Denominator != 1 {
		t.Fatalf("the confidently-known 1/1 subset must still be retained on the metric, not erased: %+v", codeQL.Metric)
	}
	if codeQL.UnknownEligibilityCount != 1 {
		t.Fatalf("expected the unresolved peer's uncertainty counted: %+v", codeQL)
	}
}

// TestAggregateFeatureCoverageUnknownOperationalCannotBeKnownZero migrates
// the exact reproduction scenario confirmed against this package: a
// repository with confidently known eligibility but whose operational
// status was never determined (CodeQLOperationalKnown false) must not be
// reported as a confident "0%" -- that status is unobserved, not confirmed
// non-operational.
func TestAggregateFeatureCoverageUnknownOperationalCannotBeKnownZero(t *testing.T) {
	codeQL, _ := AggregateFeatureCoverage([]RepositoryFeatureSignal{
		{FullName: "fixture/unknown-operation", CodeQLEligible: true, CodeQLEligibleKnown: true},
	})
	if codeQL.Metric.Status == MetricKnown {
		t.Fatalf("unobserved operational status must not be reported as a known zero: %+v", codeQL.Metric)
	}
	if codeQL.Metric.Number != nil {
		t.Fatalf("an unavailable metric must not carry a Number: %+v", codeQL.Metric)
	}
	if codeQL.UnknownOperationalCount != 1 {
		t.Fatalf("expected the unresolved operational status counted: %+v", codeQL)
	}
}

// TestAggregateFeatureCoverageFullyKnownCohortReportsConfidentPercentage is
// the sibling regression to the two unknown-gate tests above: when every
// signal's eligibility and operational status is confidently known (no
// unknowns at all), the pooled coverage must still report a genuine,
// confident MetricKnown percentage -- the unknown-gate fix must not make
// every result unavailable, only ones with real unresolved peers.
func TestAggregateFeatureCoverageFullyKnownCohortReportsConfidentPercentage(t *testing.T) {
	codeQL, dependency := AggregateFeatureCoverage([]RepositoryFeatureSignal{
		{FullName: "fixture/operational", CodeQLEligible: true, CodeQLEligibleKnown: true,
			CodeQLOperational: true, CodeQLOperationalKnown: true,
			DependencyEligible: true, DependencyEligibleKnown: true, DependencyOperational: true, DependencyOperationalKnown: true},
		{FullName: "fixture/non-operational", CodeQLEligible: true, CodeQLEligibleKnown: true, CodeQLOperationalKnown: true,
			DependencyEligible: true, DependencyEligibleKnown: true, DependencyOperationalKnown: true},
		{FullName: "fixture/ineligible", CodeQLEligibleKnown: true, DependencyEligibleKnown: true},
	})
	if codeQL.Metric.Status != MetricKnown || codeQL.Metric.Number == nil || *codeQL.Metric.Number != 50 {
		t.Fatalf("a fully-known cohort (1 of 2 eligible repositories operational) must report a confident 50%%: %+v", codeQL.Metric)
	}
	if dependency.Metric.Status != MetricKnown || dependency.Metric.Number == nil || *dependency.Metric.Number != 50 {
		t.Fatalf("dependency pooling must use the identical fully-known contract: %+v", dependency.Metric)
	}
	if codeQL.UnknownEligibilityCount != 0 || codeQL.UnknownOperationalCount != 0 ||
		dependency.UnknownEligibilityCount != 0 || dependency.UnknownOperationalCount != 0 {
		t.Fatalf("a fully-known cohort must report zero unknowns: codeQL=%+v dependency=%+v", codeQL, dependency)
	}
}

// TestAggregateFeatureCoverageDependencySameUnknownGate confirms the
// Dependency feature pools through the identical cohort-sensitive
// mechanism as CodeQL, not a separate, divergent implementation for the
// same class of bug: an unknown-eligibility peer forces Dependency
// unavailable too, and an unknown-operational known-eligible repository
// forces it unavailable as well -- in both cases the confidently-known
// subset counts are still retained, never erased.
func TestAggregateFeatureCoverageDependencySameUnknownGate(t *testing.T) {
	_, unknownEligibility := AggregateFeatureCoverage([]RepositoryFeatureSignal{
		{FullName: "fixture/known", DependencyEligible: true, DependencyEligibleKnown: true,
			DependencyOperational: true, DependencyOperationalKnown: true},
		{FullName: "fixture/unknown"},
	})
	if unknownEligibility.Metric.Status == MetricKnown {
		t.Fatalf("an unknown dependency-eligibility peer must not shrink the cohort into a known subset coverage: %+v", unknownEligibility.Metric)
	}
	if unknownEligibility.Metric.Numerator == nil || unknownEligibility.Metric.Denominator == nil ||
		*unknownEligibility.Metric.Numerator != 1 || *unknownEligibility.Metric.Denominator != 1 {
		t.Fatalf("the confidently-known 1/1 dependency subset must still be retained: %+v", unknownEligibility.Metric)
	}

	_, unknownOperational := AggregateFeatureCoverage([]RepositoryFeatureSignal{
		{FullName: "fixture/unknown-operation", DependencyEligible: true, DependencyEligibleKnown: true},
	})
	if unknownOperational.Metric.Status == MetricKnown {
		t.Fatalf("unobserved dependency operational status must not be reported as a known zero: %+v", unknownOperational.Metric)
	}
}
