// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"math"
	"testing"
)

func TestSecurityCodeScanningLanguageEligibility(t *testing.T) {
	tests := []struct {
		name      string
		languages map[string]int64
		complete  bool
		known     bool
		eligible  bool
	}{
		{"inclusive five percent", map[string]int64{"Go": 5, "HTML": 95}, true, true, true},
		{"supported secondary language", map[string]int64{"HTML": 90, "Python": 10}, true, true, true},
		{"below five percent", map[string]int64{"Go": 4, "HTML": 96}, true, true, false},
		{"empty observed inventory", map[string]int64{}, true, true, false},
		{"unobserved inventory", nil, true, false, false},
		{"incomplete inventory", map[string]int64{"Go": 100}, false, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := CodeScanningEligibility(test.languages, []string{"go", "python"}, test.complete)
			if err != nil || (value.Status == MetricKnown) != test.known {
				t.Fatalf("eligibility = %+v, error %v", value, err)
			}
			if test.known && (value.Boolean == nil || *value.Boolean != test.eligible) {
				t.Fatal("eligibility ignored byte share or supported secondary language")
			}
			if err := value.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, languages := range []map[string]int64{
		{"Go": -1}, {"": 1}, {"Go": math.MaxInt64, "HTML": 1},
	} {
		if _, err := CodeScanningEligibility(languages, []string{"Go"}, true); err == nil {
			t.Fatal("invalid language inventory accepted")
		}
	}
	if _, err := CodeScanningEligibility(map[string]int64{}, nil, true); err == nil {
		t.Fatal("missing supported-language policy was accepted")
	}
}

func TestSecurityDependencyEligibilityPreservesUnknownAndRootExclusion(t *testing.T) {
	zero, one, negative := 0, 1, -1
	tests := []struct {
		name     string
		manifest *int
		packages *int
		complete bool
		status   MetricStatus
		eligible bool
	}{
		{"supported manifest", &one, &zero, true, MetricKnown, true},
		{"actual dependency", &zero, &one, true, MetricKnown, true},
		{"repository-only root excluded", &zero, &zero, true, MetricKnown, false},
		{"missing SBOM and no manifest", &zero, nil, true, MetricUnavailable, false},
		{"partial collection", &one, &one, false, MetricUnavailable, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := DependencyEligibility(test.manifest, test.packages, test.complete)
			if err != nil || value.Status != test.status {
				t.Fatalf("eligibility = %+v, error %v", value, err)
			}
			if test.status == MetricKnown && (value.Boolean == nil || *value.Boolean != test.eligible) {
				t.Fatal("dependency eligibility was guessed")
			}
		})
	}
	if _, err := DependencyEligibility(&negative, &zero, true); err == nil {
		t.Fatal("negative dependency count accepted")
	}
}

func securityRepository(name string, eligible, enabled *bool) SecurityRepositoryObservation {
	return SecurityRepositoryObservation{
		Scope: Scope{"github.com", RepositoryScope, "fixture/" + name}, Eligible: eligible,
		FeatureEnabled: enabled, EvidenceRefs: []string{"evidence/" + name + ".json"},
	}
}

func TestSecurityFeatureCoverageUsesKnownEligibleDenominator(t *testing.T) {
	yes, no := true, false
	repositories := []SecurityRepositoryObservation{
		securityRepository("enabled", &yes, &yes),
		securityRepository("disabled", &yes, &no),
		securityRepository("ineligible", &no, nil),
	}
	value, err := SecurityFeatureCoverage(repositories, true)
	if err != nil || value.Number == nil || *value.Number != 50 || *value.Denominator != 2 {
		t.Fatalf("coverage = %+v, error %v", value, err)
	}
	repositories[1].FeatureEnabled = nil
	value, err = SecurityFeatureCoverage(repositories, true)
	if err != nil || value.Status != MetricUnavailable || value.Number != nil {
		t.Fatal("unknown feature was counted as disabled or ignored")
	}
	repositories[1].Eligible = nil
	value, err = SecurityFeatureCoverage(repositories, true)
	if err != nil || value.Status != MetricUnavailable {
		t.Fatal("unknown eligibility changed the denominator silently")
	}
	value, err = SecurityFeatureCoverage([]SecurityRepositoryObservation{securityRepository("none", &no, nil)}, true)
	if err != nil || value.Status != MetricInapplicable || value.Denominator == nil || *value.Denominator != 0 {
		t.Fatal("zero confirmed eligible population was treated as failure or compliance")
	}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := SecurityFeatureCoverage([]SecurityRepositoryObservation{repositories[0], repositories[0]}, true); err == nil {
		t.Fatal("duplicate repository inflated coverage")
	}
}

func TestSecurityConfigurationCoverageRequiresActualFinalAttachments(t *testing.T) {
	yes, no := true, false
	repositories := []SecurityRepositoryObservation{
		securityRepository("first", &yes, nil), securityRepository("second", &yes, nil),
		securityRepository("ineligible", &no, nil),
	}
	configurations := []SecurityConfigurationObservation{{
		Host: "github.com", ID: 10, Enforcement: "enforced", Features: map[string]*bool{"code_scanning": &yes, "dependabot": &yes},
	}}
	attachments := []SecurityAttachmentObservation{
		{Repository: repositories[0].Scope, ConfigurationID: 10, Status: "attached"},
		{Repository: repositories[1].Scope, ConfigurationID: 10, Status: "detached"},
	}

	required := []string{"code_scanning", "dependabot"}
	value, err := SecurityConfigurationCoverage(repositories, configurations, attachments, required, true)
	if err != nil || value.Number == nil || *value.Number != 50 {
		t.Fatalf("attachment coverage = %+v, error %v", value, err)
	}
	for _, status := range []string{"attaching", "updating", "failed"} {
		attachments[1].Status = status
		value, err = SecurityConfigurationCoverage(repositories, configurations, attachments, required, true)
		if err != nil || value.Status != MetricUnavailable {
			t.Fatalf("transitional status %s counted as known coverage", status)
		}
	}
	attachments[1].Status = "enforced"
	value, err = SecurityConfigurationCoverage(repositories, configurations, attachments, required, true)
	if err != nil || value.Number == nil || *value.Number != 100 {
		t.Fatal("confirmed enforced attachment was excluded")
	}
	configurations[0].Features["code_scanning"] = nil
	value, err = SecurityConfigurationCoverage(repositories, configurations, attachments, required, true)
	if err != nil || value.Status != MetricUnavailable {
		t.Fatal("missing configuration feature became enabled or disabled")
	}
	configurations[0].Features["dependabot"] = &no
	value, err = SecurityConfigurationCoverage(repositories, configurations, attachments, required, true)
	if err != nil || value.Number == nil || *value.Number != 0 {
		t.Fatal("known disabled required feature was ignored")
	}
	if _, err := SecurityConfigurationCoverage(repositories, configurations, append(attachments, attachments[0]), required, true); err == nil {
		t.Fatal("duplicate configuration attachment was accepted")
	}
}

func TestSecurityConfigurationIDsRemainHostQualified(t *testing.T) {
	yes, no := true, false
	repositories := []SecurityRepositoryObservation{
		securityRepository("cloud", &yes, nil),
		{Scope: Scope{"server.example.test", RepositoryScope, "fixture/server"}, Eligible: &yes},
	}
	configurations := []SecurityConfigurationObservation{
		{Host: "github.com", ID: 10, Enforcement: "enforced", Features: map[string]*bool{"code_scanning": &yes}},
		{Host: "server.example.test", ID: 10, Enforcement: "unenforced", Features: map[string]*bool{"code_scanning": &no}},
	}
	attachments := []SecurityAttachmentObservation{
		{Repository: repositories[0].Scope, ConfigurationID: 10, Status: "attached"},
		{Repository: repositories[1].Scope, ConfigurationID: 10, Status: "attached"},
	}
	value, err := SecurityConfigurationCoverage(repositories, configurations, attachments, []string{"code_scanning"}, true)
	if err != nil || value.Number == nil || *value.Number != 50 {
		t.Fatalf("configuration IDs collided across hosts: %+v %v", value, err)
	}
}
