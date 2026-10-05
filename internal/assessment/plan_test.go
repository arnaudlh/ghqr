// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import "testing"

func TestOfflinePlanDoesNotClaimCollectionOrScores(t *testing.T) {
	profile := fixtureProfile(t)
	config, err := ParseConfig([]byte("organizations: [acme]\nthresholds: {coverage_pct: 85}"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(profile, config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != "offline-plan" || len(plan.Collectors) != 67 || len(plan.Results) != 456 {
		t.Fatalf("incomplete offline plan: %s %d %d", plan.Kind, len(plan.Collectors), len(plan.Results))
	}
	for _, collector := range plan.Collectors {
		expectedReadiness := Unimplemented
		for _, implemented := range ImplementedCollectorIDs() {
			if collector.CollectorID == implemented {
				expectedReadiness = Ready
			}
		}
		if importContractCollectorIDSet[collector.CollectorID] {
			expectedReadiness = ImportOnly
		}
		if collector.Readiness != expectedReadiness || collector.Availability != NotChecked || collector.Reason == "" {
			t.Fatalf("plan invented collector feasibility: %+v", collector)
		}

	}
	for _, result := range plan.Results {
		if result.ProposedState != NotAssessed || result.Confidence != LowConfidence ||
			len(result.EvidenceRefs) != 0 || result.Decision != nil {
			t.Fatalf("plan invented a score, evidence or confirmation: %+v", result)
		}
		if result.Automation == Partial && (len(result.Flags) != 1 || result.Flags[0] != Confirm) {
			t.Fatalf("partial control is not flagged for confirmation: %s", result.ControlID)
		}
		if result.ControlID == "PRD-041" && (!result.RequiresConfirmation || len(result.Flags) != 1) {
			t.Fatal("PRD-041 lost mandatory interview confirmation")
		}
	}
	for _, metric := range plan.Metrics {
		if metric.Overall.Status != MetricUnavailable || metric.Overall.Number != nil {
			t.Fatalf("plan invented a metric: %+v", metric)
		}
		value, ok := metric.PerOrganization["github.com/organization/acme"]
		if !ok || value.Status != MetricUnavailable {
			t.Fatal("host-qualified per-organization unknown metric missing")
		}
	}
	if plan.Thresholds["coverage_pct"] != 85 {
		t.Fatal("customer override was lost")
	}
}

func TestDeploymentExclusionIsNotMissingEvidence(t *testing.T) {
	profile := fixtureProfile(t)
	profile.Controls[0].Scope = "GHE Server"
	config, err := ParseConfig([]byte("organizations: [acme]"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(profile, config)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Results[0].ProposedState != NotApplicable || plan.Results[1].ProposedState != NotAssessed {
		t.Fatal("deployment exclusion and missing evidence were conflated")
	}
}

func TestPlanRejectsUnknownThreshold(t *testing.T) {
	config, err := ParseConfig([]byte("organizations: [acme]\nthresholds: {unknown_pct: 80}"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(fixtureProfile(t), config); err == nil {
		t.Fatal("unknown profile metric override accepted")
	}
}

func TestPlanRejectsNilInputs(t *testing.T) {
	config, err := ParseConfig([]byte("organizations: [acme]"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPlan(nil, config); err == nil {
		t.Fatal("nil profile accepted")
	}
	if _, err := BuildPlan(fixtureProfile(t), nil); err == nil {
		t.Fatal("nil customer configuration accepted")
	}
}

func TestOfflinePlanReportsAdapterAndImportReadinessWithoutAccess(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(profile, config)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[Readiness]int{}
	for _, collector := range plan.Collectors {
		counts[collector.Readiness]++
		if collector.Availability != NotChecked || collector.Reason == "" {
			t.Fatalf("offline plan invented access: %+v", collector)
		}
	}
	if counts[Ready] != len(ImplementedCollectorIDs()) || counts[ImportOnly] != len(ImportContractCollectorIDs()) ||
		counts[Unimplemented] != len(profile.Collectors)-counts[Ready]-counts[ImportOnly] {
		t.Fatalf("offline readiness catalogue is inconsistent: %+v", counts)
	}
	for _, result := range plan.Results {
		if (result.ProposedState != NotAssessed && result.ProposedState != NotApplicable) || len(result.EvidenceRefs) != 0 {
			t.Fatalf("readiness was mistaken for a scored control: %+v", result)
		}
	}
}
