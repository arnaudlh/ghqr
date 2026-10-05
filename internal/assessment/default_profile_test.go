// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func TestEmbeddedProfileMatchesExactSource(t *testing.T) {
	source, err := os.ReadFile("profile/automation-spec.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(defaultProfileData, source) {
		t.Fatal("embedded profile differs from the versioned source bytes")
	}
	const sourceSHA256 = "5ba0a050468944bee41f46fa4638318d80269b45abc017244ce601c2aebba997"
	for _, path := range []string{"", "profile/automation-spec.v2.json"} {
		profile, err := LoadProfile(path)
		if err != nil {
			t.Fatal(err)
		}
		if profile.SHA256 != sourceSHA256 {
			t.Fatalf("profile %q digest = %s, want exact supplied source", path, profile.SHA256)
		}
		summary := profile.Summary()
		if summary.ControlCount != 456 || summary.CollectorCount != 67 ||
			summary.ByOrigin[FrameworkChecklist] != 384 || summary.ByOrigin[SecurityDeepDive] != 72 ||
			summary.ByAutomation[Full] != 150 || summary.ByAutomation[Partial] != 109 || summary.ByAutomation[Manual] != 197 {
			t.Fatalf("embedded profile contract changed: %+v", summary)
		}
	}
}

func TestDefaultProfileIsIndependentOfWorkingDirectoryAndPriorLoads(t *testing.T) {
	t.Chdir(t.TempDir())
	first, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	first.Controls[0].ID = "changed-by-caller"
	first.Stats["Productivity"][Full] = -1
	second, err := LoadProfile("")
	if err != nil {
		t.Fatal(err)
	}
	if second.Controls[0].ID != "PRD-001" || second.Stats["Productivity"][Full] != 13 {
		t.Fatal("loading or mutating a profile affected the bundled default")
	}
	if _, err := LoadProfile("missing-explicit-override.json"); err == nil {
		t.Fatal("missing explicit override silently fell back to the default")
	}
}

func TestEmbeddedProfilePreservesRawReferencesAndNulls(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	for _, control := range profile.Controls {
		if control.ID == "GOV-011" {
			if !reflect.DeepEqual(control.Collectors, []string{"repo.rules", "org.rulesets", "org.rulesets"}) {
				t.Fatal("raw source duplicate references were rewritten")
			}
			if !reflect.DeepEqual(control.CollectorIDs(), []string{"repo.rules", "org.rulesets"}) ||
				!reflect.DeepEqual(control.CollectorIDs(), control.CollectorIDs()) {
				t.Fatal("unique dependencies are not stable")
			}
			if control.InterviewQuestion != nil {
				t.Fatal("raw null interview question was lost")
			}
			return
		}
	}
	t.Fatal("GOV-011 is missing from the default profile")
}

func TestEmbeddedPlanRequiresEveryAssessorConfirmation(t *testing.T) {
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
	controls := make(map[string]Control, len(profile.Controls))
	for _, control := range profile.Controls {
		controls[control.ID] = control
	}
	confirmations := map[Automation]int{}
	for _, result := range plan.Results {
		control, ok := controls[result.ControlID]
		if !ok {
			t.Fatalf("unexpected planned control ID %s", result.ControlID)
		}
		wantConfirmation := control.Automation != Full || control.ID == "PRD-041"
		if result.RequiresConfirmation != wantConfirmation {
			t.Fatalf("incorrect confirmation requirement for %s", control.ID)
		}
		if wantConfirmation {
			if control.InterviewQuestion == nil || *control.InterviewQuestion == "" {
				t.Fatalf("mandatory confirmation question missing for %s", control.ID)
			}
			confirmations[control.Automation]++
		}
		if result.Decision != nil || len(result.EvidenceRefs) != 0 ||
			(result.ProposedState != NotAssessed && result.ProposedState != NotApplicable) {
			t.Fatalf("offline default plan invented an assessment for %s", control.ID)
		}
	}
	if !reflect.DeepEqual(confirmations, map[Automation]int{Full: 1, Partial: 109, Manual: 197}) {
		t.Fatalf("confirmation entries = %v", confirmations)
	}
}
