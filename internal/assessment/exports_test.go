// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func exportFixture(t *testing.T) (*Profile, []ControlResult) {
	t.Helper()
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(profile, config)
	if err != nil {
		t.Fatal(err)
	}
	return profile, plan.Results
}

func exportCSVRows(t *testing.T, data []byte) [][]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestResultsCSVExactContract(t *testing.T) {
	profile, results := exportFixture(t)
	data, err := RenderResultsCSV(profile, results)
	if err != nil {
		t.Fatal(err)
	}
	rows := exportCSVRows(t, data)
	if len(rows) != 457 || !reflect.DeepEqual(rows[0], resultsCSVHeader) {
		t.Fatalf("CSV contract: %d rows, header %v", len(rows), rows[0])
	}
	for index, control := range profile.Controls {
		row := rows[index+1]
		if row[0] != control.ID || row[4] != string(results[index].ProposedState) ||
			!json.Valid([]byte(row[7])) || row[9] == "" {
			t.Fatalf("result row %s does not preserve identity, state, metrics and reason", control.ID)
		}
	}
	results[0].Notes = "\t=HYPERLINK(\"https://example.test\", \"untrusted\")"
	results[0].EvidenceRefs = []string{"evidence/repo/fixture/a.json", "evidence/repo/fixture/b.json"}
	data, err = RenderResultsCSV(profile, results)
	if err != nil {
		t.Fatal(err)
	}
	row := exportCSVRows(t, data)[1]
	if !strings.HasPrefix(row[9], "'") || row[8] != "evidence/repo/fixture/a.json;evidence/repo/fixture/b.json" {
		t.Fatal("formula safety or evidence references lost")
	}
}

func TestInterviewGuidePreservesAllRequiredQuestions(t *testing.T) {
	profile, results := exportFixture(t)
	data, err := RenderInterviewGuide(profile, results)
	if err != nil {
		t.Fatal(err)
	}
	guide := string(data)
	questions := 0
	for _, control := range profile.Controls {
		header := "**" + control.ID + " (" + string(control.Automation) + ")**"
		if control.RequiresInterview() {
			questions++
			if strings.Count(guide, header) != 1 {
				t.Fatalf("question %s missing or duplicated", control.ID)
			}
		} else if strings.Contains(guide, header) {
			t.Fatalf("unrequested question included: %s", control.ID)
		}
	}
	if questions != 307 || !strings.Contains(guide, "Computed metrics") ||
		!strings.Contains(guide, "#### ") || !strings.Contains(guide, "NOT_ASSESSED") {
		t.Fatal("required confirmations, computed metrics or grouping were lost")
	}
}

func TestWorkbookUpdateLeavesManualControlsUntouched(t *testing.T) {
	profile, results := exportFixture(t)
	var partialIndex, manualIndex int
	for index, control := range profile.Controls {
		if control.Automation == Partial {
			partialIndex = index
		}
		if control.Automation == Manual {
			manualIndex = index
		}
	}
	results[partialIndex].EvidenceRefs = []string{"evidence/new.json", "evidence/new.json"}
	results[manualIndex].ProposedState = Implemented
	existing := map[string]string{results[partialIndex].ControlID: "Existing workbook evidence"}
	data, err := RenderWorkbookUpdateCSV(profile, results, existing)
	if err != nil {
		t.Fatal(err)
	}
	rows := exportCSVRows(t, data)
	if len(rows) != 260 || !reflect.DeepEqual(rows[0], []string{"sheet", "control_id", "current_state", "finding", "evidence"}) {
		t.Fatalf("unexpected update contract: %d rows", len(rows))
	}
	for _, row := range rows[1:] {
		if row[1] == results[manualIndex].ControlID {
			t.Fatal("manual control was written automatically")
		}
		if row[1] == results[partialIndex].ControlID {
			if !strings.HasPrefix(row[3], "Agent proposal \u2014 confirm in interview: ") ||
				row[4] != "Existing workbook evidence | evidence/new.json" {
				t.Fatal("confirmation finding or append-only evidence lost")
			}
		}
	}
	results[partialIndex].Decision = &AssessorDecision{
		State: PartiallyImplemented, Assessor: "Fixture assessor",
		ConfirmedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Rationale:   "Fixture decision", EvidenceRefs: []string{"evidence/decision.json"},
	}
	data, err = RenderWorkbookUpdateCSV(profile, results, existing)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range exportCSVRows(t, data)[1:] {
		if row[1] == results[partialIndex].ControlID &&
			(row[2] != "Partially Implemented" || row[3] != "Assessor decision: Fixture decision" ||
				row[4] != "Existing workbook evidence | evidence/new.json;evidence/decision.json") {
			t.Fatal("confirmed decision or combined evidence lost")
		}
	}
}

func TestExportRejectsInvalidResults(t *testing.T) {
	tests := []struct {
		name   string
		change func([]ControlResult) []ControlResult
	}{
		{"missing", func(r []ControlResult) []ControlResult { return r[1:] }},
		{"duplicate", func(r []ControlResult) []ControlResult { r[1] = r[0]; return r }},
		{"unknown ID", func(r []ControlResult) []ControlResult { r[0].ControlID = "OTHER-001"; return r }},
		{"unknown state", func(r []ControlResult) []ControlResult { r[0].ProposedState = "PASS"; return r }},
		{"missing explanation", func(r []ControlResult) []ControlResult { r[0].Notes = ""; return r }},
		{"wrong taxonomy", func(r []ControlResult) []ControlResult { r[0].Pillar = "Wrong"; return r }},
		{"unknown confidence", func(r []ControlResult) []ControlResult { r[0].Confidence = "certain"; return r }},
		{"missing metric", func(r []ControlResult) []ControlResult { r[0].Metrics = nil; return r }},
		{"unknown flag", func(r []ControlResult) []ControlResult { r[0].Flags = []ResultFlag{"unknown"}; return r }},
		{"invalid decision", func(r []ControlResult) []ControlResult {
			r[0].Decision = &AssessorDecision{State: Implemented}
			return r
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, results := exportFixture(t)
			if _, err := RenderResultsCSV(profile, test.change(results)); err == nil {
				t.Fatal("invalid result was exported")
			}
		})
	}
	if _, err := RenderResultsCSV(nil, nil); err == nil {
		t.Fatal("nil profile was exported")
	}
}

func TestAssessmentSummaryDoesNotInferCompliance(t *testing.T) {
	profile, results := exportFixture(t)
	gaps := 0
	for index, control := range profile.Controls {
		if control.Automation == Full && gaps < 25 {
			results[index].ProposedState = NotImplemented
			gaps++
		}
	}
	outcomes := []CollectorOutcome{{
		CollectorID: "org.settings", Scope: Scope{"github.com", OrganizationScope, "fixture-org"},
		Readiness: Ready, Availability: MissingPermission, Status: CollectionFailed,
		Reason: "Permission could not be confirmed",
	}}
	data, err := RenderAssessmentSummary(profile, results, outcomes, map[string]float64{"repos_with_pr_required_pct": 85})
	if err != nil {
		t.Fatal(err)
	}
	summary := string(data)
	gapSection := strings.Split(strings.Split(summary, "## Top 20 fully automated gaps\n\n")[1], "\n## ")[0]
	if strings.Count(gapSection, "\n- ")+1 != 20 ||
		!strings.Contains(summary, "missing-permission") ||
		!strings.Contains(summary, "repos_with_pr_required_pct: 85") ||
		!strings.Contains(summary, "Unavailability") && !strings.Contains(summary, "Unavailable") {
		t.Fatal("gap cap, permission, threshold or unavailable metric explanations lost")
	}
	if strings.Contains(summary, "posture is strong") || !strings.Contains(summary, "NOT_ASSESSED") {
		t.Fatal("summary inferred compliance or hid unknown states")
	}
}

func TestSummaryIncludesAutomatedOnlyPrinciplesAndOrganizationUnknowns(t *testing.T) {
	profile, results := exportFixture(t)
	var automatedIndex int
	for index, control := range profile.Controls {
		if control.Automation == Full && !control.RequiresInterview() {
			automatedIndex = index
			break
		}
	}
	profile.Controls[automatedIndex].DesignPrinciple = "Automated-only fixture principle"
	keys, err := profile.Controls[automatedIndex].MetricKeys()
	if err != nil {
		t.Fatal(err)
	}
	key := keys[0]
	metric := results[automatedIndex].Metrics[key]
	number := 100.0
	metric.Overall = MetricValue{Status: MetricKnown, Number: &number, Population: "Fixture population"}
	metric.PerOrganization["github.com/organization/fixture-org"] = MetricValue{
		Status: MetricUnavailable, Population: "Fixture population", Reason: "Organization evidence unavailable",
	}
	results[automatedIndex].Metrics[key] = metric
	data, err := RenderAssessmentSummary(profile, results, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Automated-only fixture principle") ||
		!strings.Contains(string(data), "Organization evidence unavailable") {
		t.Fatal("summary omitted an automated-only principle or unavailable organization observation")
	}
}

func TestWorkbookLiteralStateMapping(t *testing.T) {
	tests := map[State]string{
		Implemented: "Implemented", PartiallyImplemented: "Partially Implemented",
		NotImplemented: "Not Implemented", NotApplicable: "Not Applicable", NotAssessed: "Not Assessed",
	}
	for state, expected := range tests {
		if got := workbookState(state); got != expected {
			t.Fatalf("workbook state %s = %q, want %q", state, got, expected)
		}
	}
}
