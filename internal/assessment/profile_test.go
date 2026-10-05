// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// This synthetic catalogue tests the contract, not the supplied control wording.
func fixtureProfile(t *testing.T) *Profile {
	t.Helper()
	p := &Profile{
		Name: "Synthetic contract fixture", Version: ProfileVersion,
		Generated: "2026-09-21", APIVersionHeader: "2022-11-28",
		States:           map[State]*int{NotAssessed: nil, NotApplicable: nil},
		Definitions:      map[string]string{"origin": "fixture"},
		AutomationLevels: map[Automation]string{Full: "fixture", Partial: "fixture", Manual: "fixture"},
		Stats:            map[string]map[Automation]int{},
	}
	for state, score := range map[State]int{Implemented: 2, PartiallyImplemented: 1, NotImplemented: 0} {
		value := score
		p.States[state] = &value
	}
	for _, id := range collectorIDs {
		p.Collectors = append(p.Collectors, Collector{
			ID: id, Level: "fixture", Method: "REST",
			Endpoint: "fixture descriptor, never executed", Evidence: "fixture.json",
		})
	}
	for _, family := range controlFamilies {
		for number := 1; number <= family.count; number++ {
			id := fmt.Sprintf("%s-%03d", family.prefix, number)
			automation := Manual
			if len(p.Controls) < 150 {
				automation = Full
			} else if len(p.Controls) < 259 {
				automation = Partial
			}
			question := "Synthetic fixture question"
			p.Controls = append(p.Controls, Control{
				ID: id, Origin: expectedControls()[id].origin, Pillar: family.pillar,
				DesignPrinciple: "Fixture principle", Area: "Fixture area",
				Control: "Synthetic fixture control", Scope: "All",
				CollectionMethod: "fixture", Automation: automation,
				Collectors: []string{"org.repos"}, Rule: "fixture text, not executable",
				Metrics: "coverage_pct", Evidence: []string{"fixture.json"},
				InterviewQuestion: &question,
			})
		}
	}
	for _, family := range controlFamilies {
		p.Stats[family.pillar] = map[Automation]int{Full: 0, Partial: 0, Manual: 0}
	}
	for _, control := range p.Controls {
		p.Stats[control.Pillar][control.Automation]++
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProfile(data)
	if err != nil {
		t.Fatalf("parse synthetic profile: %v", err)
	}
	return parsed
}

func TestSuppliedProfileContract(t *testing.T) {
	// The actual source import is mandatory; do not silently skip this check.
	data, err := os.ReadFile("profile/automation-spec.v2.json")
	if err != nil {
		t.Fatalf("read exact supplied profile fixture: %v", err)
	}
	profile, err := ParseProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	summary := profile.Summary()
	if summary.ControlCount != 456 || summary.CollectorCount != 67 ||
		summary.ByOrigin[FrameworkChecklist] != 384 || summary.ByOrigin[SecurityDeepDive] != 72 {
		t.Fatalf("unexpected supplied profile counts: %+v", summary)
	}
	wantPillars := map[string]int{
		"Productivity": 76, "Collaboration": 31, "Application Security": 139, "Governance": 87, "Architecture": 123,
	}
	if !reflect.DeepEqual(summary.ByPillar, wantPillars) {
		t.Fatalf("pillar counts = %v, want %v", summary.ByPillar, wantPillars)
	}
	if len(profile.SHA256) != 64 || len(profile.Sources()) != 456 {
		t.Fatal("profile digest or source references missing")
	}
	roundTrip, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseProfile(roundTrip)
	if err != nil {
		t.Fatal(err)
	}
	profile.SHA256, restored.SHA256 = "", ""
	if !reflect.DeepEqual(profile, restored) {
		t.Fatal("profile round trip lost catalogue data")
	}
}

func TestProfileRejectsContractViolations(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Profile)
		want   string
	}{
		{"missing control", func(p *Profile) { p.Controls = p.Controls[1:] }, "456 controls"},
		{"missing collector", func(p *Profile) { p.Collectors = p.Collectors[1:] }, "67 collectors"},
		{"duplicate control", func(p *Profile) { p.Controls[1].ID = p.Controls[0].ID }, "duplicate control"},
		{"foreign control", func(p *Profile) { p.Controls[0].ID = "PRD-077" }, "unknown or duplicate control"},
		{"duplicate collector", func(p *Profile) { p.Collectors[1].ID = p.Collectors[0].ID }, "duplicate collector"},
		{"foreign collector", func(p *Profile) { p.Collectors[0].ID = "org.unknown" }, "unknown or duplicate collector"},
		{"unknown reference", func(p *Profile) { p.Controls[0].Collectors = []string{"org.unknown"} }, "collector reference"},
		{"wrong origin", func(p *Profile) { p.Controls[0].Origin = SecurityDeepDive }, "pillar or origin"},
		{"wrong pillar", func(p *Profile) { p.Controls[0].Pillar = "Security" }, "pillar or origin"},
		{"wrong version", func(p *Profile) { p.Version = "3.0" }, "version 2.0"},
		{"wrong automation count", func(p *Profile) { p.Controls[0].Automation = Manual }, "Full=150"},
		{"unknown automation", func(p *Profile) { p.Controls[0].Automation = "Auto" }, "unsupported automation"},
		{"missing question", func(p *Profile) { p.Controls[40].InterviewQuestion = nil }, "mandatory interview"},
		{"invalid metric", func(p *Profile) { p.Controls[0].Metrics = "arbitrary expression()" }, "metric descriptor"},
		{"invalid scope", func(p *Profile) { p.Controls[0].Scope = "Unknown" }, "unsupported scope"},
		{"unknown state made clean", func(p *Profile) { value := 0; p.States[NotAssessed] = &value }, "score mapping"},
		{"missing statistics", func(p *Profile) { p.Stats = nil }, "statistics require"},
		{"incorrect statistics", func(p *Profile) { p.Stats["Productivity"][Full]++ }, "do not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := fixtureProfile(t)
			tt.change(profile)
			err := profile.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestProfileDecodeRejectsExtraData(t *testing.T) {
	profile := fixtureProfile(t)
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProfile(append(data, []byte("\n{}")...)); err == nil {
		t.Fatal("accepted a second JSON object")
	}
	data = append([]byte(`{"unexpected":true,`), data[1:]...)
	if _, err := ParseProfile(data); err == nil {
		t.Fatal("accepted unknown profile metadata")
	}
}

func TestMetricDescriptorKeys(t *testing.T) {
	control := Control{Metrics: "coverage_pct; enabled (bool); age_months"}
	got, err := control.MetricKeys()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"coverage_pct", "enabled", "age_months"}) {
		t.Fatalf("metric keys = %v", got)
	}
}

func TestCollectorReferencesPreserveRawDuplicates(t *testing.T) {
	profile := fixtureProfile(t)
	profile.Controls[0].Collectors = []string{"repo.rules", "org.rulesets", "org.rulesets"}
	profile.Controls[0].InterviewQuestion = nil
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ParseProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	control := restored.Controls[0]
	if !reflect.DeepEqual(control.Collectors, profile.Controls[0].Collectors) {
		t.Fatal("raw duplicate references were lost")
	}
	if !reflect.DeepEqual(control.CollectorIDs(), []string{"repo.rules", "org.rulesets"}) {
		t.Fatalf("collection dependencies were not deduplicated: %v", control.CollectorIDs())
	}
	if control.InterviewQuestion != nil {
		t.Fatal("null interview question did not survive profile round trip")
	}
}
