// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestStructuredMetricPayloadContract(t *testing.T) {
	list := []string{"review_wait", "ci_failure"}
	dictionary := map[string]float64{"pull_request": 80, "required_status_checks": 75}
	emptyList := []string{}
	emptyDictionary := map[string]float64{}
	var nullList []string
	var nullDictionary map[string]float64
	nonfinite := map[string]float64{"pull_request": math.Inf(1)}
	zero := 0.0
	tests := []struct {
		name  string
		value MetricValue
		valid bool
	}{
		{"list", MetricValue{Status: MetricKnown, List: &list}, true},
		{"dictionary", MetricValue{Status: MetricKnown, Dictionary: &dictionary}, true},
		{"known empty list", MetricValue{Status: MetricKnown, List: &emptyList}, true},
		{"known empty dictionary", MetricValue{Status: MetricKnown, Dictionary: &emptyDictionary}, true},
		{"null list", MetricValue{Status: MetricKnown, List: &nullList}, false},
		{"null dictionary", MetricValue{Status: MetricKnown, Dictionary: &nullDictionary}, false},
		{"multiple structured payloads", MetricValue{Status: MetricKnown, List: &list, Dictionary: &dictionary}, false},
		{"number and list", MetricValue{Status: MetricKnown, Number: &zero, List: &list}, false},
		{"unknown empty list", MetricValue{Status: MetricUnavailable, List: &emptyList, Reason: "forbidden"}, false},
		{"inapplicable dictionary", MetricValue{Status: MetricInapplicable, Dictionary: &dictionary, Reason: "excluded"}, false},
		{"nonfinite dictionary", MetricValue{Status: MetricKnown, Dictionary: &nonfinite}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.value.Validate(); (err == nil) != tt.valid {
				t.Fatalf("metric validity = %v, want %v: %v", err == nil, tt.valid, err)
			}
		})
	}
	for _, value := range []MetricValue{
		{Status: MetricKnown, List: &list},
		{Status: MetricKnown, Dictionary: &dictionary},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var restored MetricValue
		if err := json.Unmarshal(data, &restored); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(restored, value) {
			t.Fatalf("structured metric lost its shape: %s", data)
		}
		if strings.Contains(string(data), `"text"`) {
			t.Fatalf("structured metric was stringified: %s", data)
		}
	}
}

func TestSignedChangeObservationsAndBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		baseline  float64
		current   float64
		want      float64
		status    MetricStatus
		wantError bool
	}{
		{"reduction", 100, 80, -20, MetricKnown, false},
		{"fully cleared", 100, 0, -100, MetricKnown, false},
		{"unchanged", 100, 100, 0, MetricKnown, false},
		{"large increase", 100, 400, 300, MetricKnown, false},
		{"empty baseline", 0, 0, 0, MetricUnavailable, false},
		{"new backlog", 0, 10, 0, MetricUnavailable, false},
		{"negative observation", 100, -1, 0, "", true},
		{"nonfinite observation", math.NaN(), 100, 0, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := SignedPercentageChange(tt.baseline, tt.current, "matched alert backlog at lookback start/end")
			if tt.wantError {
				if err == nil {
					t.Fatal("invalid signed change accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := value.Validate(); err != nil {
				t.Fatal(err)
			}
			if value.Status != tt.status || value.Baseline == nil || value.Current == nil {
				t.Fatalf("signed change lost observations: %+v", value)
			}
			if tt.status == MetricKnown && (value.Number == nil || *value.Number != tt.want) {
				t.Fatalf("signed change = %v, want %v", value.Number, tt.want)
			}
			if tt.status == MetricUnavailable && (value.Number != nil || value.Reason == "") {
				t.Fatal("zero-baseline trend was reported as known")
			}
		})
	}
}

func TestFrameworkSourcesUsePillarChecklists(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	checklists := map[string]bool{
		FrameworkURL + "/productivity/checklist":         true,
		FrameworkURL + "/collaboration/checklist":        true,
		FrameworkURL + "/application-security/checklist": true,
		FrameworkURL + "/governance/checklist":           true,
		FrameworkURL + "/architecture/checklist":         true,
	}
	seen := map[string]bool{}
	for _, source := range profile.Sources() {
		if source.Origin == SecurityDeepDive {
			if source.AuthorityURL != PlatformDocsURL || !strings.Contains(source.MappingNote, "requires review") {
				t.Fatalf("extension source invented a citation: %+v", source)
			}
		} else {
			if !checklists[source.AuthorityURL] {
				t.Fatalf("framework control lacks a pillar checklist: %+v", source)
			}
			seen[source.AuthorityURL] = true
		}
	}
	if len(seen) != 5 {
		t.Fatal("some framework pillar mappings are missing")
	}
}
