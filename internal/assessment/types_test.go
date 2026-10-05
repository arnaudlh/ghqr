// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestPercentageUnknownAndKnownZero(t *testing.T) {
	tests := []struct {
		name        string
		numerator   float64
		denominator float64
		status      MetricStatus
		number      float64
		wantError   bool
	}{
		{"empty population", 0, 0, MetricUnavailable, 0, false},
		{"known zero", 0, 10, MetricKnown, 0, false},
		{"partial coverage", 5, 10, MetricKnown, 50, false},
		{"full coverage", 10, 10, MetricKnown, 100, false},
		{"negative", -1, 10, "", 0, true},
		{"more than population", 11, 10, "", 0, true},
		{"not finite", math.NaN(), 10, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := Percentage(tt.numerator, tt.denominator, "fixture eligible repositories")
			if tt.wantError {
				if err == nil {
					t.Fatal("invalid ratio accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := value.Validate(); err != nil {
				t.Fatal(err)
			}
			if value.Status != tt.status {
				t.Fatalf("status = %s, want %s", value.Status, tt.status)
			}
			if tt.status == MetricUnavailable {
				if value.Number != nil || value.Reason == "" {
					t.Fatal("unknown denominator collapsed into a known value")
				}
			} else if value.Number == nil || *value.Number != tt.number {
				t.Fatalf("number = %v, want %v", value.Number, tt.number)
			}
		})
	}
}

func TestUnknownMetricRejectsZeroAndFalse(t *testing.T) {
	zero, no := 0.0, false
	for _, value := range []MetricValue{
		{Status: MetricUnavailable, Number: &zero, Reason: "not collected"},
		{Status: MetricUnavailable, Boolean: &no, Reason: "not collected"},
		{Status: MetricUnavailable},
		{Status: MetricKnown},
		{Status: MetricKnown, Number: &zero, Boolean: &no},
	} {
		if err := value.Validate(); err == nil {
			t.Fatalf("invalid metric accepted: %+v", value)
		}
	}
	unknown := MetricValue{Status: MetricUnavailable, Reason: "missing permission", EvidenceRefs: []string{}}
	data, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"number"`) || strings.Contains(string(data), `"boolean"`) {
		t.Fatalf("unknown metric export contains a guessed value: %s", data)
	}
}

func TestAssessmentStateContract(t *testing.T) {
	for _, state := range []State{Implemented, PartiallyImplemented, NotImplemented, NotApplicable, NotAssessed} {
		if err := state.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range []State{"", "clean", "false", "PASS"} {
		if err := state.Validate(); err == nil {
			t.Fatalf("unknown assessment state %q accepted", state)
		}
	}
}
