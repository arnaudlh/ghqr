// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/microsoft/ghqr/internal/assessment"
)

func TestAssessmentEvaluateUsesChecksOverride(t *testing.T) {
	directory := t.TempDir()
	config := writeFixtureConfig(t, directory)
	run := writeFixtureRunReport(t, directory)
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	checks, err := assessment.LoadSimpleChecks(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	for index := range checks.Checks {
		checks.Checks[index].FieldPath = "/overall/boolean"
	}
	data, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	checksPath := filepath.Join(directory, "checks.json")
	if err := os.WriteFile(checksPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "output")
	command := newAssessCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"evaluate", "--config", config, "--run", run, "--out", output, "--allow-unverified", "--checks", checksPath})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	expected, err := assessment.LoadSimpleChecks(profile, checksPath)
	if err != nil {
		t.Fatal(err)
	}
	results, err := assessment.LoadEvaluationResults(profile, output)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.ControlID == "ARC-005" || result.ControlID == "GOV-001" {
			if result.RuleDefinitionSHA256 != expected.SHA256 {
				t.Fatalf("CLI override did not reach the runtime: %+v", result)
			}
		}
	}
}
