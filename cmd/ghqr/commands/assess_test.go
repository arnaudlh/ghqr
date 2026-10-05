// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/microsoft/ghqr/internal/assessment"
)

func TestAssessCommandDiscovery(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"assess"})
	if err != nil || cmd.Name() != "assess" {
		t.Fatalf("assessment command is not discoverable: %v", err)
	}
	cmd, _, err = rootCmd.Find([]string{"scan"})
	if err != nil || cmd != scanCmd {
		t.Fatalf("legacy scan command was changed: %v", err)
	}
}

func TestAssessmentUnimplementedOperationsFailExplicitly(t *testing.T) {
	for _, operation := range []string{"run"} {
		t.Run(operation, func(t *testing.T) {
			command := newAssessCommand()
			var output bytes.Buffer
			command.SetOut(&output)
			command.SetErr(&output)
			command.SilenceErrors, command.SilenceUsage = true, true
			command.SetArgs([]string{operation})
			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), "not implemented") {
				t.Fatalf("unimplemented operation reported success: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("unimplemented operation emitted a success-shaped result: %s", output.String())
			}
		})
	}
}

func TestAssessmentDefaultProfileWorksOutsideCheckout(t *testing.T) {
	t.Chdir(t.TempDir())
	command := newAssessCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"profile"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var summary assessment.ProfileSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Version != assessment.ProfileVersion || summary.ControlCount != 456 || summary.CollectorCount != 67 {
		t.Fatalf("unexpected default profile summary: %+v", summary)
	}
}

func TestAssessmentDefaultPlanWorksOutsideCheckout(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath, []byte("organizations: [fixture-org]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(directory)
	command := newAssessCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"plan", "--config", configPath})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var plan assessment.Plan
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Results) != 456 || len(plan.Collectors) != 67 || len(plan.Metrics) != 581 {
		t.Fatal("default plan lost profile data")
	}
}

func TestAssessmentPlanRequiresExplicitCustomerConfig(t *testing.T) {
	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"plan"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("missing customer configuration error = %v", err)
	}
}

func TestAssessmentInvalidOverrideDoesNotUseDefault(t *testing.T) {
	command := newAssessCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"profile", "--profile", filepath.Join(t.TempDir(), "missing.json")})
	if err := command.Execute(); err == nil {
		t.Fatal("invalid override silently used the bundled default")
	}
	if output.Len() != 0 {
		t.Fatalf("invalid override produced a success-shaped result: %s", output.String())
	}
}
