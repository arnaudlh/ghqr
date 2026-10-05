// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"strings"
	"testing"
)

func TestPreflightRequiresExplicitLiveConsent(t *testing.T) {
	command := newAssessCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"preflight"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--live") {
		t.Fatalf("preflight implicitly contacted configured targets: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("unconsented preflight emitted a success-shaped result")
	}
}

func TestImportRequiresExplicitPayloadAndProvenance(t *testing.T) {
	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"import"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--metadata") {
		t.Fatal("import accepted data without provenance")
	}
}
