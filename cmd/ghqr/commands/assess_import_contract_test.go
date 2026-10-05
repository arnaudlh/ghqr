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
	"time"

	"github.com/microsoft/ghqr/internal/assessment"
)

// TestAssessImportCLIEnforcesUIContractAndWritesNoFilesOnRejection confirms
// the real `ghqr assess import` entry point rejects a payload that fails
// its ui.org_security_overview contract, writing exactly zero evidence
// files -- never silently sanitized and persisted anyway.
func TestAssessImportCLIEnforcesUIContractAndWritesNoFilesOnRejection(t *testing.T) {
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	evidenceDir := filepath.Join(directory, "evidence")
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath,
		[]byte("organizations: [fixture-org]\nevidence_dir: "+evidenceDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	inputPath := filepath.Join(directory, "payload.json")
	if err := os.WriteFile(inputPath, []byte(`{"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(directory, "metadata.json")
	metadata := assessment.EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "ui.org_security_overview", Feature: "capture",
		Scope:       assessment.Scope{Host: "github.com", Kind: assessment.OrganizationScope, Name: "fixture-org"},
		CollectedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Endpoint:    "import://fixture/ui-capture", Pages: 1, CredentialKind: assessment.NoCredential,
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, metadataRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"import", "--config", configPath, "--input", inputPath, "--metadata", metadataPath})
	if err := command.Execute(); err == nil {
		t.Fatalf("the real import entry point bypassed its advertised ui.org_security_overview contract and accepted an "+
			"invalid payload: output=%s", output.String())
	}
	if output.Len() != 0 {
		t.Fatalf("a rejected import must not emit a success-shaped reference: %s", output.String())
	}

	written := 0
	statErr := func() error {
		_, err := os.Stat(evidenceDir)
		return err
	}()
	if statErr != nil && !os.IsNotExist(statErr) {
		t.Fatalf("unexpected error checking evidence directory: %v", statErr)
	}
	if statErr == nil {
		if walkErr := filepath.Walk(evidenceDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !info.IsDir() {
				written++
			}
			return nil
		}); walkErr != nil {
			t.Fatal(walkErr)
		}
	}
	if written != 0 {
		t.Fatalf("a rejected import contract payload must persist NO evidence files at all, found %d", written)
	}
}

// TestAssessImportCLIAcceptsValidUIContractAndRecordsRedactedProvenance
// confirms the positive path through the real CLI entry point: a payload
// satisfying the ui.org_security_overview contract is accepted, persisted
// with imported provenance (loaded back via the evidence store, not just a
// successful command exit), and redacted.
func TestAssessImportCLIAcceptsValidUIContractAndRecordsRedactedProvenance(t *testing.T) {
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	evidenceDir := filepath.Join(directory, "evidence")
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath,
		[]byte("organizations: [fixture-org]\nevidence_dir: "+evidenceDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	inputPath := filepath.Join(directory, "payload.json")
	validPayload := `{"collector_id":"ui.org_security_overview","captured_by":"assessor@example.test",` +
		`"captured_at":"2026-10-05T00:00:00Z","fields":{"two_factor_required":true,"token":"dummy-sensitive-value",` +
		`"owner_email":"person@example.test"}}`
	if err := os.WriteFile(inputPath, []byte(validPayload), 0o600); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(directory, "metadata.json")
	metadata := assessment.EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "ui.org_security_overview", Feature: "capture",
		Scope:       assessment.Scope{Host: "github.com", Kind: assessment.OrganizationScope, Name: "fixture-org"},
		CollectedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Endpoint:    "import://fixture/ui-capture", Pages: 1, CredentialKind: assessment.NoCredential,
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, metadataRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"import", "--config", configPath, "--input", inputPath, "--metadata", metadataPath})
	if err := command.Execute(); err != nil {
		t.Fatalf("a contract-satisfying ui.org_security_overview payload must be accepted: %v", err)
	}
	var ref assessment.EvidenceRef
	if err := json.Unmarshal(output.Bytes(), &ref); err != nil {
		t.Fatalf("expected a decoded evidence reference, got %q: %v", output.String(), err)
	}

	// Load back through the real evidence-store API, not a raw file scan:
	// command success alone does not prove what was actually persisted.
	store, err := assessment.OpenEvidenceStore(evidenceDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	raw, loadedMetadata, loadedRef, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil {
		t.Fatal(err)
	}
	if loadedRef != ref {
		t.Fatalf("CLI-reported reference does not match the stored evidence reference: %+v vs %+v", ref, loadedRef)
	}
	if loadedMetadata.SourceKind != assessment.ImportedEvidence {
		t.Fatalf("persisted evidence must carry imported provenance, got %q", loadedMetadata.SourceKind)
	}
	if strings.Contains(string(raw), "dummy-sensitive-value") {
		t.Fatal("the literal secret-shaped token value must never survive sanitization")
	}
	if strings.Contains(string(raw), "person@example.test") {
		t.Fatal("the nested assessor email value must never survive sanitization")
	}
}
