// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestImportContractCollectorIDsAreSixteenAndKnownToTheCatalogue confirms
// the import-only registry matches exactly the catalogue's non-API
// collector families and every ID is a recognized catalogue collector
// (accepted by the evidence store's identity check).
func TestImportContractCollectorIDsAreSixteenAndKnownToTheCatalogue(t *testing.T) {
	ids := ImportContractCollectorIDs()
	if len(ids) != 16 {
		t.Fatalf("expected exactly 16 import-contract collector IDs, got %d: %v", len(ids), ids)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate import-contract collector ID %q", id)
		}
		seen[id] = true
		found := false
		for _, known := range collectorIDs {
			if known == id {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("import-contract collector ID %q is not a recognized catalogue collector", id)
		}
	}
}

// TestValidateImportContractPayloadGHESCLIRejectsUnknownStatus confirms the
// ghes.cli contract validates the documented OK/WARN/ERR taxonomy and
// rejects both malformed JSON and an unrecognized status, never silently
// accepting an arbitrary blob.
func TestValidateImportContractPayloadGHESCLIRejectsUnknownStatus(t *testing.T) {
	valid := GHESCLIImport{
		CapturedAt:  time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Replication: []GHESCLIReplicationEntry{{Service: "mysql_server", Status: "OK"}},
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ValidateImportContractPayload("ghes.cli", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded.(GHESCLIImport); !ok {
		t.Fatalf("expected a decoded GHESCLIImport, got %T", decoded)
	}

	invalid := []byte(`{"captured_at":"2026-10-05T00:00:00Z","replication":[{"service":"mysql_server","status":"FINE"}]}`)
	if _, err := ValidateImportContractPayload("ghes.cli", invalid); err == nil {
		t.Fatal("expected an unrecognized replication status to be rejected")
	}

	if _, err := ValidateImportContractPayload("ghes.cli", []byte(`{not json`)); err == nil {
		t.Fatal("expected malformed JSON to be rejected")
	}

	missingCapturedAt := []byte(`{"replication":[]}`)
	if _, err := ValidateImportContractPayload("ghes.cli", missingCapturedAt); err == nil {
		t.Fatal("expected a missing captured_at to be rejected")
	}
}

// TestValidateImportContractPayloadGHESBackupValidatesSnapshotStatus confirms
// the ghes.backup contract's required fields and enum validation.
func TestValidateImportContractPayloadGHESBackupValidatesSnapshotStatus(t *testing.T) {
	valid := []byte(`{"captured_at":"2026-10-05T00:00:00Z","schedule_cron_expression":"0 2 * * *",` +
		`"retained_snapshots":7,"latest_snapshot_status":"success"}`)
	if _, err := ValidateImportContractPayload("ghes.backup", valid); err != nil {
		t.Fatal(err)
	}
	invalidStatus := []byte(`{"captured_at":"2026-10-05T00:00:00Z","retained_snapshots":7,"latest_snapshot_status":"done"}`)
	if _, err := ValidateImportContractPayload("ghes.backup", invalidStatus); err == nil {
		t.Fatal("expected an unrecognized snapshot status to be rejected")
	}
	negativeSnapshots := []byte(`{"captured_at":"2026-10-05T00:00:00Z","retained_snapshots":-1,"latest_snapshot_status":"success"}`)
	if _, err := ValidateImportContractPayload("ghes.backup", negativeSnapshots); err == nil {
		t.Fatal("expected a negative retained_snapshots to be rejected")
	}
}

// TestValidateImportContractPayloadUICaptureRequiresMatchingCollectorAndFields
// confirms a ui.* capture is rejected when empty, when its declared
// collector_id does not match the target collector, or when required
// fields are missing — never silently accepted as a successful capture.
func TestValidateImportContractPayloadUICaptureRequiresMatchingCollectorAndFields(t *testing.T) {
	valid := []byte(`{"collector_id":"ui.org_security_overview","captured_by":"assessor@example.test",` +
		`"captured_at":"2026-10-05T00:00:00Z","fields":{"two_factor_required":true}}`)
	decoded, err := ValidateImportContractPayload("ui.org_security_overview", valid)
	if err != nil {
		t.Fatal(err)
	}
	capture, ok := decoded.(UISettingCapture)
	if !ok || capture.Fields["two_factor_required"] != true {
		t.Fatalf("unexpected decoded capture: %+v", decoded)
	}

	mismatched := []byte(`{"collector_id":"ui.org_pat_policy","captured_by":"assessor@example.test",` +
		`"captured_at":"2026-10-05T00:00:00Z","fields":{"x":1}}`)
	if _, err := ValidateImportContractPayload("ui.org_security_overview", mismatched); err == nil {
		t.Fatal("expected a mismatched collector_id to be rejected")
	}

	emptyFields := []byte(`{"collector_id":"ui.org_security_overview","captured_by":"assessor@example.test",` +
		`"captured_at":"2026-10-05T00:00:00Z","fields":{}}`)
	if _, err := ValidateImportContractPayload("ui.org_security_overview", emptyFields); err == nil {
		t.Fatal("expected an empty fields map (a missed capture) to be rejected")
	}
}

// TestValidateImportContractPayloadExternalFeedAndManualContracts exercises
// the remaining three contract families with one valid payload each,
// confirming required-field validation is enforced.
func TestValidateImportContractPayloadExternalFeedAndManualContracts(t *testing.T) {
	externalFeed := []byte(`{"source":"manual copy from https://www.githubstatus.com","retrieved_at":"2026-10-05T00:00:00Z",` +
		`"payload":{"status":"operational"}}`)
	if _, err := ValidateImportContractPayload("ext.github_status", externalFeed); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateImportContractPayload("ext.github_status", []byte(`{"source":"x","retrieved_at":"2026-10-05T00:00:00Z","payload":{}}`)); err == nil {
		t.Fatal("expected an empty external feed payload to be rejected")
	}

	interview := []byte(`{"control_id":"PRD-041","assessor":"assessor@example.test","answered_at":"2026-10-05T00:00:00Z",` +
		`"question":"Is X in place?","response":"Yes, per policy Y"}`)
	if _, err := ValidateImportContractPayload("manual.interview", interview); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateImportContractPayload("manual.interview", []byte(`{"control_id":"PRD-041"}`)); err == nil {
		t.Fatal("expected a missing assessor/response to be rejected")
	}

	document := []byte(`{"control_id":"GOV-010","document_title":"Access review runbook",` +
		`"reviewed_by":"assessor@example.test","reviewed_at":"2026-10-05T00:00:00Z"}`)
	if _, err := ValidateImportContractPayload("manual.document", document); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateImportContractPayload("manual.document", []byte(`{"control_id":"GOV-010"}`)); err == nil {
		t.Fatal("expected a missing document_title/reviewed_by to be rejected")
	}
}

// TestValidateImportContractPayloadRejectsNonContractCollector confirms a
// collector ID outside the 16-member import-contract family is rejected
// rather than silently validated against an arbitrary fallback shape.
func TestValidateImportContractPayloadRejectsNonContractCollector(t *testing.T) {
	if _, err := ValidateImportContractPayload("org.settings", []byte(`{}`)); err == nil {
		t.Fatal("expected a non-import-contract collector ID to be rejected")
	}
}

// TestPreflightReportsImportOnlyReadinessNotUnimplemented confirms the
// preflight feasibility report marks every import-contract collector ID as
// ImportOnly (with an explicit, accurate reason), never the default
// Unimplemented reason that would wrongly imply a future API probe is
// expected, and never Ready (no live probe is attempted for these).
func TestPreflightReportsImportOnlyReadinessNotUnimplemented(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: "github.com", Deployment: Cloud, Organizations: []string{"fixture-org"}}
	report, err := preflightWithStore(context.Background(), profile, []Target{target}, store, SystemClock{},
		func(Target) (*CollectionClient, error) {
			return nil, fmt.Errorf("no live credentials available in this fixture test")
		})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]CollectorFeasibility{}
	for _, item := range report.Collectors {
		found[item.CollectorID] = item
	}
	for _, id := range ImportContractCollectorIDs() {
		item, ok := found[id]
		if !ok {
			t.Fatalf("collector %q missing from the feasibility report", id)
		}
		if item.Readiness != ImportOnly {
			t.Fatalf("collector %q should report ImportOnly readiness, got %q", id, item.Readiness)
		}
		if item.Reason == "" || len(item.Outcomes) != 0 {
			t.Fatalf("collector %q must carry an explicit reason and no probe outcomes: %+v", id, item)
		}
	}
}

// TestImportJSONEnforcesImportContractBeforeWritingAnyEvidence is a
// regression test for the real runtime import entry point (ImportJSON, the
// same function the `ghqr assess import` CLI command calls) silently
// bypassing ValidateImportContractPayload entirely: ValidateImportContractPayload
// having its own passing unit tests never proved the live import path
// actually invoked it. A raw payload that does not satisfy the
// ui.org_security_overview contract must be rejected by ImportJSON itself,
// before any evidence store is even opened, with exactly zero files written
// to the evidence directory -- an ordinary scoped-API collector ID (outside
// the 16-member import-contract family) must remain entirely unaffected.
func TestImportJSONEnforcesImportContractBeforeWritingAnyEvidence(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]"))
	if err != nil {
		t.Fatal(err)
	}
	evidenceDir := t.TempDir()
	config.EvidenceDir = evidenceDir
	metadata := evidenceFixtureMetadata(t)
	metadata.CollectorID = "ui.org_security_overview"
	metadata.Feature = "capture"

	invalid := []byte(`{"unexpected":true}`)
	if _, err := ValidateImportContractPayload(metadata.CollectorID, invalid); err == nil {
		t.Fatal("test fixture unexpectedly satisfies the UI contract on its own")
	}
	if ref, err := ImportJSON(profile, config, invalid, metadata); err == nil {
		t.Fatalf("the real import entry point bypassed its advertised ui.org_security_overview contract and persisted "+
			"invalid evidence: %+v", ref)
	}
	writtenFiles := 0
	if walkErr := filepath.Walk(evidenceDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() {
			writtenFiles++
		}
		return nil
	}); walkErr != nil {
		t.Fatal(walkErr)
	}
	if writtenFiles != 0 {
		t.Fatalf("a rejected import-contract payload must write NO files at all, found %d", writtenFiles)
	}

	valid := []byte(`{"collector_id":"ui.org_security_overview","captured_by":"assessor@example.test",` +
		`"captured_at":"2026-10-05T00:00:00Z","fields":{"two_factor_required":true,"token":"dummy-sensitive-value"}}`)
	ref, err := ImportJSON(profile, config, valid, metadata)
	if err != nil {
		t.Fatalf("a contract-satisfying payload must be accepted: %v", err)
	}
	store := evidenceFixtureStore(t, evidenceDir, nil)
	raw, safeMetadata, restoredRef, loadErr := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if loadErr != nil || restoredRef != ref || safeMetadata.SourceKind != ImportedEvidence {
		t.Fatalf("valid import must be persisted with imported provenance: %v", loadErr)
	}
	if bytesContainAny(raw, "dummy-sensitive-value") {
		t.Fatal("the literal secret-shaped value must never survive sanitization in persisted import evidence")
	}

	// An ordinary scoped-API collector ID outside the import-contract family
	// must be entirely unaffected by this check: any well-scoped payload is
	// still accepted exactly as before.
	ordinary := evidenceFixtureMetadata(t)
	if _, err := ImportJSON(profile, config, []byte(`{"anything":true}`), ordinary); err != nil {
		t.Fatalf("an ordinary scoped-API collector import must not be affected by the import-contract gate: %v", err)
	}
}
