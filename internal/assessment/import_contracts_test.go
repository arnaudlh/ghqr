// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	omittedSnapshots := []byte(`{"captured_at":"2026-10-05T00:00:00Z","latest_snapshot_status":"success"}`)
	if _, err := ValidateImportContractPayload("ghes.backup", omittedSnapshots); err == nil {
		t.Fatal("expected an omitted retained_snapshots to be rejected, not silently treated as 0")
	}
	explicitZeroSnapshots := []byte(`{"captured_at":"2026-10-05T00:00:00Z","retained_snapshots":0,"latest_snapshot_status":"failed"}`)
	decoded, err := ValidateImportContractPayload("ghes.backup", explicitZeroSnapshots)
	if err != nil {
		t.Fatal(err)
	}
	backup, ok := decoded.(GHESBackupImport)
	if !ok || backup.RetainedSnapshots == nil || *backup.RetainedSnapshots != 0 {
		t.Fatalf("an explicit 0 must be accepted and preserved distinctly from omission: %+v", decoded)
	}
}

// TestValidateImportContractPayloadGHESCLIAcceptsTimestampOnlyNoReplication
// confirms a ghes.cli capture with no replication data (a legitimate signal
// for a non-replicated instance, or a CLI run that found nothing to report)
// is accepted, never rejected merely for having an empty replication list.
func TestValidateImportContractPayloadGHESCLIAcceptsTimestampOnlyNoReplication(t *testing.T) {
	timestampOnly := []byte(`{"captured_at":"2026-10-05T00:00:00Z","replication":[]}`)
	decoded, err := ValidateImportContractPayload("ghes.cli", timestampOnly)
	if err != nil {
		t.Fatalf("a timestamp-only capture with no replication entries must be accepted: %v", err)
	}
	cli, ok := decoded.(GHESCLIImport)
	if !ok || len(cli.Replication) != 0 {
		t.Fatalf("unexpected decoded payload: %+v", decoded)
	}
	// The replication key itself may also be entirely omitted, not merely an
	// empty array.
	replicationOmitted := []byte(`{"captured_at":"2026-10-05T00:00:00Z"}`)
	if _, err := ValidateImportContractPayload("ghes.cli", replicationOmitted); err != nil {
		t.Fatalf("an omitted replication key must also be accepted: %v", err)
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

// TestUICaptureAccessorsReportUnknownNeverCoerced confirms the shared
// UISettingCapture.Fields typed accessors report an absent field, or a
// field present with the wrong JSON type, as unknown (nil) -- never
// silently coerced to false/""/0.
func TestUICaptureAccessorsReportUnknownNeverCoerced(t *testing.T) {
	fields := map[string]any{
		"a_bool": true, "a_string": "value", "a_number": float64(42),
		"bool_as_string": "true", "string_as_bool": false, "number_as_string": "42",
	}
	if value := uiCaptureBool(fields, "a_bool"); value == nil || *value != true {
		t.Fatalf("expected the correctly-typed bool field read back: %v", value)
	}
	if value := uiCaptureBool(fields, "missing"); value != nil {
		t.Fatalf("expected an absent field to report unknown, not false: %v", *value)
	}
	if value := uiCaptureBool(fields, "bool_as_string"); value != nil {
		t.Fatalf("expected a wrong-typed field to report unknown, never coerced: %v", *value)
	}
	if value := uiCaptureString(fields, "a_string"); value == nil || *value != "value" {
		t.Fatalf("expected the correctly-typed string field read back: %v", value)
	}
	if value := uiCaptureString(fields, "string_as_bool"); value != nil {
		t.Fatalf("expected a wrong-typed field to report unknown, never coerced: %v", *value)
	}
	if value := uiCaptureFloat(fields, "a_number"); value == nil || *value != 42 {
		t.Fatalf("expected the correctly-typed numeric field read back: %v", value)
	}
	if value := uiCaptureFloat(fields, "number_as_string"); value != nil {
		t.Fatalf("expected a wrong-typed field to report unknown, never coerced: %v", *value)
	}
}

// TestNormalizeGHESBackupImportComputesAgeRelativeToCapturedAtNotWallClock
// confirms latest_snapshot_age_h is derived from the import's own
// CapturedAt timestamp, not this process's live wall clock -- a report
// generated days after collection must not silently inflate the apparent
// snapshot age -- and that every other field this round normalizes
// (backup_schedule, snapshots_retained, backup_encrypted) is a direct,
// typed carry-over.
func TestNormalizeGHESBackupImportComputesAgeRelativeToCapturedAtNotWallClock(t *testing.T) {
	captured := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	snapshot := captured.Add(-6 * time.Hour)
	retained, encrypted := 10, true
	payload := GHESBackupImport{
		CapturedAt: captured, ScheduleCronExpression: "0 2 * * *", RetainedSnapshots: &retained,
		LatestSnapshotAt: &snapshot, LatestSnapshotStatus: "success", Encrypted: &encrypted,
	}
	observation := NormalizeGHESBackupImport(payload)
	if observation.BackupSchedule == nil || *observation.BackupSchedule != "0 2 * * *" {
		t.Fatalf("expected the cron expression carried over verbatim: %+v", observation)
	}
	if observation.LatestSnapshotAgeH == nil || *observation.LatestSnapshotAgeH != 6 {
		t.Fatalf("expected a 6-hour age computed relative to captured_at, not live wall clock: %+v", observation)
	}
	if observation.SnapshotsRetained == nil || *observation.SnapshotsRetained != 10 {
		t.Fatalf("expected the retained-snapshot count carried over: %+v", observation)
	}
	if observation.BackupEncrypted == nil || !*observation.BackupEncrypted {
		t.Fatalf("expected the encrypted flag carried over: %+v", observation)
	}
}

// TestNormalizeGHESBackupImportUnknownFieldsStayUnknown confirms an absent
// schedule/snapshot timestamp/retained-count/encrypted flag, and a
// logically impossible (future) latest-snapshot timestamp, all report
// unknown -- never a fabricated zero/empty/false value.
func TestNormalizeGHESBackupImportUnknownFieldsStayUnknown(t *testing.T) {
	captured := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	observation := NormalizeGHESBackupImport(GHESBackupImport{CapturedAt: captured, LatestSnapshotStatus: "unknown"})
	if observation.BackupSchedule != nil || observation.LatestSnapshotAgeH != nil ||
		observation.SnapshotsRetained != nil || observation.BackupEncrypted != nil {
		t.Fatalf("expected every unset field to stay unknown (nil), never a fabricated value: %+v", observation)
	}

	future := captured.Add(1 * time.Hour)
	observation = NormalizeGHESBackupImport(GHESBackupImport{CapturedAt: captured, LatestSnapshotAt: &future, LatestSnapshotStatus: "success"})
	if observation.LatestSnapshotAgeH != nil {
		t.Fatalf("expected a logically impossible future snapshot timestamp to report unknown age, not a negative number: %+v", observation)
	}
}

// TestNormalizeUIEntAuthCaptureRejectsMismatchedCollectorID confirms the
// normalizer refuses to interpret a different collector's capture as
// ui.ent_auth's own fields.
func TestNormalizeUIEntAuthCaptureRejectsMismatchedCollectorID(t *testing.T) {
	_, err := NormalizeUIEntAuthCapture(UISettingCapture{CollectorID: "ui.org_pat_policy", Fields: map[string]any{"sso_mode": "saml"}})
	if err == nil {
		t.Fatal("expected a mismatched collector_id to be rejected")
	}
}

// TestNormalizeUIEntAuthCaptureKnownAndUnrecognizedModes confirms a
// recognized sso_mode value normalizes (case/whitespace-insensitively), an
// unrecognized value reports unknown rather than a fabricated new mode, and
// sso_enforced/ip_allow_list_enabled normalize independently of sso_mode.
func TestNormalizeUIEntAuthCaptureKnownAndUnrecognizedModes(t *testing.T) {
	recognized, err := NormalizeUIEntAuthCapture(UISettingCapture{
		CollectorID: "ui.ent_auth",
		Fields:      map[string]any{"sso_mode": "  SAML ", "sso_enforced": true, "ip_allow_list_enabled": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if recognized.SSOMode == nil || *recognized.SSOMode != "saml" {
		t.Fatalf("expected a recognized sso_mode to normalize case/whitespace-insensitively: %+v", recognized)
	}
	if recognized.SSOEnforced == nil || !*recognized.SSOEnforced {
		t.Fatalf("expected sso_enforced carried over: %+v", recognized)
	}
	if recognized.IPAllowListEnabled == nil || *recognized.IPAllowListEnabled {
		t.Fatalf("expected ip_allow_list_enabled carried over as false (a known, confirmed negative): %+v", recognized)
	}

	unrecognized, err := NormalizeUIEntAuthCapture(UISettingCapture{
		CollectorID: "ui.ent_auth", Fields: map[string]any{"sso_mode": "shibboleth"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if unrecognized.SSOMode != nil {
		t.Fatalf("expected an unrecognized sso_mode value to report unknown, never a fabricated new mode: %+v", unrecognized)
	}
}

// TestNormalizeUIOrgPATPolicyCaptureKnownFields confirms the three
// normalized fields carry over typed, and a mismatched collector_id is
// rejected.
func TestNormalizeUIOrgPATPolicyCaptureKnownFields(t *testing.T) {
	if _, err := NormalizeUIOrgPATPolicyCapture(UISettingCapture{CollectorID: "ui.ent_auth"}); err == nil {
		t.Fatal("expected a mismatched collector_id to be rejected")
	}
	observation, err := NormalizeUIOrgPATPolicyCapture(UISettingCapture{
		CollectorID: "ui.org_pat_policy",
		Fields: map[string]any{
			"fine_grained_requires_approval": true, "classic_restricted": false, "max_lifetime_days": float64(366),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if observation.FineGrainedRequiresApproval == nil || !*observation.FineGrainedRequiresApproval {
		t.Fatalf("expected fine_grained_requires_approval carried over: %+v", observation)
	}
	if observation.ClassicRestricted == nil || *observation.ClassicRestricted {
		t.Fatalf("expected classic_restricted carried over as a known false: %+v", observation)
	}
	if observation.MaxLifetimeDays == nil || *observation.MaxLifetimeDays != 366 {
		t.Fatalf("expected max_lifetime_days carried over: %+v", observation)
	}
}

// TestLoadNormalizedGHESBackupImportRoundTripsThroughTheEvidenceStore
// proves the full read-back path: an evidence record saved exactly as
// ImportJSON would persist it is read back out of the store and normalized
// identically to calling NormalizeGHESBackupImport directly, and a missing
// import at that scope/feature reports an explicit NotRun outcome, never a
// confident empty result.
func TestLoadNormalizedGHESBackupImportRoundTripsThroughTheEvidenceStore(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: "github.example.com", Kind: EnterpriseScope, Name: "fixture-enterprise"}
	metadata := evidenceFixtureMetadata(t)
	metadata.CollectorID, metadata.Feature, metadata.Scope = "ghes.backup", "capture", scope
	captured := metadata.CollectedAt
	snapshot := captured.Add(-3 * time.Hour)
	retained, encrypted := 14, true
	raw, err := json.Marshal(GHESBackupImport{
		CapturedAt: captured, ScheduleCronExpression: "0 3 * * *", RetainedSnapshots: &retained,
		LatestSnapshotAt: &snapshot, LatestSnapshotStatus: "success", Encrypted: &encrypted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJSON(raw, metadata); err != nil {
		t.Fatal(err)
	}

	observation, outcome, err := LoadNormalizedGHESBackupImport(store, fixtureProfileWithDefault(t), scope, "capture")
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != CollectionOK || outcome.Readiness != ImportOnly {
		t.Fatalf("expected a successful import-only outcome: %+v", outcome)
	}
	// Pages must be explicitly 1 whenever EvidenceRefs cites evidence (here,
	// exactly 2 refs: data + metadata): replay verification elsewhere in
	// this package cross-checks len(EvidenceRefs) == Pages*2 uniformly
	// across every collector's outcomes, import-sourced or not.
	if outcome.Pages != 1 || len(outcome.EvidenceRefs) != 2 {
		t.Fatalf("expected Pages:1 matching the 2 cited evidence refs (data+metadata): %+v", outcome)
	}
	if observation.LatestSnapshotAgeH == nil || *observation.LatestSnapshotAgeH != 3 {
		t.Fatalf("expected the round-tripped observation to normalize identically: %+v", observation)
	}

	_, missingOutcome, err := LoadNormalizedGHESBackupImport(store, fixtureProfileWithDefault(t), scope, "a-feature-never-imported")
	if err != nil {
		t.Fatal(err)
	}
	if missingOutcome.Status != NotRun {
		t.Fatalf("expected a missing import at this scope/feature to report an explicit not-run outcome: %+v", missingOutcome)
	}
	if missingOutcome.Pages != 0 || len(missingOutcome.EvidenceRefs) != 0 {
		t.Fatalf("expected Pages:0 matching zero cited evidence refs for a not-run outcome: %+v", missingOutcome)
	}
}

// TestLoadNormalizedUIEntAuthCaptureRoundTripsThroughTheEvidenceStore
// mirrors the ghes.backup round-trip test for the ui.ent_auth capture path.
func TestLoadNormalizedUIEntAuthCaptureRoundTripsThroughTheEvidenceStore(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: "github.com", Kind: EnterpriseScope, Name: "fixture-enterprise"}
	metadata := evidenceFixtureMetadata(t)
	metadata.CollectorID, metadata.Feature, metadata.Scope = "ui.ent_auth", "capture", scope
	raw, err := json.Marshal(UISettingCapture{
		CollectorID: "ui.ent_auth", CapturedBy: "assessor@example.com", CapturedAt: metadata.CollectedAt,
		Fields: map[string]any{"sso_mode": "oidc", "sso_enforced": true, "ip_allow_list_enabled": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJSON(raw, metadata); err != nil {
		t.Fatal(err)
	}

	observation, outcome, err := LoadNormalizedUIEntAuthCapture(store, fixtureProfileWithDefault(t), scope, "capture")
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != CollectionOK {
		t.Fatalf("expected a successful import-only outcome: %+v", outcome)
	}
	if observation.SSOMode == nil || *observation.SSOMode != "oidc" {
		t.Fatalf("expected the round-tripped sso_mode: %+v", observation)
	}
}

// TestApplyNormalizedImportsFeedsExactProfileKeysIntoReportMetrics is the
// production-wiring proof: ApplyNormalizedImports is not helper-only -- it
// actually populates report.Metrics under the exact profile keys
// NormalizedImportMetricKeys documents, with real, non-empty EvidenceRefs
// pointing at the immutable stored evidence object pair, and a
// CollectorOutcome recorded for every source (not just the successful
// ones).
func TestApplyNormalizedImportsFeedsExactProfileKeysIntoReportMetrics(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	entScope := Scope{Host: "github.com", Kind: EnterpriseScope, Name: "fixture-enterprise"}
	orgScope := Scope{Host: "github.com", Kind: OrganizationScope, Name: "fixture-org"}

	entMetadata := evidenceFixtureMetadata(t)
	entMetadata.CollectorID, entMetadata.Feature, entMetadata.Scope = "ui.ent_auth", "capture", entScope
	entRaw, err := json.Marshal(UISettingCapture{
		CollectorID: "ui.ent_auth", CapturedBy: "assessor@example.com", CapturedAt: entMetadata.CollectedAt,
		Fields: map[string]any{"sso_mode": "saml", "sso_enforced": true, "ip_allow_list_enabled": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJSON(entRaw, entMetadata); err != nil {
		t.Fatal(err)
	}

	orgMetadata := evidenceFixtureMetadata(t)
	orgMetadata.CollectorID, orgMetadata.Feature, orgMetadata.Scope = "ui.org_pat_policy", "capture", orgScope
	orgRaw, err := json.Marshal(UISettingCapture{
		CollectorID: "ui.org_pat_policy", CapturedBy: "assessor@example.com", CapturedAt: orgMetadata.CollectedAt,
		Fields: map[string]any{"fine_grained_requires_approval": true, "classic_restricted": true, "max_lifetime_days": float64(90)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJSON(orgRaw, orgMetadata); err != nil {
		t.Fatal(err)
	}

	report := &VerticalSliceReport{Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}}
	sources := []ImportSource{
		{CollectorID: "ui.ent_auth", Scope: entScope, Feature: "capture"},
		{CollectorID: "ui.org_pat_policy", Scope: orgScope, Feature: "capture"},
		{CollectorID: "ghes.backup", Scope: entScope, Feature: "a-feature-never-imported"},
	}
	if err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), sources); err != nil {
		t.Fatal(err)
	}

	ssoMode, ok := report.Metrics["sso_mode"]
	if !ok || ssoMode.Overall.Status != MetricKnown || ssoMode.Overall.Text == nil || *ssoMode.Overall.Text != "saml" {
		t.Fatalf("expected sso_mode fed into report.Metrics under its exact profile key: %+v", ssoMode)
	}
	if ssoMode.PerOrganization[entScope.Key()].Text == nil || *ssoMode.PerOrganization[entScope.Key()].Text != "saml" {
		t.Fatalf("expected sso_mode's per-organization entry keyed by the source scope: %+v", ssoMode.PerOrganization)
	}
	classicRestricted, ok := report.Metrics["classic_restricted"]
	if !ok || classicRestricted.Overall.Status != MetricKnown || classicRestricted.Overall.Boolean == nil || !*classicRestricted.Overall.Boolean {
		t.Fatalf("expected classic_restricted fed into report.Metrics under its exact profile key: %+v", classicRestricted)
	}
	maxLifetime, ok := report.Metrics["max_lifetime_days"]
	if !ok || maxLifetime.Overall.Status != MetricKnown || maxLifetime.Overall.Number == nil || *maxLifetime.Overall.Number != 90 {
		t.Fatalf("expected max_lifetime_days fed into report.Metrics under its exact profile key: %+v", maxLifetime)
	}

	// ghes.backup had no actual import at that scope/feature: its outcome
	// must still be recorded (NotRun, never silently skipped), and EVERY
	// one of its documented metric keys must still appear -- as an explicit
	// MetricUnavailable with a semantic reason, never silently absent
	// (which would be indistinguishable from "this metric was never
	// requested at all") and never a fabricated known value either.
	foundGHESBackupOutcome := false
	for _, outcome := range report.Outcomes {
		if outcome.CollectorID == "ghes.backup" {
			foundGHESBackupOutcome = true
			if outcome.Status != NotRun {
				t.Fatalf("expected the missing ghes.backup import to report an explicit not-run outcome: %+v", outcome)
			}
		}
		if len(outcome.EvidenceRefs) != 0 && (outcome.EvidenceRefs[0] == "" || outcome.EvidenceRefs[1] == "") {
			t.Fatalf("expected real, non-empty immutable evidence refs on a successful import outcome: %+v", outcome)
		}
	}
	if !foundGHESBackupOutcome {
		t.Fatal("expected an outcome recorded even for the collector whose import was never found")
	}
	backupSchedule, ok := report.Metrics["backup_schedule"]
	if !ok {
		t.Fatal("expected backup_schedule to still appear (as unavailable), never silently absent for a missing source")
	}
	if backupSchedule.Overall.Status != MetricUnavailable || backupSchedule.Overall.Reason == "" {
		t.Fatalf("expected backup_schedule to be an explicit unavailable result with a semantic reason, "+
			"never a fabricated known value: %+v", backupSchedule.Overall)
	}
}

// TestApplyNormalizedImportsRejectsASecondSourceForTheSameCollector proves
// the disclosed single-source-per-collector boundary is enforced, not
// silently overwritten (which would lose the first organization's
// per-organization value when setMetric resets PerOrganization).
func TestApplyNormalizedImportsRejectsASecondSourceForTheSameCollector(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	report := &VerticalSliceReport{Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}}
	sources := []ImportSource{
		{CollectorID: "ui.org_pat_policy", Scope: Scope{Host: "github.com", Kind: OrganizationScope, Name: "org-a"}, Feature: "capture"},
		{CollectorID: "ui.org_pat_policy", Scope: Scope{Host: "github.com", Kind: OrganizationScope, Name: "org-b"}, Feature: "capture"},
	}
	if err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), sources); err == nil {
		t.Fatal("expected a second source for an already-merged collector ID to be rejected, not silently overwritten")
	}
}

// TestApplyNormalizedImportsRejectsUnsupportedCollector confirms a
// collector this round does not normalize (even a genuine import-contract
// collector ID) is rejected rather than silently ignored or treated as
// complete.
func TestApplyNormalizedImportsRejectsUnsupportedCollector(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	report := &VerticalSliceReport{Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}}
	sources := []ImportSource{{CollectorID: "ui.org_actions_settings", Scope: Scope{Host: "github.com", Kind: OrganizationScope, Name: "org-a"}, Feature: "capture"}}
	if err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), sources); err == nil {
		t.Fatal("expected an unsupported collector ID to be rejected, not silently ignored")
	}
}

// TestNormalizedImportMetricKeysEnumeratesExactSupportedCollectors confirms
// the discoverable supported/unsupported boundary: a collector this round
// normalizes reports its exact keys, and a collector outside that set
// (including an otherwise-valid import-contract collector) reports false,
// never a fabricated empty-but-present key list.
func TestNormalizedImportMetricKeysEnumeratesExactSupportedCollectors(t *testing.T) {
	keys, ok := NormalizedImportMetricKeys("ghes.backup")
	if !ok || len(keys) != 4 {
		t.Fatalf("expected ghes.backup's exact 4 documented keys: %+v", keys)
	}
	if _, ok := NormalizedImportMetricKeys("ui.org_actions_settings"); ok {
		t.Fatal("expected a collector this round does not normalize to report false, not a fabricated key list")
	}
}

// mainImportedBackupFixture migrates main's own read-only review fixture
// helper verbatim (adjusted only for the profile parameter this round's
// fix added): a genuine ghes.backup import, with an explicit Complete flag
// so both the confident and recorded-incomplete cases can be exercised.
func mainImportedBackupFixture(t *testing.T, store *EvidenceStore, complete bool) ImportSource {
	t.Helper()
	profile := fixtureProfileWithDefault(t)
	scope := Scope{Host: "ghes.example.com", Kind: EnterpriseScope, Name: "fixture-enterprise"}
	metadata := EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "ghes.backup", Scope: scope, Feature: "capture", SourceKind: ImportedEvidence,
		CredentialKind: NoCredential, CollectedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Endpoint: "import://fixture/backup", Pages: 1, Complete: complete,
	}
	if _, err := store.SaveJSON([]byte(`{"captured_at":"2026-10-01T12:00:00Z","schedule_cron_expression":"0 2 * * *","retained_snapshots":10,"encrypted":true}`), metadata); err != nil {
		t.Fatal(err)
	}
	return ImportSource{CollectorID: "ghes.backup", Scope: scope, Feature: "capture"}
}

// TestMainNormalizedImportsBindEveryMetricToItsRawPair is main's own
// confirmed reproduction, migrated permanently: a known imported metric's
// Overall and PerOrganization EvidenceRefs must match the actual
// outcome's own immutable raw/metadata pair, never reported empty despite
// a genuine evidence pair existing.
func TestMainNormalizedImportsBindEveryMetricToItsRawPair(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	source := mainImportedBackupFixture(t, store, true)
	report := &VerticalSliceReport{Metrics: map[string]Metric{}}
	if err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), []ImportSource{source}); err != nil {
		t.Fatal(err)
	}
	want := report.Outcomes[0].EvidenceRefs
	metric := report.Metrics["backup_encrypted"]
	if len(want) != 2 || !reflect.DeepEqual(metric.Overall.EvidenceRefs, want) ||
		!reflect.DeepEqual(metric.PerOrganization[source.Scope.Key()].EvidenceRefs, want) {
		t.Fatalf("known imported metric lost its actual raw/metadata pair: %+v; outcome refs=%v", metric, want)
	}
}

// TestMainNormalizedImportsDoNotSilentlyOverwritePriorObservation is main's
// own confirmed reproduction, migrated permanently: a new imported
// observation must never silently overwrite an already-known metric
// (whether from a live collector or an earlier merge).
func TestMainNormalizedImportsDoNotSilentlyOverwritePriorObservation(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	source := mainImportedBackupFixture(t, store, true)
	value := false
	original := Metric{Key: "backup_encrypted", Overall: MetricValue{Status: MetricKnown, Boolean: &value, EvidenceRefs: []string{"earlier-source"}}}
	report := &VerticalSliceReport{Metrics: map[string]Metric{"backup_encrypted": original}}
	if err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), []ImportSource{source}); err == nil {
		t.Fatal("new imported observation silently overwrote a known earlier source")
	}
	if !reflect.DeepEqual(report.Metrics["backup_encrypted"], original) {
		t.Fatal("rejected collision changed the original observation")
	}
}

// TestMainNormalizedImportsRejectIncompleteAndUnvalidatedSource is main's
// own confirmed reproduction, migrated permanently: evidence recorded
// Complete:false at import time must never yield a confidently known
// imported setting, and stored evidence that no longer satisfies its own
// import contract (a required field since gone missing) must be rejected
// by the loader, exactly as actual ImportJSON validation would reject it.
func TestMainNormalizedImportsRejectIncompleteAndUnvalidatedSource(t *testing.T) {
	t.Run("incomplete source", func(t *testing.T) {
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		source := mainImportedBackupFixture(t, store, false)
		report := &VerticalSliceReport{Metrics: map[string]Metric{}}
		err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), []ImportSource{source})
		if err == nil && report.Metrics["backup_encrypted"].Overall.Status == MetricKnown {
			t.Fatal("incomplete evidence produced a confidently known imported setting")
		}
	})
	t.Run("invalid envelope", func(t *testing.T) {
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		source := mainImportedBackupFixture(t, store, true)
		raw, metadata, _, err := store.LoadJSON(source.Scope, source.CollectorID, source.Feature)
		if err != nil || len(raw) == 0 {
			t.Fatalf("fixture read failed: %v", err)
		}
		if _, err := store.SaveJSON([]byte(`{"encrypted":true}`), metadata); err != nil {
			t.Fatal(err)
		}
		if _, outcome, err := LoadNormalizedGHESBackupImport(store, fixtureProfileWithDefault(t), source.Scope, source.Feature); err == nil && outcome.Status == CollectionOK {
			t.Fatal("source loader accepted an envelope that actual ImportJSON contract validation would reject")
		}
	})
}

// TestMainNormalizedImportsRejectsUnusableSourcesWithoutPartialMutation is
// main's own confirmed reproduction, migrated permanently: rejecting an
// unsupported second source must never leave a partially mutated report
// behind from the first, otherwise-valid source.
func TestMainNormalizedImportsRejectsUnusableSourcesWithoutPartialMutation(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	source := mainImportedBackupFixture(t, store, true)
	source2 := source
	source2.CollectorID = "ui.org_actions_settings"
	report := &VerticalSliceReport{Metrics: map[string]Metric{}}
	if err := ApplyNormalizedImports(report, store, fixtureProfileWithDefault(t), []ImportSource{source, source2}); err == nil {
		t.Fatal("unsupported second source should be rejected")
	}
	if len(report.Metrics) != 0 || len(report.Outcomes) != 0 {
		t.Fatal("rejected multi-source merge left a partially mutated report")
	}
}
