// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/microsoft/ghqr/internal/assessment"
)

func TestApplyImportsRequiresReportAndSources(t *testing.T) {
	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"apply-imports"})
	if err := command.Execute(); err == nil {
		t.Fatal("expected apply-imports to require --report and --sources")
	}
}

func TestApplyImportsRejectsNonexistentReportAndSourcesFiles(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath, []byte("organizations: [fixture-org]\nevidence_dir: "+filepath.Join(directory, "evidence")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	validSources := filepath.Join(directory, "sources.json")
	if err := os.WriteFile(validSources, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	validReport := filepath.Join(directory, "report.json")
	if err := os.WriteFile(validReport, []byte(`{"metrics":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"apply-imports", "--config", configPath, "--report", filepath.Join(directory, "no-such-report.json"), "--sources", validSources})
	if err := command.Execute(); err == nil {
		t.Fatal("expected a nonexistent --report file to be rejected")
	}

	command = newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"apply-imports", "--config", configPath, "--report", validReport, "--sources", filepath.Join(directory, "no-such-sources.json")})
	if err := command.Execute(); err == nil {
		t.Fatal("expected a nonexistent --sources file to be rejected")
	}
}

func TestApplyImportsRejectsMalformedReportJSON(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath, []byte("organizations: [fixture-org]\nevidence_dir: "+filepath.Join(directory, "evidence")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{not valid json`), 0o600); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(directory, "sources.json")
	if err := os.WriteFile(sourcesPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"apply-imports", "--config", configPath, "--report", reportPath, "--sources", sourcesPath})
	if err := command.Execute(); err == nil {
		t.Fatal("expected a malformed report JSON file to be rejected")
	}
}

func TestApplyImportsRejectsEmptySourcesList(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath, []byte("organizations: [fixture-org]\nevidence_dir: "+filepath.Join(directory, "evidence")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"metrics":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(directory, "sources.json")
	if err := os.WriteFile(sourcesPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"apply-imports", "--config", configPath, "--report", reportPath, "--sources", sourcesPath})
	if err := command.Execute(); err == nil {
		t.Fatal("expected an empty import sources list to be rejected")
	}
}

func TestApplyImportsRejectsUnsupportedCollectorSource(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(configPath, []byte("organizations: [fixture-org]\nevidence_dir: "+filepath.Join(directory, "evidence")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"metrics":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(directory, "sources.json")
	sources := `[{"collector_id":"ui.org_actions_settings","scope":{"host":"github.com","kind":"organization","name":"fixture-org"},"feature":"capture"}]`
	if err := os.WriteFile(sourcesPath, []byte(sources), 0o600); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"apply-imports", "--config", configPath, "--report", reportPath, "--sources", sourcesPath})
	if err := command.Execute(); err == nil {
		t.Fatal("expected a source naming a collector this round does not normalize to be rejected")
	}
}

// TestApplyImportsCLIProducesExactProfileKeysFromARealImportedPayload is the
// full production-wiring proof through the real CLI entry points: a
// ghes.backup payload is accepted by the real `ghqr assess import` command,
// then the real `ghqr assess apply-imports` command merges it into a
// report, producing the exact profile metric keys
// (backup_schedule/latest_snapshot_age_h/snapshots_retained/backup_encrypted)
// with a real, non-empty, immutable evidence reference and Pages:1 -- not a
// helper-only, never-invoked normalization.
func TestApplyImportsCLIProducesExactProfileKeysFromARealImportedPayload(t *testing.T) {
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	evidenceDir := filepath.Join(directory, "evidence")
	configPath := filepath.Join(directory, "customer.yaml")
	entScope := assessment.Scope{Host: "ghes.example.com", Kind: assessment.EnterpriseScope, Name: "fixture-enterprise"}
	configYAML := "evidence_dir: " + evidenceDir + "\n" +
		"targets:\n  - host: ghes.example.com\n    deployment: ghes\n    enterprise: fixture-enterprise\n    organizations: [fixture-org]\n"
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	inputPath := filepath.Join(directory, "ghes-backup.json")
	payload := `{"captured_at":"2026-10-01T12:00:00Z","schedule_cron_expression":"0 2 * * *",` +
		`"retained_snapshots":10,"latest_snapshot_at":"2026-10-01T06:00:00Z","latest_snapshot_status":"success","encrypted":true}`
	if err := os.WriteFile(inputPath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(directory, "metadata.json")
	metadata := assessment.EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "ghes.backup", Feature: "capture", Scope: entScope,
		CollectedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Endpoint:    "import://fixture/ghes-backup", Pages: 1, CredentialKind: assessment.NoCredential, Complete: true,
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, metadataRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	importCmd := newAssessCommand()
	importCmd.SilenceErrors, importCmd.SilenceUsage = true, true
	var importOutput bytes.Buffer
	importCmd.SetOut(&importOutput)
	importCmd.SetArgs([]string{"import", "--config", configPath, "--input", inputPath, "--metadata", metadataPath})
	if err := importCmd.Execute(); err != nil {
		t.Fatalf("the real import entry point must accept a contract-satisfying ghes.backup payload: %v", err)
	}

	reportPath := filepath.Join(directory, "report.json")
	reportRaw, err := json.Marshal(assessment.VerticalSliceReport{Profile: profile.Summary(), Metrics: map[string]assessment.Metric{}, Outcomes: []assessment.CollectorOutcome{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, reportRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(directory, "sources.json")
	sourcesRaw, err := json.Marshal([]assessment.ImportSource{{CollectorID: "ghes.backup", Scope: entScope, Feature: "capture"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcesPath, sourcesRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	applyCmd := newAssessCommand()
	applyCmd.SilenceErrors, applyCmd.SilenceUsage = true, true
	var applyOutput bytes.Buffer
	applyCmd.SetOut(&applyOutput)
	applyCmd.SetArgs([]string{"apply-imports", "--config", configPath, "--report", reportPath, "--sources", sourcesPath})
	if err := applyCmd.Execute(); err != nil {
		t.Fatalf("the real apply-imports entry point must merge a genuinely imported ghes.backup payload: %v", err)
	}

	var merged assessment.VerticalSliceReport
	if err := json.Unmarshal(applyOutput.Bytes(), &merged); err != nil {
		t.Fatalf("expected a decoded merged report, got %q: %v", applyOutput.String(), err)
	}

	schedule, ok := merged.Metrics["backup_schedule"]
	if !ok || schedule.Overall.Status != assessment.MetricKnown || schedule.Overall.Text == nil || *schedule.Overall.Text != "0 2 * * *" {
		t.Fatalf("expected backup_schedule fed into the merged report under its exact profile key: %+v", schedule)
	}
	age, ok := merged.Metrics["latest_snapshot_age_h"]
	if !ok || age.Overall.Number == nil || *age.Overall.Number != 6 {
		t.Fatalf("expected latest_snapshot_age_h computed and fed into the merged report: %+v", age)
	}
	if _, ok := merged.Metrics["snapshots_retained"]; !ok {
		t.Fatal("expected snapshots_retained fed into the merged report")
	}
	if _, ok := merged.Metrics["backup_encrypted"]; !ok {
		t.Fatal("expected backup_encrypted fed into the merged report")
	}

	found := false
	for _, outcome := range merged.Outcomes {
		if outcome.CollectorID != "ghes.backup" {
			continue
		}
		found = true
		if outcome.Status != assessment.CollectionOK || outcome.Readiness != assessment.ImportOnly {
			t.Fatalf("expected a successful import-only outcome: %+v", outcome)
		}
		if outcome.Pages != 1 || len(outcome.EvidenceRefs) != 2 || outcome.EvidenceRefs[0] == "" || outcome.EvidenceRefs[1] == "" {
			t.Fatalf("expected Pages:1 with 2 real, non-empty immutable evidence refs: %+v", outcome)
		}
	}
	if !found {
		t.Fatal("expected a ghes.backup CollectorOutcome recorded in the merged report")
	}
}

// TestApplyImportsCLIRejectsUnauthorizedSourceScope is main's own confirmed
// reproduction, migrated permanently (the fixture's import payload is
// corrected to satisfy ghes.backup's own required-field contract --
// retained_snapshots -- so the test exercises scope authorization
// specifically, not an incidental contract-validation rejection): a source
// imported under a WIDER config (which authorizes the enterprise scope) is
// rejected by apply-imports when invoked with a NARROWER config that does
// not authorize that scope, exactly like `assess import` itself would
// reject it. A rejected scope must emit no merged report bytes at all.
func TestApplyImportsCLIRejectsUnauthorizedSourceScope(t *testing.T) {
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	evidenceDirectory := filepath.Join(directory, "evidence")
	wider, err := assessment.ParseConfig([]byte(
		"evidence_dir: " + evidenceDirectory + "\n" +
			"targets:\n  - host: ghes.example.com\n    deployment: ghes\n    enterprise: fixture-enterprise\n    organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	scope := assessment.Scope{Host: "ghes.example.com", Kind: assessment.EnterpriseScope, Name: "fixture-enterprise"}
	metadata := assessment.EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "ghes.backup", Feature: "capture", Scope: scope, CredentialKind: assessment.NoCredential,
		CollectedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), Endpoint: "import://fixture/backup", Pages: 1,
	}
	payload := `{"captured_at":"2026-10-01T12:00:00Z","retained_snapshots":10,"latest_snapshot_status":"success","encrypted":true}`
	if _, err := assessment.ImportJSON(profile, wider, []byte(payload), metadata); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "narrow.yaml")
	if err := os.WriteFile(configPath, []byte("organizations: [fixture-org]\nevidence_dir: "+evidenceDirectory+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(directory, "report.json")
	raw, err := json.Marshal(assessment.VerticalSliceReport{Profile: profile.Summary(), Metrics: map[string]assessment.Metric{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sourcesPath := filepath.Join(directory, "sources.json")
	raw, err = json.Marshal([]assessment.ImportSource{{CollectorID: "ghes.backup", Scope: scope, Feature: "capture"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcesPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"apply-imports", "--config", configPath, "--report", reportPath, "--sources", sourcesPath})
	if err := command.Execute(); err == nil {
		t.Fatal("actual apply-imports CLI emitted foreign-host enterprise metrics outside its current configured scope")
	}
	if output.Len() != 0 {
		t.Fatalf("rejected scope emitted merged report bytes: %s", output.Bytes())
	}
}
