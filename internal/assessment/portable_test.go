// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func syntheticPortableSource(t *testing.T, directory string) (*Profile, *CustomerConfig, []byte) {
	t.Helper()
	profile := fixtureProfileWithDefault(t)
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	config.EvidenceDir = filepath.Join(directory, "evidence")
	config.CheckDefinitions, err = LoadSimpleChecks(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJSON([]byte(`{"items":[]}`), evidenceFixtureMetadata(t)); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ref, err := WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{}, now, []CollectorOutcome{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	report := VerticalSliceReport{Profile: profile.Summary(), CollectedAt: now, ContextRef: ref,
		ImplementedCollectors: RunImplementedCollectorIDs(), ImplementedEvaluators: []string{},
		Organizations: []OrganizationRunResult{}, Targets: []TargetOperationalResult{},
		Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}, Caveats: []string{}}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return profile, config, data
}

func TestPortableRoundTripAfterSourceRelocation(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	profile, config, data := syntheticPortableSource(t, source)
	bundle := filepath.Join(directory, "transfer.zip")
	manifest, err := ExportPortableBundle(profile, config, data, config.EvidenceDir, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Analysis != "not performed by export" {
		t.Fatal("export invented an analysis result")
	}
	if err := os.Rename(source, filepath.Join(directory, "moved-away")); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "receiver", "results")
	summary, err := AnalysePortableBundle(bundle, PortableAnalysisOptions{OutputDirectory: output, AcceptBundleScope: true})
	if err != nil {
		t.Fatal(err)
	}
	if summary.VerificationMode != VerificationModeVerified || summary.EvidenceVerification == nil ||
		!summary.EvidenceVerification.Verified {
		t.Fatalf("relocated data lost genuine source/context verification: %+v", summary)
	}
	for _, name := range EvaluationOutputFileNames() {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ExportPortableBundle(profile, config, data, filepath.Join(directory, "moved-away", "evidence"), bundle); err == nil {
		t.Fatal("existing transfer artifact was silently overwritten")
	}
}

func portableTestMembers(t *testing.T, bundle string) map[string][]byte {
	t.Helper()
	reader, err := zip.OpenReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	files := map[string][]byte{}
	for _, file := range reader.File {
		body, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		var data bytes.Buffer
		if _, err := data.ReadFrom(body); err != nil {
			t.Fatal(err)
		}
		if err := body.Close(); err != nil {
			t.Fatal(err)
		}
		files[file.Name] = data.Bytes()
	}
	return files
}

func writePortableTestArchive(t *testing.T, destination string, files map[string][]byte, extra *zip.FileHeader) {
	t.Helper()
	file, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, name := range sortedExportKeys(files) {
		member, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if extra != nil {
		if _, err := writer.CreateRaw(extra); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPortableRejectsUnsafeMissingChangedAndForgedData(t *testing.T) {
	directory := t.TempDir()
	profile, config, data := syntheticPortableSource(t, filepath.Join(directory, "source"))
	bundle := filepath.Join(directory, "valid.zip")
	if _, err := ExportPortableBundle(profile, config, data, config.EvidenceDir, bundle); err != nil {
		t.Fatal(err)
	}
	for _, test := range []string{"traversal", "duplicate", "symlink", "oversize", "missing", "changed", "resigned-unproven-analysis"} {
		t.Run(test, func(t *testing.T) {
			files := portableTestMembers(t, bundle)
			var extra *zip.FileHeader
			switch test {
			case "traversal":
				extra = &zip.FileHeader{Name: "../outside.json"}
			case "duplicate":
				extra = &zip.FileHeader{Name: "run.json"}
			case "symlink":
				extra = &zip.FileHeader{Name: "evidence/link.json"}
				extra.SetMode(os.ModeSymlink | 0o777)
			case "oversize":
				extra = &zip.FileHeader{Name: "evidence/large.json", UncompressedSize64: portableFileLimit + 1}
			case "missing":
				delete(files, "checks.json")
			case "changed":
				files["run.json"] = append(files["run.json"], ' ')
			case "resigned-unproven-analysis":
				var report VerticalSliceReport
				if err := json.Unmarshal(files["run.json"], &report); err != nil {
					t.Fatal(err)
				}
				value := 1.0
				report.Metrics["owner_count"] = Metric{Key: "owner_count", Overall: MetricValue{Status: MetricKnown, Number: &value}}
				var err error
				files["run.json"], err = json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				var manifest PortableManifest
				if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
					t.Fatal(err)
				}
				for index := range manifest.Files {
					if manifest.Files[index].Path == "run.json" {
						manifest.Files[index].SHA256 = digestBytes(files["run.json"])
						manifest.Files[index].Size = int64(len(files["run.json"]))
					}
				}
				files["manifest.json"], err = json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
			}
			bad := filepath.Join(t.TempDir(), "bad.zip")
			writePortableTestArchive(t, bad, files, extra)
			output := filepath.Join(t.TempDir(), "output")
			if _, err := AnalysePortableBundle(bad, PortableAnalysisOptions{OutputDirectory: output, AcceptBundleScope: true}); err == nil {
				t.Fatal("unsafe or unproven data earned a verified analysis")
			}
			if _, err := os.Stat(filepath.Join(output, EvaluationResultsFileName)); !os.IsNotExist(err) {
				t.Fatal("rejected data left success-shaped canonical output")
			}
		})
	}
	if _, err := AnalysePortableBundle(bundle, PortableAnalysisOptions{OutputDirectory: t.TempDir()}); err == nil {
		t.Fatal("implicit bundle-scope consent was accepted")
	}
	wrongConfig, err := ParseConfig([]byte("organizations: [outside-scope]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AnalysePortableBundle(bundle, PortableAnalysisOptions{OutputDirectory: t.TempDir(), Config: wrongConfig}); err == nil {
		t.Fatal("a portable file unlocked scope beyond the caller's configuration")
	}
}

func TestPortableRejectsSensitiveFilesAndExtractionOverride(t *testing.T) {
	directory := t.TempDir()
	profile, config, data := syntheticPortableSource(t, filepath.Join(directory, "source"))
	bundle := filepath.Join(directory, "valid.zip")
	if _, err := ExportPortableBundle(profile, config, data, config.EvidenceDir, bundle); err != nil {
		t.Fatal(err)
	}
	override := strings.Replace(string(defaultSimpleChecks), "/security_and_analysis/dependabot_security_updates/status",
		"/security_and_analysis/secret_scanning/status", 1)
	checksPath := filepath.Join(directory, "override.json")
	if err := os.WriteFile(checksPath, []byte(override), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := AnalysePortableBundle(bundle, PortableAnalysisOptions{OutputDirectory: t.TempDir(),
		AcceptBundleScope: true, ChecksPath: checksPath}); err == nil {
		t.Fatal("analysis silently changed the original extraction contract")
	}
	if err := os.WriteFile(filepath.Join(config.EvidenceDir, "private.json"), []byte(`{"password":"synthetic-forbidden-value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := portableSafeJSON([]byte(`{"password":"synthetic-forbidden-value"}`)); err == nil {
		t.Fatal("unredacted sensitive data passed the portable member boundary")
	}
	filtered := filepath.Join(directory, "filtered.zip")
	if _, err := ExportPortableBundle(profile, config, data, config.EvidenceDir, filtered); err != nil {
		t.Fatal(err)
	}
	for name := range portableTestMembers(t, filtered) {
		if strings.Contains(name, "private.json") {
			t.Fatal("uncited data was exported from a multi-run store")
		}
	}
}

func TestPortableCollectedEvidenceSeparateProcessAndScopeFiltering(t *testing.T) {
	if os.Getenv("GHQR_COLLECTED_CHILD") == "1" {
		summary, err := AnalysePortableBundle(os.Getenv("GHQR_COLLECTED_BUNDLE"), PortableAnalysisOptions{
			OutputDirectory: os.Getenv("GHQR_COLLECTED_OUTPUT"), AcceptBundleScope: true, AnswersPath: os.Getenv("GHQR_COLLECTED_ANSWERS"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !summary.EvidenceVerification.Verified || summary.EvidenceVerification.PagesVerified == 0 ||
			summary.EvidenceVerification.OutcomesChecked == 0 {
			t.Fatal("the representative transfer did not verify actual cited pages/outcomes")
		}
		return
	}
	directory := t.TempDir()
	if retained := os.Getenv("GHQR_PORTABLE_COLLECTED_FIXTURE_ROOT"); retained != "" {
		directory = retained
	}
	source := filepath.Join(directory, "source")
	server := newVerticalSliceFixtureServer(t)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	config.GHESHost = client.base.Hostname()
	config.Deployment = Server
	config.EvidenceDir = filepath.Join(source, "evidence")
	config.CheckDefinitions, err = LoadSimpleChecks(client.profile, "")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, targets, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef, err = WriteRunCollectionContextWithOutcomes(store, client.profile, config, targets, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	outsideScope := Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "outside-org"}
	outside, outsideErr := client.CollectGET(context.Background(), store, outsideScope, "org.settings", "settings", "orgs/outside-org", "", false)
	if outsideErr == nil || len(outside.EvidenceRefs) == 0 {
		t.Fatal("second-scope fixture must record a genuine failed attempt with evidence")
	}
	outsideConfig, err := ParseConfig([]byte("organizations: [outside-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	outsideConfig.GHESHost = client.base.Hostname()
	outsideConfig.Deployment = Server
	outsideTargets, err := outsideConfig.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	outsideRef, err := WriteRunCollectionContextWithOutcomes(store, client.profile, outsideConfig, outsideTargets, time.Now().UTC(), []CollectorOutcome{outside})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	writeFixture := func(name string, data []byte) string {
		destination := filepath.Join(source, name)
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return destination
	}
	runData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture("run.json", runData)
	configData, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture("config.json", configData)
	writeFixture("profile.json", defaultProfileData)
	writeFixture("checks-default.json", defaultSimpleChecks)
	writeFixture("checks-custom-extraction.json", bytes.Replace(defaultSimpleChecks,
		[]byte("/security_and_analysis/dependabot_security_updates/status"), []byte("/security_and_analysis/secret_scanning/status"), 1))
	writeFixture("checks-custom-policy.json", bytes.ReplaceAll(defaultSimpleChecks, []byte("[90]"), []byte("[95]")))
	answerData, err := json.Marshal([]InterviewAnswer{{ControlID: "GOV-001", Answer: "Synthetic discussion: fixture rules have an owner.",
		Respondent: "fixture-reviewer", AnsweredAt: report.CollectedAt.Add(-time.Hour), EvidenceRefs: []string{"interview:synthetic-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture("answers.json", answerData)
	bundle := filepath.Join(directory, "synthetic-collected-data.zip")
	manifest, err := ExportPortableBundle(client.profile, config, runData, config.EvidenceDir, bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Files {
		if entry.Path == "evidence/"+runCollectionContextObjectPath(outsideRef) {
			t.Fatal("another run's context escaped its authorized scope")
		}
		for _, ref := range outside.EvidenceRefs {
			if entry.Path == "evidence/"+ref {
				t.Fatal("another scope's raw page/sidecar escaped its authorized scope")
			}
		}
	}
	if err := os.Rename(source, filepath.Join(directory, "source-moved")); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "receiver", "results")
	child := exec.Command(os.Args[0], "-test.run=^TestPortableCollectedEvidenceSeparateProcessAndScopeFiltering$")
	child.Dir = directory
	child.Env = []string{"PATH=" + os.Getenv("PATH"), "GHQR_COLLECTED_CHILD=1", "GHQR_COLLECTED_BUNDLE=" + bundle,
		"GHQR_COLLECTED_OUTPUT=" + output, "GHQR_COLLECTED_ANSWERS=" + filepath.Join(directory, "source-moved", "answers.json"),
		"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1"}
	if data, err := child.CombinedOutput(); err != nil {
		t.Fatalf("nonempty separate-process source replay failed: %v\n%s", err, data)
	}
	outcomes, err := LoadCollectionLog(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(compareOriginalOutcomes(outcomes, report.Outcomes)) != 0 {
		t.Fatal("relocation/transfer changed the original outcome inventory or references")
	}
}

func TestPortableExactArchiveBudgetLimits(t *testing.T) {
	if err := portableBudget(100, portableTotalLimit); err != nil {
		t.Fatal("exact expanded boundary, including the manifest, must be accepted")
	}
	if err := portableBudget(100, portableTotalLimit+1); err == nil {
		t.Fatal("manifest bytes were excluded from the exact total boundary")
	}
	if err := portableBudget(portableFileLimit+1, portableTotalLimit); err == nil {
		t.Fatal("manifest member bytes were excluded from the member limit")
	}
	for _, test := range []struct {
		name  string
		count int
		size  uint64
	}{
		{"member count above 20000", portableEntryLimit + 1, 0},
		{"expanded total above 512 MiB", portableTotalLimit/portableFileLimit + 1, portableFileLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			bundle := filepath.Join(directory, "over-budget.zip")
			file, err := os.Create(bundle)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(file)
			for index := 0; index < test.count; index++ {
				if _, err := writer.CreateRaw(&zip.FileHeader{Name: fmt.Sprintf("evidence/%d.json", index),
					UncompressedSize64: test.size}); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := unpackPortableBundle(bundle, directory); err == nil {
				t.Fatal("declared exact member/expanded budget was not enforced before extraction")
			}
		})
	}
}
