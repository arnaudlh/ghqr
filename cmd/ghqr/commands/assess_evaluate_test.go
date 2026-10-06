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

func writeFixtureRunReport(t *testing.T, directory string) string {
	t.Helper()
	report := assessment.VerticalSliceReport{
		CollectedAt:           time.Now().UTC(),
		ImplementedCollectors: assessment.RunImplementedCollectorIDs(),
		ImplementedEvaluators: []string{},
		Organizations:         []assessment.OrganizationRunResult{},
		Metrics:               map[string]assessment.Metric{},
		Outcomes:              []assessment.CollectorOutcome{},
		Caveats:               []string{},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "run.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeFixtureRunReportWithContext is writeFixtureRunReport's genuinely
// context-bound counterpart: the same zero-outcome, zero-organization
// shape, but with CollectedAt and ContextRef set to match a real
// RunCollectionContext a caller already wrote, so VerifyReportEvidence's
// context-binding gate finds a genuine, resolvable ref to bind to instead
// of unconditionally treating this as a context-less report.
func writeFixtureRunReportWithContext(t *testing.T, directory string, collectedAt time.Time, contextRef string) string {
	t.Helper()
	report := assessment.VerticalSliceReport{
		CollectedAt:           collectedAt,
		ContextRef:            contextRef,
		ImplementedCollectors: assessment.RunImplementedCollectorIDs(),
		ImplementedEvaluators: []string{},
		Organizations:         []assessment.OrganizationRunResult{},
		Metrics:               map[string]assessment.Metric{},
		Outcomes:              []assessment.CollectorOutcome{},
		Caveats:               []string{},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "run-context-bound.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFixtureConfig(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "customer.yaml")
	if err := os.WriteFile(path, []byte("organizations: [fixture-org]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAssessmentEvaluateRequiresRunAndOutputFlags(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"evaluate", "--config", configPath})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--run") {
		t.Fatalf("evaluate without --run should fail explicitly: %v", err)
	}

	command = newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	runPath := writeFixtureRunReport(t, directory)
	command.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", ""})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("evaluate with an empty --out should fail explicitly: %v", err)
	}
}

func TestAssessmentEvaluateRequiresExactlyOneOfEvidenceDirOrAllowUnverified(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)
	runPath := writeFixtureRunReport(t, directory)
	outputDirectory := filepath.Join(directory, "out")

	// Neither flag: must refuse rather than silently trust the report.
	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "exactly one of") {
		t.Fatalf("evaluate with neither --evidence-dir nor --allow-unverified should fail explicitly: %v", err)
	}
	if entries, _ := os.ReadDir(outputDirectory); len(entries) != 0 {
		t.Fatalf("a refused evaluation must not write any export files: %v", entries)
	}

	// Both flags: also mutually exclusive, also refused.
	evidenceDirectory := filepath.Join(directory, "evidence")
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	command = newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{
		"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory,
		"--evidence-dir", evidenceDirectory, "--allow-unverified",
	})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "exactly one of") {
		t.Fatalf("evaluate with both --evidence-dir and --allow-unverified should fail explicitly: %v", err)
	}
	if entries, _ := os.ReadDir(outputDirectory); len(entries) != 0 {
		t.Fatalf("a refused evaluation must not write any export files: %v", entries)
	}
}

func TestAssessmentEvaluateRefusesExistingCanonicalResultsWithoutOverwrite(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)
	runPath := writeFixtureRunReport(t, directory)
	outputDirectory := filepath.Join(directory, "out")

	first := newAssessCommand()
	first.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory, "--allow-unverified"})
	if err := first.Execute(); err != nil {
		t.Fatal(err)
	}
	originalResults, err := os.ReadFile(filepath.Join(outputDirectory, assessment.EvaluationResultsFileName))
	if err != nil {
		t.Fatal(err)
	}

	// A second pass into the SAME --out without --overwrite must refuse,
	// leaving the prior canonical results completely untouched.
	second := newAssessCommand()
	second.SilenceErrors, second.SilenceUsage = true, true
	second.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory, "--allow-unverified"})
	if err := second.Execute(); err == nil || !strings.Contains(err.Error(), "already contains") {
		t.Fatalf("a repeat evaluate into an --out already holding canonical results must refuse without --overwrite: %v", err)
	}
	afterRefusal, err := os.ReadFile(filepath.Join(outputDirectory, assessment.EvaluationResultsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalResults, afterRefusal) {
		t.Fatal("a refused evaluate pass must never modify the existing canonical results")
	}

	// The SAME repeat pass with --overwrite must be permitted.
	third := newAssessCommand()
	third.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory, "--allow-unverified", "--overwrite"})
	if err := third.Execute(); err != nil {
		t.Fatalf("a repeat evaluate into an --out already holding canonical results must be permitted with --overwrite: %v", err)
	}
}

func TestAssessmentEvaluateAllowUnverifiedPersistsDisclosureAndConfirmPreservesIt(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)
	runPath := writeFixtureRunReport(t, directory)
	outputDirectory := filepath.Join(directory, "out")

	command := newAssessCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory, "--allow-unverified"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var summary assessment.EvaluationOutputSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.VerificationMode != assessment.VerificationModeUnverifiedConsent {
		t.Fatalf("an --allow-unverified pass must report VerificationModeUnverifiedConsent in its summary: %+v", summary)
	}

	statusData, err := os.ReadFile(filepath.Join(outputDirectory, assessment.VerificationStatusFileName))
	if err != nil {
		t.Fatalf("an --allow-unverified pass must persist %s: %v", assessment.VerificationStatusFileName, err)
	}
	var status assessment.VerificationStatus
	if err := json.Unmarshal(statusData, &status); err != nil {
		t.Fatal(err)
	}
	if status.Mode != assessment.VerificationModeUnverifiedConsent {
		t.Fatalf("persisted verification-status.json must disclose the unverified-consent mode: %+v", status)
	}

	summaryMarkdown, err := os.ReadFile(filepath.Join(outputDirectory, assessment.SummaryFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summaryMarkdown), "UNVERIFIED supplied analysis") {
		t.Fatalf("an --allow-unverified pass's summary.md must prepend an explicit UNVERIFIED disclosure: %s", summaryMarkdown)
	}

	// confirm must load and preserve the original unverified-consent mode
	// unchanged -- never silently upgrade it merely because confirm itself
	// performs no verification of its own either.
	decisions := []assessment.AssessorInput{{
		ControlID: summary.PendingConfirmations[0], State: assessment.NotAssessed, Assessor: "Jane Reviewer (customer SRE team)",
		ConfirmedAt: time.Now().UTC().Add(-time.Minute), Rationale: "Reviewed; not yet ready to confirm a final state.",
		EvidenceRefs: []string{"interviews/" + summary.PendingConfirmations[0] + ".md"},
	}}
	decisionsData, err := json.Marshal(decisions)
	if err != nil {
		t.Fatal(err)
	}
	decisionsPath := filepath.Join(directory, "decisions.json")
	if err := os.WriteFile(decisionsPath, decisionsData, 0o600); err != nil {
		t.Fatal(err)
	}
	confirmCommand := newAssessCommand()
	confirmCommand.SetArgs([]string{"confirm", "--config", configPath, "--decisions", decisionsPath, "--out", outputDirectory})
	if err := confirmCommand.Execute(); err != nil {
		t.Fatal(err)
	}
	afterConfirmStatusData, err := os.ReadFile(filepath.Join(outputDirectory, assessment.VerificationStatusFileName))
	if err != nil {
		t.Fatal(err)
	}
	var afterConfirmStatus assessment.VerificationStatus
	if err := json.Unmarshal(afterConfirmStatusData, &afterConfirmStatus); err != nil {
		t.Fatal(err)
	}
	if afterConfirmStatus.Mode != assessment.VerificationModeUnverifiedConsent {
		t.Fatalf("confirm must preserve the original unverified-consent mode, never upgrade it: %+v", afterConfirmStatus)
	}
	afterConfirmSummaryMarkdown, err := os.ReadFile(filepath.Join(outputDirectory, assessment.SummaryFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(afterConfirmSummaryMarkdown), "UNVERIFIED supplied analysis") {
		t.Fatalf("confirm's re-rendered summary.md must still carry the UNVERIFIED disclosure: %s", afterConfirmSummaryMarkdown)
	}
}

func TestAssessmentEvaluateAndConfirmOfflineRoundTrip(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)
	runPath := writeFixtureRunReport(t, directory)
	outputDirectory := filepath.Join(directory, "out")

	command := newAssessCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory, "--allow-unverified"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var summary assessment.EvaluationOutputSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.ControlCount != 456 || summary.MetricKeyCount != 581 {
		t.Fatalf("evaluate command summary lost profile data: %+v", summary)
	}
	for _, name := range assessment.EvaluationOutputFileNames() {
		if _, err := os.Stat(filepath.Join(outputDirectory, name)); err != nil {
			t.Fatalf("evaluate did not write required file %s: %v", name, err)
		}
	}

	pending := summary.PendingConfirmations
	if len(pending) == 0 {
		t.Fatal("a fresh evaluation must have pending confirmations")
	}
	decisions := []assessment.AssessorInput{{
		ControlID: pending[0], State: assessment.NotAssessed, Assessor: "Jane Reviewer (customer SRE team)",
		ConfirmedAt: time.Now().UTC().Add(-time.Minute), Rationale: "Reviewed; not yet ready to confirm a final state.",
		EvidenceRefs: []string{"interviews/" + pending[0] + ".md"},
	}}
	decisionsData, err := json.Marshal(decisions)
	if err != nil {
		t.Fatal(err)
	}
	decisionsPath := filepath.Join(directory, "decisions.json")
	if err := os.WriteFile(decisionsPath, decisionsData, 0o600); err != nil {
		t.Fatal(err)
	}

	confirmCommand := newAssessCommand()
	var confirmOutput bytes.Buffer
	confirmCommand.SetOut(&confirmOutput)
	confirmCommand.SetArgs([]string{"confirm", "--config", configPath, "--decisions", decisionsPath, "--out", outputDirectory})
	if err := confirmCommand.Execute(); err != nil {
		t.Fatal(err)
	}
	var confirmSummary assessment.EvaluationOutputSummary
	if err := json.Unmarshal(confirmOutput.Bytes(), &confirmSummary); err != nil {
		t.Fatal(err)
	}
	if len(confirmSummary.PendingConfirmations) != len(pending)-1 {
		t.Fatalf("confirming one control should reduce pending confirmations by one: before=%d after=%d",
			len(pending), len(confirmSummary.PendingConfirmations))
	}
}

func TestAssessmentConfirmRejectsMissingDecisionsFlag(t *testing.T) {
	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"confirm"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "--decisions") {
		t.Fatalf("confirm without --decisions should fail explicitly: %v", err)
	}
}

func writeFixtureRunReportWithForgedOutcome(t *testing.T, directory string) string {
	t.Helper()
	scope := assessment.Scope{Host: "github.com", Kind: assessment.RepositoryScope, Name: "acme/repo"}
	report := assessment.VerticalSliceReport{
		CollectedAt:           time.Now().UTC(),
		ImplementedCollectors: assessment.RunImplementedCollectorIDs(),
		ImplementedEvaluators: []string{},
		Organizations:         []assessment.OrganizationRunResult{},
		Metrics:               map[string]assessment.Metric{},
		Outcomes: []assessment.CollectorOutcome{{
			CollectorID: "repo.rules", Feature: "a-page-that-was-never-collected", Scope: scope, Pages: 1,
		}},
		Caveats: []string{},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "forged-run.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAssessmentEvaluateAcceptsTriviallyVerifiedEvidenceDir(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)
	outputDirectory := filepath.Join(directory, "out")
	evidenceDirectory := filepath.Join(directory, "evidence")

	// Zero-outcome reports only earn AnalysisVerified/Verified when they
	// are genuinely bound to a real RunCollectionContext (a context-less
	// report, even an empty one, is never a blanket pass -- see
	// internal/assessment's own
	// TestVerifyReportEvidenceEmptyContextLessReportNeverEarnsAnalysisVerified).
	// This fixture therefore writes a genuine, explicitly zero-target
	// context (not derived from --config's own "fixture-org" resolution,
	// which would require a real collection fixture server to satisfy)
	// and binds the report's own ContextRef to it, so this exercises the
	// --evidence-dir flag wiring end to end through a genuinely verified,
	// still trivially small path -- never a context-less shortcut.
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	config, err := assessment.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := assessment.OpenEvidenceStore(evidenceDirectory, assessment.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	collectedAt := time.Now().UTC()
	ref, err := assessment.WriteRunCollectionContext(store, profile, config, []assessment.Target{}, collectedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	runPath := writeFixtureRunReportWithContext(t, directory, collectedAt, ref)

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"evaluate", "--config", configPath, "--run", runPath, "--out", outputDirectory, "--evidence-dir", evidenceDirectory})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outputDirectory, assessment.ResultsFileName)); err != nil {
		t.Fatalf("a trivially-verified (zero-outcome, genuinely context-bound) report must still produce its export files: %v", err)
	}
}

func TestAssessmentEvaluateRefusesForgedRunReportAgainstEvidenceDir(t *testing.T) {
	directory := t.TempDir()
	configPath := writeFixtureConfig(t, directory)
	forgedRunPath := writeFixtureRunReportWithForgedOutcome(t, directory)
	outputDirectory := filepath.Join(directory, "out")
	evidenceDirectory := filepath.Join(directory, "evidence")
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	command := newAssessCommand()
	command.SilenceErrors, command.SilenceUsage = true, true
	command.SetArgs([]string{"evaluate", "--config", configPath, "--run", forgedRunPath, "--out", outputDirectory, "--evidence-dir", evidenceDirectory})
	if err := command.Execute(); err == nil {
		t.Fatal("a run report citing evidence never persisted in --evidence-dir must be refused")
	}
	if entries, _ := os.ReadDir(outputDirectory); len(entries) != 0 {
		t.Fatalf("a refused evaluation must not write any export files: %v", entries)
	}
}
