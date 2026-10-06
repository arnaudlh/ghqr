// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/microsoft/ghqr/internal/assessment"
)

type portableNoNetwork struct{}

func (portableNoNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("synthetic portable acceptance denies all network")
}

func writeSyntheticPortableCLIData(t *testing.T, directory string) (string, string, string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	config, err := assessment.ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	config.EvidenceDir = filepath.Join(directory, "evidence")
	config.CheckDefinitions, err = assessment.LoadSimpleChecks(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := assessment.OpenEvidenceStore(config.EvidenceDir, assessment.NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	contextRef, err := assessment.WriteRunCollectionContextWithOutcomes(store, profile, config, []assessment.Target{}, now, []assessment.CollectorOutcome{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	report := assessment.VerticalSliceReport{Profile: profile.Summary(), CollectedAt: now, ContextRef: contextRef,
		ImplementedCollectors: assessment.RunImplementedCollectorIDs(), ImplementedEvaluators: []string{},
		Organizations: []assessment.OrganizationRunResult{}, Targets: []assessment.TargetOperationalResult{},
		Metrics: map[string]assessment.Metric{}, Outcomes: []assessment.CollectorOutcome{}, Caveats: []string{}}
	writeJSONFile := func(name string, value any) string {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(directory, name)
		if err := os.WriteFile(destination, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return destination
	}
	runPath := writeJSONFile("run.json", report)
	configPath := writeJSONFile("config.json", config)
	writeJSONFile("checks-default.json", config.CheckDefinitions)
	custom := *config.CheckDefinitions
	custom.Checks = append([]assessment.SimpleCheck{}, custom.Checks...)
	custom.Checks[1].MetricKey = "active_org_rulesets_count"
	writeJSONFile("checks-custom-policy.json", custom)
	customExtraction := *config.CheckDefinitions
	customExtraction.Extractions = append([]assessment.ScalarExtraction{}, customExtraction.Extractions...)
	customExtraction.Extractions[0].FieldPath = "/security_and_analysis/secret_scanning/status"
	writeJSONFile("checks-custom-extraction.json", customExtraction)
	answerPath := writeJSONFile("answers.json", []assessment.InterviewAnswer{{
		ControlID: "GOV-001", Answer: "Synthetic discussion: the fixture team maintains its rules.",
		Respondent: "fixture-reviewer", AnsweredAt: now.Add(-time.Hour), EvidenceRefs: []string{"interview:synthetic-1"},
	}})
	return runPath, configPath, answerPath
}

func TestAssessmentPortableSeparateProcess(t *testing.T) {
	if os.Getenv("GHQR_PORTABLE_CHILD") == "1" {
		http.DefaultTransport = portableNoNetwork{}
		var arguments []string
		if err := json.Unmarshal([]byte(os.Getenv("GHQR_PORTABLE_ARGUMENTS")), &arguments); err != nil {
			t.Fatal(err)
		}
		command := newAssessCommand()
		command.SetOut(&bytes.Buffer{})
		command.SetArgs(arguments)
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
		return
	}
	root := t.TempDir()
	if retained := os.Getenv("GHQR_PORTABLE_FIXTURE_ROOT"); retained != "" {
		root = retained
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(root, "source")
	runPath, configPath, answersPath := writeSyntheticPortableCLIData(t, source)
	bundle := filepath.Join(root, "synthetic-data.zip")
	command := newAssessCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"export", "--config", configPath, "--run", runPath, "--evidence-dir", filepath.Join(source, "evidence"), "--out", bundle})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, filepath.Join(root, "source-moved")); err != nil {
		t.Fatal(err)
	}
	answersPath = filepath.Join(root, "source-moved", filepath.Base(answersPath))
	receiver := filepath.Join(root, "receiver")
	if err := os.MkdirAll(receiver, 0o700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(receiver, "results")
	arguments, err := json.Marshal([]string{"analyse", "--bundle", bundle, "--accept-bundle-scope", "--out", output, "--answers", answersPath})
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestAssessmentPortableSeparateProcess$")
	child.Dir = receiver
	child.Env = []string{"PATH=" + os.Getenv("PATH"), "GHQR_PORTABLE_CHILD=1", "GHQR_PORTABLE_ARGUMENTS=" + string(arguments),
		"HTTP_PROXY=http://127.0.0.1:1", "HTTPS_PROXY=http://127.0.0.1:1"}
	if data, err := child.CombinedOutput(); err != nil {
		t.Fatalf("separate-directory, no-token offline command failed: %v\n%s", err, data)
	}
	profile, err := assessment.LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	results, err := assessment.LoadEvaluationResults(profile, output)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.ControlID == "GOV-001" && (result.Discussion == nil || result.Decision != nil || !result.RequiresConfirmation) {
			t.Fatal("separate discussion answer was omitted or turned into a confirmation")
		}
	}
	status, err := assessment.LoadVerificationStatus(output)
	if err != nil || status.Mode != assessment.VerificationModeVerified || !status.Verification.Verified {
		t.Fatalf("portable source proof lost: %+v %v", status, err)
	}
	guide, err := os.ReadFile(filepath.Join(output, "interview-guide.md"))
	if err != nil || !strings.Contains(string(guide), "Synthetic discussion") || !strings.Contains(string(guide), "Discussion answer: Pending") {
		t.Fatal("facts/answers/pending questions were not rendered separately")
	}
	for _, name := range assessment.EvaluationOutputFileNames() {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Fatal(err)
		}
	}
}
