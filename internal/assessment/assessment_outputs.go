// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Output file names for the offline evaluation pipeline's required artifacts.
// These are written into an explicit, caller-chosen output directory distinct
// from a live run's evidence_dir, so evaluating a run never collides with, or
// overwrites, that run's own collection artifacts.
const (
	FeasibilityFileName        = "feasibility.json"
	MetricsFileName            = "metrics.json"
	ResultsFileName            = "results.csv"
	InterviewGuideFileName     = "interview-guide.md"
	CollectionLogFileName      = "collection-log.json"
	SummaryFileName            = "summary.md"
	WorkbookUpdateFileName     = "workbook-update.csv"
	EvaluationResultsFileName  = "evaluation-results.json"
	VerificationStatusFileName = "verification-status.json"
)

// EvaluationOutputFileNames lists every file RunOfflineEvaluation writes, in
// the fixed order documented for this pipeline.
func EvaluationOutputFileNames() []string {
	return []string{
		FeasibilityFileName, MetricsFileName, ResultsFileName, InterviewGuideFileName,
		CollectionLogFileName, SummaryFileName, WorkbookUpdateFileName, EvaluationResultsFileName,
		VerificationStatusFileName,
	}
}

// EvaluationFeasibility reports, from an already-collected run's raw outcomes,
// which catalogue collectors this run actually exercised and how each one
// resolved. It is read-only derived reporting over a prior run; it never
// probes GitHub itself and never synthesizes a successful feasibility result
// from the profile's catalogue alone (a collector with zero recorded outcomes
// stays explicitly unimplemented/unexercised, not assumed working).
type EvaluationFeasibility struct {
	Profile               ProfileSummary         `json:"profile"`
	SourceRunCollectedAt  time.Time              `json:"source_run_collected_at"`
	ImplementedCollectors []string               `json:"implemented_collectors"`
	ImplementedEvaluators []string               `json:"implemented_evaluators"`
	Collectors            []CollectorFeasibility `json:"collectors"`
}

// buildEvaluationFeasibility groups a run's recorded CollectorOutcome entries
// by collector ID and reports each catalogue collector's readiness and raw
// outcomes, reusing the same CollectorFeasibility shape RunPreflight uses.
func buildEvaluationFeasibility(profile *Profile, report *VerticalSliceReport) EvaluationFeasibility {
	byCollector := map[string][]CollectorOutcome{}
	for _, outcome := range report.Outcomes {
		byCollector[outcome.CollectorID] = append(byCollector[outcome.CollectorID], outcome)
	}
	implementedByRun := make(map[string]bool, len(report.ImplementedCollectors))
	for _, id := range report.ImplementedCollectors {
		implementedByRun[id] = true
	}
	items := make([]CollectorFeasibility, 0, len(profile.Collectors))
	for _, collector := range profile.Collectors {
		outcomes := byCollector[collector.ID]
		item := CollectorFeasibility{CollectorID: collector.ID, Outcomes: outcomes, Readiness: Unimplemented}
		switch {
		case implementedByRun[collector.ID] && len(outcomes) > 0:
			item.Readiness = Ready
		case implementedByRun[collector.ID]:
			item.Readiness = Ready
			item.Reason = "collector is registered as implemented by the source run, but no outcome was recorded " +
				"(no explicitly configured scope exercised it in this run)"
		default:
			item.Reason = "collector implementation is not registered in the source run; access has not been probed"
		}
		items = append(items, item)
	}
	return EvaluationFeasibility{
		Profile: profile.Summary(), SourceRunCollectedAt: report.CollectedAt,
		ImplementedCollectors: report.ImplementedCollectors, ImplementedEvaluators: ImplementedEvaluatorIDs(),
		Collectors: items,
	}
}

// VerificationMode is an explicit, always-present disclosure of how trusted
// the analysis behind one evaluation pass actually is: never left to be
// inferred from the mere presence or absence of an EvidenceVerificationResult
// (which a caller skimming only the in-memory summary, not this package's own
// persisted VerificationStatusFileName, could otherwise miss entirely).
type VerificationMode string

const (
	// VerificationModeVerified means the supplied report's cited evidence was
	// independently verified (VerifyReportEvidence) and genuinely replayed
	// (ReplayVerticalSlice) against a real evidence directory before this
	// pass's analysis was scored; see EvidenceVerification for the exact
	// result.
	VerificationModeVerified VerificationMode = "verified"
	// VerificationModeUnverifiedConsent means a caller (the CLI's
	// --allow-unverified flag, after explicit, mutually-exclusive-with
	// --evidence-dir operator consent) explicitly accepted an unverified
	// report at face value for a synthetic/trusted-fixture input; this
	// pass's exports carry an explicit disclosure and must never be
	// confused with a genuinely proven one.
	VerificationModeUnverifiedConsent VerificationMode = "unverified_explicit_consent"
	// VerificationModeTrustedCaller means RunOfflineEvaluation was called
	// directly (not through the CLI's own consent gate at all) and performed
	// no verification of its own; a direct library caller is trusted to
	// already know its own report's provenance, but the persisted output
	// still discloses that this specific pass performed no verification.
	VerificationModeTrustedCaller VerificationMode = "trusted_caller_unverified"
)

// VerificationStatus is this package's own persisted disclosure of
// VerificationMode/EvidenceVerification, written into the SAME atomic
// output-directory batch as every other export artifact (never a separate,
// later write a crash or error between writes could leave inconsistent):
// an auditor inspecting only the files in an output directory -- not a
// CLI's in-memory stdout summary, which is easy to miss or discard -- must
// always be able to read this file and know exactly how trusted the
// analysis next to it actually is.
type VerificationStatus struct {
	Mode         VerificationMode            `json:"mode"`
	Verification *EvidenceVerificationResult `json:"verification,omitempty"`
}

// EvaluationOutputSummary is the CLI-facing receipt for one offline evaluation
// or confirmation pass: where its files were written, how many controls
// landed in each proposed state, which controls still await assessor
// confirmation, and how many of the profile's declared metric keys this run
// computed. It is not itself one of the required export files; it exists so
// the command can report exact counts instead of a caller re-deriving them.
type EvaluationOutputSummary struct {
	OutputDirectory         string                      `json:"output_directory"`
	Profile                 ProfileSummary              `json:"profile"`
	ControlCount            int                         `json:"control_count"`
	ImplementedEvaluatorIDs []string                    `json:"implemented_evaluator_ids"`
	StateCounts             map[State]int               `json:"state_counts"`
	PendingConfirmations    []string                    `json:"pending_confirmations"`
	MetricKeyCount          int                         `json:"metric_key_count"`
	Files                   []string                    `json:"files"`
	VerificationMode        VerificationMode            `json:"verification_mode"`
	EvidenceVerification    *EvidenceVerificationResult `json:"evidence_verification,omitempty"`
}

func summarizeEvaluationOutputs(outputDirectory string, profile *Profile, results []ControlResult, metricKeyCount int, mode VerificationMode) *EvaluationOutputSummary {
	stateCounts := map[State]int{}
	for _, result := range results {
		stateCounts[result.ProposedState]++
	}
	return &EvaluationOutputSummary{
		OutputDirectory: outputDirectory, Profile: profile.Summary(), ControlCount: len(results),
		ImplementedEvaluatorIDs: ImplementedEvaluatorIDs(), StateCounts: stateCounts,
		PendingConfirmations: PendingConfirmations(results), MetricKeyCount: metricKeyCount,
		Files: EvaluationOutputFileNames(), VerificationMode: mode,
	}
}

// RunOfflineEvaluation performs the complete offline evaluate pipeline from an
// already-collected VerticalSliceReport (loaded from a prior `ghqr assess
// run --live` run.json, a synthetic fixture, or other already-collected
// evidence in the same shape): typed evaluation of every profile control,
// followed by every contractual export, written into a dedicated,
// root-bounded output directory. It performs no network access and reads no
// live credentials; a collector with no recorded outcome is reported
// unexercised, never synthesized as a successful probe.
//
// RunOfflineEvaluation itself remains the explicit trusted-caller API this
// package has always documented: it performs no evidence verification and no
// scope-authorization gate of its own, trusting the caller to already know
// its own report's provenance. Its persisted VerificationStatusFileName
// nonetheless always discloses VerificationModeTrustedCaller, so inspecting
// only an output directory's own files (never only an in-memory summary a
// caller may discard) is always enough to know this specific pass performed
// no verification. Callers needing the CLI's own explicit-consent and
// scope-authorization gate for a deliberately-unverified input should use
// RunOfflineEvaluationWithExplicitConsent instead; callers with genuine
// evidence should use RunVerifiedOfflineEvaluation.
func RunOfflineEvaluation(profile *Profile, report *VerticalSliceReport, config *CustomerConfig, outputDirectory string) (*EvaluationOutputSummary, error) {
	return runOfflineEvaluationCore(profile, report, config, outputDirectory, VerificationModeTrustedCaller, nil)
}

// RunOfflineEvaluationWithExplicitConsent is the explicit-consent path for a
// deliberately unverified report (the CLI's --allow-unverified flag, after
// an operator has explicitly chosen not to supply --evidence-dir): it
// performs the SAME mandatory scope-authorization gate
// RunVerifiedOfflineEvaluation performs for a verified report -- a report's
// own claimed scope must never exceed what the CURRENT caller's own
// configuration authorizes, regardless of whether this pass is verified or
// explicitly-consented-unverified -- then runs the same pipeline as
// RunOfflineEvaluation, but persists VerificationModeUnverifiedConsent (not
// VerificationModeTrustedCaller) and prepends an explicit "UNVERIFIED
// supplied analysis" disclosure to the rendered summary.md, so this
// deliberately-trusted-at-face-value pass is never mistaken for either a
// genuinely verified one or an un-consented direct library call.
func RunOfflineEvaluationWithExplicitConsent(profile *Profile, report *VerticalSliceReport, config *CustomerConfig, outputDirectory string) (*EvaluationOutputSummary, error) {
	currentTargets, targetsErr := config.ResolvedTargets()
	if targetsErr != nil {
		return nil, fmt.Errorf("resolve current configuration's authorized scope: %w", targetsErr)
	}
	if err := targetsAuthorizeScope(currentTargets, deriveClaimedScope(report)); err != nil {
		return nil, fmt.Errorf("report claims scope beyond what the current configuration authorizes: %w", err)
	}
	return runOfflineEvaluationCore(profile, report, config, outputDirectory, VerificationModeUnverifiedConsent, nil)
}

const unverifiedSummaryDisclosure = "> **UNVERIFIED supplied analysis.** This evaluation was run with explicit " +
	"operator consent to trust its supplied report at face value (`--allow-unverified`), without verifying its " +
	"cited evidence against a real evidence directory. Every proposed state and metric below reflects the " +
	"supplied report's own claims, not an independently proven analysis. See `" + VerificationStatusFileName + "` " +
	"for this pass's full, persisted verification disclosure.\n\n"

func runOfflineEvaluationCore(profile *Profile, report *VerticalSliceReport, config *CustomerConfig, outputDirectory string,
	mode VerificationMode, verification *EvidenceVerificationResult) (*EvaluationOutputSummary, error) {
	if outputDirectory == "" {
		return nil, fmt.Errorf("offline evaluation requires an explicit output directory")
	}
	results, err := EvaluateReport(profile, report, config)
	if err != nil {
		return nil, fmt.Errorf("evaluate assessment report: %w", err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, fmt.Errorf("resolve evaluation targets: %w", err)
	}
	metrics, err := BuildMetricsCatalogue(profile, results, targets)
	if err != nil {
		return nil, fmt.Errorf("build evaluation metrics catalogue: %w", err)
	}

	store, err := OpenEvidenceStore(outputDirectory, NewRedactor())
	if err != nil {
		return nil, fmt.Errorf("open evaluation output directory: %w", err)
	}
	disclosure := ""
	if mode == VerificationModeUnverifiedConsent {
		disclosure = unverifiedSummaryDisclosure
	}
	writeErr := func() error {
		feasibility := buildEvaluationFeasibility(profile, report)
		if err := store.WriteReport(FeasibilityFileName, feasibility); err != nil {
			return fmt.Errorf("write %s: %w", FeasibilityFileName, err)
		}
		if err := store.WriteReport(MetricsFileName, metrics); err != nil {
			return fmt.Errorf("write %s: %w", MetricsFileName, err)
		}
		if err := store.WriteReport(CollectionLogFileName, report.Outcomes); err != nil {
			return fmt.Errorf("write %s: %w", CollectionLogFileName, err)
		}
		// Written inside this SAME atomic open/close batch as every other
		// artifact, never a separate later write a crash or error between
		// writes could leave an output directory's other files on disk
		// with no persisted verification disclosure at all.
		if err := store.WriteReport(VerificationStatusFileName, VerificationStatus{Mode: mode, Verification: verification}); err != nil {
			return fmt.Errorf("write %s: %w", VerificationStatusFileName, err)
		}
		return writeExportArtifacts(store, profile, config, results, report.Outcomes, disclosure)
	}()
	closeErr := store.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	summary := summarizeEvaluationOutputs(outputDirectory, profile, results, len(metrics), mode)
	summary.EvidenceVerification = verification
	return summary, nil
}

// writeExportArtifacts renders and writes the four contractual export
// artifacts that depend only on the control-result list and the run's raw
// collection outcomes (results.csv, interview-guide.md, summary.md,
// workbook-update.csv) plus this package's own canonical
// evaluation-results.json round-trip artifact, so a later confirmation pass
// can re-render them without needing the original VerticalSliceReport again.
// outcomes must be the run's real, persisted CollectorOutcome list (loaded
// back via LoadCollectionLog for the confirmation path): passing a nil/empty
// slice here would silently drop genuine collection failures (for example a
// permission-denied organization outcome) from summary.md, even though the
// original run recorded them. CSV/Markdown text is sanitized through the
// plain-text redaction boundary (Redactor.Text), never the JSON boundary,
// before the same atomic, root-bounded write every other output uses.
// summaryDisclosure, when non-empty, is prepended verbatim to the rendered
// summary.md content before sanitization (an explicit "UNVERIFIED supplied
// analysis" notice for VerificationModeUnverifiedConsent); it is empty for
// every other verification mode.
func writeExportArtifacts(store *EvidenceStore, profile *Profile, config *CustomerConfig, results []ControlResult,
	outcomes []CollectorOutcome, summaryDisclosure string) error {
	resultsCSV, err := RenderResultsCSV(profile, results)
	if err != nil {
		return fmt.Errorf("render %s: %w", ResultsFileName, err)
	}
	if err := writeSanitizedText(store, ResultsFileName, resultsCSV); err != nil {
		return fmt.Errorf("write %s: %w", ResultsFileName, err)
	}

	guide, err := RenderInterviewGuide(profile, results)
	if err != nil {
		return fmt.Errorf("render %s: %w", InterviewGuideFileName, err)
	}
	if err := writeSanitizedText(store, InterviewGuideFileName, guide); err != nil {
		return fmt.Errorf("write %s: %w", InterviewGuideFileName, err)
	}

	var thresholds map[string]float64
	if config != nil {
		thresholds = config.Thresholds
	}
	summary, err := RenderAssessmentSummary(profile, results, outcomes, thresholds)
	if err != nil {
		return fmt.Errorf("render %s: %w", SummaryFileName, err)
	}
	if summaryDisclosure != "" {
		summary = append([]byte(summaryDisclosure), summary...)
	}
	if err := writeSanitizedText(store, SummaryFileName, summary); err != nil {
		return fmt.Errorf("write %s: %w", SummaryFileName, err)
	}

	workbook, err := RenderWorkbookUpdateCSV(profile, results, map[string]string{})
	if err != nil {
		return fmt.Errorf("render %s: %w", WorkbookUpdateFileName, err)
	}
	if err := writeSanitizedText(store, WorkbookUpdateFileName, workbook); err != nil {
		return fmt.Errorf("write %s: %w", WorkbookUpdateFileName, err)
	}

	if err := store.WriteReport(EvaluationResultsFileName, results); err != nil {
		return fmt.Errorf("write %s: %w", EvaluationResultsFileName, err)
	}
	return nil
}

// writeSanitizedText applies the plain-text redaction boundary (Redactor.Text)
// to already-rendered CSV/Markdown content, then writes it through the same
// atomic, root-bounded path every other evidence object uses. It must never be
// used with JSON content (EvidenceStore.WriteReport owns that boundary
// instead): running the structural JSON redactor over CSV/Markdown text would
// reject it as invalid JSON rather than sanitizing it.
func writeSanitizedText(store *EvidenceStore, path string, data []byte) error {
	sanitized := store.redactor.Text(string(data))
	return store.atomicWrite(path, []byte(sanitized))
}

// LoadEvaluationResults reads back a prior RunOfflineEvaluation pass's
// canonical evaluation-results.json from outputDirectory, validating that it
// matches the supplied profile's exact control count before returning it.
func LoadEvaluationResults(profile *Profile, outputDirectory string) ([]ControlResult, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate confirmation profile: %w", err)
	}
	store, err := OpenEvidenceStore(outputDirectory, NewRedactor())
	if err != nil {
		return nil, fmt.Errorf("open evaluation output directory: %w", err)
	}
	data, readErr := store.root.ReadFile(EvaluationResultsFileName)
	closeErr := store.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read prior evaluation results from %s: %w", outputDirectory, readErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	var results []ControlResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("decode prior evaluation results: %w", err)
	}
	if len(results) != len(profile.Controls) {
		return nil, fmt.Errorf("prior evaluation results (%d) do not match the selected profile's control count (%d)",
			len(results), len(profile.Controls))
	}
	return results, nil
}

// LoadCollectionLog reads back a prior RunOfflineEvaluation pass's
// collection-log.json from outputDirectory: the original run's raw
// CollectorOutcome list, recorded verbatim at evaluation time. A later
// confirmation pass needs this to re-render summary.md with the run's real
// collection failures/incompleteness (for example a permission-denied
// organization outcome) preserved, since ApplyConfirmationsAndReexport has no
// VerticalSliceReport of its own to read Outcomes from directly.
func LoadCollectionLog(outputDirectory string) ([]CollectorOutcome, error) {
	store, err := OpenEvidenceStore(outputDirectory, NewRedactor())
	if err != nil {
		return nil, fmt.Errorf("open evaluation output directory: %w", err)
	}
	data, readErr := store.root.ReadFile(CollectionLogFileName)
	closeErr := store.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read prior collection log from %s: %w", outputDirectory, readErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	var outcomes []CollectorOutcome
	if err := json.Unmarshal(data, &outcomes); err != nil {
		return nil, fmt.Errorf("decode prior collection log: %w", err)
	}
	return outcomes, nil
}

// LoadVerificationStatus reads back a prior evaluation pass's own persisted
// VerificationStatus, the authoritative disclosure ApplyConfirmationsAndReexport
// must preserve byte-for-byte rather than recompute: a confirmation pass never
// re-verifies evidence or re-authorizes scope, so it must never silently
// upgrade (or downgrade) an original pass's own genuine verification mode. An
// output directory predating this file entirely (written by an older build)
// falls back to the most conservative label, VerificationModeTrustedCaller
// with no verification result, rather than erroring out or guessing a more
// trusted mode than the original pass ever genuinely earned.
func LoadVerificationStatus(outputDirectory string) (VerificationStatus, error) {
	store, err := OpenEvidenceStore(outputDirectory, NewRedactor())
	if err != nil {
		return VerificationStatus{}, fmt.Errorf("open evaluation output directory: %w", err)
	}
	data, readErr := store.root.ReadFile(VerificationStatusFileName)
	closeErr := store.Close()
	if closeErr != nil {
		return VerificationStatus{}, closeErr
	}
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return VerificationStatus{Mode: VerificationModeTrustedCaller}, nil
		}
		return VerificationStatus{}, fmt.Errorf("read prior verification status from %s: %w", outputDirectory, readErr)
	}
	var status VerificationStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return VerificationStatus{}, fmt.Errorf("decode prior verification status: %w", err)
	}
	return status, nil
}

// ApplyConfirmationsAndReexport loads a prior RunOfflineEvaluation pass's
// canonical results from outputDirectory, applies the supplied explicit
// assessor decisions (validated the same way ApplyAssessorDecisions always
// validates them), and re-renders every result-derived export artifact in
// place. It never re-derives feasibility.json/metrics.json/collection-log.json
// (those depend only on the original collected run, which this confirmation
// step does not require again) and never re-runs any typed evaluator: a
// confirmed control's proposal is exactly what RunOfflineEvaluation already
// computed, only its separate Decision changes. It reads back the original
// run's raw collection outcomes via LoadCollectionLog so re-rendered
// summary.md keeps any real collection failures/incompleteness the original
// run recorded, rather than silently dropping them on confirmation. It also
// reads back (via LoadVerificationStatus) and re-persists, completely
// unchanged, the original pass's own VerificationMode/EvidenceVerification
// and summary.md disclosure: a confirmation pass performs no verification or
// scope-authorization of its own and must never upgrade an unverified pass
// into one that merely looks verified because a later confirm happened to
// clear its own, unrelated error checks.
func ApplyConfirmationsAndReexport(profile *Profile, config *CustomerConfig, outputDirectory string, decisions []AssessorInput, now time.Time) (*EvaluationOutputSummary, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate confirmation configuration: %w", err)
	}
	results, err := LoadEvaluationResults(profile, outputDirectory)
	if err != nil {
		return nil, err
	}
	outcomes, err := LoadCollectionLog(outputDirectory)
	if err != nil {
		return nil, err
	}
	status, err := LoadVerificationStatus(outputDirectory)
	if err != nil {
		return nil, err
	}
	confirmed, err := ApplyAssessorDecisions(profile, results, decisions, now)
	if err != nil {
		return nil, err
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, fmt.Errorf("resolve confirmation targets: %w", err)
	}
	metrics, err := BuildMetricsCatalogue(profile, confirmed, targets)
	if err != nil {
		return nil, fmt.Errorf("build confirmation metrics catalogue: %w", err)
	}

	store, err := OpenEvidenceStore(outputDirectory, NewRedactor())
	if err != nil {
		return nil, fmt.Errorf("open evaluation output directory: %w", err)
	}
	disclosure := ""
	if status.Mode == VerificationModeUnverifiedConsent {
		disclosure = unverifiedSummaryDisclosure
	}
	writeErr := func() error {
		if err := store.WriteReport(VerificationStatusFileName, status); err != nil {
			return fmt.Errorf("write %s: %w", VerificationStatusFileName, err)
		}
		return writeExportArtifacts(store, profile, config, confirmed, outcomes, disclosure)
	}()
	closeErr := store.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	summary := summarizeEvaluationOutputs(outputDirectory, profile, confirmed, len(metrics), status.Mode)
	summary.EvidenceVerification = status.Verification
	return summary, nil
}

// EvidenceVerificationResult reports whether a collected run report's cited
// evidence references actually resolve to real, digest-verified, sanitized
// objects in an explicit evidence store, rather than trusting the report's
// claims at face value, plus a bounded replay check (see
// replayWorkflowReferences) that re-derives one specific claimed fact
// directly from stored raw evidence and flags a mismatch as tampering. It is
// not a full re-derivation of the report's analysis (it never replays the
// multi-endpoint ruleset/legacy branch-protection merge or feature-coverage
// aggregation, which remain the collecting run's own responsibility,
// explicitly out of scope here): existence/digest-verified evidence refs
// alone only prove a page was genuinely persisted, not that every claimed
// derived fact still matches it, which is exactly the gap full-pipeline
// replay closes.
//
// IntegrityVerified and AnalysisVerified are reported separately and
// explicitly, because they prove two different things: IntegrityVerified
// means every cited evidence page's identity/digest genuinely resolves (the
// page exists and was not swapped for different bytes); AnalysisVerified
// means this run's own ReplayVerticalSlice, re-deriving every organization/
// population/repository/metric from that same stored evidence through the
// real collection/analysis pipeline, independently reaches the same facts
// the report claims. A report can have perfect page-level integrity while
// its claimed analysis is still wrong (genuine, unrelated evidence; a
// claimed metric no corresponding collector evidence actually supports);
// Verified is true only when both hold.
type EvidenceVerificationResult struct {
	EvidenceDirectory string   `json:"evidence_directory"`
	OutcomesChecked   int      `json:"outcomes_checked"`
	PagesVerified     int      `json:"pages_verified"`
	IntegrityVerified bool     `json:"integrity_verified"`
	// ContextBound is true when evidenceDirectory carried a genuine,
	// immutable RunCollectionContext (see run_collection_context.go) that
	// AnalysisVerified's replay reconstruction was bound to directly, and
	// false for a legacy bundle replayed via best-effort inference instead
	// (see ReplayVerticalSlice). AnalysisVerified is never a blanket true
	// for a legacy (ContextBound=false) bundle that genuinely claims
	// analysis, regardless of how cleanly its inferred-settings comparison
	// happens to come out; see Failures for the explicit disclosed reason.
	ContextBound     bool     `json:"context_bound"`
	AnalysisVerified bool     `json:"analysis_verified"`
	Verified         bool     `json:"verified"`
	Failures         []string `json:"failures,omitempty"`
}

// VerifyReportEvidence proves both evidence integrity and claimed-analysis
// correctness for a run report against evidenceDirectory.
//
// Integrity: every CollectorOutcome the report cites must resolve, page by
// page, to a real evidence object whose identity and content digest match
// what the EvidenceStore itself recorded at collection time
// (EvidenceStore.LoadJSON's existing identity/digest contract). An outcome
// with zero recorded pages is not a failure; a non-zero page count that
// fails to resolve is. A report that claims analysis (any repository's
// effective protection/workflows, a feature signal, or a known pooled
// metric) while zero pages actually resolve is explicitly rejected as a
// vacuous, zero-evidence pass, never silently accepted.
//
// Analysis: resolving pages only proves they were persisted, not that the
// report's claimed derived facts match them (a hand-edited report can cite
// entirely genuine evidence while independently altering a claimed result,
// or cite a genuine-but-semantically-unrelated page). This is closed by
// genuinely replaying the ENTIRE collection/analysis/pooling pipeline --
// every organization, population, critical-population determination,
// repository and metric, not a narrowed subset -- through
// ReplayVerticalSlice, which calls the exact same runVerticalSliceWithStore
// a live `ghqr assess run` uses via a replay-mode client factory that serves
// only already-persisted pages and never dials out, then comparing every
// claimed fact against what that replay genuinely, independently derives.
// profile must be the exact profile the original collection used.
func VerifyReportEvidence(profile *Profile, report *VerticalSliceReport, evidenceDirectory string) (*EvidenceVerificationResult, error) {
	if profile == nil {
		return nil, fmt.Errorf("evidence verification requires the profile the original collection used")
	}
	if report == nil {
		return nil, fmt.Errorf("evidence verification requires a collected run report")
	}
	if evidenceDirectory == "" {
		return nil, fmt.Errorf("evidence verification requires an explicit evidence directory")
	}
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		return nil, fmt.Errorf("open evidence store for verification: %w", err)
	}
	result := &EvidenceVerificationResult{EvidenceDirectory: evidenceDirectory, IntegrityVerified: true}
	for _, outcome := range report.Outcomes {
		result.OutcomesChecked++
		// Binds to this outcome's own cited EvidenceRefs (the exact,
		// content-addressed object pair genuinely written for each page at
		// collection time), not merely whatever the current, mutable
		// per-feature manifest pointer happens to resolve to right now: an
		// older report's own cited evidence must remain independently
		// verifiable even after a later run into the same directory moves
		// that logical key's pointer to different, equally genuine
		// content. Rejects a wrong pair, scope, collector, feature/page or
		// profile identity, not just "does some object exist at all".
		verified, failures := verifyOutcomeEvidenceRefs(store, profile, outcome)
		result.PagesVerified += verified
		if len(failures) > 0 {
			result.IntegrityVerified = false
			result.Failures = append(result.Failures, failures...)
		}
	}
	if claim := reportClaimsAnalysis(report); claim != "" && result.PagesVerified == 0 {
		result.IntegrityVerified = false
		result.Failures = append(result.Failures, fmt.Sprintf(
			"report claims computed analysis (%s) but zero evidence pages were verified across %d recorded outcome(s); "+
				"metadata/outcome existence alone cannot prove genuine collection, refusing to treat this as verified", claim, result.OutcomesChecked))
	}
	closeErr := store.Close()
	if closeErr != nil {
		return nil, closeErr
	}

	replayedReport, contextBound, replayErr := ReplayVerticalSlice(context.Background(), profile, report, evidenceDirectory)
	result.ContextBound = contextBound
	// reportClaimsNothing is only used to choose which disclosed reason
	// text applies below (AnalysisVerified is unconditionally false
	// whenever !contextBound regardless); it must itself require there to
	// be genuinely nothing claimed anywhere in the report, not merely that
	// Organizations/Targets happen to be empty while Metrics/Outcomes still
	// claim something -- a report could otherwise misleadingly read as
	// "claims nothing" while still carrying known pooled metrics or
	// recorded collector outcomes.
	reportClaimsNothing := len(report.Organizations) == 0 && len(report.Targets) == 0 &&
		len(report.Metrics) == 0 && len(report.Outcomes) == 0
	switch {
	case replayErr != nil:
		result.AnalysisVerified = false
		result.Failures = append(result.Failures, fmt.Sprintf("full-pipeline replay could not run: %v", replayErr))
	case !contextBound:
		// AnalysisVerified must never be a blanket true without a genuinely
		// bound run collection context -- not even for a report that
		// claims nothing at all. A context-less "empty" report proves
		// nothing about genuine collection-time provenance either: it is
		// exactly as unproven as a context-less report that claims
		// something, just with zero substantive content to disagree with
		// its own replay about. Treating "found nothing to contradict" as
		// equivalent to "genuinely verified" here would be the same
		// generic shortcut this branch exists to close for a legacy,
		// inferred-settings bundle, applied instead to an empty one.
		//
		// A genuinely context-less, genuinely empty report (fresh, never
		// collected anything, zero bound context) still reports
		// IntegrityVerified=true (nothing claimed, nothing failed to
		// resolve) and is never treated as an error -- only
		// AnalysisVerified/Verified stay honestly false, with an explicit,
		// disclosed reason distinct from the legacy-bundle-with-content
		// case below.
		result.AnalysisVerified = false
		mismatches := compareVerticalSliceReports(report, replayedReport)
		result.Failures = append(result.Failures, mismatches...)
		if reportClaimsNothing {
			result.Failures = append(result.Failures, "report claims no analysis at all and has no bound run "+
				"collection context; an empty, context-less report is never a blanket AnalysisVerified=true pass, "+
				"since it proves nothing about genuine collection-time provenance either")
		} else {
			// A legacy evidence bundle with no bound RunCollectionContext
			// was replayed via best-effort inference
			// (legacyDeriveReplayTargets/legacyReplayConfig), never
			// genuine collection-time provenance. An inferred Deployment/
			// defaulted lookback-critical-property-values/production-
			// regex/trusted-claimed-repository-cap could just as easily
			// make an altered claim compare clean under invented settings
			// as it could catch a genuine one. Any comparison mismatches
			// found are still surfaced (still useful signal), but the
			// overall verdict for this run is an explicit, disclosed
			// compatibility limitation, not full analysis verification.
			result.Failures = append(result.Failures, "no bound run collection context: this evidence directory "+
				"predates RunCollectionContext and was replayed via best-effort inference from the claimed report "+
				"itself, not genuine collection-time provenance; full analysis verification is an explicit "+
				"compatibility limitation, never a blanket pass, for a bundle collected this way")
		}
	default:
		mismatches := compareVerticalSliceReports(report, replayedReport)
		// Even with a genuinely bound context, a report that claims
		// computed analysis must have actually had at least one page
		// independently verified (via the integrity loop above) before
		// AnalysisVerified can be true: zero mismatches found is not proof
		// of anything when there was nothing to compare against in the
		// first place (for example every claimed page having failed
		// integrity resolution, while the replayed side -- reconstructed
		// from genuinely different or absent evidence -- happens to also
		// come out structurally empty). Mirrors the same "claim without
		// proof" concern reportClaimsAnalysis/PagesVerified already guards
		// for IntegrityVerified, applied here to AnalysisVerified too.
		if claim := reportClaimsAnalysis(report); claim != "" && result.PagesVerified == 0 {
			result.AnalysisVerified = false
			result.Failures = append(result.Failures, fmt.Sprintf(
				"report claims computed analysis (%s) under a bound context, but zero evidence pages were "+
					"independently verified; AnalysisVerified cannot be a blanket pass without at least one "+
					"genuinely verified page to have actually proven anything", claim))
		} else {
			result.AnalysisVerified = len(mismatches) == 0
		}
		result.Failures = append(result.Failures, mismatches...)
	}
	result.Verified = result.IntegrityVerified && result.AnalysisVerified
	return result, nil
}

// reportClaimsAnalysis reports a short, human-readable description of the
// first genuinely computed analysis fact found in report (a repository's
// effective default-branch protection, workflow analysis, or a known,
// non-empty feature signal; or a pooled metric with MetricKnown status), or
// an empty string when the report contains no such claim at all (an entirely
// empty/unanalyzed report legitimately has zero evidence to verify, and must
// not be rejected merely for having zero outcomes).
func reportClaimsAnalysis(report *VerticalSliceReport) string {
	for _, organization := range report.Organizations {
		for _, repository := range organization.Repositories {
			if repository.EffectiveProtection != nil {
				return fmt.Sprintf("effective default-branch protection computed for %s", repository.FullName)
			}
			if repository.Workflows != nil {
				return fmt.Sprintf("workflow action-reference analysis computed for %s", repository.FullName)
			}
			if repository.Feature.DependencyEligible || repository.Feature.DependencyOperational {
				return fmt.Sprintf("feature-eligibility signal computed for %s", repository.FullName)
			}
		}
	}
	for key, metric := range report.Metrics {
		if metric.Overall.Status == MetricKnown {
			return fmt.Sprintf("pooled metric %s reported as known", key)
		}
	}
	return ""
}

// RunVerifiedOfflineEvaluation wraps RunOfflineEvaluation with an optional
// source-provenance gate: when evidenceDirectory is non-empty, the supplied
// report's cited evidence is verified against that real evidence store
// first, and evaluation is refused outright (no export files are written)
// when verification fails, rather than silently producing scores from a
// report that cannot be proven genuine. An empty evidenceDirectory skips
// verification entirely and behaves exactly like RunOfflineEvaluation,
// preserving the existing trusted-run.json/fixture workflow.
func RunVerifiedOfflineEvaluation(profile *Profile, report *VerticalSliceReport, config *CustomerConfig, outputDirectory, evidenceDirectory string) (*EvaluationOutputSummary, error) {
	// The CURRENT caller's own config is mandatory scope authorization,
	// independent of whatever the report or its bound context might
	// otherwise claim, and independent of whether this specific call ends
	// up verified or not: a report (or a context an attacker fabricated
	// into one) is never allowed to implicitly "unlock" evaluation of
	// organizations/enterprises this specific call's own config does not
	// itself authorize, regardless of evidenceDirectory.
	currentTargets, targetsErr := config.ResolvedTargets()
	if targetsErr != nil {
		return nil, fmt.Errorf("resolve current configuration's authorized scope: %w", targetsErr)
	}
	if err := targetsAuthorizeScope(currentTargets, deriveClaimedScope(report)); err != nil {
		return nil, fmt.Errorf("report claims scope beyond what the current configuration authorizes: %w", err)
	}
	if evidenceDirectory == "" {
		return runOfflineEvaluationCore(profile, report, config, outputDirectory, VerificationModeTrustedCaller, nil)
	}
	result, err := VerifyReportEvidence(profile, report, evidenceDirectory)
	if err != nil {
		return nil, fmt.Errorf("verify run report evidence: %w", err)
	}
	if !result.Verified {
		return nil, fmt.Errorf("run report evidence failed verification against %s (%d pages verified across "+
			"%d outcomes, %d failure(s)); refusing to evaluate an unproven report. First failure: %s",
			evidenceDirectory, result.PagesVerified, result.OutcomesChecked, len(result.Failures), firstOrEmpty(result.Failures))
	}
	// Once verified, evaluation scores the independently replayed
	// report -- reconstructed afresh from this run's own stored
	// evidence through the real pipeline -- never the originally
	// supplied report's own claimed metrics, even though
	// compareVerticalSliceReports found no contradiction between them.
	replayedReport, _, replayErr := ReplayVerticalSlice(context.Background(), profile, report, evidenceDirectory)
	if replayErr != nil {
		return nil, fmt.Errorf("replay verified run report evidence for evaluation: %w", replayErr)
	}
	// Collection REPORTING (collection-log.json/summary.md's outcome text)
	// uses the originally supplied report's own Outcomes, not the
	// replayed reconstruction's: a zero-page outcome (a transport failure
	// before any HTTP response was observed, a permission-denied
	// organization) has no persisted evidence pages at all, so replay can
	// only ever synthesize a generic substitute reason for it, never
	// recover the true original. ReplayVerticalSlice already proved
	// report.Outcomes exactly matches its bound context's immutable
	// OriginalOutcomes snapshot before reaching this point (when a context
	// is bound at all), so using it here for reporting is independently
	// justified, not merely "trusted because supplied." Scoring itself is
	// untouched: every other field (Metrics/Organizations/Targets) remains
	// the canonical, independently replayed analysis.
	reportingReport := *replayedReport
	reportingReport.Outcomes = report.Outcomes
	// VerificationModeVerified/result are passed straight into the SAME
	// atomic open/close batch runOfflineEvaluationCore uses for every other
	// export artifact -- never written in a separate pass after the fact,
	// so a crash or error between two separate writes can never leave an
	// output directory's other files on disk with no persisted
	// verification disclosure, or (worse) a disclosure some other mode's
	// files were never actually produced under.
	return runOfflineEvaluationCore(profile, &reportingReport, config, outputDirectory, VerificationModeVerified, result)
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
