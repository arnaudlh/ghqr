// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/microsoft/ghqr/internal/assessment"
	"github.com/spf13/cobra"
)

// addAssessmentEvaluateCommands registers the fully offline evaluate and
// confirm subcommands. Unlike run/preflight, these never contact GitHub: they
// operate entirely on an already-collected VerticalSliceReport (a prior
// `ghqr assess run --live` run.json, a synthetic fixture, or other
// already-collected evidence in the same JSON shape) and explicit assessor
// confirmation input.
func addAssessmentEvaluateCommands(command *cobra.Command, profilePath, configPath *string) {
	var runPath, outputDirectory, evidenceDirectory string
	var allowUnverified, overwrite bool
	evaluate := &cobra.Command{
		Use:   "evaluate",
		Short: "Typed-evaluate a collected run and write all contractual export artifacts (offline)",
		Long: "Reads an already-collected vertical-slice run report (from `ghqr assess run --live`, a synthetic " +
			"fixture, or other already-collected evidence in the same JSON shape) and proposes one result per profile " +
			"control using the registered typed evaluators; every other control gets an explicit NOT_ASSESSED reason, " +
			"never a blank default. It then writes every contractual export artifact (feasibility.json, metrics.json, " +
			"results.csv, interview-guide.md, collection-log.json, summary.md, workbook-update.csv, this package's " +
			"own evaluation-results.json round-trip file, and verification-status.json) to --out. This command never " +
			"contacts GitHub, never resolves credentials and never synthesizes a successful collector outcome the " +
			"source run did not actually record.\n" +
			"Exactly one of --evidence-dir or --allow-unverified is required (mutually exclusive): this command " +
			"never silently trusts a supplied report at face value by default. --evidence-dir supplies the real " +
			"evidence store the run report claims to be backed by: this command's own --config must first authorize " +
			"every organization/enterprise/host the run report itself claims (a report or evidence directory can " +
			"never implicitly \"unlock\" evaluating scope beyond what this specific invocation's own configuration " +
			"permits), then every cited collector outcome is verified, page by page, against that store's own " +
			"identity/digest contract and genuinely replayed before evaluation proceeds, and evaluation is refused " +
			"outright (no files written) if any cited evidence does not genuinely resolve there or the replayed " +
			"analysis disagrees with the supplied claim. --allow-unverified is the explicit, deliberate opt-out for " +
			"a synthetic/trusted fixture input with no real evidence store to verify against: it still enforces the " +
			"same --config scope authorization, but trusts the supplied report's own claims at face value, and " +
			"every export this produces (verification-status.json and a prepended summary.md notice) is explicitly " +
			"labeled unverified so it can never be mistaken for a genuinely proven analysis.\n" +
			"--out has no default and must be supplied explicitly. If --out already contains a prior evaluate pass's " +
			"canonical results (evaluation-results.json), this command refuses to silently overwrite them unless " +
			"--overwrite is also set; `ghqr assess confirm` remains the intentional, in-place update path for an " +
			"existing evaluate pass's own output directory and is unaffected by this refusal.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runPath == "" {
				return fmt.Errorf("evaluate requires --run pointing at a collected vertical-slice run report")
			}
			if outputDirectory == "" {
				return fmt.Errorf("evaluate requires an explicit --out output directory")
			}
			if (evidenceDirectory == "") == !allowUnverified {
				return fmt.Errorf("evaluate requires exactly one of --evidence-dir (verified analysis) or " +
					"--allow-unverified (explicit operator consent to trust the supplied report at face value); " +
					"it never silently trusts a report by default")
			}
			if err := refuseExistingCanonicalResults(outputDirectory, overwrite); err != nil {
				return err
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			report, err := readVerticalSliceReport(runPath)
			if err != nil {
				return err
			}
			var summary *assessment.EvaluationOutputSummary
			if allowUnverified {
				summary, err = assessment.RunOfflineEvaluationWithExplicitConsent(profile, report, config, outputDirectory)
			} else {
				summary, err = assessment.RunVerifiedOfflineEvaluation(profile, report, config, outputDirectory, evidenceDirectory)
			}
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); err != nil {
				return fmt.Errorf("write evaluation summary: %w", err)
			}
			return nil
		},
	}
	evaluate.Flags().StringVar(&runPath, "run", "", "Path to a collected VerticalSliceReport JSON (from `ghqr assess run --live` or an equivalent fixture)")
	evaluate.Flags().StringVar(&evidenceDirectory, "evidence-dir", "", "Verify --run's cited evidence against this real evidence store before evaluating; mutually exclusive with --allow-unverified")
	evaluate.Flags().BoolVar(&allowUnverified, "allow-unverified", false, "Explicit operator consent to trust --run's supplied report at face value with no real evidence store to verify against; mutually exclusive with --evidence-dir")
	evaluate.Flags().StringVar(&outputDirectory, "out", "", "Explicit output directory for every evaluate export artifact (required; refuses to overwrite an existing evaluate pass's results unless --overwrite is set)")
	evaluate.Flags().BoolVar(&overwrite, "overwrite", false, "Permit writing into an --out directory that already contains a prior evaluate pass's canonical results")

	var decisionsPath string
	var confirmOutputDirectory string
	confirm := &cobra.Command{
		Use:   "confirm",
		Short: "Apply explicit assessor decisions to a prior evaluate pass and re-render its exports (offline)",
		Long: "Loads a prior `ghqr assess evaluate` pass's canonical evaluation-results.json from --out, applies the " +
			"explicit assessor decisions supplied via --decisions (a JSON array of control_id/state/assessor/" +
			"confirmed_at/rationale/evidence_refs objects), and re-renders every result-derived export artifact in " +
			"place. Every decision is validated the same way regardless of caller: an unknown control ID or state, an " +
			"empty assessor identity or rationale, a missing, zero, or future-dated confirmation timestamp, or a " +
			"decision with no evidence reference at all is rejected, and a single invalid decision fails the entire " +
			"batch rather than partially applying it. This command never fabricates a confirmation and never rates an " +
			"unobserved control on the assessor's behalf.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if decisionsPath == "" {
				return fmt.Errorf("confirm requires --decisions pointing at a JSON array of assessor decisions")
			}
			if confirmOutputDirectory == "" {
				return fmt.Errorf("confirm requires the --out directory of a prior evaluate pass")
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			decisions, err := readAssessorDecisions(decisionsPath)
			if err != nil {
				return err
			}
			summary, err := assessment.ApplyConfirmationsAndReexport(profile, config, confirmOutputDirectory, decisions, time.Now().UTC())
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); err != nil {
				return fmt.Errorf("write confirmation summary: %w", err)
			}
			return nil
		},
	}
	confirm.Flags().StringVar(&decisionsPath, "decisions", "", "Path to a JSON array of explicit assessor decisions")
	confirm.Flags().StringVar(&confirmOutputDirectory, "out", "./assessment-evaluation", "Output directory of a prior `assess evaluate` pass to update in place")

	command.AddCommand(evaluate, confirm)
}

// readVerticalSliceReport decodes an already-collected VerticalSliceReport
// from disk. It never fetches, infers or synthesizes one: an invalid or
// absent file is a hard error, never a silently empty report.
func readVerticalSliceReport(path string) (*assessment.VerticalSliceReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read collected run report: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report assessment.VerticalSliceReport
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("decode collected run report: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("collected run report must contain exactly one JSON object")
	}
	return &report, nil
}

// readAssessorDecisions decodes an explicit JSON array of assessor decisions
// from disk. Decisions are not validated here; assessment.ApplyAssessorDecisions
// (via assessment.ApplyConfirmationsAndReexport) performs the single
// authoritative validation pass shared by every caller.
func readAssessorDecisions(path string) ([]assessment.AssessorInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read assessor decisions: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decisions []assessment.AssessorInput
	if err := decoder.Decode(&decisions); err != nil {
		return nil, fmt.Errorf("decode assessor decisions: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("assessor decisions file must contain exactly one JSON array")
	}
	return decisions, nil
}

// refuseExistingCanonicalResults refuses to let evaluate write into an --out
// directory that already contains a prior pass's canonical
// evaluation-results.json, unless overwrite is explicitly set: --out has no
// default (the caller must always choose where results land), so an
// existing canonical result set in that directory can only mean a repeat
// invocation against the same path, which must never silently clobber a
// prior pass's own results. A directory that does not exist yet, or exists
// but has never held a canonical result set (for example an empty
// directory, or one holding unrelated files), is never refused: there is
// nothing to protect yet, and evaluate's own underlying evidence store
// creates the directory itself when it does not already exist. The check is
// scoped via os.Root so a crafted --out path cannot be used to probe or
// escape outside the intended output directory.
func refuseExistingCanonicalResults(outputDirectory string, overwrite bool) error {
	if overwrite {
		return nil
	}
	info, statErr := os.Stat(outputDirectory)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil
		}
		return fmt.Errorf("check --out directory %s: %w", outputDirectory, statErr)
	}
	if !info.IsDir() {
		return fmt.Errorf("--out %s already exists and is not a directory", outputDirectory)
	}
	root, err := os.OpenRoot(outputDirectory)
	if err != nil {
		return fmt.Errorf("open --out directory %s: %w", outputDirectory, err)
	}
	defer func() { _ = root.Close() }()
	if _, statErr := root.Stat(assessment.EvaluationResultsFileName); statErr == nil {
		return fmt.Errorf("--out %s already contains a prior evaluate pass's canonical results (%s); refusing to "+
			"overwrite them without --overwrite", outputDirectory, assessment.EvaluationResultsFileName)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("check existing canonical results in --out %s: %w", outputDirectory, statErr)
	}
	return nil
}
