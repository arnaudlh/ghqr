// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/microsoft/ghqr/internal/assessment"
	"github.com/spf13/cobra"
)

func addAssessmentCollectionCommands(command *cobra.Command, profilePath, configPath *string) {
	var live bool
	preflight := &cobra.Command{
		Use: "preflight", Short: "Probe explicitly scoped implemented collectors; requires --live",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !live {
				return fmt.Errorf("preflight requires explicit --live consent; assess plan is offline")
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			report, err := assessment.RunPreflight(cmd.Context(), profile, config)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
				return fmt.Errorf("write feasibility report: %w", err)
			}
			return nil
		},
	}
	preflight.Flags().BoolVar(&live, "live", false, "Explicitly consent to the configured, read-only live API probes")
	var inputPath, metadataPath string
	importCommand := &cobra.Command{
		Use: "import", Short: "Sanitize structured evidence and retain explicitly imported provenance",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputPath == "" || metadataPath == "" {
				return fmt.Errorf("evidence import requires --input and --metadata")
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("read import payload: %w", err)
			}
			data, err := os.ReadFile(metadataPath)
			if err != nil {
				return fmt.Errorf("read import metadata: %w", err)
			}
			var metadata assessment.EvidenceMetadata
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&metadata); err != nil {
				return fmt.Errorf("decode import metadata: %w", err)
			}
			var extra any
			if err := decoder.Decode(&extra); err != io.EOF {
				return fmt.Errorf("import metadata must contain exactly one JSON object")
			}
			ref, err := assessment.ImportJSON(profile, config, raw, metadata)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(ref); err != nil {
				return fmt.Errorf("write import reference: %w", err)
			}
			return nil
		},
	}
	importCommand.Flags().StringVar(&inputPath, "input", "", "Structured JSON evidence input (always sanitized again)")
	importCommand.Flags().StringVar(&metadataPath, "metadata", "", "Explicit scope, time, profile and source provenance JSON")
	var reportPath, sourcesPath string
	applyImportsCommand := &cobra.Command{
		Use:   "apply-imports",
		Short: "Merge previously imported UI/external/backup captures into an existing report's metrics",
		Long: "Reads an existing assess-run report and an explicit list of (collector_id, scope, feature) import " +
			"sources, merges each source's already-imported, already-validated evidence into the report's metrics " +
			"under the exact profile keys assessment.NormalizedImportMetricKeys documents, and writes the updated " +
			"report back out. Every source must already have been accepted by `assess import`; this command " +
			"never performs a live probe, and never infers a \"latest\" import -- each source names its exact " +
			"collector_id/scope/feature identity explicitly. Every source's scope is authorized against the " +
			"active profile/config (the same gate `assess import` itself enforces) before the evidence store is " +
			"even opened.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if reportPath == "" || sourcesPath == "" {
				return fmt.Errorf("apply-imports requires --report and --sources")
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			reportRaw, err := os.ReadFile(reportPath)
			if err != nil {
				return fmt.Errorf("read report: %w", err)
			}
			var report assessment.VerticalSliceReport
			if err := json.Unmarshal(reportRaw, &report); err != nil {
				return fmt.Errorf("decode report: %w", err)
			}
			if report.Metrics == nil {
				return fmt.Errorf("report does not contain a metrics object to merge into")
			}
			if report.Profile.Version != profile.Version || report.Profile.SHA256 != profile.SHA256 {
				return fmt.Errorf("report's own profile identity does not match the active profile")
			}
			sourcesRaw, err := os.ReadFile(sourcesPath)
			if err != nil {
				return fmt.Errorf("read import sources: %w", err)
			}
			var sources []assessment.ImportSource
			sourcesDecoder := json.NewDecoder(bytes.NewReader(sourcesRaw))
			sourcesDecoder.DisallowUnknownFields()
			if err := sourcesDecoder.Decode(&sources); err != nil {
				return fmt.Errorf("decode import sources: %w", err)
			}
			if len(sources) == 0 {
				return fmt.Errorf("import sources must name at least one source")
			}
			for _, source := range sources {
				if err := assessment.ValidateImportSourceAuthorization(profile, config, source); err != nil {
					return fmt.Errorf("import source for %q is not authorized: %w", source.CollectorID, err)
				}
			}
			store, err := assessment.OpenEvidenceStore(config.EvidenceDir, assessment.NewRedactor())
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			if err := assessment.ApplyNormalizedImports(&report, store, profile, sources); err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
				return fmt.Errorf("write merged report: %w", err)
			}
			return nil
		},
	}
	applyImportsCommand.Flags().StringVar(&reportPath, "report", "", "Existing assess-run report JSON to merge normalized imports into")
	applyImportsCommand.Flags().StringVar(&sourcesPath, "sources", "",
		"JSON array of explicit {collector_id, scope, feature} import sources to merge (no \"latest\" inference)")
	command.AddCommand(preflight, importCommand, applyImportsCommand, newAssessmentReplayCommand(profilePath, configPath))
}
