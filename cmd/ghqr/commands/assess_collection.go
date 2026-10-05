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
	command.AddCommand(preflight, importCommand, newAssessmentReplayCommand(profilePath, configPath))
}
