// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"encoding/json"
	"fmt"

	"github.com/microsoft/ghqr/internal/assessment"
	"github.com/spf13/cobra"
)

// addAssessmentRunCommand registers the vertical-slice collection command. It
// requires explicit --live consent, mirroring preflight's contract: this run
// contacts the configured, read-only GitHub REST endpoints and never starts new
// network access by default.
func addAssessmentRunCommand(command *cobra.Command, profilePath, configPath *string) {
	var live bool
	run := &cobra.Command{
		Use: "run", Short: "Collect org inventory/settings, effective default-branch rules and workflow pin metrics; requires --live",
		Long: "Runs the inventory/rules/workflows vertical slice: organization settings and repository inventory, " +
			"active/eligible/critical population determination, effective default-branch rule merging (rulesets plus " +
			"legacy branch protection) and workflow YAML action-reference analysis. It emits measured metrics and raw " +
			"collection outcomes, not full per-control IMPLEMENTED/PARTIAL/NOT_IMPLEMENTED decisions.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !live {
				return fmt.Errorf("run requires explicit --live consent; assess plan is offline")
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			report, err := assessment.RunVerticalSlice(cmd.Context(), profile, config)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(report); err != nil {
				return fmt.Errorf("write vertical slice run report: %w", err)
			}
			return nil
		},
	}
	run.Flags().BoolVar(&live, "live", false, "Explicitly consent to the configured, read-only live API collection")
	command.AddCommand(run)
}
