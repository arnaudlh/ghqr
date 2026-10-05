// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"encoding/json"
	"fmt"

	"github.com/microsoft/ghqr/internal/assessment"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(newAssessCommand())
}

func newAssessCommand() *cobra.Command {
	var profilePath, configPath string
	command := &cobra.Command{
		Use: "assess", Short: "Inspect the evidence-backed Well-Architected assessment foundation",
		Long: "A separate assessment workflow with a bundled version-2 profile and explicit customer configuration.\n" +
			"Profile and plan operations are offline. Collection and scoring are not implemented yet.",
		Args: cobra.NoArgs,
	}
	command.PersistentFlags().StringVar(&profilePath, "profile", "", "Override the bundled version-2 profile with an explicit automation-spec.json")
	command.PersistentFlags().StringVar(&configPath, "config", "", "Path to explicit customer scope YAML")
	command.AddCommand(&cobra.Command{
		Use: "profile", Short: "Validate profile identities, origins and collector references (offline)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := assessment.LoadProfile(profilePath)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(profile.Summary()); err != nil {
				return fmt.Errorf("write assessment profile summary: %w", err)
			}
			return nil
		},
	})
	command.AddCommand(&cobra.Command{
		Use: "plan", Short: "List unimplemented collectors, unknown metrics and unassessed controls (offline)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := assessment.LoadProfile(profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(configPath)
			if err != nil {
				return err
			}
			plan, err := assessment.BuildPlan(profile, config)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(plan); err != nil {
				return fmt.Errorf("write offline assessment plan: %w", err)
			}
			return nil
		},
	})
	for _, operation := range []string{"run"} {
		command.AddCommand(&cobra.Command{
			Use: operation, Short: "Not implemented; returns an explicit error without network access",
			Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return fmt.Errorf("assessment %s is not implemented; assess plan is offline planning, not preflight or scoring", cmd.Name())
			},
		})
	}
	addAssessmentCollectionCommands(command, &profilePath, &configPath)
	return command
}
