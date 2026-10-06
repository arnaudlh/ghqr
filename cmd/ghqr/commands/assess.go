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
	var profilePath, configPath, checksPath, answersPath string
	command := &cobra.Command{
		Use: "assess", Short: "Inspect the evidence-backed Well-Architected assessment foundation",
		Long: "A separate assessment workflow with a bundled version-2 profile and explicit customer configuration.\n" +
			"Profile and plan operations are offline. Preflight and run require explicit --live consent before contacting " +
			"GitHub; import, replay, evaluate, portable export and analysis are offline. Only registered controls are " +
			"scored; unsupported checks remain unassessed, and discussion answers never create confirmations.",
		Args: cobra.NoArgs,
	}
	command.PersistentFlags().StringVar(&profilePath, "profile", "", "Override the bundled version-2 profile with an explicit automation-spec.json")
	command.PersistentFlags().StringVar(&configPath, "config", "", "Path to explicit customer scope YAML")
	command.PersistentFlags().StringVar(&checksPath, "checks", "", "Versioned JSON policy for existing simple checks and one repo.details configuration-field extraction")
	command.PersistentFlags().StringVar(&answersPath, "answers", "", "Separate discussion-answer JSON; answers never automatically confirm controls")
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
	addAssessmentCollectionCommands(command, &profilePath, &configPath)
	addAssessmentRunCommand(command, &profilePath, &configPath, &checksPath)
	addAssessmentEvaluateCommands(command, &profilePath, &configPath, &checksPath, &answersPath)
	addAssessmentPortableCommands(command, &profilePath, &configPath, &checksPath, &answersPath)
	return command
}
