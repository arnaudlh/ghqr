// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"encoding/json"
	"fmt"

	"github.com/microsoft/ghqr/internal/assessment"
	"github.com/spf13/cobra"
)

func newAssessmentReplayCommand(profilePath, configPath *string) *cobra.Command {
	var host, kind, name, collectorID, feature string
	command := &cobra.Command{
		Use: "replay", Short: "Verify and replay scoped sanitized evidence without network access",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			result, err := assessment.ReplayEvidence(profile, config,
				assessment.Scope{Host: host, Kind: assessment.ScopeKind(kind), Name: name}, collectorID, feature)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
				return fmt.Errorf("write replayed evidence: %w", err)
			}
			return nil
		},
	}
	command.Flags().StringVar(&host, "host", "", "Explicit GitHub host for the evidence scope")
	command.Flags().StringVar(&kind, "scope-kind", "", "enterprise, organization, repository or instance")
	command.Flags().StringVar(&name, "scope", "", "Scope name (owner/repo for repository evidence)")
	command.Flags().StringVar(&collectorID, "collector", "", "Profile collector ID")
	command.Flags().StringVar(&feature, "feature", "", "Exact evidence feature/page identifier")
	return command
}
