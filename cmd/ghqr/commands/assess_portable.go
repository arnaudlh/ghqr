// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/microsoft/ghqr/internal/assessment"
	"github.com/spf13/cobra"
)

func addAssessmentPortableCommands(command *cobra.Command, profilePath, configPath, checksPath, answersPath *string) {
	var runPath, evidenceDirectory, bundleOutput string
	export := &cobra.Command{
		Use: "export", Short: "Export exact saved data to one private portable ZIP (offline)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if runPath == "" || evidenceDirectory == "" || bundleOutput == "" {
				return fmt.Errorf("export requires --run, --evidence-dir and --out (a new portable file)")
			}
			profile, err := assessment.LoadProfile(*profilePath)
			if err != nil {
				return err
			}
			config, err := assessment.LoadConfig(*configPath)
			if err != nil {
				return err
			}
			if *checksPath != "" {
				config.CheckDefinitions, err = assessment.LoadSimpleChecks(profile, *checksPath)
				if err != nil {
					return err
				}
			}
			if _, err := readVerticalSliceReport(runPath); err != nil {
				return err
			}
			data, err := os.ReadFile(runPath)
			if err != nil {
				return fmt.Errorf("read exact portable run bytes: %w", err)
			}
			var profileData [][]byte
			if *profilePath != "" {
				exactProfile, err := os.ReadFile(*profilePath)
				if err != nil {
					return fmt.Errorf("read exact portable profile bytes: %w", err)
				}
				profileData = append(profileData, exactProfile)
			}
			manifest, err := assessment.ExportPortableBundle(profile, config, data, evidenceDirectory, bundleOutput, profileData...)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(manifest); err != nil {
				return fmt.Errorf("write portable export summary: %w", err)
			}
			return nil
		},
	}
	export.Flags().StringVar(&runPath, "run", "", "Collected run JSON to preserve byte-for-byte")
	export.Flags().StringVar(&evidenceDirectory, "evidence-dir", "", "Existing complete sanitized evidence directory")
	export.Flags().StringVar(&bundleOutput, "out", "", "New private portable ZIP file; existing files are never overwritten")

	var bundlePath, analysisOutput string
	var acceptScope, overwrite bool
	analyse := &cobra.Command{
		Use: "analyse", Aliases: []string{"analyze"}, Short: "Verify and analyse a portable data file offline, optionally with separate discussion answers",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if *profilePath != "" {
				return fmt.Errorf("analyse uses the portable file's exact captured profile; --profile cannot override it")
			}
			if bundlePath == "" || analysisOutput == "" {
				return fmt.Errorf("analyse requires --bundle and an explicit --out directory")
			}
			if err := refuseExistingCanonicalResults(analysisOutput, overwrite); err != nil {
				return err
			}
			var config *assessment.CustomerConfig
			if *configPath != "" {
				var err error
				config, err = assessment.LoadConfig(*configPath)
				if err != nil {
					return err
				}
			}
			summary, err := assessment.AnalysePortableBundle(bundlePath, assessment.PortableAnalysisOptions{
				OutputDirectory: analysisOutput, Config: config, AcceptBundleScope: acceptScope,
				ChecksPath: *checksPath, AnswersPath: *answersPath,
			})
			if err != nil {
				return err
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); err != nil {
				return fmt.Errorf("write portable analysis summary: %w", err)
			}
			return nil
		},
	}
	analyse.Flags().StringVar(&bundlePath, "bundle", "", "One self-contained portable data ZIP")
	analyse.Flags().StringVar(&analysisOutput, "out", "", "Explicit analysis output directory")
	analyse.Flags().BoolVar(&acceptScope, "accept-bundle-scope", false, "Explicitly authorize only the portable file's recorded scope without a separate --config")
	analyse.Flags().BoolVar(&overwrite, "overwrite", false, "Permit replacing canonical analysis results in --out")
	command.AddCommand(export, analyse)
}
