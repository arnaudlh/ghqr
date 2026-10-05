// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/google/go-github/v83/github"
)

// RunImplementedCollectorIDs lists the collector catalogue IDs this vertical
// slice run actually calls. It is distinct from the narrower preflight probe
// registry (ImplementedCollectorIDs), which only knows how to probe org.settings
// and ghes.meta before any repository has been discovered: the repository-level
// collectors here require the organization's repository inventory to already be
// known, so they cannot be exercised by a pre-discovery preflight probe.
func RunImplementedCollectorIDs() []string {
	return []string{
		"org.settings", "org.repos", "org.properties",
		"repo.details", "repo.rules", "repo.workflows", "repo.languages", "repo.sbom",
	}
}

// RepositoryRunResult is one analyzed repository's effective branch protection,
// workflow analysis and feature-eligibility signal.
type RepositoryRunResult struct {
	FullName            string                     `json:"full_name"`
	DefaultBranch       string                     `json:"default_branch"`
	EffectiveProtection *EffectiveBranchProtection `json:"effective_protection,omitempty"`
	Workflows           *WorkflowAnalysisResult    `json:"workflows,omitempty"`
	Feature             RepositoryFeatureSignal    `json:"feature"`
}

// OrganizationRunResult is one organization scope's population and
// per-repository analysis.
type OrganizationRunResult struct {
	Scope        Scope                   `json:"scope"`
	Population   *OrganizationPopulation `json:"population"`
	Repositories []RepositoryRunResult   `json:"repositories"`
}

// VerticalSliceReport is the typed, evidence-backed result of `ghqr assess run`.
// It reports measured metrics and raw collection outcomes; it does not produce
// full per-control ControlResult records, which remain a later phase's
// responsibility ("this run emits measured metrics plus raw refs/completeness,
// not guessed states based on pure file presence").
type VerticalSliceReport struct {
	Profile               ProfileSummary          `json:"profile"`
	CollectedAt           time.Time               `json:"collected_at"`
	ImplementedCollectors []string                `json:"implemented_collectors"`
	ImplementedEvaluators []string                `json:"implemented_evaluators"`
	Organizations         []OrganizationRunResult `json:"organizations"`
	Metrics               map[string]Metric       `json:"metrics"`
	Outcomes              []CollectorOutcome      `json:"collector_outcomes"`
	Caveats               []string                `json:"caveats"`
}

// RunVerticalSlice performs explicitly live-consented collection across every
// configured target: organization inventory and settings, active/eligible/
// critical population determination, effective default-branch rule merging,
// workflow YAML action-reference analysis and feature-eligibility signals. Every
// control outside this scope remains NOT_ASSESSED; this run never fabricates a
// state from mere file presence.
func RunVerticalSlice(ctx context.Context, profile *Profile, config *CustomerConfig) (*VerticalSliceReport, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, err
	}
	budget, err := NewRequestBudget(config.Concurrency)
	if err != nil {
		return nil, err
	}
	clock := SystemClock{}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		return nil, err
	}
	report, runErr := runVerticalSliceWithStore(ctx, profile, config, targets, store, clock,
		func(target Target) (*CollectionClient, error) {
			return NewCollectionClient(target, RESTEvidence, profile, budget, clock)
		})
	closeErr := store.Close()
	if runErr != nil {
		return nil, runErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return report, nil
}

func runVerticalSliceWithStore(ctx context.Context, profile *Profile, config *CustomerConfig, targets []Target,
	store *EvidenceStore, clock Clock, newClient func(Target) (*CollectionClient, error)) (*VerticalSliceReport, error) {
	report := &VerticalSliceReport{
		Profile: profile.Summary(), CollectedAt: clock.Now(),
		ImplementedCollectors: RunImplementedCollectorIDs(), ImplementedEvaluators: []string{},
		Organizations: []OrganizationRunResult{}, Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}, Caveats: []string{},
	}
	accumulator := newMetricAccumulator()

	for _, target := range targets {
		client, err := newClient(target)
		if err != nil {
			return nil, fmt.Errorf("initialize collection client for host %s: %w", target.Host, err)
		}
		for _, organization := range target.Organizations {
			orgScope := Scope{Host: target.Host, Kind: OrganizationScope, Name: organization}
			settingsOutcome, settingsErr := client.CollectGET(ctx, store, orgScope, "org.settings", "settings",
				"orgs/"+url.PathEscape(organization), "", false)
			report.Outcomes = append(report.Outcomes, settingsOutcome)
			if settingsErr != nil {
				report.Caveats = append(report.Caveats, fmt.Sprintf(
					"organization settings probe for %s was incomplete (%s); repository inventory collection proceeded regardless",
					orgScope.Key(), settingsOutcome.Availability))
			}

			population, eligible, populationOutcomes, err := BuildOrganizationPopulation(ctx, client, store, orgScope, organization, config, clock.Now())
			report.Outcomes = append(report.Outcomes, populationOutcomes...)
			if err != nil {
				return nil, fmt.Errorf("build repository population for %s: %w", orgScope.Key(), err)
			}

			orgResult := OrganizationRunResult{Scope: orgScope, Population: population, Repositories: []RepositoryRunResult{}}
			for _, repo := range eligible {
				fullName := repo.GetFullName()
				owner, name := splitOwnerRepo(fullName)
				repoScope := Scope{Host: target.Host, Kind: RepositoryScope, Name: fullName}
				repoResult := analyzeOneRepository(ctx, client, store, orgScope, repoScope, organization, owner, name, repo, report, accumulator)
				orgResult.Repositories = append(orgResult.Repositories, repoResult)
			}
			report.Organizations = append(report.Organizations, orgResult)
		}
	}

	accumulator.populate(report.Metrics)
	report.Caveats = append(report.Caveats,
		"this run computes metrics and raw collection outcomes only; it does not produce full per-control "+
			"ControlResult records or IMPLEMENTED/PARTIAL/NOT_IMPLEMENTED decisions, which remain a later phase's responsibility",
		"the automation profile's shared \"eligible_repos_count\" metric key is overloaded across SEC-001 (dependency-scanning "+
			"eligibility) and SEC-004 (code-scanning eligibility); this run reports each feature's population under a distinct "+
			"key instead of writing that ambiguous shared key")

	if err := store.WriteReport("run.json", report); err != nil {
		return nil, err
	}
	if err := store.WriteReport("runs/run-"+clock.Now().Format("20060102T150405.000000000Z")+".json", report); err != nil {
		return nil, err
	}
	return report, nil
}

// analyzeOneRepository runs effective-rules, workflow and feature-eligibility
// analysis for one repository and folds its contribution into the run-wide
// metric accumulator.
func analyzeOneRepository(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope, repoScope Scope,
	organization, owner, name string, repo *github.Repository, report *VerticalSliceReport, accumulator *metricAccumulator) RepositoryRunResult {
	details, detailsOutcome, detailsErr := FetchRepositoryDetails(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, detailsOutcome)
	defaultBranch := repo.GetDefaultBranch()
	if detailsErr == nil && details != nil && details.GetDefaultBranch() != "" {
		defaultBranch = details.GetDefaultBranch()
	}
	result := RepositoryRunResult{
		FullName: repo.GetFullName(), DefaultBranch: defaultBranch,
		Feature: RepositoryFeatureSignal{FullName: repo.GetFullName()},
	}

	if defaultBranch != "" {
		effective, ruleOutcomes, ruleErr := ComputeEffectiveBranchProtection(ctx, client, store, orgScope, repoScope,
			organization, owner, name, defaultBranch)
		report.Outcomes = append(report.Outcomes, ruleOutcomes...)
		if ruleErr == nil && effective != nil {
			result.EffectiveProtection = effective
			accumulator.addEffectiveProtection(effective)
		}
	}

	workflows, workflowOutcomes, workflowErr := AnalyzeRepositoryWorkflows(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, workflowOutcomes...)
	if workflowErr == nil && workflows != nil {
		result.Workflows = workflows
		accumulator.addReferences(workflows.References)
		result.Feature.CodeQLOperational = workflows.CodeQLOperational
	}

	languages, languagesOutcome, _ := FetchRepositoryLanguages(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, languagesOutcome)
	result.Feature.CodeQLEligible = HasPositiveCodeQLSupportedLanguageBytes(languages)

	sbomAvailable, sbomOutcome, _ := ProbeDependencyGraphSBOM(ctx, client, store, repoScope, owner, name)
	report.Outcomes = append(report.Outcomes, sbomOutcome)
	result.Feature.DependencyEligible = sbomAvailable
	if sbomAvailable && detailsErr == nil && details != nil {
		if analysis := details.GetSecurityAndAnalysis(); analysis != nil {
			if updates := analysis.GetDependabotSecurityUpdates(); updates != nil {
				result.Feature.DependencyOperational = updates.GetStatus() == "enabled"
			}
		}
	}

	accumulator.addFeatureSignal(result.Feature)
	return result
}
