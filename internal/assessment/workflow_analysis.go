// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-github/v83/github"
	"gopkg.in/yaml.v3"
)

// exact40HexSHA matches a complete, nothing-but, 40-character hexadecimal commit
// SHA. A 39- or 41-character value, a tag, a branch or a value with trailing
// characters all fail this exact match and are treated as not pinned.
var exact40HexSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// dynamicRefExpression detects a GitHub Actions expression inside a ref, which
// cannot be statically resolved to a pin status.
var dynamicRefExpression = regexp.MustCompile(`\$\{\{.*\}\}`)

// ActionReference is one classified `uses:` reference from one workflow step or
// job-level reusable workflow call. Parsing only ever reads the YAML document;
// it never evaluates or executes workflow content.
type ActionReference struct {
	WorkflowPath string `json:"workflow_path"`
	JobID        string `json:"job_id"`
	StepIndex    int    `json:"step_index"`
	Raw          string `json:"raw"`
	Owner        string `json:"owner,omitempty"`
	ActionRepo   string `json:"action_repo,omitempty"`
	Ref          string `json:"ref,omitempty"`
	Category     string `json:"category"`
	PinStatus    string `json:"pin_status"`
}

// Reference categories.
const (
	categoryLocal       = "local"
	categoryDocker      = "docker"
	categoryGitHubOwned = "github-owned"
	categorySameOrg     = "same-org"
	categoryThirdParty  = "third-party"
)

// Reference pin statuses.
const (
	pinStatusSHAPinned     = "sha-pinned"
	pinStatusNotPinned     = "not-pinned"
	pinStatusDynamic       = "dynamic"
	pinStatusNotApplicable = "n-a"
)

// WorkflowAnalysisResult is one repository's workflow inventory and classified
// action references.
type WorkflowAnalysisResult struct {
	Repository          string            `json:"repository"`
	WorkflowCount       int               `json:"workflow_count"`
	ActiveWorkflowCount int               `json:"active_workflow_count"`
	References          []ActionReference `json:"references"`
	CodeQLOperational   bool              `json:"codeql_operational"`
	Notes               []string          `json:"notes"`
}

type workflowYAML struct {
	Jobs map[string]workflowJobYAML `yaml:"jobs"`
}

type workflowJobYAML struct {
	Uses  string             `yaml:"uses"`
	Steps []workflowStepYAML `yaml:"steps"`
}

type workflowStepYAML struct {
	Uses string `yaml:"uses"`
}

// AnalyzeRepositoryWorkflows lists a repository's registered workflows (reflecting
// their actual registered/enabled state, not merely file presence) and parses
// each workflow file's `uses:` references for step- and job-level action and
// reusable-workflow calls.
func AnalyzeRepositoryWorkflows(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (*WorkflowAnalysisResult, []CollectorOutcome, error) {
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)
	workflows, listOutcome, listErr := collectJSONArray[*github.Workflow](ctx, client, store, scope,
		"repo.workflows", "workflows", "repos/"+ownerPath+"/"+repoPath+"/actions/workflows", "workflows", true)
	outcomes := []CollectorOutcome{listOutcome}
	result := &WorkflowAnalysisResult{Repository: owner + "/" + repo, WorkflowCount: len(workflows), References: []ActionReference{}, Notes: []string{}}
	if listErr != nil {
		result.Notes = append(result.Notes, "the workflow listing was incomplete; action reference and CodeQL operational analysis may undercount")
	}
	paths := make([]string, 0, len(workflows))
	stateByPath := make(map[string]string, len(workflows))
	for _, workflow := range workflows {
		if workflow == nil || workflow.GetPath() == "" {
			continue
		}
		paths = append(paths, workflow.GetPath())
		stateByPath[workflow.GetPath()] = workflow.GetState()
		if workflow.GetState() == "active" {
			result.ActiveWorkflowCount++
		}
	}
	sort.Strings(paths)
	for _, path := range paths {
		content, contentOutcome, contentErr := collectJSONObject[github.RepositoryContent](ctx, client, store, scope,
			"repo.workflows", safeFeatureName("content", path), "repos/"+ownerPath+"/"+repoPath+"/contents/"+path)
		outcomes = append(outcomes, contentOutcome)
		if contentErr != nil || content == nil {
			result.Notes = append(result.Notes, fmt.Sprintf("workflow file %s could not be read (%s); its action references were not analyzed", path, contentOutcome.Availability))
			continue
		}
		text, err := content.GetContent()
		if err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("workflow file %s content could not be decoded; its action references were not analyzed", path))
			continue
		}
		var document workflowYAML
		if err := yaml.Unmarshal([]byte(text), &document); err != nil {
			result.Notes = append(result.Notes, fmt.Sprintf("workflow file %s is not parseable YAML; its action references were not analyzed", path))
			continue
		}
		active := stateByPath[path] == "active"
		jobIDs := make([]string, 0, len(document.Jobs))
		for jobID := range document.Jobs {
			jobIDs = append(jobIDs, jobID)
		}
		sort.Strings(jobIDs)
		for _, jobID := range jobIDs {
			job := document.Jobs[jobID]
			if strings.TrimSpace(job.Uses) != "" {
				reference := classifyActionReference(job.Uses, owner)
				reference.WorkflowPath, reference.JobID, reference.StepIndex = path, jobID, -1
				result.References = append(result.References, reference)
				if active && isCodeQLActionReference(reference) {
					result.CodeQLOperational = true
				}
			}
			for index, step := range job.Steps {
				if strings.TrimSpace(step.Uses) == "" {
					continue
				}
				reference := classifyActionReference(step.Uses, owner)
				reference.WorkflowPath, reference.JobID, reference.StepIndex = path, jobID, index
				result.References = append(result.References, reference)
				if active && isCodeQLActionReference(reference) {
					result.CodeQLOperational = true
				}
			}
		}
	}
	return result, outcomes, nil
}

// classifyActionReference categorizes one `uses:` value without resolving or
// contacting its target. Docker image references use a distinct sha256 digest
// scheme and are never mispresented as a pinned (or unpinned) GitHub commit SHA.
func classifyActionReference(raw, repositoryOwner string) ActionReference {
	reference := ActionReference{Raw: raw}
	trimmed := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(trimmed, "./"):
		reference.Category, reference.PinStatus = categoryLocal, pinStatusNotApplicable
		return reference
	case strings.HasPrefix(trimmed, "docker://"):
		reference.Category, reference.PinStatus = categoryDocker, pinStatusNotApplicable
		return reference
	}
	atIndex := strings.LastIndex(trimmed, "@")
	if atIndex < 0 {
		reference.Category, reference.PinStatus = classifyOwnerCategory(ownerOf(trimmed), repositoryOwner), pinStatusNotPinned
		reference.Owner, reference.ActionRepo = splitOwnerRepo(trimmed)
		return reference
	}
	path, ref := trimmed[:atIndex], trimmed[atIndex+1:]
	reference.Ref = ref
	reference.Owner, reference.ActionRepo = splitOwnerRepo(path)
	reference.Category = classifyOwnerCategory(reference.Owner, repositoryOwner)
	switch {
	case dynamicRefExpression.MatchString(ref) || strings.Contains(ref, "${{"):
		reference.PinStatus = pinStatusDynamic
	case exact40HexSHA.MatchString(ref):
		reference.PinStatus = pinStatusSHAPinned
	default:
		reference.PinStatus = pinStatusNotPinned
	}
	return reference
}

func ownerOf(path string) string {
	owner, _ := splitOwnerRepo(path)
	return owner
}

func splitOwnerRepo(path string) (owner, repo string) {
	segments := strings.SplitN(path, "/", 3)
	if len(segments) >= 2 {
		return segments[0], segments[1]
	}
	if len(segments) == 1 {
		return segments[0], ""
	}
	return "", ""
}

func classifyOwnerCategory(owner, repositoryOwner string) string {
	switch strings.ToLower(owner) {
	case "actions", "github":
		return categoryGitHubOwned
	}
	if owner != "" && repositoryOwner != "" && strings.EqualFold(owner, repositoryOwner) {
		return categorySameOrg
	}
	return categoryThirdParty
}

func isCodeQLActionReference(reference ActionReference) bool {
	return strings.EqualFold(reference.Owner, "github") && strings.HasPrefix(strings.ToLower(reference.ActionRepo), "codeql-action")
}

// ActionPinCoverage pools classified action references across analyzed
// repositories into the profile's github_owned_refs_sha_pinned_pct and
// third_party_refs_sha_pinned_pct metrics, plus raw counts for categories that
// do not have a percentage (local, Docker, same-organization and dynamic/unknown
// references).
type ActionPinCoverage struct {
	GitHubOwned     FeatureCoverage `json:"github_owned"`
	ThirdParty      FeatureCoverage `json:"third_party"`
	DockerRefCount  int             `json:"docker_ref_count"`
	DynamicRefCount int             `json:"dynamic_ref_count"`
	LocalRefCount   int             `json:"local_ref_count"`
	SameOrgRefCount int             `json:"same_org_ref_count"`
}

// AggregateActionPinCoverage pools per-reference classifications across every
// analyzed repository into org-wide pinning coverage. A zero third-party (or
// GitHub-owned) reference count reports as unavailable, never as a false 100%.
// A dynamic/unresolvable ref stays inside its category's applicable population
// (denominator) instead of being silently dropped from it: excluding it would
// shrink the denominator and could present a false, artificially "clean" 100%
// when the one remaining reference happens to be pinned. Any dynamic reference
// in a category instead marks that category's whole metric explicitly
// uncertain/unavailable, preserving the computed numerator and denominator for
// audit.
func AggregateActionPinCoverage(references []ActionReference) ActionPinCoverage {
	var githubNumerator, githubDenominator, githubUnknown int
	var thirdNumerator, thirdDenominator, thirdUnknown int
	var docker, dynamic, local, sameOrg int
	for _, reference := range references {
		switch reference.Category {
		case categoryLocal:
			local++
			continue
		case categoryDocker:
			docker++
			continue
		case categorySameOrg:
			sameOrg++
			continue
		}
		unresolved := reference.PinStatus == pinStatusDynamic
		if unresolved {
			dynamic++
		}
		switch reference.Category {
		case categoryGitHubOwned:
			githubDenominator++
			switch {
			case unresolved:
				githubUnknown++
			case reference.PinStatus == pinStatusSHAPinned:
				githubNumerator++
			}
		case categoryThirdParty:
			thirdDenominator++
			switch {
			case unresolved:
				thirdUnknown++
			case reference.PinStatus == pinStatusSHAPinned:
				thirdNumerator++
			}
		}
	}
	githubMetric, _ := Percentage(float64(githubNumerator), float64(githubDenominator),
		"actions-ecosystem references classified as GitHub-owned (actions/*, github/*)")
	if githubUnknown > 0 {
		githubMetric = markCoverageUncertain(githubMetric, fmt.Sprintf(
			"%d of %d applicable GitHub-owned references use a dynamic ref expression and could not be confirmed pinned or unpinned",
			githubUnknown, githubDenominator))
	}
	thirdMetric, _ := Percentage(float64(thirdNumerator), float64(thirdDenominator),
		"actions-ecosystem references excluding local, Docker, GitHub-owned and same-organization actions")
	if thirdUnknown > 0 {
		thirdMetric = markCoverageUncertain(thirdMetric, fmt.Sprintf(
			"%d of %d applicable third-party references use a dynamic ref expression and could not be confirmed pinned or unpinned",
			thirdUnknown, thirdDenominator))
	}
	return ActionPinCoverage{
		GitHubOwned:    FeatureCoverage{Feature: "github_owned_refs_sha_pinned_pct", Numerator: githubNumerator, Denominator: githubDenominator, Metric: githubMetric},
		ThirdParty:     FeatureCoverage{Feature: "third_party_refs_sha_pinned_pct", Numerator: thirdNumerator, Denominator: thirdDenominator, Metric: thirdMetric},
		DockerRefCount: docker, DynamicRefCount: dynamic, LocalRefCount: local, SameOrgRefCount: sameOrg,
	}
}
