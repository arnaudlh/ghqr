// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyActionReferencePinStatuses(t *testing.T) {
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	sha39 := sha40[:39]
	sha41 := sha40 + "a"
	trailing := sha40 + "abc"
	tests := []struct {
		name         string
		raw          string
		owner        string
		wantCategory string
		wantPin      string
	}{
		{"github-owned exact 40-hex SHA is pinned", "actions/checkout@" + sha40, "fixture-org", categoryGitHubOwned, pinStatusSHAPinned},
		{"github org (not actions) is also github-owned", "github/codeql-action/analyze@" + sha40, "fixture-org", categoryGitHubOwned, pinStatusSHAPinned},
		{"39-hex ref is not pinned", "some-vendor/action@" + sha39, "fixture-org", categoryThirdParty, pinStatusNotPinned},
		{"41-hex ref is not pinned", "some-vendor/action@" + sha41, "fixture-org", categoryThirdParty, pinStatusNotPinned},
		{"trailing characters after an exact SHA is not pinned", "some-vendor/action@" + trailing, "fixture-org", categoryThirdParty, pinStatusNotPinned},
		{"a tag is not pinned", "some-vendor/action@v4", "fixture-org", categoryThirdParty, pinStatusNotPinned},
		{"a dynamic expression ref is unknown, not pinned or unpinned", "other-org/dynamic-action@${{ env.PIN }}", "fixture-org", categoryThirdParty, pinStatusDynamic},
		{"a local action reference is excluded from pin metrics", "./.github/actions/local-action", "fixture-org", categoryLocal, pinStatusNotApplicable},
		{"a Docker reference uses a distinct digest scheme", "docker://alpine@sha256:deadbeef", "fixture-org", categoryDocker, pinStatusNotApplicable},
		{"a same-organization action is not third-party", "fixture-org/shared-action@" + sha40, "fixture-org", categorySameOrg, pinStatusSHAPinned},
		{"an unversioned reference without @ref is not pinned", "actions/checkout", "fixture-org", categoryGitHubOwned, pinStatusNotPinned},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reference := classifyActionReference(tt.raw, tt.owner)
			if reference.Category != tt.wantCategory || reference.PinStatus != tt.wantPin {
				t.Fatalf("classifyActionReference(%q) = {%s %s}, want {%s %s}", tt.raw, reference.Category, reference.PinStatus, tt.wantCategory, tt.wantPin)
			}
		})
	}
}

func TestAggregateActionPinCoverageZeroDenominatorIsNotAFalse100Percent(t *testing.T) {
	coverage := AggregateActionPinCoverage(nil)
	if coverage.ThirdParty.Metric.Status != MetricUnavailable || coverage.ThirdParty.Metric.Number != nil {
		t.Fatalf("zero third-party references produced a numeric (possibly 100%%) result instead of unavailable: %+v", coverage.ThirdParty.Metric)
	}
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	references := []ActionReference{
		classifyActionReference("some-vendor/action@"+sha40, "fixture-org"),
		classifyActionReference("other-vendor/action@v4", "fixture-org"),
	}
	coverage = AggregateActionPinCoverage(references)
	if coverage.ThirdParty.Numerator != 1 || coverage.ThirdParty.Denominator != 2 || coverage.ThirdParty.Metric.Status != MetricKnown {
		t.Fatalf("third-party pin coverage miscomputed: %+v", coverage.ThirdParty)
	}
}

// TestAggregateActionPinCoverageDynamicRefNeverProducesAFalseCleanPercent is a
// regression test: excluding a dynamic/unresolvable reference from its
// category's denominator previously let one pinned reference alongside one
// dynamic reference report a false, artificially clean 100% third-party (or
// GitHub-owned) coverage. The dynamic reference must stay in the applicable
// population (denominator) and the whole category's metric must become
// explicitly unavailable/uncertain, never a clean known percentage.
func TestAggregateActionPinCoverageDynamicRefNeverProducesAFalseCleanPercent(t *testing.T) {
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	references := []ActionReference{
		classifyActionReference("some-vendor/action@"+sha40, "fixture-org"),
		classifyActionReference("other-vendor/dynamic-action@${{ env.PIN }}", "fixture-org"),
	}
	coverage := AggregateActionPinCoverage(references)
	if coverage.ThirdParty.Denominator != 2 {
		t.Fatalf("dynamic reference was dropped from the applicable third-party denominator: %+v", coverage.ThirdParty)
	}
	if coverage.ThirdParty.Numerator != 1 {
		t.Fatalf("known-pinned count was lost: %+v", coverage.ThirdParty)
	}
	if coverage.ThirdParty.Metric.Status == MetricKnown {
		t.Fatalf("one pinned + one dynamic reference falsely reported a clean known percentage (would be a false 100%%): %+v", coverage.ThirdParty.Metric)
	}
	if coverage.ThirdParty.Metric.Status != MetricUnavailable || coverage.ThirdParty.Metric.Number != nil || coverage.ThirdParty.Metric.Reason == "" {
		t.Fatalf("uncertain coverage must be unavailable with a reason and no numeric value: %+v", coverage.ThirdParty.Metric)
	}
	if coverage.ThirdParty.Metric.Numerator == nil || *coverage.ThirdParty.Metric.Numerator != 1 ||
		coverage.ThirdParty.Metric.Denominator == nil || *coverage.ThirdParty.Metric.Denominator != 2 {
		t.Fatalf("the known numerator/denominator must be preserved for audit even when marked uncertain: %+v", coverage.ThirdParty.Metric)
	}

	// The same reference set as GitHub-owned must behave identically.
	githubReferences := []ActionReference{
		classifyActionReference("actions/checkout@"+sha40, "fixture-org"),
		classifyActionReference("github/dynamic-action@${{ env.PIN }}", "fixture-org"),
	}
	githubCoverage := AggregateActionPinCoverage(githubReferences)
	if githubCoverage.GitHubOwned.Denominator != 2 || githubCoverage.GitHubOwned.Metric.Status != MetricUnavailable {
		t.Fatalf("GitHub-owned dynamic-ref uncertainty was not preserved: %+v", githubCoverage.GitHubOwned)
	}
}

func base64YAML(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

func TestAnalyzeRepositoryWorkflowsParsesYAMLAndRequiresAnActiveWorkflowForCodeQL(t *testing.T) {
	sha40 := "2f3b4a2d3b1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
	ciYAML := `
name: CI
on: [push]
jobs:
  build:
    steps:
      - uses: actions/checkout@` + sha40 + `
      - uses: some-vendor/action@v4
      - uses: ./.github/actions/local-action
      - uses: docker://alpine@sha256:deadbeef
      - uses: fixture-org/shared-action@main
      - uses: other-org/dynamic-action@${{ env.PIN }}
  reuse:
    uses: fixture-org/.github/.github/workflows/shared.yml@` + sha40 + `
`
	codeQLYAML := `
name: CodeQL
on: [push]
jobs:
  analyze:
    steps:
      - uses: actions/checkout@` + sha40 + `
      - uses: github/codeql-action/analyze@` + sha40 + `
`
	disabledYAML := `
name: Disabled CodeQL
on: [push]
jobs:
  analyze:
    steps:
      - uses: github/codeql-action/analyze@` + sha40 + `
`
	workflows := []map[string]any{
		{"id": 1, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
		{"id": 2, "name": "CodeQL", "path": ".github/workflows/codeql.yml", "state": "active"},
		{"id": 3, "name": "Disabled CodeQL", "path": ".github/workflows/disabled.yml", "state": "disabled_manually"},
	}
	contents := map[string]string{
		".github/workflows/ci.yml":       ciYAML,
		".github/workflows/codeql.yml":   codeQLYAML,
		".github/workflows/disabled.yml": disabledYAML,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/widget/actions/workflows":
			writeJSON(t, writer, map[string]any{"total_count": len(workflows), "workflows": workflows})
		default:
			for path, text := range contents {
				if request.URL.Path == "/repos/fixture-org/widget/contents/"+path {
					writeJSON(t, writer, map[string]any{
						"type": "file", "encoding": "base64", "path": path, "name": path, "content": base64YAML(text),
					})
					return
				}
			}
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), RepositoryScope, "fixture-org/widget"}

	result, outcomes, err := AnalyzeRepositoryWorkflows(context.Background(), client, store, scope, "fixture-org", "widget")
	if err != nil {
		t.Fatal(err)
	}
	if len(outcomes) == 0 {
		t.Fatal("workflow analysis recorded no collector outcomes")
	}
	if result.WorkflowCount != 3 || result.ActiveWorkflowCount != 2 {
		t.Fatalf("workflow counts incorrect: %+v", result)
	}
	if !result.CodeQLOperational {
		t.Fatal("CodeQL operational signal was not detected from the active workflow")
	}

	byRaw := map[string]ActionReference{}
	for _, reference := range result.References {
		byRaw[reference.WorkflowPath+"|"+reference.Raw] = reference
	}
	checkoutRef, ok := byRaw[".github/workflows/ci.yml|actions/checkout@"+sha40]
	if !ok || checkoutRef.Category != categoryGitHubOwned || checkoutRef.PinStatus != pinStatusSHAPinned {
		t.Fatalf("github-owned pinned reference misclassified: %+v", checkoutRef)
	}
	thirdPartyRef, ok := byRaw[".github/workflows/ci.yml|some-vendor/action@v4"]
	if !ok || thirdPartyRef.Category != categoryThirdParty || thirdPartyRef.PinStatus != pinStatusNotPinned {
		t.Fatalf("third-party unpinned reference misclassified: %+v", thirdPartyRef)
	}
	localRef, ok := byRaw[".github/workflows/ci.yml|./.github/actions/local-action"]
	if !ok || localRef.Category != categoryLocal {
		t.Fatalf("local reference misclassified: %+v", localRef)
	}
	dockerRef, ok := byRaw[".github/workflows/ci.yml|docker://alpine@sha256:deadbeef"]
	if !ok || dockerRef.Category != categoryDocker || dockerRef.PinStatus == pinStatusSHAPinned {
		t.Fatalf("Docker digest reference was mispresented as GitHub SHA pin support: %+v", dockerRef)
	}
	sameOrgRef, ok := byRaw[".github/workflows/ci.yml|fixture-org/shared-action@main"]
	if !ok || sameOrgRef.Category != categorySameOrg {
		t.Fatalf("same-organization reference misclassified: %+v", sameOrgRef)
	}
	dynamicRef, ok := byRaw[".github/workflows/ci.yml|other-org/dynamic-action@${{ env.PIN }}"]
	if !ok || dynamicRef.PinStatus != pinStatusDynamic {
		t.Fatalf("dynamic expression reference was not classified as unknown: %+v", dynamicRef)
	}
	reusableRef, ok := byRaw[".github/workflows/ci.yml|fixture-org/.github/.github/workflows/shared.yml@"+sha40]
	if !ok || reusableRef.StepIndex != -1 {
		t.Fatalf("job-level reusable workflow call was not recorded: %+v", reusableRef)
	}
	disabledCodeQLRef, ok := byRaw[".github/workflows/disabled.yml|github/codeql-action/analyze@"+sha40]
	if !ok {
		t.Fatal("disabled workflow's references were not analyzed at all")
	}
	_ = disabledCodeQLRef

	codeQLCoverage, _ := AggregateFeatureCoverage([]RepositoryFeatureSignal{{
		FullName: "fixture-org/widget", CodeQLEligible: true, CodeQLOperational: result.CodeQLOperational,
	}})
	if codeQLCoverage.Numerator != 1 || codeQLCoverage.Denominator != 1 {
		t.Fatalf("CodeQL coverage did not fold the disabled workflow out of the operational signal: %+v", codeQLCoverage)
	}
}
