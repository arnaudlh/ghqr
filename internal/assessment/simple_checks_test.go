// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v83/github"
)

func TestSimpleChecksTypedUnknownsAndEvidence(t *testing.T) {
	input := fixtureEvaluationInput(t, fixtureReport())
	control := Control{ID: "ARC-005", Automation: Full}
	zero, partial, implemented, text := 0.0, 60.0, 90.0, "90"
	for _, test := range []struct {
		name  string
		value MetricValue
		state State
	}{
		{"zero is observed", MetricValue{Status: MetricKnown, Number: &zero}, NotImplemented},
		{"partial boundary", MetricValue{Status: MetricKnown, Number: &partial}, PartiallyImplemented},
		{"implemented boundary", MetricValue{Status: MetricKnown, Number: &implemented}, Implemented},
		{"missing", MetricValue{}, NotAssessed},
		{"null payload", MetricValue{Status: MetricKnown}, NotAssessed},
		{"wrong payload type", MetricValue{Status: MetricKnown, Text: &text}, NotAssessed},
		{"unavailable", MetricValue{Status: MetricUnavailable, Reason: "permission denied"}, NotAssessed},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := newControlResult(control)
			test.value.EvidenceRefs = []string{"objects/synthetic.json"}
			result.EvidenceRefs = test.value.EvidenceRefs
			result.Metrics["repos_with_default_branch_protection_pct"] = Metric{
				Key: "repos_with_default_branch_protection_pct", Overall: test.value,
			}
			got := evaluateSimpleCheck(control, input, result, true)
			if got.ProposedState != test.state || len(got.EvidenceRefs) != 1 || got.RuleDefinitionSHA256 == "" {
				t.Fatalf("typed state/evidence/policy mismatch: %+v", got)
			}
		})
	}
}

func TestSimpleChecksRejectUnboundAndMutatedPolicies(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	loaded, err := LoadSimpleChecks(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	unbound := *loaded
	unbound.sourceJSON = nil
	if err := unbound.Validate(profile); err == nil {
		t.Fatal("a constructed policy without exact loaded source bytes was accepted")
	}
	for _, mutate := range []func(*SimpleChecks){
		func(c *SimpleChecks) { c.SHA256 = "invented" },
		func(c *SimpleChecks) { c.sourceJSON = append(c.sourceJSON, '\n') },
		func(c *SimpleChecks) { c.Checks[0].FieldPath = "/overall/text" },
	} {
		checks, err := LoadSimpleChecks(profile, "")
		if err != nil {
			t.Fatal(err)
		}
		mutate(checks)
		if err := checks.Validate(profile); err == nil {
			t.Fatal("mutated policy retained an authentic definition identity")
		}
	}
}

func TestSimpleChecksSelectedMetricOwnsEvidence(t *testing.T) {
	input := fixtureEvaluationInput(t, fixtureReport())
	var policy map[string]any
	if err := json.Unmarshal(defaultSimpleChecks, &policy); err != nil {
		t.Fatal(err)
	}
	checks := policy["checks"].([]any)
	governance := checks[1].(map[string]any)
	governance["metric_key"] = "active_org_rulesets_count"
	governance["implemented"] = map[string]any{"operator": "gte", "expected_values": []int{2}}
	governance["partial"] = map[string]any{"operator": "gte", "expected_values": []int{1}}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	input.Checks, err = ParseSimpleChecks(input.Profile, data)
	if err != nil {
		t.Fatal(err)
	}
	value := 3.0
	control := Control{ID: "GOV-001", Automation: Partial}
	result := newControlResult(control)
	result.EvidenceRefs = []string{"old-protection-source"}
	result.Metrics["active_org_rulesets_count"] = Metric{Key: "active_org_rulesets_count",
		Overall: MetricValue{Status: MetricKnown, Number: &value, EvidenceRefs: []string{"org-rules-source"}}}
	got := evaluateSimpleCheck(control, input, result, true)
	if got.ProposedState != Implemented || len(got.EvidenceRefs) != 1 ||
		got.EvidenceRefs[0] != "org-rules-source" || !got.RequiresConfirmation {
		t.Fatalf("selected metric/evidence/interview separation lost: %+v", got)
	}
}

func TestConfiguredExtractionChangesCollectedFactAndProposal(t *testing.T) {
	base := newVerticalSliceFixtureServer(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/fixture-org/repo-1":
			writeJSON(t, writer, map[string]any{"id": 1, "name": "repo-1", "full_name": "fixture-org/repo-1", "default_branch": "main",
				"security_and_analysis": map[string]any{
					"dependabot_security_updates": map[string]string{"status": "enabled"},
					"secret_scanning":             map[string]string{"status": "disabled"},
				}})
		case "/repos/fixture-org/repo-1/git/trees/main":
			writeJSON(t, writer, map[string]any{"truncated": false, "tree": []map[string]string{{"path": "package.json", "type": "blob"}}})
		default:
			base.Config.Handler.ServeHTTP(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	for _, custom := range []bool{false, true} {
		data := bytes.Clone(defaultSimpleChecks)
		if custom {
			data = bytes.Replace(data, []byte("/security_and_analysis/dependabot_security_updates/status"),
				[]byte("/security_and_analysis/secret_scanning/status"), 1)
		}
		client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
		checks, err := ParseSimpleChecks(client.profile, data)
		if err != nil {
			t.Fatal(err)
		}
		store := evidenceFixtureStore(t, t.TempDir(), nil)
		now := time.Now().UTC()
		report := fixtureReport()
		scope := Scope{Host: client.base.Hostname(), Kind: RepositoryScope, Name: "fixture-org/repo-1"}
		organization := Scope{Host: scope.Host, Kind: OrganizationScope, Name: "fixture-org"}
		name, branch := scope.Name, "main"
		repository := &github.Repository{FullName: &name, DefaultBranch: &branch}
		collected := analyzeOneRepository(context.Background(), client, client, store, organization, scope, "fixture-org",
			"fixture-org", "repo-1", repository, now.AddDate(0, 0, -90), now, false, false, nil, report, newMetricAccumulator(), checks)
		if !collected.Feature.DependencyEligible || !collected.Feature.DependencyOperationalKnown ||
			collected.Feature.DependencyOperational == custom {
			t.Fatalf("configured existing-source extraction did not change a present observed fact: custom=%v %+v", custom, collected.Feature)
		}
		input := fixtureEvaluationInput(t, fixtureReport(fixtureOrganization("fixture-org", nil, nil, collected)))
		result := evaluateSEC043(Control{ID: "SEC-043", Automation: Full}, input)
		expected := NotAssessed
		if custom {
			expected = NotImplemented
		}
		if result.ProposedState != expected {
			t.Fatalf("path change did not reach measured proposal: custom=%v %+v", custom, result)
		}
	}
}
func TestSimpleChecksOverrideRealEvaluation(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	report := fixtureReport(fixtureOrganization("acme", nil, nil,
		fixtureRepoResult("acme/protected", fixtureEffectiveProtection(true, false, false, CollectionOK), nil, nil, RepositoryFeatureSignal{})))
	override := bytes.ReplaceAll(defaultSimpleChecks, []byte(`"/overall/number"`), []byte(`"/overall/boolean"`))
	checks, err := ParseSimpleChecks(profile, override)
	if err != nil {
		t.Fatal(err)
	}
	config.CheckDefinitions = checks
	results, err := EvaluateReport(profile, report, config)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.ControlID != "ARC-005" && result.ControlID != "GOV-001" {
			continue
		}
		if result.ProposedState != NotAssessed || result.RuleDefinitionSHA256 != checks.SHA256 {
			t.Fatalf("custom path was not used by the real evaluation: %+v", result)
		}
		if result.ControlID == "GOV-001" && !result.RequiresConfirmation {
			t.Fatal("JSON mapping removed the separate interview requirement")
		}
	}
}

func TestSimpleChecksRejectUnsafeOrExpandedMappings(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	for _, replacement := range [][2]string{
		{`"ARC-005"`, `"ARC-006"`},
		{`"/overall/number"`, `"/per_organization/github.com/organization/acme/number"`},
		{`"gte"`, `"execute"`},
		{`"expected_values": [90]`, `"expected_values": [null]`},
		{`"type": "number"`, `"type": "script"`},
		{`"profile_version": "2.0"`, `"profile_version": "3.0"`},
	} {
		data := strings.ReplaceAll(string(defaultSimpleChecks), replacement[0], replacement[1])
		if _, err := ParseSimpleChecks(profile, []byte(data)); err == nil {
			t.Fatalf("accepted unsafe mapping %s", replacement[1])
		}
	}
	if _, err := ParseSimpleChecks(profile, append(bytes.Clone(defaultSimpleChecks), []byte("{}")...)); err == nil {
		t.Fatal("accepted multiple JSON documents")
	}
	for _, data := range []string{`{"overall":{}}`, `{"overall":{"number":null}}`} {
		if _, err := simpleField([]byte(data), "/overall/number"); err == nil {
			t.Fatal("missing/null extraction was accepted")
		}
	}
	checks, err := LoadSimpleChecks(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		`{}`,
		`{"security_and_analysis":{"dependabot_security_updates":{"status":null}}}`,
		`{"security_and_analysis":{"dependabot_security_updates":{"status":false}}}`,
		`{"security_and_analysis":{"dependabot_security_updates":{"status":"unexpected"}}}`,
	} {
		if value, err := extractRepositoryConfiguration([]byte(data), checks); err == nil || value != nil {
			t.Fatal("missing/null/wrong-type/unrecognized configuration became known disabled")
		}
	}
}
