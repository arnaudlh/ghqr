// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunCollectionContextCapturesGenuineNondefaultConfiguration proves
// WriteRunCollectionContext captures the ACTUAL, nondefault configuration a
// live run was genuinely authorized against -- not ParseConfig's own
// documented defaults a replay-time inference might otherwise invent --
// and that ReplayVerticalSlice binds to exactly those captured values
// (repository_cap, lookback, critical property/values, production-env
// regex all set to values that differ from every default replayConfig/
// legacyReplayConfig would otherwise use).
func TestRunCollectionContextCapturesGenuineNondefaultConfiguration(t *testing.T) {
	server := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte(
		"organizations: [fixture-org]\n" +
			"repository_cap: 2\n" +
			"lookback_days: 30\n" +
			"critical_property: tier\n" +
			"critical_values: [sev1, sev0]\n" +
			"production_env_regex: \"^prod$\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if *config.CriticalProperty != "tier" || config.LookbackDays != 30 || config.RepositoryCap != 2 {
		t.Fatalf("test fixture assumption broken: nondefault config values were not parsed as expected: %+v", config)
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	readBack, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	runContext, err := LoadRunCollectionContextByRef(readBack, ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := readBack.Close(); err != nil {
		t.Fatal(err)
	}
	if runContext.RepositoryCap != 2 || runContext.LookbackDays != 30 || runContext.CriticalProperty != "tier" ||
		runContext.ProductionEnvRegex != "^prod$" || len(runContext.CriticalValues) != 2 ||
		runContext.CriticalValues[0] != "sev1" || runContext.CriticalValues[1] != "sev0" {
		t.Fatalf("the persisted context must capture the exact, genuine nondefault configuration this run actually "+
			"used, not ParseConfig's own defaults: %+v", runContext)
	}

	profile := fixtureProfileWithDefault(t)
	replayed, contextBound, err := ReplayVerticalSlice(context.Background(), profile, report, evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !contextBound {
		t.Fatal("a bundle with a written RunCollectionContext must report contextBound=true")
	}
	if mismatches := compareVerticalSliceReports(report, replayed); len(mismatches) != 0 {
		t.Fatalf("replay bound to the genuine nondefault configuration must reconstruct the same claim cleanly: %v", mismatches)
	}
}

// TestReplayRejectsReportCitingWrongLegitimateContextRef proves content
// addressing closes the direct-JSON-edit tamper vector (any edit to a
// content-addressed context object invalidates its own embedded digest,
// and LoadRunCollectionContextByRef additionally confirms the loaded
// content's own digest equals the exact ref requested, so a same-path edit
// can no longer simply swap in an altered-but-self-consistent claim) while
// still proving a genuinely DIFFERENT, independently legitimate context
// cannot be substituted either: a report whose ContextRef is tampered to
// point at a second, perfectly real, self-consistent context -- genuinely
// written by WriteRunCollectionContext for a DIFFERENT organization, never
// altered byte-for-byte -- must still be rejected, because
// contextAuthorizesScope finds the cited context's own authorized scope
// does not cover what the report itself actually claims.
func TestReplayRejectsReportCitingWrongLegitimateContextRef(t *testing.T) {
	server := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	genuineRef, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = genuineRef

	// A second, independently genuine context: same mechanism, same store,
	// a later CollectedAt, claiming a DIFFERENT organization this run never
	// touched. Never edited after writing -- it is exactly as legitimate,
	// self-consistent, and correctly digested as the first.
	differentOrganizationTarget := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"an-organization-never-genuinely-collected"}}
	wrongRef, err := WriteRunCollectionContext(store, client.profile, config, []Target{differentOrganizationTarget}, report.CollectedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if wrongRef == genuineRef {
		t.Fatal("test fixture assumption broken: two contexts claiming different organizations must hash to different, independently addressable refs")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a forged/misattributed report: its ContextRef now cites the
	// second context instead of the one genuinely produced alongside it.
	// Both refs independently resolve (proving multi-run/multi-context
	// storage genuinely works), but the cited context does not authorize
	// this report's own claimed organization.
	tamperedReport := *report
	tamperedReport.ContextRef = wrongRef

	profile := fixtureProfileWithDefault(t)
	replayed, contextBound, err := ReplayVerticalSlice(context.Background(), profile, &tamperedReport, evidenceDirectory)
	if !contextBound {
		t.Fatal("a report citing an existing, resolvable context ref must still report contextBound=true")
	}
	if err != nil {
		if !strings.Contains(err.Error(), "not authorized") {
			t.Fatalf("replay must reject a report whose cited context does not authorize its own claimed organization: %v", err)
		}
		return
	}
	mismatches := compareVerticalSliceReports(&tamperedReport, replayed)
	if len(mismatches) == 0 {
		t.Fatal("a report's genuine organization claim must be caught as a mismatch when replay is bound (via a tampered ContextRef) to a " +
			"different, independently legitimate context that never authorized that organization")
	}
}

// TestVerifyReportEvidenceLegacyBundleWithoutContextIsExplicitlyLimited
// proves a legacy evidence directory (collected before RunCollectionContext
// existed, or produced by any tool that never wrote one) never earns a
// blanket AnalysisVerified=true merely because its best-effort, inferred-
// settings replay comparison happens to come out clean: ContextBound must
// be false, AnalysisVerified must be false with an explicit disclosed
// compatibility-limitation reason, and therefore Verified must be false
// overall, even though IntegrityVerified (every cited page genuinely
// resolves) and the underlying legacy-path comparison can both still
// legitimately be clean. A genuine (non-replay) collection is used -- not a
// hand-built report naming an organization with no real org.repos evidence
// at all -- specifically so the legacy fallback path can actually succeed
// structurally and this test observes the DISCLOSED compatibility message,
// not an unrelated hard replay failure.
func TestVerifyReportEvidenceLegacyBundleWithoutContextIsExplicitlyLimited(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config, err := ParseConfig([]byte("organizations: [fixture-org]\nrepository_cap: 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately never call WriteRunCollectionContext: this directory
	// simulates a legacy bundle collected before that mechanism existed,
	// even though the underlying evidence is otherwise completely genuine.
	if _, err := LoadRunCollectionContext(store); err == nil {
		t.Fatal("test fixture assumption broken: this directory must genuinely have no context file")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	result, err := VerifyReportEvidence(profile, report, evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if result.ContextBound {
		t.Fatalf("a legacy bundle with no written context must report ContextBound=false: %+v", result)
	}
	if !result.IntegrityVerified {
		t.Fatalf("test fixture assumption broken: this genuine evidence's integrity should still verify cleanly: %+v", result)
	}
	if result.AnalysisVerified {
		t.Fatalf("a legacy bundle must never earn a blanket AnalysisVerified=true, even when its underlying "+
			"legacy-path comparison happens to come out clean: %+v", result)
	}
	if result.Verified {
		t.Fatalf("a legacy bundle's overall Verified must be false, regardless of IntegrityVerified: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Failures, " "), "no bound run collection context") {
		t.Fatalf("the compatibility limitation must be explicitly disclosed, not silently applied: %v", result.Failures)
	}
}

// TestRunCollectionContextRoundTripsSCIMModeAndCredentialKind guards the
// two pieces of non-secret target-level provenance that previously had no
// bound source at all: SCIMMode (emu/saml_sso/ghes -- genuinely omitted
// before this round, since no CollectorOutcome field records which SCIM
// routing mode produced a given outcome) and CredentialKind. Both must
// round-trip through WriteRunCollectionContext/LoadRunCollectionContext and
// rebuild via targetsFromContext exactly as configured, for each of the
// three legitimate SCIM routing configurations (Cloud "emu", Cloud
// "saml_sso" organization-only, and Server "ghes").
func TestRunCollectionContextRoundTripsSCIMModeAndCredentialKind(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	cases := []struct {
		name   string
		target Target
	}{
		{"cloud emu", Target{
			Host: "github.com", Deployment: Cloud, Enterprise: "fixture-enterprise",
			Credentials: CredentialReferences{Kind: ClassicPAT}, SCIMMode: "emu",
		}},
		{"cloud saml_sso organization-only", Target{
			Host: "github.com", Deployment: Cloud, Organizations: []string{"fixture-org"},
			Credentials: CredentialReferences{Kind: ClassicPAT}, SCIMMode: "saml_sso",
		}},
		{"server ghes", Target{
			Host: "ghes.example.internal", Deployment: Server, Organizations: []string{"fixture-org"},
			Credentials: CredentialReferences{Kind: ClassicPAT}, SCIMMode: "ghes",
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			evidenceDirectory := t.TempDir()
			store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
			if err != nil {
				t.Fatal(err)
			}
			config := &CustomerConfig{
				Targets: []Target{testCase.target}, RepositoryCap: 300, LookbackDays: 90,
				ProductionEnvRegex: "prod|production|live|release", EvidenceDir: "./evidence",
			}
			if _, err := WriteRunCollectionContext(store, profile, config, []Target{testCase.target}, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			readBack, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
			if err != nil {
				t.Fatal(err)
			}
			runContext, err := LoadRunCollectionContext(readBack)
			if err != nil {
				t.Fatal(err)
			}
			if err := readBack.Close(); err != nil {
				t.Fatal(err)
			}
			if len(runContext.Targets) != 1 {
				t.Fatalf("expected exactly one persisted target: %+v", runContext.Targets)
			}
			rebuilt := targetsFromContext(runContext)
			if len(rebuilt) != 1 {
				t.Fatalf("expected exactly one rebuilt target: %+v", rebuilt)
			}
			if rebuilt[0].SCIMMode != testCase.target.SCIMMode {
				t.Fatalf("SCIMMode must round-trip exactly: persisted %q, want %q", rebuilt[0].SCIMMode, testCase.target.SCIMMode)
			}
			if rebuilt[0].Credentials.Kind != testCase.target.Credentials.Kind {
				t.Fatalf("CredentialKind must round-trip exactly: persisted %q, want %q",
					rebuilt[0].Credentials.Kind, testCase.target.Credentials.Kind)
			}
			if rebuilt[0].Enterprise != testCase.target.Enterprise {
				t.Fatalf("Enterprise must round-trip exactly: persisted %q, want %q", rebuilt[0].Enterprise, testCase.target.Enterprise)
			}
		})
	}
}

// TestFullPipelineReplaysGenuineEMUSCIMThroughBoundContext proves SCIMMode
// genuinely flows end to end: a real (non-replay) collection run configured
// with SCIMMode "emu" and a real ClassicPAT-gated SCIM collector call
// (FetchEnterpriseSCIMUsers), replayed afterward through a bound
// RunCollectionContext that carries that same SCIMMode/CredentialKind/
// Enterprise -- not inferred, not omitted -- reconstructs the identical
// EnterpriseSCIMUsers result, with zero mismatches. GHES mode is used
// (Deployment: Server) rather than EMU/saml_sso (Deployment: Cloud) because
// validateTarget's data-residency rule requires a Cloud target's host to be
// "github.com" or a ".ghe.com" subdomain, which a local httptest server's
// address can never genuinely be; Cloud "saml_sso" organization-only
// provenance round-tripping is covered directly by
// TestRunCollectionContextRoundTripsSCIMModeAndCredentialKind instead,
// without needing a live Cloud-hostname-compliant fixture server.
func TestFullPipelineReplaysGenuineGHESSCIMThroughBoundContext(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/scim/v2/Users":
			writeJSON(t, writer, scimUsersPageResponse(2, 1, 1, 1))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := scimFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	evidenceDirectory := t.TempDir()
	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{
		Host: client.base.Hostname(), Deployment: Server,
		Credentials: CredentialReferences{Kind: ClassicPAT}, SCIMMode: "ghes",
	}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 300, LookbackDays: 90,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: "./evidence",
	}
	report, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Targets) != 1 || report.Targets[0].EnterpriseSCIMUsers == nil ||
		report.Targets[0].EnterpriseSCIMUsers.ResourcesReturnedCount != 2 {
		t.Fatalf("test fixture assumption broken: expected a genuine 2-resource GHES SCIM result: %+v", report.Targets)
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	profile := fixtureProfileWithDefault(t)
	replayed, contextBound, err := ReplayVerticalSlice(context.Background(), profile, report, evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !contextBound {
		t.Fatal("a bundle with a written RunCollectionContext must report contextBound=true")
	}
	if len(replayed.Targets) != 1 || replayed.Targets[0].EnterpriseSCIMUsers == nil ||
		replayed.Targets[0].EnterpriseSCIMUsers.ResourcesReturnedCount != 2 {
		t.Fatalf("replay bound to the genuine SCIMMode/Enterprise/CredentialKind context must reconstruct the same "+
			"GHES SCIM result, not report it unreachable: %+v", replayed.Targets)
	}
	if mismatches := compareVerticalSliceReports(report, replayed); len(mismatches) != 0 {
		t.Fatalf("a genuine GHES SCIM claim bound to its real context must replay cleanly: %v", mismatches)
	}
}

// TestRunCollectionContextValidShapeTamperMustBeRejected proves the
// content-addressed self-digest closes the direct-JSON-edit tamper vector:
// a valid-shape, schema-correct edit (changing lookback_days to a different
// plausible integer) applied directly to the "latest convenience copy" at
// runCollectionContextPath must invalidate LoadRunCollectionContext's own
// digest recomputation, even though the edited bytes still parse and carry
// the correct schema/engine version -- the earlier (pre-digest)
// implementation only checked JSON-parse-ability and schema version, so it
// silently accepted this exact edit.
func TestRunCollectionContextValidShapeTamperMustBeRejected(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	profile := fixtureProfileWithDefault(t)
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	if _, err := WriteRunCollectionContext(store, profile, config, targets, at); err != nil {
		t.Fatal(err)
	}
	raw, err := store.root.ReadFile(runCollectionContextPath)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["lookback_days"] = float64(config.LookbackDays + 1)
	altered, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.root.WriteFile(runCollectionContextPath, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadRunCollectionContext(store); err == nil {
		t.Fatalf("valid-shape context edits must not retain immutable provenance: %+v", loaded)
	}
}

// TestRunCollectionContextMultipleRunsRetainIndependentContexts proves a
// SECOND genuine run into the SAME evidence directory never fails merely
// because an OLDER run's context already lives there: both the fixed
// "latest convenience copy" write and each run's own content-addressed
// object write must succeed independently, with distinct refs, every time.
func TestRunCollectionContextMultipleRunsRetainIndependentContexts(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	profile := fixtureProfileWithDefault(t)
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	firstRef, err := WriteRunCollectionContext(store, profile, config, targets, at)
	if err != nil {
		t.Fatal(err)
	}
	secondRef, err := WriteRunCollectionContext(store, profile, config, targets, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("a fresh run must not fail merely because this evidence directory retains an older run context: %v", err)
	}
	if firstRef == secondRef {
		t.Fatal("two genuinely different runs (different CollectedAt) must hash to different, independently addressable refs")
	}
	if _, err := LoadRunCollectionContextByRef(store, firstRef); err != nil {
		t.Fatalf("the FIRST run's context must remain independently loadable by its own ref after a second run: %v", err)
	}
	if _, err := LoadRunCollectionContextByRef(store, secondRef); err != nil {
		t.Fatalf("the SECOND run's context must be loadable by its own ref: %v", err)
	}
	latest, err := LoadRunCollectionContext(store)
	if err != nil {
		t.Fatal(err)
	}
	if !latest.CollectedAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("the 'latest convenience copy' must reflect the most recently written run: got CollectedAt %v, want %v",
			latest.CollectedAt, at.Add(time.Hour))
	}
}

// newTwoWaveInventoryServer serves a single organization whose repository
// inventory genuinely changes between two waves: wave 1 ("50%") returns only
// repo-001; wave 2 ("100%"), switched via the returned setWave func, adds
// repo-002 to the SAME org.repos response. Every other endpoint both
// repositories need (rules/rulesets/protection/workflows/languages/
// dependency-graph/code-scanning) is served identically and unconditionally
// for both repositories regardless of wave, so the ONLY genuine difference
// between a wave-1 and a wave-2 collection is the organization's own
// repository inventory -- and, downstream, every count/membership/metric
// that inventory feeds.
func newTwoWaveInventoryServer(t *testing.T) (server *httptest.Server, setWave func(int)) {
	t.Helper()
	var wave atomic.Int32
	wave.Store(1)
	repos := []map[string]any{
		fixtureRepository(1, false, false, 5, "public", "Go"),
		fixtureRepository(2, false, false, 5, "public", "Go"),
	}
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		switch {
		case path == "/orgs/fixture-org":
			writeJSON(t, writer, map[string]any{"login": "fixture-org", "two_factor_requirement_enabled": true})
		case path == "/orgs/fixture-org/repos":
			if wave.Load() >= 2 {
				writeJSON(t, writer, repos)
			} else {
				writeJSON(t, writer, repos[:1])
			}
		case path == "/orgs/fixture-org/properties/schema":
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/rules/branches/main"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/rulesets"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/branches/main/protection"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "Branch not protected"})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/actions/workflows"):
			writeJSON(t, writer, map[string]any{"total_count": 0, "workflows": []map[string]any{}})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/languages"):
			writeJSON(t, writer, map[string]any{"Go": 12345})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/dependency-graph/sbom"):
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "dependency graph is not enabled"})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/code-scanning/default-setup"):
			writeJSON(t, writer, map[string]any{"state": "not-configured"})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.HasSuffix(path, "/code-scanning/analyses"):
			writeJSON(t, writer, []map[string]any{})
		case strings.HasPrefix(path, "/repos/fixture-org/repo-") && strings.Count(path, "/") == 3:
			name := strings.TrimPrefix(path, "/repos/fixture-org/")
			for _, repo := range repos {
				if repo["name"] == name {
					writeJSON(t, writer, repo)
					return
				}
			}
			writer.WriteHeader(http.StatusNotFound)
		default:
			writer.WriteHeader(http.StatusNotFound)
			writeJSON(t, writer, map[string]string{"message": "not found"})
		}
	}))
	t.Cleanup(server.Close)
	return server, func(w int) { wave.Store(int32(w)) }
}

// TestFullPipelineReplayPreservesIndependentHistoryAcrossMovedLogicalRefs is
// the "exact historical reconstruction" acceptance fixture: two genuinely
// separate collection runs into the SAME evidence directory, against the
// SAME organization, where the SECOND run's own org.repos page (wave 2: two
// repositories) genuinely overwrites the FIRST run's org.repos page (wave 1:
// one repository) at the exact same logical (scope, collectorID, feature)
// manifest key -- the real "later logical ref moves" scenario, not a
// simulated one. Each run's own report keeps its own ContextRef, and each
// one's own cited EvidenceRefs remain independently resolvable afterward
// (proving multi-run/multi-context storage genuinely works, not merely
// that writing twice no longer errors). Replaying the FIRST report must
// still reconstruct exactly one repository (never silently inheriting the
// second run's two-repository inventory merely because that is what the
// evidence directory's manifest now points to); replaying the SECOND report
// must reconstruct exactly two. Both replays must compare clean against
// their own report, never against each other's.
func TestFullPipelineReplayPreservesIndependentHistoryAcrossMovedLogicalRefs(t *testing.T) {
	server, setWave := newTwoWaveInventoryServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: "./evidence",
	}

	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	firstReport, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	firstRef, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, firstReport.CollectedAt, firstReport.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	firstReport.ContextRef = firstRef
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if len(firstReport.Organizations) != 1 || len(firstReport.Organizations[0].Repositories) != 1 {
		t.Fatalf("test fixture assumption broken: wave 1 must collect exactly one repository: %+v", firstReport.Organizations)
	}

	// Second genuine run into the SAME evidence directory: wave 2 means
	// org.repos now genuinely returns two repositories, so this run's own
	// org.repos page overwrites the first run's manifest pointer at the
	// identical logical key.
	setWave(2)
	store, err = OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	secondReport, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	secondRef, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, secondReport.CollectedAt, secondReport.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	secondReport.ContextRef = secondRef
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if len(secondReport.Organizations) != 1 || len(secondReport.Organizations[0].Repositories) != 2 {
		t.Fatalf("test fixture assumption broken: wave 2 must collect exactly two repositories: %+v", secondReport.Organizations)
	}
	if firstRef == secondRef {
		t.Fatal("two genuinely different collection passes must bind to two genuinely different context refs")
	}

	profile := fixtureProfileWithDefault(t)

	// The FIRST report's own history must remain independently
	// reconstructable, even though the directory's org.repos logical
	// manifest now points at the SECOND run's two-repository page.
	replayedFirst, firstContextBound, err := ReplayVerticalSlice(context.Background(), profile, firstReport, evidenceDirectory)
	if err != nil {
		t.Fatalf("replaying the FIRST report must still succeed after a later run moved the shared logical ref: %v", err)
	}
	if !firstContextBound {
		t.Fatal("the first report's own ContextRef must still bind")
	}
	if len(replayedFirst.Organizations) != 1 || len(replayedFirst.Organizations[0].Repositories) != 1 {
		t.Fatalf("replaying the FIRST report must reconstruct exactly its own one-repository inventory, not the "+
			"second run's two-repository inventory the directory's logical manifest now points to: %+v", replayedFirst.Organizations)
	}
	if mismatches := compareVerticalSliceReports(firstReport, replayedFirst); len(mismatches) != 0 {
		t.Fatalf("the first report must replay cleanly against its OWN history: %v", mismatches)
	}

	// The SECOND report's own history must independently reconstruct too.
	replayedSecond, secondContextBound, err := ReplayVerticalSlice(context.Background(), profile, secondReport, evidenceDirectory)
	if err != nil {
		t.Fatalf("replaying the SECOND report must succeed: %v", err)
	}
	if !secondContextBound {
		t.Fatal("the second report's own ContextRef must still bind")
	}
	if len(replayedSecond.Organizations) != 1 || len(replayedSecond.Organizations[0].Repositories) != 2 {
		t.Fatalf("replaying the SECOND report must reconstruct its own two-repository inventory: %+v", replayedSecond.Organizations)
	}
	if mismatches := compareVerticalSliceReports(secondReport, replayedSecond); len(mismatches) != 0 {
		t.Fatalf("the second report must replay cleanly against its OWN history: %v", mismatches)
	}

	// Cross-checking the two replays against EACH OTHER's claim must
	// surface a mismatch: proof the two histories were never conflated.
	if mismatches := compareVerticalSliceReports(firstReport, replayedSecond); len(mismatches) == 0 {
		t.Fatal("the first report's one-repository claim must NOT match the second run's two-repository replay")
	}

	// Both context refs must remain independently loadable from the same
	// directory after both runs.
	readBack, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readBack.Close() }()
	if _, err := LoadRunCollectionContextByRef(readBack, firstRef); err != nil {
		t.Fatalf("the first run's context must remain independently loadable by its own ref: %v", err)
	}
	if _, err := LoadRunCollectionContextByRef(readBack, secondRef); err != nil {
		t.Fatalf("the second run's context must remain independently loadable by its own ref: %v", err)
	}
}

// TestFullPipelineReplayRejectsContextBoundReportWithStrippedOutcomeRefs
// proves the hard gate closing the "strip EvidenceRefs to launder through
// whatever the latest logical manifest now resolves to" attack: a
// genuinely context-bound (ContextRef set) report's org.repos outcome has
// its EvidenceRefs set to nil (Pages left unchanged, simulating refs that
// were stripped after the fact) and is replayed/verified AFTER a SECOND,
// genuinely later run has moved that exact (scope, collectorID, feature)
// logical manifest to point at different content. The report MUST be
// rejected outright -- never silently fall back to a best-effort logical
// lookup that would return the SECOND run's data under the FIRST run's
// claimed identity -- because a context-bound report claims modern, fully
// exact-ref-bound provenance throughout; a nonzero-page outcome missing its
// refs can only mean they were stripped, never a legitimate legacy gap.
func TestFullPipelineReplayRejectsContextBoundReportWithStrippedOutcomeRefs(t *testing.T) {
	server, setWave := newTwoWaveInventoryServer(t)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	evidenceDirectory := t.TempDir()
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: "./evidence",
	}

	store, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	firstReport, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	firstRef, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, firstReport.CollectedAt, firstReport.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	firstReport.ContextRef = firstRef
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	orgReposIndex := -1
	for index, outcome := range firstReport.Outcomes {
		if outcome.CollectorID == "org.repos" {
			orgReposIndex = index
			break
		}
	}
	if orgReposIndex < 0 || firstReport.Outcomes[orgReposIndex].Pages == 0 || len(firstReport.Outcomes[orgReposIndex].EvidenceRefs) == 0 {
		t.Fatalf("test fixture assumption broken: expected a genuine, nonzero-page org.repos outcome with EvidenceRefs: %+v", firstReport.Outcomes)
	}

	// A second, genuinely later run into the SAME evidence directory: wave
	// 2 means org.repos now returns two repositories, so this run's own
	// org.repos page genuinely overwrites the first run's manifest pointer
	// at the identical logical key.
	setWave(2)
	store, err = OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	secondReport, err := runVerticalSliceWithStore(context.Background(), client.profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRunCollectionContextWithOutcomes(store, client.profile, config, []Target{target}, secondReport.CollectedAt, secondReport.Outcomes); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Strip the FIRST report's org.repos EvidenceRefs (Pages left
	// unchanged): this simulates a report whose refs were removed after
	// the fact, the exact scenario that must never be allowed to silently
	// fall back to whatever the directory's logical manifest for
	// org.repos now resolves to (the SECOND run's two-repository page).
	strippedReport := *firstReport
	strippedOutcomes := append([]CollectorOutcome{}, firstReport.Outcomes...)
	strippedOutcomes[orgReposIndex].EvidenceRefs = nil
	strippedReport.Outcomes = strippedOutcomes

	profile := fixtureProfileWithDefault(t)
	if _, _, err := ReplayVerticalSlice(context.Background(), profile, &strippedReport, evidenceDirectory); err == nil {
		t.Fatal("replaying a context-bound report with a stripped-refs, nonzero-page outcome must be rejected outright, " +
			"never silently fall back to the directory's current (later-run) logical manifest")
	}

	result, err := VerifyReportEvidence(profile, &strippedReport, evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified || result.AnalysisVerified {
		t.Fatalf("a context-bound report with a stripped-refs outcome must never be Verified/AnalysisVerified, "+
			"even though its context itself still resolves fine: %+v", result)
	}
}

// TestTargetsAuthorizeScopeRejectsHostOnlyClaimForUnconfiguredHost proves
// targetsAuthorizeScope checks candidate HOST membership itself, not only
// organization/enterprise membership within an already-authorized host: a
// bare host-only claim (zero organizations, zero enterprise -- for example
// a target-level operational fact) for a host the authority never mentions
// must be rejected, not vacuously accepted merely because its empty
// organization/enterprise lists have nothing to individually check.
func TestTargetsAuthorizeScopeRejectsHostOnlyClaimForUnconfiguredHost(t *testing.T) {
	authority := []Target{{Host: "github.com", Organizations: []string{"fixture-org"}}}
	if err := targetsAuthorizeScope(authority, []Target{{Host: "unconfigured.example"}}); err == nil {
		t.Fatal("host-only operational scope bypassed configured host authorization")
	}
}

// TestRunOfflineEvaluationWithExplicitConsentRejectsUnconfiguredOutcomeScope
// proves the scope-authorization gate derives candidates from EVERY
// outcome's own Scope, not only report.Organizations/Targets: a report with
// zero Organizations entries but one outcome scoped to an organization the
// current configuration never authorized must still be rejected, with no
// output files written at all.
func TestRunOfflineEvaluationWithExplicitConsentRejectsUnconfiguredOutcomeScope(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	report := &VerticalSliceReport{
		Profile: profile.Summary(), CollectedAt: time.Now().UTC(), Metrics: map[string]Metric{},
		Outcomes: []CollectorOutcome{{
			CollectorID: "org.settings", Feature: "settings",
			Scope: Scope{Host: "unconfigured.example", Kind: OrganizationScope, Name: "outside-org"},
			Readiness: Ready, Availability: NotChecked, Status: NotRun, Reason: "not attempted",
		}},
	}
	output := filepath.Join(t.TempDir(), "outputs")
	if _, err := RunOfflineEvaluationWithExplicitConsent(profile, report, config, output); err == nil {
		t.Fatal("explicit unverified consent bypassed the configured scope for a foreign outcome")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("rejected scope must leave no output files: %v", err)
	}
}

// TestCompareMetricMapsRejectsEveryTamperedObservation proves
// compareMetricMaps/metricValuesEqual catch every semantically relevant
// tamper of a single genuine Metric observation: a per-organization scalar
// tampered while Overall stays untouched, a retained Denominator tampered
// while Number stays untouched, a Number tampered by a tiny delta (smaller
// than the old 0.01 tolerance this replaced) while Numerator/Denominator
// stay untouched, and a claimed-Known value downgraded to Unavailable to
// hide an unfavorable fact entirely.
func TestCompareMetricMapsRejectsEveryTamperedObservation(t *testing.T) {
	overall, perOrg, numerator, denominator := 80.0, 10.0, 8.0, 10.0
	genuine := Metric{
		Key: "fixture", Overall: MetricValue{Status: MetricKnown, Number: &overall, Numerator: &numerator, Denominator: &denominator},
		PerOrganization: map[string]MetricValue{"github.com/organization/fixture-org": {Status: MetricKnown, Number: &perOrg}},
	}
	for _, test := range []struct {
		name   string
		mutate func(*Metric)
	}{
		{"per-org scalar", func(metric *Metric) {
			altered := 90.0
			metric.PerOrganization["github.com/organization/fixture-org"] = MetricValue{Status: MetricKnown, Number: &altered}
		}},
		{"retained counts", func(metric *Metric) {
			altered := 800.0
			metric.Overall.Denominator = &altered
		}},
		{"near-boundary scalar", func(metric *Metric) {
			altered := overall + 0.005
			metric.Overall.Number = &altered
		}},
		{"known downgraded to unknown", func(metric *Metric) {
			metric.Overall = MetricValue{Status: MetricUnavailable, Reason: "edited claim"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(genuine)
			if err != nil {
				t.Fatal(err)
			}
			var claimed Metric
			if err := json.Unmarshal(raw, &claimed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&claimed)
			if failures := compareMetricMaps(map[string]Metric{"fixture": claimed}, map[string]Metric{"fixture": genuine}); len(failures) == 0 {
				t.Fatal("altered analysis observation was accepted as verified")
			}
		})
	}
}

// TestCompareVerticalSliceReportsRejectsTamperedPopulationAndOperationalClaims
// runs ONE genuine fixture collection through the full pipeline (collection
// then context-bound replay), confirms the untouched claim compares cleanly
// against its own genuine replay, then proves every one of the following
// tampers is independently caught: a population's critical-determination
// Method, its Sample record, an organization's own operational
// CodeSecurityConfigCoverage metric, and a repository's DefaultBranch.
func TestCompareVerticalSliceReportsRejectsTamperedPopulationAndOperationalClaims(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90, Concurrency: 1,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: directory,
	}
	report, err := runVerticalSliceWithStore(context.Background(), profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	replayed, bound, err := ReplayVerticalSlice(context.Background(), profile, report, directory)
	if err != nil || !bound {
		t.Fatalf("genuine fixture did not replay: bound=%v err=%v", bound, err)
	}
	if failures := compareVerticalSliceReports(report, replayed); len(failures) != 0 {
		t.Fatalf("genuine raw fixture did not compare cleanly: %v", failures)
	}
	for _, test := range []struct {
		name   string
		mutate func(*VerticalSliceReport)
	}{
		{"critical determination method", func(claimed *VerticalSliceReport) {
			claimed.Organizations[0].Population.Critical.Method = "unknown"
		}},
		{"sampling status", func(claimed *VerticalSliceReport) {
			claimed.Organizations[0].Population.Sample = &SampleResult{Cap: 1, PopulationSize: 999}
		}},
		{"organization operational metric", func(claimed *VerticalSliceReport) {
			value := 100.0
			if claimed.Organizations[0].Operational == nil {
				claimed.Organizations[0].Operational = &OrganizationOperationalResult{}
			}
			claimed.Organizations[0].Operational.CodeSecurityConfigCoverage = &MetricValue{Status: MetricKnown, Number: &value}
		}},
		{"repository default branch", func(claimed *VerticalSliceReport) {
			claimed.Organizations[0].Repositories[0].DefaultBranch = "invented-default"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var claimed VerticalSliceReport
			if err := json.Unmarshal(raw, &claimed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&claimed)
			if failures := compareVerticalSliceReports(&claimed, replayed); len(failures) == 0 {
				t.Fatal("altered claim passed against the full genuine pipeline replay")
			}
		})
	}
}

// TestMaterializeExactReplaySourceRejectsTruncatedPaginationClaim proves the
// PaginationContinues terminal-pagination proof catches an outcome whose
// genuine two-page partial pagination (page1 OK with a Link rel="next",
// page2 denied) is truncated down to a one-page claim relabeled
// Status:CollectionOK/Complete:true: page1's own immutable metadata records
// that pagination was not yet done after it, so this claim must be
// rejected by materializeExactReplaySource outright, or -- if seeding is
// somehow still permitted -- must never let a subsequent replay collection
// upgrade the claim into a clean, complete result.
func TestMaterializeExactReplaySourceRejectsTruncatedPaginationClaim(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("page") == "2" {
			writer.WriteHeader(http.StatusForbidden)
			writeJSON(t, writer, map[string]string{"message": "permission denied"})
			return
		}
		writer.Header().Set("Link", "<"+server.URL+"/orgs/fixture-org/repos?per_page=100&page=2>; rel=\"next\"")
		writeJSON(t, writer, []map[string]any{{"id": 1}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	original := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "fixture-org"}
	outcome, err := client.CollectGET(context.Background(), original, scope, "org.repos", "inventory", "orgs/fixture-org/repos", "", true)
	if err == nil || outcome.Pages != 2 || outcome.Status != CollectionPartial || outcome.Complete {
		t.Fatalf("genuine two-page partial fixture did not exercise denial: %+v err=%v", outcome, err)
	}
	stripped := outcome
	stripped.Pages = 1
	stripped.EvidenceRefs = append([]string{}, outcome.EvidenceRefs[:2]...)
	stripped.Status, stripped.Availability, stripped.Complete = CollectionOK, Available, true
	status := http.StatusOK
	stripped.HTTPStatus = &status
	stripped.Reason = ""
	frozen, err := materializeExactReplaySource(original, client.profile, &VerticalSliceReport{Outcomes: []CollectorOutcome{stripped}}, true, t.TempDir())
	if err != nil {
		return // Rejecting the shortened page inventory is the safe outcome.
	}
	t.Cleanup(func() { _ = frozen.Close() })
	replay, err := NewReplayCollectionClient(Target{Host: scope.Host, Deployment: Server}, RESTEvidence, client.profile, frozen, SystemClock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := replay.CollectGET(context.Background(), evidenceFixtureStore(t, t.TempDir(), nil), scope, "org.repos", "inventory", "orgs/fixture-org/repos", "", true)
	if err == nil && replayed.Complete && replayed.Status == CollectionOK {
		t.Fatal("stripping the genuinely denied second page upgraded partial paginated evidence into complete clean replay")
	}
}

// TestRunVerifiedOfflineEvaluationPreservesGenuineZeroPageFailureReason
// proves a zero-page transport failure's TRUE original Reason text (a
// collector call that failed before any HTTP response was even observed,
// which therefore has no persisted evidence pages at all) survives into
// the exported collection-log.json verbatim, rather than being silently
// replaced by collectFromReplay's own generic "no replay evidence is
// stored for this feature" substitute -- the only reconstruction it can
// ever produce for a feature with genuinely nothing stored. This relies on
// RunCollectionContext's own bound OriginalOutcomes snapshot (captured by
// RunVerticalSlice at collection time, before any export could alter it),
// which ReplayVerticalSlice checks the claimed report's own Outcomes
// against before trusting them for reporting.
func TestRunVerifiedOfflineEvaluationPreservesGenuineZeroPageFailureReason(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90, Concurrency: 1,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: directory,
	}
	report, err := runVerticalSliceWithStore(context.Background(), profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	// Inject a genuine-shaped zero-page transport failure, exactly as
	// CollectGET itself records one when sdk.Do returns an error before
	// any HTTP response was ever observed (capture.status == 0): Pages:0,
	// no EvidenceRefs, this exact Reason text.
	transportFailure := CollectorOutcome{
		CollectorID: "org.hooks", Feature: "hooks",
		Scope: Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "fixture-org"},
		Readiness: Ready, Availability: NotChecked, Status: CollectionFailed,
		Reason: "request failed before an HTTP response was observed",
	}
	// The fixture server does not implement org.hooks, so a genuine
	// collection attempt against it already produces its own (different)
	// real failure for that identity; replace it with the exact transport
	// failure this test exercises rather than appending a second,
	// conflicting entry for the same identity.
	filtered := report.Outcomes[:0]
	for _, outcome := range report.Outcomes {
		if outcome.CollectorID == transportFailure.CollectorID && outcome.Scope == transportFailure.Scope {
			continue
		}
		filtered = append(filtered, outcome)
	}
	report.Outcomes = append(filtered, transportFailure)

	ref, err := WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	outputDirectory := filepath.Join(t.TempDir(), "out")
	summary, err := RunVerifiedOfflineEvaluation(profile, report, config, outputDirectory, directory)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EvidenceVerification == nil || !summary.EvidenceVerification.Verified {
		t.Fatalf("a genuine report whose outcomes exactly match its bound context's original inventory must verify: %+v", summary.EvidenceVerification)
	}
	outcomes, err := LoadCollectionLog(outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, outcome := range outcomes {
		if outcome.CollectorID == "org.hooks" {
			found = true
			if outcome.Reason != "request failed before an HTTP response was observed" {
				t.Fatalf("exported collection-log must preserve the TRUE original transport-failure reason, "+
					"not a replay-synthesized substitute: %q", outcome.Reason)
			}
			if outcome.Pages != 0 || outcome.Status != CollectionFailed {
				t.Fatalf("exported collection-log must preserve the genuine zero-page failure shape: %+v", outcome)
			}
		}
	}
	if !found {
		t.Fatal("exported collection-log must retain the genuine zero-page org.hooks outcome")
	}
}

// TestReplayVerticalSliceRejectsOutcomesDivergingFromBoundOriginalInventory
// proves a context-bound report's own claimed Outcomes must match its
// bound context's immutable OriginalOutcomes snapshot exactly: a tampered
// Reason string on an otherwise-identical zero-page outcome (which has no
// persisted evidence pages for any other check to verify against) is
// rejected, and an outcome the claim omits entirely (silently dropping a
// genuinely recorded failure) is also rejected.
func TestReplayVerticalSliceRejectsOutcomesDivergingFromBoundOriginalInventory(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config, err := ParseConfig([]byte("organizations: [fixture-org]\n"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	originalOutcomes := []CollectorOutcome{{
		CollectorID: "org.hooks", Feature: "hooks",
		Scope: Scope{Host: "github.com", Kind: OrganizationScope, Name: "fixture-org"},
		Readiness: Ready, Availability: NotChecked, Status: CollectionFailed,
		Reason: "request failed before an HTTP response was observed",
	}}
	ref, err := WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{}, time.Now().UTC(), originalOutcomes)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("tampered reason", func(t *testing.T) {
		tampered := append([]CollectorOutcome{}, originalOutcomes...)
		tampered[0].Reason = "organization not found"
		report := &VerticalSliceReport{Profile: profile.Summary(), ContextRef: ref, Metrics: map[string]Metric{}, Outcomes: tampered}
		if _, _, err := ReplayVerticalSlice(context.Background(), profile, report, directory); err == nil {
			t.Fatal("a claimed outcome whose Reason diverges from the bound original inventory must be rejected")
		}
	})

	t.Run("omitted outcome", func(t *testing.T) {
		report := &VerticalSliceReport{Profile: profile.Summary(), ContextRef: ref, Metrics: map[string]Metric{}, Outcomes: []CollectorOutcome{}}
		if _, _, err := ReplayVerticalSlice(context.Background(), profile, report, directory); err == nil {
			t.Fatal("a claim that silently omits a genuinely recorded original outcome must be rejected")
		}
	})
}

// TestMaterializeExactReplaySourceNeverTreatsUnknownTerminalProofAsFalse
// proves pageProvablyTerminal never treats missing/unparseable terminal
// proof as an equivalent to a confirmed-false (provably terminal) page: a
// page collected before PaginationContinues existed (its JSON field simply
// absent, decoding to nil) and a page whose Link header names a
// cross-origin next URL (nextLink's own existing same-origin check
// rejecting it, discarding that error must never silently become false)
// must both still be rejected by materializeExactReplaySource when a
// claim relabels that single page as a clean, complete outcome.
func TestMaterializeExactReplaySourceNeverTreatsUnknownTerminalProofAsFalse(t *testing.T) {
	for _, test := range []struct {
		name       string
		link       string
		legacyMeta bool
	}{
		{name: "legacy omitted terminal proof", legacyMeta: true},
		{name: "invalid next-link origin", link: "<https://outside.invalid/orgs/fixture-org/repos>; rel=\"next\""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if test.link != "" {
					writer.Header().Set("Link", test.link)
				}
				writeJSON(t, writer, []map[string]any{{"id": 1}})
			}))
			t.Cleanup(server.Close)
			client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
			source := evidenceFixtureStore(t, t.TempDir(), nil)
			scope := Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "fixture-org"}
			outcome, collectionErr := client.CollectGET(context.Background(), source, scope, "org.repos", "inventory", "orgs/fixture-org/repos", "", true)
			if outcome.Pages != 1 || (!test.legacyMeta && collectionErr == nil) {
				t.Fatalf("fixture did not exercise expected terminal-provenance case: %+v err=%v", outcome, collectionErr)
			}
			if test.legacyMeta {
				raw, _, ref, err := source.LoadJSON(scope, outcome.CollectorID, pageFeatureName(outcome.Feature, 1))
				if err != nil {
					t.Fatal(err)
				}
				metaBytes, err := source.root.ReadFile(ref.MetadataPath)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]any
				if err := json.Unmarshal(metaBytes, &fields); err != nil {
					t.Fatal(err)
				}
				delete(fields, "pagination_continues")
				metaBytes, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				objectID := digestBytes(append(append([]byte{}, raw...), metaBytes...))
				dataPath, metadataPath := "objects/"+objectID+".json", "objects/"+objectID+".meta.json"
				if err := source.writeObject(dataPath, raw); err != nil {
					t.Fatal(err)
				}
				if err := source.writeObject(metadataPath, metaBytes); err != nil {
					t.Fatal(err)
				}
				outcome.EvidenceRefs = []string{dataPath, metadataPath}
			}
			outcome.Status, outcome.Complete, outcome.Reason = CollectionOK, true, ""
			frozen, err := materializeExactReplaySource(source, client.profile, &VerticalSliceReport{Outcomes: []CollectorOutcome{outcome}}, true, t.TempDir())
			if err == nil {
				_ = frozen.Close()
				t.Fatal("unknown/malformed terminal pagination proof became a confident false and accepted clean source")
			}
		})
	}
}

// TestCompareOrganizationOperationalRejectsAuditWindowTamper proves the
// audit-log lookback window itself (RequestedSince/RequestedUntil) is a
// genuine claim compareOrganizationOperational still catches when it
// diverges meaningfully -- the auditLogIgnoringRequestWindow exception only
// tolerates the microsecond-scale drift inherent to two independent
// collection passes each reading the wall clock once, never a
// deliberately widened/narrowed lookback window.
func TestCompareOrganizationOperationalRejectsAuditWindowTamper(t *testing.T) {
	since := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	until := since.Add(90 * 24 * time.Hour)
	original := &OrganizationOperationalResult{AuditLog: &AuditLogResult{
		RequestedSince: since, RequestedUntil: until, Complete: true, CategoryCounts: map[string]int{},
	}}
	altered := &OrganizationOperationalResult{AuditLog: &AuditLogResult{
		RequestedSince: since.Add(-365 * 24 * time.Hour), RequestedUntil: until.Add(365 * 24 * time.Hour),
		Complete: true, CategoryCounts: map[string]int{},
	}}
	if failures := compareOrganizationOperational("github.com/organization/fixture-org", altered, original); len(failures) == 0 {
		t.Fatal("claimed audit lookback/time-window tamper was explicitly ignored by full-analysis verification")
	}
}

// TestCompareOrganizationOperationalAcceptsGenuineEmptyTeamRosterSerializationRoundTrip
// proves normalizeEmptyTeamRoster's exact, narrow purpose: Teams carries
// `omitempty`, so a report that round-tripped through JSON decodes a
// genuinely-observed, confirmed-zero-team roster back as nil, while this
// run's own freshly, independently in-memory-collected replay result still
// holds the exact same roster as a non-nil, zero-length slice (as
// FetchOrgTeams/collectJSONArray always build on a successful,
// zero-result page) -- the identical JSON, the identical roster, so this
// must never be reported as a mismatch.
func TestCompareOrganizationOperationalAcceptsGenuineEmptyTeamRosterSerializationRoundTrip(t *testing.T) {
	claimed := &OrganizationOperationalResult{Teams: nil, Roles: &OrgRolesResult{Roles: []roleAssignment{}}}
	replayed := &OrganizationOperationalResult{Teams: []teamSummary{}, Roles: &OrgRolesResult{Roles: []roleAssignment{}}}
	if failures := compareOrganizationOperational("github.com/organization/fixture-org", claimed, replayed); len(failures) != 0 {
		t.Fatalf("genuine nil-vs-empty-slice Teams serialization artifact was reported as a mismatch: %v", failures)
	}
	// The reverse nil-ness pairing must also be accepted.
	claimed.Teams, replayed.Teams = []teamSummary{}, nil
	if failures := compareOrganizationOperational("github.com/organization/fixture-org", claimed, replayed); len(failures) != 0 {
		t.Fatalf("genuine empty-slice-vs-nil Teams serialization artifact was reported as a mismatch: %v", failures)
	}
}

// TestCompareOrganizationOperationalRejectsGenuineTeamRosterDivergence
// proves the Teams normalization is surgical: it only ever closes the
// nil-vs-empty-slice gap when BOTH sides already independently agree the
// roster is zero-length, and never masks any other, genuine divergence --
// a team actually added or removed, a team's own member/repo counts
// differing, or a claimed non-empty roster where replay's own
// independently-collected source could only ever be nil (the "unknown
// source" tamper case, which must never be laundered through this
// normalization into looking like an accepted confirmed-empty roster).
func TestCompareOrganizationOperationalRejectsGenuineTeamRosterDivergence(t *testing.T) {
	baseline := []teamSummary{{Slug: "platform", Privacy: "closed", MembersCount: 3, ReposCount: 2, Repos: []teamRepoAccess{}, ReposComplete: true}}
	cases := map[string]struct {
		claimed, replayed []teamSummary
	}{
		"team added": {
			claimed:  append(append([]teamSummary{}, baseline...), teamSummary{Slug: "extra", Privacy: "secret", Repos: []teamRepoAccess{}, ReposComplete: true}),
			replayed: baseline,
		},
		"team removed": {
			claimed:  baseline,
			replayed: nil,
		},
		"different member count": {
			claimed:  baseline,
			replayed: []teamSummary{{Slug: "platform", Privacy: "closed", MembersCount: 9, ReposCount: 2, Repos: []teamRepoAccess{}, ReposComplete: true}},
		},
		"unknown source tamper: claimed nonempty, replay independently established none": {
			claimed:  baseline,
			replayed: nil,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			claimed := &OrganizationOperationalResult{Teams: testCase.claimed}
			replayed := &OrganizationOperationalResult{Teams: testCase.replayed}
			if failures := compareOrganizationOperational("github.com/organization/fixture-org", claimed, replayed); len(failures) == 0 {
				t.Fatalf("genuine team roster divergence (%s) was masked by the nil-vs-empty-slice normalization", name)
			}
		})
	}
}

// preResponseConnectionFailureTransport wraps a transport, deliberately
// failing a specific request path before any HTTP response is ever
// observed (mirroring a genuine DNS/connection-level failure a real
// collector call can hit), so a test can exercise CollectGET's own
// zero-page, pre-response CollectionFailed path exactly as it genuinely
// occurs, rather than hand-constructing a CollectorOutcome that merely
// looks the same.
type preResponseConnectionFailureTransport struct {
	http.RoundTripper
	failSuffix string
}

func (transport preResponseConnectionFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, transport.failSuffix) {
		return nil, fmt.Errorf("synthetic pre-response connection failure")
	}
	return transport.RoundTripper.RoundTrip(request)
}

// TestRunVerifiedOfflineEvaluationPreservesRealPreResponseZeroPageFailure
// is TestRunVerifiedOfflineEvaluationPreservesGenuineZeroPageFailureReason's
// more realistic counterpart: instead of hand-constructing a
// CollectorOutcome that merely looks like a pre-response transport
// failure, it genuinely induces one (org.hooks's underlying request
// failing before any HTTP response is observed) through the real
// collection pipeline, then proves the exported collection-log.json
// preserves that exact, genuine Reason/Status/Pages, never replacing it
// with a replay-synthesized substitute.
func TestRunVerifiedOfflineEvaluationPreservesRealPreResponseZeroPageFailure(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	transport, ok := client.http.Transport.(*readTransport)
	if !ok {
		t.Fatal("fixture transport does not support interception")
	}
	transport.wrapped = preResponseConnectionFailureTransport{RoundTripper: transport.wrapped, failSuffix: "/hooks"}
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90, Concurrency: 1,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: directory,
	}
	report, err := runVerticalSliceWithStore(context.Background(), profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	var sourceOutcome *CollectorOutcome
	for index := range report.Outcomes {
		outcome := &report.Outcomes[index]
		if outcome.CollectorID == "org.hooks" && outcome.Pages == 0 && outcome.Status == CollectionFailed {
			sourceOutcome = outcome
			break
		}
	}
	if sourceOutcome == nil {
		t.Fatal("fixture did not retain original pre-response zero-page failure")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "outputs")
	if _, err := RunVerifiedOfflineEvaluation(profile, report, config, output, directory); err != nil {
		t.Fatalf("genuine partial run could not be evaluated: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(output, CollectionLogFileName))
	if err != nil {
		t.Fatal(err)
	}
	var logged []CollectorOutcome
	if err := json.Unmarshal(raw, &logged); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range logged {
		if outcome.CollectorID == sourceOutcome.CollectorID && outcome.Feature == sourceOutcome.Feature && outcome.Scope == sourceOutcome.Scope {
			if outcome.Reason != sourceOutcome.Reason || outcome.Status != sourceOutcome.Status || outcome.Pages != sourceOutcome.Pages {
				t.Fatalf("verified exports replaced the real source failure with a generic replay observation: source=%+v logged=%+v", sourceOutcome, outcome)
			}
			return
		}
	}
	t.Fatal("verified exports omitted the original zero-page source failure")
}

// TestReplayVerticalSliceRejectsZeroPageForgeryUnderOutcomesUnboundContext
// proves a config-only context (one written via the plain
// WriteRunCollectionContext, with no bound OriginalOutcomes inventory at
// all) can never be used to launder a forged zero-page claim: a genuine
// zero-page transport failure, relabeled clean/complete, has no persisted
// evidence pages for compareVerticalSliceReports or the per-page integrity
// loop to catch it with either, so without a bound original-outcomes
// inventory this specific claim can never be independently proven genuine
// by anything in this pipeline -- this must be an explicit refusal, never
// a silent pass that happens to leave AnalysisVerified/Verified true
// merely because nothing else found a contradiction.
func TestReplayVerticalSliceRejectsZeroPageForgeryUnderOutcomesUnboundContext(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90, Concurrency: 1,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: directory,
	}
	report, err := runVerticalSliceWithStore(context.Background(), profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	// A config-only context: no OriginalOutcomes bound at all, exactly as
	// a context predating this mechanism (or one written by a caller that
	// bypassed WriteRunCollectionContextWithOutcomes) would be.
	ref, err := WriteRunCollectionContext(store, profile, config, []Target{target}, report.CollectedAt)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Forge a zero-page transport failure into a clean, complete claim --
	// this outcome has no persisted evidence pages, so neither
	// compareVerticalSliceReports nor the per-page integrity loop has
	// anything to check it against.
	report.Outcomes = append(report.Outcomes, CollectorOutcome{
		CollectorID: "org.hooks", Feature: "hooks",
		Scope: Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "fixture-org"},
		Readiness: Ready, Availability: Available, Status: CollectionOK, Complete: true,
	})

	if _, _, err := ReplayVerticalSlice(context.Background(), profile, report, directory); err == nil {
		t.Fatal("a forged zero-page outcome under a config-only (outcomes-unbound) context must be rejected, " +
			"never silently accepted as genuine")
	}

	result, err := VerifyReportEvidence(profile, report, directory)
	if err != nil {
		t.Fatal(err)
	}
	if result.AnalysisVerified || result.Verified {
		t.Fatalf("a forged zero-page outcome under an outcomes-unbound context must never earn "+
			"AnalysisVerified/Verified=true: %+v", result)
	}

	output := filepath.Join(t.TempDir(), "out")
	if _, err := RunVerifiedOfflineEvaluation(profile, report, config, output, directory); err == nil {
		t.Fatal("RunVerifiedOfflineEvaluation must refuse a forged zero-page outcome under an outcomes-unbound context")
	}
}

// TestMaterializeExactReplaySourceAcceptsImportOnlyBareFeatureOutcome proves
// an ImportOnly outcome (ghes.cli/ghes.backup, every ui.*/ext.* capture,
// manual.interview/manual.document) replays correctly despite its own
// genuinely different storage shape from a live REST collector's: its
// evidence is addressed at its own bare feature name (ImportJSON/
// loadImportedPayload never apply the "-page-NNNNNN" convention, since an
// import is inherently a single, complete record), and it carries no
// terminal-pagination proof at all (PaginationContinues is never set by
// the import path, genuinely correct for a mechanism with no pagination
// concept to prove absent) -- materializeExactReplaySource must seed it
// successfully rather than reject it for either reason.
func TestMaterializeExactReplaySourceAcceptsImportOnlyBareFeatureOutcome(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	source := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: "github.com", Kind: OrganizationScope, Name: "fixture-org"}
	metadata := EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "manual.document", Feature: "workbook-evidence", Scope: scope,
		CollectedAt: time.Now().UTC(), Endpoint: "manual://workbook-evidence", SourceKind: ImportedEvidence,
		CredentialKind: NoCredential,
		Pages: 1, Complete: true,
	}
	ref, err := source.SaveJSON([]byte(`{"imported":true}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	outcome := CollectorOutcome{
		CollectorID: "manual.document", Feature: "workbook-evidence", Scope: scope,
		Readiness: ImportOnly, Availability: Available, Status: CollectionOK, Complete: true,
		Pages: 1, EvidenceRefs: []string{ref.DataPath, ref.MetadataPath},
	}
	frozen, err := materializeExactReplaySource(source, profile, &VerticalSliceReport{Outcomes: []CollectorOutcome{outcome}}, true, t.TempDir())
	if err != nil {
		t.Fatalf("an ImportOnly outcome's own bare-feature-name, non-paginated evidence must seed cleanly: %v", err)
	}
	defer func() { _ = frozen.Close() }()
	raw, loaded, _, err := frozen.LoadJSON(scope, "manual.document", "workbook-evidence")
	if err != nil {
		t.Fatalf("the seeded scratch source must resolve the import's own bare feature name directly: %v", err)
	}
	if !bytes.Contains(raw, []byte("imported")) || loaded.CollectorID != "manual.document" {
		t.Fatalf("seeded import evidence does not match the original: raw=%s metadata=%+v", raw, loaded)
	}
}

// TestMaterializeExactReplaySourceAcceptsGenuinePartialWithInvalidNextLink
// proves the terminal-pagination-proof check (pageProvablyTerminal) is only
// ever required when an outcome itself claims a clean, complete finish
// (Status:CollectionOK, Complete:true): a genuine single-page success (HTTP
// 200, a valid record count) followed by a malformed/invalid Link header on
// its own next-page attempt is an honest CollectionPartial/Complete:false
// claim with Reason "pagination next link is invalid" -- it never claims to
// have finished cleanly, so it must be reconstructed faithfully as the
// genuine partial result it is, never rejected merely because its own last
// page's terminal proof happens to be unknown (nil, from the exact same
// invalid-link condition). The SAME last-page metadata relabeled to a false
// clean/complete claim (the established truncation-forgery attack) must
// still be rejected exactly as before.
func TestMaterializeExactReplaySourceAcceptsGenuinePartialWithInvalidNextLink(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Link", "<https://outside.invalid/orgs/fixture-org/repos>; rel=\"next\"")
		writeJSON(t, writer, []map[string]any{{"id": 1}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	source := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: client.base.Hostname(), Kind: OrganizationScope, Name: "fixture-org"}
	outcome, collectionErr := client.CollectGET(context.Background(), source, scope, "org.repos", "inventory", "orgs/fixture-org/repos", "", true)
	if collectionErr == nil || outcome.Pages != 1 || outcome.Status != CollectionPartial || outcome.Complete {
		t.Fatalf("fixture did not exercise a genuine invalid-next-link partial outcome: %+v err=%v", outcome, collectionErr)
	}

	// The genuine, HONEST partial claim must replay cleanly, never rejected.
	genuineReplaySource, err := materializeExactReplaySource(source, client.profile,
		&VerticalSliceReport{Outcomes: []CollectorOutcome{outcome}}, true, t.TempDir())
	if err != nil {
		t.Fatalf("a genuine, honestly-disclosed partial outcome (invalid next link) must seed cleanly, "+
			"never rejected for lacking terminal proof it never claimed: %v", err)
	}
	_ = genuineReplaySource.Close()

	// The SAME outcome relabeled to a false clean/complete claim (the
	// established truncation-forgery attack) must still be rejected.
	forged := outcome
	forged.Status, forged.Complete, forged.Reason = CollectionOK, true, ""
	if frozen, err := materializeExactReplaySource(source, client.profile,
		&VerticalSliceReport{Outcomes: []CollectorOutcome{forged}}, true, t.TempDir()); err == nil {
		_ = frozen.Close()
		t.Fatal("relabeling the same unproven-terminal page as a clean, complete claim must still be rejected")
	}
}

// injectInvalidNextLinkTransport wraps a transport, adding an invalid
// (cross-origin) Link rel="next" header to every genuine response for one
// specific request path -- inducing a REAL CollectGET partial outcome
// (page 1 genuinely succeeds, the follow-up next-link is invalid) through
// the actual collection pipeline, rather than hand-constructing an outcome
// that merely looks the same.
type injectInvalidNextLinkTransport struct {
	http.RoundTripper
	path string
}

func (transport injectInvalidNextLinkTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.RoundTripper.RoundTrip(request)
	if err != nil || response == nil || request.URL.Path != transport.path {
		return response, err
	}
	response.Header.Set("Link", "<https://outside.invalid"+transport.path+"?page=2>; rel=\"next\"")
	return response, err
}

// TestFullPipelineReplayFaithfullyReproducesGenuinePartialPaginationOutcome
// is the full end-to-end proof requested beyond the materialization-only
// check: a genuine org.repos outcome (page 1 succeeds for real, its own
// next-link is genuinely invalid) must replay through the COMPLETE
// ReplayVerticalSlice/RunVerifiedOfflineEvaluation pipeline reproducing the
// SAME Partial/incomplete terminal state it genuinely claimed -- not
// silently upgraded to a clean, complete finish by collectFromReplay's own
// "ran out of stored pages" fallthrough merely because nothing more is
// stored (which looks identical, from stored-page presence alone, to a
// genuinely clean ending). The SAME underlying evidence relabeled to a
// false clean/complete claim must still be rejected (materialization-level
// terminal-proof gate, proven independently by
// TestMaterializeExactReplaySourceAcceptsGenuinePartialWithInvalidNextLink,
// reconfirmed here through the full pipeline too).
func TestFullPipelineReplayFaithfullyReproducesGenuinePartialPaginationOutcome(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	server := newVerticalSliceFixtureServer(t)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	transport, ok := client.http.Transport.(*readTransport)
	if !ok {
		t.Fatal("fixture transport does not support interception")
	}
	transport.wrapped = injectInvalidNextLinkTransport{RoundTripper: transport.wrapped, path: "/orgs/fixture-org/repos"}
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture-org"}}
	config := &CustomerConfig{
		Targets: []Target{target}, RepositoryCap: 10, LookbackDays: 90, Concurrency: 1,
		ProductionEnvRegex: "prod|production|live|release", EvidenceDir: directory,
	}
	report, err := runVerticalSliceWithStore(context.Background(), profile, config, []Target{target}, store, SystemClock{},
		func(Target, EvidenceSource) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	var original *CollectorOutcome
	for index := range report.Outcomes {
		outcome := &report.Outcomes[index]
		if outcome.CollectorID == "org.repos" {
			original = outcome
			break
		}
	}
	if original == nil || original.Status != CollectionPartial || original.Complete || original.Pages != 1 {
		t.Fatalf("fixture did not retain a genuine single-page partial org.repos outcome: %+v", original)
	}
	if original.Reason == "" {
		t.Fatal("test fixture assumption broken: expected a disclosed reason for the genuine partial outcome")
	}
	ref, err := WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{target}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef = ref
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, bound, err := ReplayVerticalSlice(context.Background(), profile, report, directory)
	if err != nil || !bound {
		t.Fatalf("genuine partial fixture did not replay: bound=%v err=%v", bound, err)
	}
	var replayedOutcome *CollectorOutcome
	for index := range replayed.Outcomes {
		outcome := &replayed.Outcomes[index]
		if outcome.CollectorID == "org.repos" {
			replayedOutcome = outcome
			break
		}
	}
	if replayedOutcome == nil {
		t.Fatal("replay lost the org.repos outcome entirely")
	}
	if replayedOutcome.Status != CollectionPartial || replayedOutcome.Complete {
		t.Fatalf("collectFromReplay silently upgraded a genuine, honestly-disclosed partial outcome to a clean, "+
			"complete finish merely because no further page was stored: claimed=%+v replayed=%+v", original, replayedOutcome)
	}
	if replayedOutcome.Reason != original.Reason {
		t.Fatalf("replay did not preserve the original partial outcome's own disclosed reason: claimed=%q replayed=%q",
			original.Reason, replayedOutcome.Reason)
	}

	output := filepath.Join(t.TempDir(), "out")
	summary, err := RunVerifiedOfflineEvaluation(profile, report, config, output, directory)
	if err != nil {
		t.Fatalf("a genuine, honestly-disclosed partial run must be accepted as verified, not refused: %v", err)
	}
	if summary.EvidenceVerification == nil || !summary.EvidenceVerification.Verified {
		t.Fatalf("a genuine partial run with an exactly-bound original outcome inventory must verify: %+v", summary.EvidenceVerification)
	}

	// The SAME underlying evidence, relabeled to a false clean/complete
	// claim, must still be rejected (materialization-level terminal-proof
	// gate; reconfirmed here through the full pipeline).
	forgedReport := *report
	forgedOutcomes := append([]CollectorOutcome{}, report.Outcomes...)
	for index := range forgedOutcomes {
		if forgedOutcomes[index].CollectorID == "org.repos" {
			forgedOutcomes[index].Status, forgedOutcomes[index].Complete, forgedOutcomes[index].Reason = CollectionOK, true, ""
		}
	}
	forgedReport.Outcomes = forgedOutcomes
	if _, _, err := ReplayVerticalSlice(context.Background(), profile, &forgedReport, directory); err == nil {
		t.Fatal("relabeling the genuine invalid-next-link partial outcome as a clean, complete claim must still be rejected")
	}
}
