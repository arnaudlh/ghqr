// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// frozenClock freezes Now() to a fixed instant, so replaying a prior run's
// stored evidence reproduces the exact same lookback/alert windows and
// critical-population recency ranking the original collection used, rather
// than drifting with the current wall-clock time. Sleep never actually
// waits: replay never contends for a live rate-limit budget, since no
// network call is ever made.
type frozenClock struct{ at time.Time }

func (f frozenClock) Now() time.Time { return f.at }

func (f frozenClock) Sleep(_ context.Context, _ time.Duration) error { return nil }

// NewReplayCollectionClient builds a *CollectionClient that never dials the
// network and never reads a real secret from the environment: it serves
// only already-persisted evidence from replaySource. NewCollectionClient
// itself is deliberately NOT called here, because its credential-resolution
// branch would hard-require a live TokenEnv/ManagementUsernameEnv value an
// offline replay context cannot and must not need. The resulting client's
// credentialKind reflects the given target's configured credential kind
// exactly when one is explicitly set (preserved, non-secret provenance --
// which authentication family a page was genuinely collected under, not a
// secret value), or ManagementConsole when the source itself implies it
// (matching NewCollectionClient's own behavior); an unset kind defaults to
// NoCredential, identically to a live client, never invented as something
// stronger than what the caller actually configured. This preservation
// matters because some collectors gate what they even attempt to replay on
// credentialKind (for example FetchEnterpriseSCIMUsers only proceeds when
// credentialKind == ClassicPAT, live or replayed alike, since GitHub's SCIM
// endpoints document only classic-PAT authentication): a genuine original
// ClassicPAT collection must replay through that same gate unmodified, not
// be silently downgraded to NoCredential and rejected for evidence that
// genuinely exists. CollectGET/CollectGraphQL both branch on replaySource
// before any field derived from a real credential (c.http's transport,
// c.base) is ever read for an outbound request, so no actual
// token/username/password value is ever resolved or needed regardless of
// which credentialKind is preserved.
func NewReplayCollectionClient(target Target, source EvidenceSource, profile *Profile, replaySource *EvidenceStore, clock Clock) (*CollectionClient, error) {
	if replaySource == nil {
		return nil, fmt.Errorf("replay collection client requires a replay evidence source")
	}
	if clock == nil {
		clock = SystemClock{}
	}
	base, graphQLPath, err := resolveCollectionEndpointAddress(target, source)
	if err != nil {
		return nil, err
	}
	kind := target.Credentials.Kind
	switch {
	case source == ManagementEvidence:
		kind = ManagementConsole
	case kind == "":
		kind = NoCredential
	}
	budget, err := NewRequestBudget(1)
	if err != nil {
		return nil, err
	}
	// This transport is fully formed (not a bare zero-value http.Client)
	// purely as a defense-in-depth consistency measure: CollectGET and
	// CollectGraphQL both branch on replaySource before ever reaching code
	// that would use it, so it is never actually dialed for this client,
	// and carries no real token/username/password (replay never resolves
	// or needs one).
	transport := &readTransport{
		base: base, graphQLPath: graphQLPath, budget: budget, clock: clock, wrapped: http.DefaultTransport,
	}
	return &CollectionClient{
		http: &http.Client{Transport: transport, Timeout: 2 * time.Minute,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
		base: base, source: source, credentialKind: kind,
		profile: profile, clock: clock, redactor: NewRedactor(), replaySource: replaySource,
	}, nil
}

// newReplayClientFactory adapts runVerticalSliceWithStore's existing
// injectable client-factory seam (already used for both the real live path
// in RunVerticalSlice and that function's own synthetic-server tests) to
// NewReplayCollectionClient, always serving pages from the same
// replaySource and never contending for a live rate-limit budget. clock is
// the SAME frozenClock{at: at} ReplayVerticalSlice passes to
// runVerticalSliceWithStore for its own lookback/recency math -- no actual
// network call is ever made during replay (collectFromReplay never reads
// c.clock at all, copying each page's original CollectedAt verbatim
// instead of re-stamping it), so this is current pure defense-in-depth
// consistency, not something any collection timing presently depends on.
func newReplayClientFactory(profile *Profile, replaySource *EvidenceStore, clock Clock) func(Target, EvidenceSource) (*CollectionClient, error) {
	return func(target Target, source EvidenceSource) (*CollectionClient, error) {
		return NewReplayCollectionClient(target, source, profile, replaySource, clock)
	}
}

// legacyDeriveReplayTargets is the FALLBACK path used only when
// evidenceDirectory has no bound RunCollectionContext at all (a legacy
// bundle collected before that mechanism existed). It groups a claimed
// report's own Organizations[].Scope AND Targets[].Host entries by host,
// inferring Cloud vs Server deployment from the host name, and binds
// enterprise/credential-kind provenance from the report's own
// CollectorOutcome entries -- all best-effort INFERENCE from the claim
// itself, not genuine bound provenance (the report's own Outcomes are part
// of what full replay is supposed to independently verify, not an
// authoritative source to configure that verification from). A legacy
// bundle replayed this way never earns AnalysisVerified=true regardless of
// how cleanly its comparison happens to come out; see ReplayVerticalSlice's
// contextBound return value and VerifyReportEvidence's explicit
// compatibility-limitation handling. This does NOT recover SCIMMode
// (emu/saml_sso/ghes): no CollectorOutcome field records which SCIM routing
// mode produced a given outcome, so ent.scim_users remains unreachable
// during legacy-mode replay even when bound by this fallback.
// deriveClaimedScope is the comprehensive, security-gate-only counterpart to
// legacyDeriveReplayTargets: it extracts EVERY host/organization/enterprise a
// report could possibly be claiming analysis about, not just enough to
// reconstruct a replay pipeline. legacyDeriveReplayTargets only adds a host
// from report.Organizations/report.Targets, then mines report.Outcomes
// purely for Enterprise/CredentialKind facts about a host ALREADY added that
// way -- an outcome whose own Scope names a host/organization never
// otherwise claimed (for example a report with zero Organizations entries
// but one organization- or repository-scoped CollectorOutcome, or a
// per-organization metric observation for an organization never listed
// elsewhere) is invisible to it entirely, which is exactly the reconstruction
// helper's own intended, narrower purpose -- but is never acceptable for a
// scope-AUTHORIZATION gate, whose entire job is to catch every claim a
// report could make, not just the ones convenient to replay. This is used
// everywhere a caller's own configuration must authorize a report's FULL
// claimed scope (targetsAuthorizeScope's candidates), never for replay
// target reconstruction itself.
func deriveClaimedScope(report *VerticalSliceReport) []Target {
	hosts := map[string]bool{}
	organizationsByHost := map[string]map[string]bool{}
	enterprisesByHost := map[string]map[string]bool{}
	addHost := func(host string) {
		host = strings.ToLower(host)
		if host == "" {
			return
		}
		hosts[host] = true
	}
	addOrganization := func(host, organization string) {
		host = strings.ToLower(host)
		if host == "" || organization == "" {
			return
		}
		hosts[host] = true
		if organizationsByHost[host] == nil {
			organizationsByHost[host] = map[string]bool{}
		}
		organizationsByHost[host][organization] = true
	}
	addEnterprise := func(host, enterprise string) {
		host = strings.ToLower(host)
		if host == "" || enterprise == "" {
			return
		}
		hosts[host] = true
		if enterprisesByHost[host] == nil {
			enterprisesByHost[host] = map[string]bool{}
		}
		enterprisesByHost[host][enterprise] = true
	}
	// Scope.Key() format is "host/kind/name", lowercased, built by Scope.Key()
	// itself; a repository's own Name additionally carries "organization/repo"
	// (Scope's own documented contract: "repository names must include their
	// organization"), so a repository-scoped claim's organization is its
	// Name's own first path segment.
	addScope := func(scope Scope) {
		addHost(scope.Host)
		switch scope.Kind {
		case OrganizationScope:
			addOrganization(scope.Host, scope.Name)
		case RepositoryScope:
			if organization, _, ok := strings.Cut(scope.Name, "/"); ok && organization != "" {
				addOrganization(scope.Host, organization)
			}
		case EnterpriseScope:
			addEnterprise(scope.Host, scope.Name)
		}
	}
	for _, organization := range report.Organizations {
		addScope(organization.Scope)
	}
	for _, target := range report.Targets {
		addHost(target.Host)
	}
	for _, outcome := range report.Outcomes {
		addScope(outcome.Scope)
	}
	// A per-organization metric observation is itself a claim about that
	// organization, even when no Organizations/Outcomes entry happens to
	// name it too (for example a metric map hand-edited or supplied
	// independently of the rest of the report): organizationKey, like
	// Scope.Key(), is "host/organization/name" -- parsed the same way.
	for _, metric := range report.Metrics {
		for organizationKey := range metric.PerOrganization {
			parts := strings.SplitN(organizationKey, "/", 3)
			if len(parts) == 3 && parts[1] == string(OrganizationScope) {
				addOrganization(parts[0], parts[2])
			}
		}
	}
	hostList := make([]string, 0, len(hosts))
	for host := range hosts {
		hostList = append(hostList, host)
	}
	sort.Strings(hostList)
	targets := make([]Target, 0, len(hostList))
	for _, host := range hostList {
		organizations := make([]string, 0, len(organizationsByHost[host]))
		for organization := range organizationsByHost[host] {
			organizations = append(organizations, organization)
		}
		sort.Strings(organizations)
		enterprise := ""
		for candidate := range enterprisesByHost[host] {
			enterprise = candidate
			break
		}
		targets = append(targets, Target{Host: host, Organizations: organizations, Enterprise: enterprise})
	}
	return targets
}

func legacyDeriveReplayTargets(report *VerticalSliceReport) []Target {
	organizationsByHost := map[string][]string{}
	var hosts []string
	addHost := func(host string) {
		host = strings.ToLower(host)
		if host == "" {
			return
		}
		if _, seen := organizationsByHost[host]; !seen {
			organizationsByHost[host] = nil
			hosts = append(hosts, host)
		}
	}
	for _, organization := range report.Organizations {
		addHost(organization.Scope.Host)
		host := strings.ToLower(organization.Scope.Host)
		if host != "" {
			organizationsByHost[host] = append(organizationsByHost[host], organization.Scope.Name)
		}
	}
	for _, target := range report.Targets {
		addHost(target.Host)
	}
	enterpriseByHost := map[string]string{}
	credentialKindByHost := map[string]CredentialKind{}
	for _, outcome := range report.Outcomes {
		host := strings.ToLower(outcome.Scope.Host)
		if host == "" {
			continue
		}
		if outcome.Scope.Kind == EnterpriseScope && outcome.Scope.Name != "" {
			if _, known := enterpriseByHost[host]; !known {
				enterpriseByHost[host] = outcome.Scope.Name
			}
		}
		if outcome.CredentialKind != "" && outcome.CredentialKind != NoCredential {
			if _, known := credentialKindByHost[host]; !known {
				credentialKindByHost[host] = outcome.CredentialKind
			}
		}
	}
	sort.Strings(hosts)
	targets := make([]Target, 0, len(hosts))
	for _, host := range hosts {
		deployment := Cloud
		if host != "github.com" && !strings.HasSuffix(host, ".ghe.com") {
			deployment = Server
		}
		names := append([]string{}, organizationsByHost[host]...)
		sort.Strings(names)
		credentials := CredentialReferences{Kind: NoCredential}
		if kind, ok := credentialKindByHost[host]; ok {
			credentials.Kind = kind
		}
		targets = append(targets, Target{
			Host: host, Deployment: deployment, Enterprise: enterpriseByHost[host],
			Organizations: names, Credentials: credentials,
		})
	}
	return targets
}

// replayConcurrency is pinned to 1, NOT ParseConfig's own documented default
// of 4, for both the context-bound and legacy-fallback replay paths.
// Measured directly against this package's own >=50-repository full-pipeline
// fixture under `go test -race`, Concurrency:4 reproduced an intermittent
// (roughly 1-in-3 runs) permanent hang: a goroutine dump during one such hang
// showed a stuck raw syscall inside os.(*Root).Rename, occurring specifically
// under replay's dual evidence-store access pattern (collectFromReplay reads
// concurrently from replaySource while concurrently writing into a separate
// scratch store, both os.Root-backed, from multiple goroutines at once).
// This is a bounded empirical fix for that one observed, reproducible
// failure mode in this specific usage pattern -- confirmed stable across
// 10+ repeated full-pipeline runs with comparable wall-clock cost (replay
// has no live rate limit for higher concurrency to usefully hide) -- not a
// general claim that concurrent os.Root access is inherently unsafe in Go,
// which was not independently root-caused or isolated from this package's
// own dual-store pattern (for example, bisecting whether it reproduces with
// a single shared store, or whether it is platform/toolchain-specific).
// Raising this above 1 (up to the package maximum of 4, per
// NewRequestBudget) remains possible if a future change needs it, but must
// be re-verified against this same fixture under `-race` first.
const replayConcurrency = 1

// legacyReplayConfig builds a best-effort CustomerConfig for the FALLBACK,
// no-bound-context replay path alone: every setting is either a
// ParseConfig-matching default (lookback window, critical property/values,
// production-environment pattern) or inferred from the claimed report
// itself (RepositoryCap, from any organization's claimed Population.Sample.Cap
// when stratified sampling genuinely activated) -- never genuine, bound
// collection-time provenance. A legacy bundle replayed against these
// inferred/defaulted settings never earns AnalysisVerified=true regardless
// of how cleanly the comparison happens to come out (see
// legacyDeriveReplayTargets and ReplayVerticalSlice's contextBound
// contract); this exists only so a legacy bundle's evidence INTEGRITY can
// still be meaningfully exercised, not to claim full analysis verification
// for a customer run whose real lookback/critical-property/repository-cap
// configuration was never captured.
func legacyReplayConfig(targets []Target, report *VerticalSliceReport) *CustomerConfig {
	property := "criticality"
	repositoryCap := 300
	for _, organization := range report.Organizations {
		if organization.Population != nil && organization.Population.Sample != nil && organization.Population.Sample.Cap > 0 {
			repositoryCap = organization.Population.Sample.Cap
			break
		}
	}
	return &CustomerConfig{
		Targets: targets, RepositoryCap: repositoryCap, LookbackDays: 90, Concurrency: replayConcurrency,
		CriticalProperty: &property, CriticalValues: []string{"critical", "high", "tier-0", "tier-1"},
		ProductionEnvRegex: "prod|production|live|release",
		Thresholds:         map[string]float64{}, EvidenceDir: "./evidence",
	}
}

// targetsFromContext and configFromContext build replay's Targets/CustomerConfig
// directly from a genuine, bound RunCollectionContext -- the PRIMARY replay
// path -- with zero inference from the claimed report itself: deployment,
// host, enterprise, organizations, credential kind and SCIM routing mode all
// come from the context's own RunCollectionContextTarget entries (not
// pattern-matched from a hostname or scanned out of the claim's own
// Outcomes), and RepositoryCap/LookbackDays/CriticalProperty/CriticalValues/
// ProductionEnvRegex all come from the context's own fields (not fixed
// defaults). This is what makes AnalysisVerified meaningful: a claim is
// compared against a reconstruction driven by the run's own genuinely
// authorized configuration, not a replay-time guess that happens to produce
// a match.
func targetsFromContext(runContext *RunCollectionContext) []Target {
	targets := make([]Target, 0, len(runContext.Targets))
	for _, target := range runContext.Targets {
		targets = append(targets, Target{
			Host: target.Host, Deployment: target.Deployment, Enterprise: target.Enterprise,
			Organizations: append([]string{}, target.Organizations...),
			Credentials:   CredentialReferences{Kind: target.CredentialKind},
			SCIMMode:      target.SCIMMode,
		})
	}
	return targets
}

func configFromContext(runContext *RunCollectionContext, targets []Target) *CustomerConfig {
	var criticalProperty *string
	if runContext.CriticalProperty != "" {
		value := runContext.CriticalProperty
		criticalProperty = &value
	}
	return &CustomerConfig{
		Targets: targets, RepositoryCap: runContext.RepositoryCap, LookbackDays: runContext.LookbackDays,
		Concurrency: replayConcurrency, CriticalProperty: criticalProperty,
		CriticalValues: append([]string{}, runContext.CriticalValues...), ProductionEnvRegex: runContext.ProductionEnvRegex,
		Thresholds: map[string]float64{}, EvidenceDir: "./evidence",
	}
}

// ReplayVerticalSlice re-derives an entire VerticalSliceReport -- every
// organization, population, critical-population determination, repository,
// feature signal and pooled/per-organization metric -- directly from
// replaySource by calling the exact same runVerticalSliceWithStore pipeline
// a live `ghqr assess run` uses, through a replay-mode client factory that
// never makes a network call. This is genuine, full reconstruction of the
// collection/analysis/pooling pipeline: no algorithm from any of those
// stages is duplicated, narrowed or proxied anywhere in this path. A
// scratch, discarded evidence store satisfies the pipeline's own
// *EvidenceStore parameter so the directory under verification is never
// mutated (WriteReport never touches replaySource itself).
//
// evidenceByExactRef reads a specific, content-addressed evidence object
// pair by its own cited paths (an outcome's EvidenceRefs entries), never by
// the mutable per-feature "latest" manifest pointer EvidenceStore.LoadJSON
// resolves through. Loading by exact ref is what lets an OLDER report's own
// cited evidence remain independently verifiable even after a LATER run
// into the SAME evidence directory moves that logical (scope, collectorID,
// feature) key's manifest pointer to point at different, equally genuine
// content: the underlying content-addressed objects under objects/ are
// never overwritten (EvidenceStore.writeObject refuses to replace existing
// content with different bytes at the same content-addressed path), only
// the separate, mutable "latest" pointer can move. This mirrors LoadJSON's
// own self-consistency checks (digest match, content-addressed path
// matches its own contents, re-sanitization is a no-op) without needing a
// new exported EvidenceStore method, using the same-package field access
// Go already grants every file in this package.
func evidenceByExactRef(store *EvidenceStore, dataPath, metadataPath string) ([]byte, EvidenceMetadata, error) {
	if !filepath.IsLocal(dataPath) || !filepath.IsLocal(metadataPath) {
		return nil, EvidenceMetadata{}, fmt.Errorf("cited evidence reference escapes its root")
	}
	raw, err := store.root.ReadFile(dataPath)
	if err != nil {
		return nil, EvidenceMetadata{}, fmt.Errorf("read cited raw evidence object %s: %w", dataPath, err)
	}
	metaBytes, err := store.root.ReadFile(metadataPath)
	if err != nil {
		return nil, EvidenceMetadata{}, fmt.Errorf("read cited evidence sidecar %s: %w", metadataPath, err)
	}
	var metadata EvidenceMetadata
	if err := json.Unmarshal(metaBytes, &metadata); err != nil {
		return nil, EvidenceMetadata{}, fmt.Errorf("decode cited evidence sidecar: %w", err)
	}
	if err := validateEvidenceMetadata(metadata); err != nil {
		return nil, EvidenceMetadata{}, err
	}
	if digestBytes(raw) != metadata.ContentSHA256 {
		return nil, EvidenceMetadata{}, fmt.Errorf("cited evidence object digest mismatch")
	}
	objectID := digestBytes(append(append([]byte{}, raw...), metaBytes...))
	if dataPath != "objects/"+objectID+".json" || metadataPath != "objects/"+objectID+".meta.json" {
		return nil, EvidenceMetadata{}, fmt.Errorf("cited evidence pair reference does not match its own contents")
	}
	clean, _, err := store.redactor.JSON(raw)
	if err != nil {
		return nil, EvidenceMetadata{}, fmt.Errorf("sanitize cited evidence: %w", err)
	}
	if !bytes.Equal(clean, raw) {
		return nil, EvidenceMetadata{}, fmt.Errorf("cited evidence object needs sanitized re-import before use")
	}
	return clean, metadata, nil
}

// verifyOutcomeEvidenceRefs checks one claimed CollectorOutcome's own cited
// EvidenceRefs against its own claimed identity (Scope/CollectorID/Feature
// per page, profile) and genuinely counts a page verified only once its
// EXACT cited object pair resolves and matches: a logical-key lookup that
// happens to find SOMETHING at the current "latest" manifest pointer for
// this (scope, collectorID, feature) is never sufficient (it could be
// unrelated content a later, unrelated run wrote there afterward); outcomes
// predating EvidenceRefs (legacy bundles collected before this field
// existed) fall back to the logical lookup, the only binding such a bundle
// ever had.
func verifyOutcomeEvidenceRefs(store *EvidenceStore, profile *Profile, outcome CollectorOutcome) (verified int, failures []string) {
	if len(outcome.EvidenceRefs) == 0 {
		for page := 1; page <= outcome.Pages; page++ {
			if _, _, _, loadErr := store.LoadJSON(outcome.Scope, outcome.CollectorID, pageFeatureName(outcome.Feature, page)); loadErr != nil {
				failures = append(failures, fmt.Sprintf(
					"%s/%s page %d (%s): %v", outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), loadErr))
				continue
			}
			verified++
		}
		return verified, failures
	}
	if len(outcome.EvidenceRefs) != outcome.Pages*2 {
		failures = append(failures, fmt.Sprintf(
			"%s/%s (%s): claims %d page(s) but cites %d evidence reference(s), not the %d a genuine collection would record",
			outcome.CollectorID, outcome.Feature, outcome.Scope.Key(), outcome.Pages, len(outcome.EvidenceRefs), outcome.Pages*2))
		return 0, failures
	}
	for page := 1; page <= outcome.Pages; page++ {
		dataPath, metadataPath := outcome.EvidenceRefs[(page-1)*2], outcome.EvidenceRefs[(page-1)*2+1]
		_, metadata, err := evidenceByExactRef(store, dataPath, metadataPath)
		expectedFeature := pageFeatureName(outcome.Feature, page)
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf(
				"%s/%s page %d (%s): %v", outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), err))
		case metadata.Scope != outcome.Scope:
			failures = append(failures, fmt.Sprintf(
				"%s/%s page %d: cited evidence scope %s does not match the claimed scope %s",
				outcome.CollectorID, outcome.Feature, page, metadata.Scope.Key(), outcome.Scope.Key()))
		case metadata.CollectorID != outcome.CollectorID:
			failures = append(failures, fmt.Sprintf(
				"%s/%s page %d (%s): cited evidence collector %q does not match the claimed collector",
				outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), metadata.CollectorID))
		case metadata.Feature != expectedFeature:
			failures = append(failures, fmt.Sprintf(
				"%s/%s page %d (%s): cited evidence feature %q does not match the expected page-qualified feature %q",
				outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), metadata.Feature, expectedFeature))
		case metadata.ProfileVersion != profile.Version || metadata.ProfileSHA256 != profile.SHA256:
			failures = append(failures, fmt.Sprintf(
				"%s/%s page %d (%s): cited evidence was collected under a different profile (%s/%s) than the active one (%s/%s)",
				outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(),
				metadata.ProfileVersion, metadata.ProfileSHA256, profile.Version, profile.SHA256))
		case outcome.CredentialKind != "" && metadata.CredentialKind != outcome.CredentialKind:
			failures = append(failures, fmt.Sprintf(
				"%s/%s page %d (%s): cited evidence was collected under credential kind %q, not this outcome's own claimed %q",
				outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), metadata.CredentialKind, outcome.CredentialKind))
		default:
			verified++
		}
	}
	return verified, failures
}

// genuine, immutable RunCollectionContext (see run_collection_context.go)
// this call bound its own Targets/CustomerConfig reconstruction to
// directly -- no inferred Deployment from a claimed hostname, no
// enterprise/credential-kind/SCIM-mode recovered from the claim's own
// Outcomes, no defaulted lookback/critical-property/values/production-regex,
// no trusted claimed repository-cap. false means evidenceDirectory predates
// that mechanism (a legacy bundle) and this call fell back to
// legacyDeriveReplayTargets/legacyReplayConfig's best-effort inference
// instead; callers (VerifyReportEvidence) must never treat a legacy
// replay's comparison result as full AnalysisVerified, regardless of how
// cleanly it happens to come out, since it was never bound to the run's
// actual genuine configuration.
func ReplayVerticalSlice(ctx context.Context, profile *Profile, report *VerticalSliceReport, evidenceDirectory string) (*VerticalSliceReport, bool, error) {
	if evidenceDirectory == "" {
		return nil, false, fmt.Errorf("replay requires an explicit evidence directory")
	}
	// Opened here, not accepted as a possibly-nil *EvidenceStore parameter:
	// a nil replaySource would make newReplayClientFactory's constructed
	// clients fall through to the live network path, which must never
	// happen for a replay. Any failure to open evidenceDirectory is a hard
	// error, never a silent live-network fallback.
	replaySource, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		return nil, false, fmt.Errorf("open evidence directory for replay: %w", err)
	}
	defer func() { _ = replaySource.Close() }()

	var runContext *RunCollectionContext
	var contextBound bool
	if report.ContextRef != "" {
		// The report names a SPECIFIC, content-addressed context: this
		// evidence directory may hold many runs' worth of history, each
		// with its own report citing its own context, so this is the exact
		// historical context this specific report was collected under,
		// never whichever context happens to be "latest" in the directory
		// right now. A cited ref that fails to resolve or self-verify is a
		// hard error (the report's own claimed provenance is broken or
		// forged), never silently downgraded to the legacy no-context path.
		loaded, loadErr := LoadRunCollectionContextByRef(replaySource, report.ContextRef)
		if loadErr != nil {
			return nil, false, fmt.Errorf("report cites run collection context ref %s which could not be verified: %w",
				report.ContextRef, loadErr)
		}
		runContext = loaded
		contextBound = true
	} else {
		// A ref-less report is ALWAYS treated as genuinely context-less,
		// regardless of whether evidenceDirectory happens to contain SOME
		// context file: multi-run/multi-context storage is a first-class,
		// fully supported scenario (see run_collection_context.go), so an
		// evidence directory's "latest convenience copy" can easily belong
		// to a DIFFERENT, later run than the one that actually produced
		// THIS report. Deliberately never calling LoadRunCollectionContext
		// here at all: a ref-less report must never be silently upgraded
		// to contextBound=true merely because some other run's context
		// happens to be sitting in the same directory right now -- only a
		// report that itself cites its own ref earns contextBound=true.
		contextBound = false
	}

	var targets []Target
	var config *CustomerConfig
	var at time.Time
	if contextBound {
		if err := contextAuthorizesScope(runContext, deriveClaimedScope(report)); err != nil {
			return nil, true, fmt.Errorf("claimed report scope exceeds what its bound run collection context "+
				"actually authorized: %w", err)
		}
		// A report's own claimed Outcomes list is checked field-by-field
		// against its bound context's immutable OriginalOutcomes snapshot
		// (see that field's own doc): this is the ONLY place a zero-page
		// transport failure's Reason/Status text, or the omission of a
		// genuinely recorded outcome entirely, can be caught -- neither
		// compareVerticalSliceReports' derived-fact comparison nor the
		// per-page evidence-integrity loop below has anything to check
		// such a claim against, since a zero-page outcome has no persisted
		// evidence of its own. A context with NO bound OriginalOutcomes at
		// all (written via the plain WriteRunCollectionContext, or one
		// genuinely predating this mechanism) is an explicit compatibility
		// downgrade, never a silent pass: a report claiming ANY zero-page
		// outcome under such a context can never be proven genuine by
		// anything in this pipeline, so this is a hard refusal, not a
		// no-op skip -- a forged zero-page Reason/Status under a
		// config-only context must never earn the same AnalysisVerified
		// a genuinely outcomes-bound context's identical, honest claim
		// would. A report with NO zero-page outcomes at all under such a
		// context has nothing this specific gap could hide, and proceeds
		// as before (every one of its outcomes has real pages for
		// compareVerticalSliceReports/the integrity loop to independently
		// check instead).
		if len(runContext.OriginalOutcomes) == 0 {
			for _, outcome := range report.Outcomes {
				if outcome.Pages == 0 {
					return nil, true, fmt.Errorf("%s/%s (%s): this outcome has zero pages and this report's bound "+
						"run collection context has no OriginalOutcomes inventory at all, so this claim's own "+
						"Reason/Status cannot be independently proven genuine by anything in this pipeline; "+
						"refusing to treat a config-only, outcomes-unbound context as sufficient proof for a "+
						"zero-page claim -- a genuine run must bind its original outcomes via "+
						"WriteRunCollectionContextWithOutcomes", outcome.CollectorID, outcome.Feature, outcome.Scope.Key())
				}
			}
		} else if mismatches := compareOriginalOutcomes(report.Outcomes, runContext.OriginalOutcomes); len(mismatches) > 0 {
			return nil, true, fmt.Errorf("claimed report outcomes do not match this run's own bound original "+
				"outcome inventory: %s", strings.Join(mismatches, "; "))
		}
		targets = targetsFromContext(runContext)
		config = configFromContext(runContext, targets)
		at = runContext.CollectedAt
	} else {
		targets = legacyDeriveReplayTargets(report)
		config = legacyReplayConfig(targets, report)
		at = report.CollectedAt
	}
	if len(targets) == 0 {
		// A report/context that claims no organizations or target-level
		// (host) operational results at all has nothing for the pipeline
		// to analyze; this is the legitimately empty case (see
		// reportClaimsAnalysis), not a failure to replay. Returning an
		// equally empty report here lets compareVerticalSliceReports find
		// nothing to iterate on either side, rather than forcing a
		// synthetic single-organization target nothing actually claimed.
		// contextBound is still reported honestly: a context that itself
		// legitimately has zero targets is still a genuine, bound context,
		// not a compatibility fallback.
		return &VerticalSliceReport{
			Profile: profile.Summary(), CollectedAt: report.CollectedAt,
			ImplementedCollectors: RunImplementedCollectorIDs(), ImplementedEvaluators: []string{},
			Organizations: []OrganizationRunResult{}, Targets: []TargetOperationalResult{}, Metrics: map[string]Metric{},
			Outcomes: []CollectorOutcome{}, Caveats: []string{},
		}, contextBound, nil
	}
	if err := config.Validate(); err != nil {
		return nil, contextBound, fmt.Errorf("build replay configuration: %w", err)
	}
	// exactSource is a throwaway store seeded ONLY from report's own cited
	// EvidenceRefs (read from replaySource via the exact, content-addressed
	// evidenceByExactRef binding -- never replaySource's own mutable,
	// movable per-feature "latest" manifest pointers): this is what makes
	// collectFromReplay's ordinary, UNCHANGED logical-key lookup resolve to
	// precisely the historical pages THIS report cited, even after a later,
	// unrelated run into the SAME evidenceDirectory has since moved some of
	// those same logical keys to point at different (equally genuine)
	// content. Reusing collectFromReplay's existing resolution algorithm
	// unmodified (zero duplicated pagination/lookup logic, no network
	// fallback) by simply pointing it at a frozen, historically-exact
	// source instead of the live directory directly.
	exactSourceDirectory, err := os.MkdirTemp("", "ghqr-replay-exact-source-*")
	if err != nil {
		return nil, contextBound, fmt.Errorf("create exact-ref replay source directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(exactSourceDirectory) }()
	exactSource, err := materializeExactReplaySource(replaySource, profile, report, contextBound, exactSourceDirectory)
	if err != nil {
		return nil, contextBound, fmt.Errorf("materialize exact-ref replay source from report's own cited evidence: %w", err)
	}
	defer func() { _ = exactSource.Close() }()

	scratchDirectory, err := os.MkdirTemp("", "ghqr-replay-pipeline-*")
	if err != nil {
		return nil, contextBound, fmt.Errorf("create replay scratch directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratchDirectory) }()
	scratchStore, err := OpenEvidenceStore(scratchDirectory, NewRedactor())
	if err != nil {
		return nil, contextBound, fmt.Errorf("open replay scratch store: %w", err)
	}
	defer func() { _ = scratchStore.Close() }()

	if at.IsZero() {
		at = time.Now().UTC()
	}
	frozen := frozenClock{at: at}
	replayed, runErr := runVerticalSliceWithStore(ctx, profile, config, targets, scratchStore, frozen,
		newReplayClientFactory(profile, exactSource, frozen))
	return replayed, contextBound, runErr
}

// materializeExactReplaySource builds a fresh, throwaway EvidenceStore
// (scratchDirectory, expected empty) seeded EXCLUSIVELY from report's own
// cited EvidenceRefs: every page any outcome in report.Outcomes claims is
// read from originalSource via its own exact, content-addressed ref
// (evidenceByExactRef -- the identical binding VerifyReportEvidence's
// integrity loop uses), re-validated against that outcome's own claimed
// Scope/CollectorID/page-qualified-Feature identity, and re-persisted
// verbatim (original metadata preserved byte for byte -- CollectedAt,
// SourceKind, CredentialKind, HTTPStatus, Complete, Endpoint, Redactions
// are never re-stamped as if this were a fresh collection). Re-persisting
// via the ordinary EvidenceStore.SaveJSON registers the FRESH scratch
// store's own per-feature manifest to point at exactly this historical
// object -- there is no "latest" ambiguity to resolve, since each
// (scope, collectorID, feature+page) key is written to this store exactly
// once, directly from the report's own history.
//
// contextBound reflects whether report itself carries a cited, verified
// RunCollectionContext (see ReplayVerticalSlice): when true, this report
// claims to be a MODERN, fully exact-ref-bound report, so an outcome
// claiming nonzero Pages with zero EvidenceRefs is NEVER a legitimate
// legacy gap to best-effort fall back on -- a genuine modern collection
// always records EvidenceRefs alongside Pages together, so missing refs on
// an otherwise context-bound report can only mean the refs were stripped
// (accidentally or to launder a tampered claim through whatever the
// evidence directory's own mutable logical manifest currently resolves
// to), and this is a hard, unrecoverable failure: it must never silently
// fall back to originalSource's own logical, movable lookup. Only when
// contextBound is false (a genuinely legacy, pre-ContextRef bundle, which
// VerifyReportEvidence's own switch already forces AnalysisVerified=false
// for unconditionally) is the best-effort per-outcome logical fallback
// below ever attempted, purely for whatever diagnostic comparison value it
// still offers -- never as a path that could let a context-bound report
// reach a passing verdict without its own exact refs.
//
// An outcome with zero EvidenceRefs and zero claimed Pages (a genuine
// NotRun/CollectionFailed/Inapplicable collector call) seeds nothing: its
// absence from the scratch store IS the faithful replay of that original
// non-collection, reproduced automatically once collectFromReplay's own
// unmodified "no replay evidence is stored for this feature" path runs
// against it. Everything else is a hard failure: a page-count/
// reference-count mismatch, an unresolvable or identity-mismatched cited
// ref, is never silently skipped or treated as "pagination ended early",
// since that would quietly undercount a report's own genuine claim rather
// than surfacing the real problem. Every resolved page's own recorded
// ProfileVersion/ProfileSHA256/CredentialKind is also cross-checked
// (against the profile this replay is actually running under, and against
// the outcome's own claimed CredentialKind respectively) even though the
// outcome's Scope/CollectorID/Feature key alone cannot express either: a
// page genuinely collected under a different profile or a different
// credential than this outcome itself claims is rejected, not silently
// seeded as if its identity were fully proven by the logical key match
// alone. Two outcomes (or two pages) that resolve to the SAME logical
// (scope, collectorID, feature) identity but cite DIFFERENT, conflicting
// content are rejected as an ambiguous duplicate -- never silently
// resolved by whichever one happens to be seeded last overwriting the
// scratch store's own manifest pointer for that key.
// pageProvablyTerminal is the one gate for trusting a page's own
// EvidenceMetadata.PaginationContinues as proof that pagination genuinely
// ended at it: only a confident false (the page was validly checked and
// genuinely carried no next link, or pagination was never requested for
// that call at all) counts. nil (genuinely unknown: a pre-this-field
// legacy page, or one whose Link header could not even be parsed) and true
// (a valid next link was genuinely found) are both NOT provably terminal --
// nil is never silently treated as an equivalent to a confirmed false.
func pageProvablyTerminal(value *bool) bool {
	return value != nil && !*value
}

func materializeExactReplaySource(originalSource *EvidenceStore, profile *Profile, report *VerticalSliceReport, contextBound bool, scratchDirectory string) (*EvidenceStore, error) {
	scratch, err := OpenEvidenceStore(scratchDirectory, NewRedactor())
	if err != nil {
		return nil, fmt.Errorf("open scratch replay source: %w", err)
	}
	seedFailed := true
	defer func() {
		if seedFailed {
			_ = scratch.Close()
		}
	}()
	seenDigests := map[string]string{}
	checkDuplicate := func(outcome CollectorOutcome, feature string, metadata EvidenceMetadata) error {
		key := outcome.Scope.Key() + "/" + outcome.CollectorID + "/" + feature
		if existing, ok := seenDigests[key]; ok && existing != metadata.ContentSHA256 {
			return fmt.Errorf("%s (%s): resolves to two different, conflicting pieces of evidence content across "+
				"this report's own outcomes; refusing to silently pick one over the other", key, outcome.Scope.Key())
		}
		seenDigests[key] = metadata.ContentSHA256
		return nil
	}
	for _, outcome := range report.Outcomes {
		if len(outcome.EvidenceRefs) == 0 {
			if outcome.Pages == 0 {
				continue
			}
			if contextBound {
				return nil, fmt.Errorf("%s/%s (%s): report is context-bound (claims modern, exact-ref provenance) "+
					"but this outcome claims %d page(s) with zero EvidenceRefs; a genuine modern collection always "+
					"records EvidenceRefs alongside Pages together, so refusing to fall back to a movable logical "+
					"lookup for it -- stripped or missing refs on an otherwise context-bound report can never be "+
					"treated as a legitimate legacy gap", outcome.CollectorID, outcome.Feature, outcome.Scope.Key(), outcome.Pages)
			}
			var lastPageMetadata EvidenceMetadata
			for page := 1; page <= outcome.Pages; page++ {
				feature := pageFeatureName(outcome.Feature, page)
				raw, metadata, _, loadErr := originalSource.LoadJSON(outcome.Scope, outcome.CollectorID, feature)
				if loadErr != nil {
					return nil, fmt.Errorf("%s/%s page %d (%s): legacy outcome has no EvidenceRefs and its logical "+
						"evidence could not be resolved either, so an exact replay source cannot be seeded for it: %w",
						outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), loadErr)
				}
				if outcome.CredentialKind != "" && metadata.CredentialKind != outcome.CredentialKind {
					return nil, fmt.Errorf("%s/%s page %d (%s): resolved evidence was collected under credential "+
						"kind %q, not this outcome's own claimed %q; refusing to seed a mismatched page",
						outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), metadata.CredentialKind, outcome.CredentialKind)
				}
				if err := checkDuplicate(outcome, feature, metadata); err != nil {
					return nil, err
				}
				if _, saveErr := scratch.SaveJSON(raw, metadata); saveErr != nil {
					return nil, fmt.Errorf("%s/%s page %d (%s): seeding the exact replay source failed: %w",
						outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), saveErr)
				}
				lastPageMetadata = metadata
			}
			if !pageProvablyTerminal(lastPageMetadata.PaginationContinues) {
				return nil, fmt.Errorf("%s/%s (%s): the last logically-resolved page's own recorded metadata "+
					"does not prove this organization/collector/feature's pagination had actually finished at "+
					"page %d (missing/unparseable terminal proof is never treated as confirmed termination); "+
					"refusing to seed a truncated replay source", outcome.CollectorID, outcome.Feature,
					outcome.Scope.Key(), outcome.Pages)
			}
			continue
		}
		if len(outcome.EvidenceRefs) != outcome.Pages*2 {
			return nil, fmt.Errorf("%s/%s (%s): claims %d page(s) but cites %d evidence reference(s); refusing to "+
				"seed an exact replay source from a reference count that does not match the claimed page count",
				outcome.CollectorID, outcome.Feature, outcome.Scope.Key(), outcome.Pages, len(outcome.EvidenceRefs))
		}
		var lastPageMetadata EvidenceMetadata
		for page := 1; page <= outcome.Pages; page++ {
			dataPath, metadataPath := outcome.EvidenceRefs[(page-1)*2], outcome.EvidenceRefs[(page-1)*2+1]
			raw, metadata, refErr := evidenceByExactRef(originalSource, dataPath, metadataPath)
			if refErr != nil {
				return nil, fmt.Errorf("%s/%s page %d (%s): %w",
					outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), refErr)
			}
			// An ImportOnly outcome (ghes.cli/ghes.backup, every ui.*/
			// ext.* capture, manual.interview/manual.document) has no live
			// pagination concept at all: it is addressed at its own bare
			// feature name (ImportJSON/loadImportedPayload never apply
			// the REST page-suffix convention, since an import is
			// inherently a single, complete record, not one page of a
			// paginated sequence), so its expected identity is the bare
			// Feature, not pageFeatureName's "-page-NNNNNN" form a live
			// collector's own CollectGET loop always produces.
			expectedFeature := pageFeatureName(outcome.Feature, page)
			if outcome.Readiness == ImportOnly {
				expectedFeature = outcome.Feature
			}
			switch {
			case metadata.Scope != outcome.Scope || metadata.CollectorID != outcome.CollectorID || metadata.Feature != expectedFeature:
				return nil, fmt.Errorf("%s/%s page %d (%s): cited evidence identity (scope %s, collector %q, "+
					"feature %q) does not match this outcome's own claim; refusing to seed a mismatched page into "+
					"the exact replay source", outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(),
					metadata.Scope.Key(), metadata.CollectorID, metadata.Feature)
			case metadata.ProfileVersion != profile.Version || metadata.ProfileSHA256 != profile.SHA256:
				return nil, fmt.Errorf("%s/%s page %d (%s): cited evidence was collected under a different "+
					"profile (%s/%s) than the one this replay is running under (%s/%s); refusing to seed it",
					outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(),
					metadata.ProfileVersion, metadata.ProfileSHA256, profile.Version, profile.SHA256)
			case outcome.CredentialKind != "" && metadata.CredentialKind != outcome.CredentialKind:
				return nil, fmt.Errorf("%s/%s page %d (%s): cited evidence was collected under credential kind "+
					"%q, not this outcome's own claimed %q; refusing to seed a mismatched page",
					outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), metadata.CredentialKind, outcome.CredentialKind)
			}
			if err := checkDuplicate(outcome, expectedFeature, metadata); err != nil {
				return nil, err
			}
			if _, saveErr := scratch.SaveJSON(raw, metadata); saveErr != nil {
				return nil, fmt.Errorf("%s/%s page %d (%s): seeding the exact replay source failed: %w",
					outcome.CollectorID, outcome.Feature, page, outcome.Scope.Key(), saveErr)
			}
			lastPageMetadata = metadata
		}
		// Terminal-pagination proof is a live-REST-pagination concept only:
		// an ImportOnly outcome has no "next page" to prove absent (its
		// own PaginationContinues is never even set by the import path,
		// which is genuinely correct -- not a gap to paper over), so it is
		// exempt from this specific check, never required to carry proof
		// no import mechanism produces in the first place.
		if outcome.Readiness != ImportOnly {
			// Terminal-pagination proof: CollectGET's own pagination loop only
			// ever exits cleanly (without an early return/break on failure) when
			// the fetched page's own response carried no valid next link, so a
			// genuine outcome's LAST page always has PaginationContinues
			// confidently false, unconditionally -- regardless of whatever
			// Status/Complete this outcome itself goes on to claim. Anything
			// other than a confident false -- a confident true (a valid next
			// link was genuinely found), OR nil (unknown: a pre-this-field
			// legacy page, or one whose Link header could not even be parsed,
			// which still often indicates the server WAS trying to express a
			// next link) -- means this specific page cannot be trusted as
			// proof pagination genuinely ended here, from that page's own
			// immutable, content-addressed metadata (never a directory-
			// presence/page-count heuristic, which cannot distinguish a
			// genuinely truncated claim from this same logical key's own
			// unrelated sibling run). pageProvablyTerminal is the one and only
			// gate for "this page's own claim to be the end of pagination may
			// be trusted"; nil is never silently equivalent to a confirmed
			// false.
			if outcome.Pages > 0 && !pageProvablyTerminal(lastPageMetadata.PaginationContinues) {
				return nil, fmt.Errorf("%s/%s (%s): the last cited page's own recorded metadata does not prove this "+
					"organization/collector/feature's pagination had actually finished at page %d -- missing/"+
					"unparseable terminal proof is never treated as confirmed termination, so this outcome's own "+
					"claimed page count cannot be trusted as complete; refusing to seed a truncated replay source",
					outcome.CollectorID, outcome.Feature, outcome.Scope.Key(), outcome.Pages)
			}
		}
	}
	seedFailed = false
	return scratch, nil
}

// compareVerticalSliceReports reports every semantically meaningful mismatch
// between a report's claim and what ReplayVerticalSlice genuinely
// reconstructed from stored evidence: organization population counts and
// critical-population membership, every analyzed repository's effective
// protection/workflow analysis/feature signals (matched by FullName, never
// assumed present), and every metric key the claim reports as known. An
// organization or repository the claim does not mention at all is not
// compared (nothing claimed, nothing to contradict); one it does claim
// something for, with replay unable to find a corresponding entry at all, is
// reported as an explicit mismatch -- an unbound claim is never silently
// accepted merely because some other part of the same report happened to
// replay cleanly.
// compareOriginalOutcomes compares a report's own claimed Outcomes list
// against the complete, original list its bound RunCollectionContext
// captured at collection time (see RunCollectionContext.OriginalOutcomes'
// own doc) -- the ONLY place a zero-page outcome's Reason/Status (a
// transport failure before any HTTP response was observed, a
// permission-denied organization, an inapplicable collector) can ever be
// independently proven genuine, since such an outcome has no persisted
// evidence pages for any other check (compareVerticalSliceReports'
// derived-fact comparison, or the per-page evidence-integrity loop) to
// verify against. A claimed outcome absent from the bound original, one
// present in both but differing in ANY field, or an original outcome the
// claim simply omits, are all reported as mismatches -- a claim must never
// be allowed to selectively drop or reword a genuinely recorded result. A
// context with no bound OriginalOutcomes at all (nil/empty -- one written
// before this mechanism existed, or by a caller/test that never captured
// real outcomes) has nothing to compare against and is never treated as a
// mismatch merely for being absent.
func compareOriginalOutcomes(claimed, original []CollectorOutcome) []string {
	if len(original) == 0 {
		return nil
	}
	identityKey := func(outcome CollectorOutcome) string {
		return outcome.Scope.Key() + "/" + outcome.CollectorID + "/" + outcome.Feature
	}
	originalByKey := make(map[string]CollectorOutcome, len(original))
	for _, outcome := range original {
		originalByKey[identityKey(outcome)] = outcome
	}
	claimedByKey := make(map[string]CollectorOutcome, len(claimed))
	for _, outcome := range claimed {
		claimedByKey[identityKey(outcome)] = outcome
	}
	keys := make([]string, 0, len(originalByKey)+len(claimedByKey))
	seenKeys := map[string]bool{}
	for key := range originalByKey {
		keys = append(keys, key)
		seenKeys[key] = true
	}
	for key := range claimedByKey {
		if !seenKeys[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var mismatches []string
	for _, key := range keys {
		originalOutcome, hasOriginal := originalByKey[key]
		claimedOutcome, hasClaimed := claimedByKey[key]
		switch {
		case hasOriginal && !hasClaimed:
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: this run's own bound original outcome inventory records this collector/feature, but the claimed report omits it entirely", key))
		case !hasOriginal && hasClaimed:
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: claimed outcome has no corresponding entry in this run's own bound original outcome inventory at all", key))
		case !reflect.DeepEqual(claimedOutcome, originalOutcome):
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: claimed outcome %+v does not match this run's own bound original outcome %+v", key, claimedOutcome, originalOutcome))
		}
	}
	return mismatches
}

func compareVerticalSliceReports(claimed, replayed *VerticalSliceReport) []string {
	var failures []string
	replayedOrganizations := make(map[string]OrganizationRunResult, len(replayed.Organizations))
	for _, organization := range replayed.Organizations {
		replayedOrganizations[organization.Scope.Key()] = organization
	}
	for _, claimedOrganization := range claimed.Organizations {
		key := claimedOrganization.Scope.Key()
		replayedOrganization, ok := replayedOrganizations[key]
		if !ok {
			failures = append(failures, fmt.Sprintf(
				"%s: claimed organization has no corresponding organization in this run's own replayed analysis at all", key))
			continue
		}
		failures = append(failures, compareOrganizationPopulations(key, claimedOrganization.Population, replayedOrganization.Population)...)
		failures = append(failures, compareOrganizationOperational(key, claimedOrganization.Operational, replayedOrganization.Operational)...)

		replayedRepositories := make(map[string]RepositoryRunResult, len(replayedOrganization.Repositories))
		for _, repository := range replayedOrganization.Repositories {
			replayedRepositories[repository.FullName] = repository
		}
		for _, claimedRepository := range claimedOrganization.Repositories {
			replayedRepository, ok := replayedRepositories[claimedRepository.FullName]
			if !ok {
				if claimedRepository.EffectiveProtection != nil || claimedRepository.Workflows != nil ||
					claimedRepository.PullRequests != nil || claimedRepository.ActionsRuns != nil ||
					claimedRepository.Access != nil || claimedRepository.ContentsProbe != nil ||
					claimedRepository.CommitVerification != nil || claimedRepository.SecretsEnv != nil ||
					claimedRepository.Releases != nil || claimedRepository.DiscussionsProjects != nil ||
					claimedRepository.CodeScanningAnalyses != nil || claimedRepository.AttestationCoverage != nil {
					failures = append(failures, fmt.Sprintf(
						"%s: claimed analysis for a repository this run's own replayed inventory does not contain at all",
						claimedRepository.FullName))
				}
				continue
			}
			for _, mismatch := range compareRepositoryResult(claimedRepository, replayedRepository) {
				failures = append(failures, fmt.Sprintf("%s: %s", claimedRepository.FullName, mismatch))
			}
		}
	}
	failures = append(failures, compareMetricMaps(claimed.Metrics, replayed.Metrics)...)
	failures = append(failures, compareTargetOperationalResults(claimed.Targets, replayed.Targets)...)
	return failures
}

// compareTargetOperationalResults compares every per-target (not
// per-organization) operational result a report claims -- enterprise info,
// GHES management-console basics, Actions permissions, code security
// configurations, audit log/streams, billing, Copilot, policies and SCIM
// users -- against what ReplayVerticalSlice genuinely reconstructed for
// that same host. These fields live outside Organizations[] entirely
// (TargetOperationalResult is keyed by host, not by organization scope), so
// without this comparison an enterprise-only report (no Organizations
// claimed at all) or a report that pads its organization-level claims with
// a fabricated enterprise-level fact would never be checked against
// anything replay independently establishes. A host the claim does not
// mention at all is not compared (nothing claimed, nothing to contradict);
// one it does claim something for, with replay finding no corresponding
// entry, is reported as an explicit mismatch, matching the same contract as
// every other comparison in this file. A plain field-by-field equality
// check (not a bespoke per-field comparator) is sufficient here: every
// TargetOperationalResult sub-field is itself a typed, already-sanitized
// result struct (never raw provider payload), so no field can legitimately
// differ for a genuine, untampered claim -- including EnterpriseAuditLog's
// own RequestedSince/RequestedUntil, which a genuine replay reproduces
// exactly: runVerticalSliceWithStore reads its own clock exactly once and
// reuses that single value for report.CollectedAt and every lookback
// computation, and ReplayVerticalSlice seeds its own replay invocation
// with a frozenClock pinned to that SAME original report.CollectedAt --
// never a second, independent wall-clock read -- so there is no genuine
// drift left to except.
func compareTargetOperationalResults(claimed, replayed []TargetOperationalResult) []string {
	var failures []string
	replayedByHost := make(map[string]TargetOperationalResult, len(replayed))
	for _, target := range replayed {
		replayedByHost[strings.ToLower(target.Host)] = target
	}
	for _, claimedTarget := range claimed {
		hostKey := strings.ToLower(claimedTarget.Host)
		replayedTarget, ok := replayedByHost[hostKey]
		if !ok {
			failures = append(failures, fmt.Sprintf(
				"%s: claimed target-level (enterprise/instance) operational results, replay established none for this host at all", claimedTarget.Host))
			continue
		}
		if !reflect.DeepEqual(claimedTarget, replayedTarget) {
			failures = append(failures, fmt.Sprintf(
				"%s: claimed target-level operational results do not match this run's own independently replayed results", claimedTarget.Host))
		}
	}
	return failures
}

func compareOrganizationPopulations(organizationKey string, claimed, replayed *OrganizationPopulation) []string {
	if claimed == nil {
		return nil
	}
	if replayed == nil {
		return []string{fmt.Sprintf("%s: claimed a population, replay established none", organizationKey)}
	}
	var mismatches []string
	if claimed.TotalRepositories != replayed.TotalRepositories {
		mismatches = append(mismatches, fmt.Sprintf(
			"%s: claimed total_repositories=%d, replay derives %d", organizationKey, claimed.TotalRepositories, replayed.TotalRepositories))
	}
	if claimed.ActiveRepositoryCount != replayed.ActiveRepositoryCount {
		mismatches = append(mismatches, fmt.Sprintf(
			"%s: claimed active_repository_count=%d, replay derives %d", organizationKey, claimed.ActiveRepositoryCount, replayed.ActiveRepositoryCount))
	}
	if claimed.Critical != nil && replayed.Critical != nil {
		if claimed.Critical.Method != replayed.Critical.Method {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: claimed critical-population method %q, replay derives %q (a tampered method can misrepresent "+
					"whether the critical population came from a configured custom property or the documented "+
					"recent-pushed fallback, which downstream confidence/caveat reporting depends on)",
				organizationKey, claimed.Critical.Method, replayed.Critical.Method))
		}
		claimedNames := append([]string{}, claimed.Critical.FullNames...)
		replayedNames := append([]string{}, replayed.Critical.FullNames...)
		sort.Strings(claimedNames)
		sort.Strings(replayedNames)
		if !equalStringMultisets(claimedNames, replayedNames) {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: claimed critical-population membership %v does not match this run's own independently replayed membership %v",
				organizationKey, claimedNames, replayedNames))
		}
	} else if claimed.Critical != nil && replayed.Critical == nil {
		mismatches = append(mismatches, fmt.Sprintf(
			"%s: claimed a critical-population determination, replay established none", organizationKey))
	}
	// Sample (the deterministic stratified-sample record, nil meaning the
	// full active population was in scope) is itself a small, fully typed,
	// already-sanitized derived result with no raw provider payload inside
	// it -- a genuine, untampered claim can never legitimately differ here,
	// so a full DeepEqual (rather than hand-picking Cap/PopulationSize) is
	// both sufficient and future-proof against fields added later. A
	// tampered Sample (for example an inflated PopulationSize or a smaller
	// Cap than genuinely applied) changes exactly the sampled-vs-unsampled
	// confidence distinction evaluators key off of, so this must never be
	// silently unchecked.
	if (claimed.Sample == nil) != (replayed.Sample == nil) {
		mismatches = append(mismatches, fmt.Sprintf(
			"%s: claimed sample presence does not match this run's own independently replayed sample presence (claimed nil=%v, replay nil=%v)",
			organizationKey, claimed.Sample == nil, replayed.Sample == nil))
	} else if claimed.Sample != nil && replayed.Sample != nil && !reflect.DeepEqual(*claimed.Sample, *replayed.Sample) {
		mismatches = append(mismatches, fmt.Sprintf(
			"%s: claimed sample %+v does not match this run's own independently replayed sample %+v",
			organizationKey, *claimed.Sample, *replayed.Sample))
	}
	return mismatches
}

// compareOrganizationOperational compares a claimed organization's Phase 4
// operational collector bundle (alert lifecycles, code security
// configuration coverage, membership/role/governance inventories, and
// every other field this struct carries) against what replay independently
// reconstructed, via a full struct equality check rather than a hand-picked
// subset: like RepositoryFeatureSignal/TargetOperationalResult, every field
// here is itself a typed, already-sanitized derived-signal result, never
// raw provider payload, so a genuine, untampered claim can never
// legitimately differ in any field -- including ones added to this
// struct after this comparison function was first written, which are
// covered automatically with zero future maintenance. This includes
// AuditLog's own RequestedSince/RequestedUntil: a genuine replay reproduces
// these exactly (see compareTargetOperationalResults' own doc for why), so
// there is no genuine drift left to except, and a deliberately widened or
// narrowed claimed lookback window is caught like any other field.
func compareOrganizationOperational(organizationKey string, claimed, replayed *OrganizationOperationalResult) []string {
	if claimed == nil {
		return nil
	}
	if replayed == nil {
		return []string{fmt.Sprintf("%s: claimed organization-scoped operational results, replay established none at all", organizationKey)}
	}
	if reflect.DeepEqual(*claimed, *replayed) {
		return nil
	}
	return []string{fmt.Sprintf(
		"%s: claimed organization-scoped operational results do not match this run's own independently replayed results", organizationKey)}
}

// compareRepositoryResult compares one repository's claimed vs replayed
// RepositoryRunResult. DefaultBranch and the three fields with their own
// dedicated, semantically-scoped comparators (EffectiveProtection/
// Workflows/Feature) are checked explicitly; every other sub-result this
// struct carries (PullRequests, ActionsRuns, Access, ContentsProbe,
// CommitVerification, SecretsEnv, Releases, DiscussionsProjects,
// CodeScanningAnalyses, AttestationCoverage, and any added later) is
// covered by a catch-all DeepEqual with the explicitly-handled fields
// zeroed first -- the same "zero what is separately compared, then
// DeepEqual the rest" pattern compareFeatureSignal already establishes,
// giving every current and future sub-result field real coverage without
// per-field maintenance.
func compareRepositoryResult(claimed, replayed RepositoryRunResult) []string {
	var failures []string
	if claimed.DefaultBranch != replayed.DefaultBranch {
		failures = append(failures, fmt.Sprintf(
			"claimed default_branch=%q, replay derives %q", claimed.DefaultBranch, replayed.DefaultBranch))
	}
	failures = append(failures, compareEffectiveProtection(claimed.EffectiveProtection, replayed.EffectiveProtection)...)
	failures = append(failures, compareWorkflowAnalysis(claimed.Workflows, replayed.Workflows)...)
	failures = append(failures, compareFeatureSignal(claimed.Feature, replayed.Feature)...)
	claimed.FullName, replayed.FullName = "", ""
	claimed.DefaultBranch, replayed.DefaultBranch = "", ""
	claimed.EffectiveProtection, replayed.EffectiveProtection = nil, nil
	claimed.Workflows, replayed.Workflows = nil, nil
	claimed.Feature, replayed.Feature = RepositoryFeatureSignal{}, RepositoryFeatureSignal{}
	if !reflect.DeepEqual(claimed, replayed) {
		failures = append(failures, fmt.Sprintf(
			"claimed repository analysis %+v does not match this run's own independently replayed analysis %+v", claimed, replayed))
	}
	return failures
}

// compareFeatureSignal compares every field of a repository's claimed vs
// replayed RepositoryFeatureSignal via a full struct equality check (not a
// hand-picked subset of fields): this feature-coverage struct is itself a
// typed, already-sanitized derived-signal result (never raw provider
// payload), so a genuine, untampered claim can never legitimately differ in
// any field, including ones added after this comparison function was first
// written (for example CodeQLEligibleKnown/CodeQLOperationalKnown/
// CodeQLWorkflowReferenced/CodeQLDefaultSetupConfigured/
// CodeQLDefaultSetupConfiguredKnown). A full comparison means a newly added
// field is covered automatically, without this function needing a matching
// edit each time the struct grows; FullName is excluded only because the
// caller already matches claimed-vs-replayed repositories by that same
// field before ever reaching this comparison.
func compareFeatureSignal(claimed, replayed RepositoryFeatureSignal) []string {
	claimed.FullName, replayed.FullName = "", ""
	if reflect.DeepEqual(claimed, replayed) {
		return nil
	}
	return []string{fmt.Sprintf(
		"feature signal: claimed %+v does not match this run's own independently replayed signal %+v", claimed, replayed)}
}

// compareMetricMaps checks every metric key EITHER side reports (the union
// of claimed and replayed keys, not just the claim's own keys) against the
// other side, for BOTH the pooled Overall value and every PerOrganization
// entry. Consuming only the claim's own known keys would miss two real
// attack surfaces: a per-organization value tampered while the pooled
// Overall coincidentally stays correct (SEC-016/ARC-093/ARC-104 all
// consume per-organization metrics directly), and a claimed-known value
// quietly downgraded to Unavailable to hide an unfavorable fact entirely
// (a naive "only walk claimed-known keys" loop never even visits such a
// key). See compareMetricValuesForKey for the exact four-way known/unknown
// matrix this now evaluates for every (key, scope) pair.
func compareMetricMaps(claimed, replayed map[string]Metric) []string {
	keySet := make(map[string]bool, len(claimed)+len(replayed))
	for key := range claimed {
		keySet[key] = true
	}
	for key := range replayed {
		keySet[key] = true
	}
	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var failures []string
	for _, key := range keys {
		claimedMetric, replayedMetric := claimed[key], replayed[key]
		failures = append(failures, compareMetricValuesForKey(key, "overall", claimedMetric.Overall, replayedMetric.Overall)...)
		organizationKeySet := make(map[string]bool, len(claimedMetric.PerOrganization)+len(replayedMetric.PerOrganization))
		for organizationKey := range claimedMetric.PerOrganization {
			organizationKeySet[organizationKey] = true
		}
		for organizationKey := range replayedMetric.PerOrganization {
			organizationKeySet[organizationKey] = true
		}
		organizationKeys := make([]string, 0, len(organizationKeySet))
		for organizationKey := range organizationKeySet {
			organizationKeys = append(organizationKeys, organizationKey)
		}
		sort.Strings(organizationKeys)
		for _, organizationKey := range organizationKeys {
			failures = append(failures, compareMetricValuesForKey(key, organizationKey,
				claimedMetric.PerOrganization[organizationKey], replayedMetric.PerOrganization[organizationKey])...)
		}
	}
	return failures
}

// compareMetricValuesForKey compares one claimed vs replayed MetricValue
// pair (either a metric's pooled Overall value, or one of its
// PerOrganization entries, named by scopeLabel for readable failures)
// across all four combinations of genuinely-known status. Neither side
// known is never a mismatch (nothing asserted on either side to
// contradict). Claimed known with replay not establishing it is the
// long-standing "replay cannot independently prove this" mismatch. Claimed
// NOT known (Unavailable, or simply absent from the claim's own map) while
// replay's own pooling independently establishes a known value is an
// equally serious, separately-named mismatch: a claim that silently
// downgrades an unfavorable known fact to unavailable must never pass
// merely because the comparison loop only walked the claim's own known
// keys. Both known is checked via metricValuesEqual's strict, exact
// per-field comparison.
func compareMetricValuesForKey(metricKey, scopeLabel string, claimedValue, replayedValue MetricValue) []string {
	claimedKnown := claimedValue.Status == MetricKnown
	replayedKnown := replayedValue.Status == MetricKnown
	switch {
	case !claimedKnown && !replayedKnown:
		return nil
	case claimedKnown && !replayedKnown:
		return []string{fmt.Sprintf(
			"metric %s (%s): claimed known (%s), but replay of this run's own stored evidence cannot independently establish it",
			metricKey, scopeLabel, metricSummary(claimedValue))}
	case !claimedKnown && replayedKnown:
		return []string{fmt.Sprintf(
			"metric %s (%s): claimed unavailable/unknown, but replay of this run's own stored evidence "+
				"independently establishes a known value (%s) -- a known fact cannot be silently downgraded to "+
				"unavailable", metricKey, scopeLabel, metricSummary(replayedValue))}
	default:
		if !metricValuesEqual(claimedValue, replayedValue) {
			return []string{fmt.Sprintf(
				"metric %s (%s): claimed %s, replay derives %s", metricKey, scopeLabel, metricSummary(claimedValue), metricSummary(replayedValue))}
		}
		return nil
	}
}

// metricValuesEqual is the strict, exact-field comparator two genuinely
// Known MetricValue observations must satisfy to be considered the same
// claim -- every payload field independently, not just Number, and with
// EXACT equality, not any tolerance: the underlying computation this run's
// own evaluators perform (a sum, a ratio, a percentage derived from
// Numerator/Denominator) is fully deterministic given the same stored
// evidence and the same unmodified Go algorithm, and a float64 round-trips
// bit-for-bit through Go's own encoding/json (it marshals the shortest
// decimal representation that re-parses to the identical IEEE754 value),
// so a genuine, untampered claim can never legitimately differ by even one
// ULP. Any nonzero tolerance here is an arbitrary magic number that could
// let a threshold-adjacent tamper (a deliberately tiny Number delta with an
// unchanged Numerator/Denominator, internally inconsistent with how every
// genuine percentage/ratio MetricValue is actually derived) pass as
// "verified" merely because it happened to fall under whatever epsilon was
// chosen. Numerator and Denominator are checked independently of Number,
// not skipped merely because Number already matched: a tampered Denominator
// with an unchanged, coincidentally-matching Number is still a real,
// catchable tamper (it changes what the SAME claimed Number would imply
// about population size).
func metricValuesEqual(a, b MetricValue) bool {
	numbersEqual := func(x, y *float64) bool {
		if (x == nil) != (y == nil) {
			return false
		}
		return x == nil || *x == *y
	}
	if !numbersEqual(a.Number, b.Number) || !numbersEqual(a.Numerator, b.Numerator) ||
		!numbersEqual(a.Denominator, b.Denominator) || !numbersEqual(a.Baseline, b.Baseline) || !numbersEqual(a.Current, b.Current) {
		return false
	}
	if !boolPointersEqual(a.Boolean, b.Boolean) || !stringPointersEqual(a.Text, b.Text) {
		return false
	}
	return stringSlicePointersEqual(a.List, b.List) && dictionaryPointersEqual(a.Dictionary, b.Dictionary)
}

// compareEffectiveProtection reports every semantically meaningful
// difference between a report's claimed EffectiveBranchProtection for a
// repository and the one ReplayVerticalSlice genuinely re-derived from
// that run's own stored evidence (via the real ComputeEffectiveBranchProtection
// call inside the replayed pipeline). It compares only the fields that
// evaluators actually gate on (protection presence, force-push/deletion
// blocking, signatures, and the overall completeness this run could
// actually prove), not every cosmetic field, so a claim backed by
// equivalent-but-differently-ordered evidence is never flagged as
// tampered.
func compareEffectiveProtection(claimed, replayed *EffectiveBranchProtection) []string {
	if claimed == nil {
		return nil
	}
	if replayed == nil {
		return []string{"claimed effective default-branch protection, but replay produced no result at all from this run's own stored evidence"}
	}
	var mismatches []string
	note := func(field string, claimedValue, replayedValue any) {
		mismatches = append(mismatches, fmt.Sprintf(
			"%s: claimed %v, replay of this run's own stored evidence derives %v", field, claimedValue, replayedValue))
	}
	if claimed.PullRequestRequired != replayed.PullRequestRequired {
		note("pr_required", claimed.PullRequestRequired, replayed.PullRequestRequired)
	}
	if claimed.BlockForcePush != replayed.BlockForcePush {
		note("block_force_push", claimed.BlockForcePush, replayed.BlockForcePush)
	}
	if claimed.BlockDeletion != replayed.BlockDeletion {
		note("block_deletion", claimed.BlockDeletion, replayed.BlockDeletion)
	}
	if claimed.Signatures != replayed.Signatures {
		note("signatures", claimed.Signatures, replayed.Signatures)
	}
	if claimed.Unprotected != replayed.Unprotected {
		note("unprotected", claimed.Unprotected, replayed.Unprotected)
	}
	// A claim of stronger completeness than replay can itself prove from the
	// same stored evidence is exactly the "metadata existence is not proof"
	// gap this replay closes: replay must independently reach at least the
	// claimed completeness, not merely exist.
	if completenessRank(claimed.Completeness) > completenessRank(replayed.Completeness) {
		mismatches = append(mismatches, fmt.Sprintf(
			"completeness: claimed %s, but replay of this run's own stored evidence only independently establishes %s",
			claimed.Completeness, replayed.Completeness))
	}
	return mismatches
}

// completenessRank orders OutcomeStatus from least to most proven, so two
// completeness claims can be compared for "at least as proven as" rather
// than requiring byte-for-byte equality (a replay that independently reaches
// a stronger, fully-known completeness than a cautious original claim is not
// a contradiction).
func completenessRank(status OutcomeStatus) int {
	switch status {
	case CollectionOK:
		return 2
	case CollectionPartial:
		return 1
	default:
		return 0
	}
}

// compareWorkflowAnalysis reports every repository whose claimed action
// reference catalogue (Raw/Category/PinStatus, order-independent, duplicates
// preserved as a multiset) does not match what the replayed pipeline's own
// AnalyzeRepositoryWorkflows call genuinely re-derives from this run's own
// stored workflow-content evidence.
func compareWorkflowAnalysis(claimed, replayed *WorkflowAnalysisResult) []string {
	if claimed == nil {
		return nil
	}
	if replayed == nil {
		return []string{"claimed workflow action-reference analysis, but replay produced no result at all from this run's own stored evidence"}
	}
	claimedKeys := actionReferenceKeys(claimed.References)
	replayedKeys := actionReferenceKeys(replayed.References)
	if equalStringMultisets(claimedKeys, replayedKeys) {
		return nil
	}
	return []string{fmt.Sprintf(
		"workflow action references: claimed %d reference(s) do not match the %d this run's own stored workflow "+
			"content, replayed through AnalyzeRepositoryWorkflows, actually supports", len(claimedKeys), len(replayedKeys))}
}

func actionReferenceKeys(references []ActionReference) []string {
	keys := make([]string, 0, len(references))
	for _, reference := range references {
		keys = append(keys, reference.Raw+"\x00"+reference.Category+"\x00"+reference.PinStatus)
	}
	sort.Strings(keys)
	return keys
}

func equalStringMultisets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
