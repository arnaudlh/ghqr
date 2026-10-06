// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// runCollectionContextSchemaVersion versions this file's own JSON SHAPE
// (field names/types), independent of the profile version and of
// collectionEngineVersion below: a future field addition or removal to
// RunCollectionContext itself is what this tracks, never "did the
// population/critical-population/pooling algorithm change."
const runCollectionContextSchemaVersion = "1"

// collectionEngineVersion identifies the version of the actual collection/
// analysis ALGORITHM (population determination, critical-population
// recency/custom-property policy, lookback window semantics, pooling) that
// produced evidence bound to a given context -- deliberately a SEPARATE
// concept from runCollectionContextSchemaVersion (which only tracks this
// struct's own JSON field shape) and from Profile.Version (which tracks the
// declarative control catalogue, not this engine's own code). A future
// change to runVerticalSliceWithStore's own population/critical-population/
// window-policy semantics that would make an OLDER context's replay no
// longer faithfully reproducible under the CURRENT engine must bump this
// constant; LoadRunCollectionContext then rejects the mismatch explicitly
// rather than silently replaying an incompatible older run under new
// algorithm semantics and calling the result AnalysisVerified.
const collectionEngineVersion = "1"

// runCollectionContextPath is the "latest convenience copy" of the most
// recently written context in an evidence directory: a fixed, well-known
// top-level path (not nested under scopes/<host>/<kind>/<name>/, since this
// is run-level configuration, not one collector's scoped page), used by
// LoadRunCollectionContext's no-ref fallback lookup. Unlike every other
// evidence object in this store, this path is intentionally NOT
// collision-checked on write (see WriteRunCollectionContext): a fixed,
// write-once-only path would make a second genuine collection run into the
// SAME evidence directory fail merely because its own context's CollectedAt
// (or any other genuinely different setting) differs from an earlier run's,
// even though both runs' raw collector pages coexist in the same directory
// without conflict. Each context's own immutable, canonical copy instead
// lives at its own content-addressed path (runCollectionContextObjectPath),
// which genuinely cannot collide across runs; THAT path, not this one, is
// what a report's own ContextRef names and what replay actually binds to
// once a report carries one.
const runCollectionContextPath = "run-context.json"

func runCollectionContextObjectPath(digest string) string {
	return "contexts/" + digest + ".json"
}

// RunCollectionContextTarget is one Target's immutable, non-secret
// collection-time configuration: explicit host/deployment/enterprise/
// organizations/credential KIND (never a token, username or password
// value)/SCIM routing mode, exactly as config.Validate()/ResolvedTargets()
// already authorized them for the live run that collected this evidence.
type RunCollectionContextTarget struct {
	Host           string         `json:"host"`
	Deployment     Deployment     `json:"deployment"`
	Enterprise     string         `json:"enterprise,omitempty"`
	Organizations  []string       `json:"organizations"`
	CredentialKind CredentialKind `json:"credential_kind"`
	SCIMMode       string         `json:"scim_mode,omitempty"`
}

// RunCollectionContext is the immutable, non-secret record of exactly which
// explicit configuration a live collection run used, captured at collection
// time from the real *CustomerConfig/*Profile the run was actually
// authorized and validated against (never a replay-time inference, invented
// default or a value read from the claimed report's own analysis). It
// excludes every credential VALUE (TokenEnv/ManagementUsernameEnv/
// ManagementPasswordEnv name no secret by themselves, but this record omits
// even those identifiers, carrying only CredentialKind) and reads no global
// process state at replay time: once written, it is the sole source
// ReplayVerticalSlice binds its own CustomerConfig/Target reconstruction to.
//
// ContentSHA256 makes this record self-verifying independent of WHERE it is
// read from: it is computed over this exact struct with ContentSHA256
// itself zeroed, so any edit to any OTHER field (a same-shape, same-schema
// tamper that would otherwise load without error) invalidates it. This is
// deliberately not merely "the context lives at a content-addressed path,
// so its path implies its hash": a caller handed this struct value directly
// (not re-reading it from the store) can still independently confirm it was
// never altered since it was written.
type RunCollectionContext struct {
	SchemaVersion      string                       `json:"schema_version"`
	EngineVersion      string                       `json:"engine_version"`
	ProfileVersion     string                       `json:"profile_version"`
	ProfileSHA256      string                       `json:"profile_sha256"`
	CollectedAt        time.Time                    `json:"collected_at"`
	Targets            []RunCollectionContextTarget `json:"targets"`
	RepositoryCap      int                          `json:"repository_cap"`
	LookbackDays       int                          `json:"lookback_days"`
	CriticalProperty   string                       `json:"critical_property,omitempty"`
	CriticalValues     []string                     `json:"critical_values,omitempty"`
	ProductionEnvRegex string                       `json:"production_env_regex"`
	// OriginalOutcomes is the complete, verbatim CollectorOutcome list
	// RunVerticalSlice itself captured the moment this same run finished
	// collecting -- before any export, serialization or external handling
	// had a chance to alter it. This is the ONLY place a zero-page outcome
	// (a transport failure before any HTTP response was even observed, a
	// permission-denied organization, an inapplicable collector) can ever
	// be independently proven genuine: such an outcome has no persisted
	// evidence pages at all, so neither compareVerticalSliceReports'
	// derived-fact comparison nor VerifyReportEvidence's per-page integrity
	// loop has anything to check its own claimed Reason/Status text
	// against, and a replayed reconstruction of it can only ever synthesize
	// a generic "no replay evidence is stored for this feature" substitute,
	// never recover the true original reason. Binding the complete,
	// original list here -- self-digested alongside every other context
	// field via ContentSHA256 -- lets a later verification/export pass
	// compare a supplied report's own Outcomes field-by-field against this
	// trusted baseline (catching a tamper compareVerticalSliceReports was
	// never positioned to see) and lets collection reporting (the exported
	// collection-log.json/summary.md) surface the TRUE original text for
	// every outcome, not a replay-synthesized substitute. Omitted (nil) for
	// a context some other caller/test constructs without real outcomes to
	// bind; such a context simply has nothing to compare/report from this
	// mechanism, never treated as a tampered absence.
	OriginalOutcomes []CollectorOutcome `json:"original_outcomes,omitempty"`
	CheckDefinitions []byte             `json:"check_definitions,omitempty"`
	ContentSHA256    string             `json:"content_sha256"`
}

// contextDigest computes the self-verifying content digest: a canonical
// JSON encoding of context with ContentSHA256 itself forced empty first, so
// the digest never depends on (or is invalidated merely by recomputing)
// itself.
func contextDigest(context RunCollectionContext) (string, error) {
	context.ContentSHA256 = ""
	canonical, err := json.Marshal(context)
	if err != nil {
		return "", fmt.Errorf("canonicalize run collection context: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// buildRunCollectionContext derives a RunCollectionContext directly from the
// real profile/config/resolved-targets/collection timestamp a live run
// actually used, with no inference and no defaulting beyond what that
// config itself already resolved via config.Validate()/ResolvedTargets().
func buildRunCollectionContext(profile *Profile, config *CustomerConfig, targets []Target, collectedAt time.Time,
	originalOutcomes []CollectorOutcome) (RunCollectionContext, error) {
	contextTargets := make([]RunCollectionContextTarget, 0, len(targets))
	for _, target := range targets {
		contextTargets = append(contextTargets, RunCollectionContextTarget{
			Host: target.Host, Deployment: target.Deployment, Enterprise: target.Enterprise,
			Organizations:  append([]string{}, target.Organizations...),
			CredentialKind: target.Credentials.Kind, SCIMMode: target.SCIMMode,
		})
	}
	criticalProperty := ""
	if config.CriticalProperty != nil {
		criticalProperty = *config.CriticalProperty
	}
	context := RunCollectionContext{
		SchemaVersion: runCollectionContextSchemaVersion, EngineVersion: collectionEngineVersion,
		ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectedAt: collectedAt, Targets: contextTargets, RepositoryCap: config.RepositoryCap,
		LookbackDays: config.LookbackDays, CriticalProperty: criticalProperty,
		CriticalValues: append([]string{}, config.CriticalValues...), ProductionEnvRegex: config.ProductionEnvRegex,
		OriginalOutcomes: append([]CollectorOutcome{}, originalOutcomes...),
	}
	if config.CheckDefinitions != nil {
		if err := config.CheckDefinitions.Validate(profile); err != nil {
			return RunCollectionContext{}, err
		}
		context.CheckDefinitions = append([]byte{}, config.CheckDefinitions.sourceJSON...)
	}
	digest, err := contextDigest(context)
	if err != nil {
		return RunCollectionContext{}, err
	}
	context.ContentSHA256 = digest
	return context, nil
}

// WriteRunCollectionContext persists the exact, real configuration a live
// collection run was authorized and validated against (profile.Validate()/
// config.Validate()/config.ResolvedTargets() all having already succeeded
// for this same run). It returns the context's own content digest (its
// permanent, content-addressed ref): callers that themselves own a
// publishable run report (see VerticalSliceReport.ContextRef) MUST record
// this exact value there before publishing that report to any caller,
// library or CLI, so a later verification/replay binds to precisely this
// historical context, never "whatever the latest context in this directory
// happens to be by the time someone gets around to verifying."
//
// The canonical, permanent copy is written ONCE to a content-addressed path
// derived from its own digest (runCollectionContextObjectPath): this can
// never collide with any OTHER run's context in the same evidence
// directory, however many runs that directory accumulates, because
// genuinely different configuration/collection-time content always hashes
// to a genuinely different path, and genuinely identical content writing
// to the same path again is the existing, safe, already-collision-checked
// no-op EvidenceStore.writeObject itself already guarantees. A convenience
// "latest" copy is ALSO written to the fixed runCollectionContextPath, but
// as a plain overwrite (not collision-checked): unlike every other evidence
// object in this store, this one fixed path is expected to change across
// repeated runs into the same directory, and must never block a second
// genuine collection merely because its own context's CollectedAt (or any
// other genuinely different setting) differs from an earlier run's.
func WriteRunCollectionContext(store *EvidenceStore, profile *Profile, config *CustomerConfig, targets []Target, collectedAt time.Time) (string, error) {
	return WriteRunCollectionContextWithOutcomes(store, profile, config, targets, collectedAt, nil)
}

// WriteRunCollectionContextWithOutcomes is WriteRunCollectionContext's
// counterpart for a caller that also has the run's own, just-collected,
// complete CollectorOutcome list in hand (RunVerticalSlice, immediately
// after its own collection loop finishes and before any export/caller
// handling can alter it): originalOutcomes is bound into the context
// verbatim (see RunCollectionContext.OriginalOutcomes' own doc) and covered
// by the SAME self-digest every other context field already is. A nil/empty
// originalOutcomes behaves identically to WriteRunCollectionContext (no
// outcomes bound, nothing to compare/report from this specific mechanism).
func WriteRunCollectionContextWithOutcomes(store *EvidenceStore, profile *Profile, config *CustomerConfig,
	targets []Target, collectedAt time.Time, originalOutcomes []CollectorOutcome) (string, error) {
	if store == nil {
		return "", fmt.Errorf("writing a run collection context requires an evidence store")
	}
	context, err := buildRunCollectionContext(profile, config, targets, collectedAt, originalOutcomes)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(context)
	if err != nil {
		return "", fmt.Errorf("encode run collection context: %w", err)
	}
	if err := store.writeObject(runCollectionContextObjectPath(context.ContentSHA256), data); err != nil {
		return "", fmt.Errorf("persist run collection context: %w", err)
	}
	if err := store.atomicWrite(runCollectionContextPath, data); err != nil {
		return "", fmt.Errorf("persist latest run collection context pointer: %w", err)
	}
	return context.ContentSHA256, nil
}

// errRunCollectionContextAbsent distinguishes "no context was ever written
// for this evidence directory" (a legacy bundle collected before this
// mechanism existed, or one some other tool produced) from any other read
// failure (a corrupt, truncated or tampered file, which must still surface
// as a hard error, never be silently treated as merely "absent").
var errRunCollectionContextAbsent = errors.New("evidence directory has no bound run collection context")

// verifyLoadedContext decodes and self-verifies raw context bytes: schema
// version, engine version and the embedded content digest must all match
// exactly, or the content is rejected outright. This is what makes a
// same-shape, same-schema field edit (for example silently bumping
// lookback_days by one) detectable even though it remains syntactically
// valid JSON that would otherwise decode without error.
func verifyLoadedContext(data []byte) (*RunCollectionContext, error) {
	var context RunCollectionContext
	if err := json.Unmarshal(data, &context); err != nil {
		return nil, fmt.Errorf("decode run collection context: %w", err)
	}
	if context.SchemaVersion != runCollectionContextSchemaVersion {
		return nil, fmt.Errorf("run collection context schema %q is not the %q this build understands",
			context.SchemaVersion, runCollectionContextSchemaVersion)
	}
	if context.EngineVersion != collectionEngineVersion {
		return nil, fmt.Errorf("run collection context engine version %q is not the %q this build's collection/"+
			"analysis algorithm understands; replaying it under a different engine version's window/pooling "+
			"policy would not faithfully reproduce the original run", context.EngineVersion, collectionEngineVersion)
	}
	claimedDigest := context.ContentSHA256
	if claimedDigest == "" {
		return nil, fmt.Errorf("run collection context is missing its own content digest")
	}
	actualDigest, err := contextDigest(context)
	if err != nil {
		return nil, err
	}
	if claimedDigest != actualDigest {
		return nil, fmt.Errorf("run collection context content digest mismatch (claimed %s, recomputed %s): this "+
			"context's content was altered after it was written", claimedDigest, actualDigest)
	}
	return &context, nil
}

// LoadRunCollectionContext reads back the "latest convenience copy"
// (runCollectionContextPath) and self-verifies it. This is the fallback
// used only when no specific ContextRef is available to bind to (a report
// predating that field, or a direct caller with no report at all); any
// report carrying its own ContextRef must be loaded via
// LoadRunCollectionContextByRef instead, which binds to that EXACT
// historical context regardless of how many later runs have since
// overwritten this convenience copy.
func LoadRunCollectionContext(store *EvidenceStore) (*RunCollectionContext, error) {
	if store == nil {
		return nil, fmt.Errorf("loading a run collection context requires an evidence store")
	}
	data, err := store.root.ReadFile(runCollectionContextPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", runCollectionContextPath, errRunCollectionContextAbsent)
		}
		return nil, fmt.Errorf("read run collection context: %w", err)
	}
	return verifyLoadedContext(data)
}

// LoadRunCollectionContextByRef reads the canonical, content-addressed copy
// of the context named by ref (a VerticalSliceReport.ContextRef digest, as
// returned by WriteRunCollectionContext), independent of whatever the
// "latest convenience copy" at runCollectionContextPath currently holds.
// This is what lets an evidence directory accumulate many runs' worth of
// history, each with its own report citing its own context, and still have
// an OLDER report's verification/replay bind to precisely the context that
// was genuinely in effect when IT was collected -- never silently
// substituting whatever the newest run happened to leave behind.
func LoadRunCollectionContextByRef(store *EvidenceStore, ref string) (*RunCollectionContext, error) {
	if store == nil {
		return nil, fmt.Errorf("loading a run collection context requires an evidence store")
	}
	if ref == "" {
		return nil, fmt.Errorf("a run collection context ref is required")
	}
	data, err := store.root.ReadFile(runCollectionContextObjectPath(ref))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", ref, errRunCollectionContextAbsent)
		}
		return nil, fmt.Errorf("read run collection context %s: %w", ref, err)
	}
	context, err := verifyLoadedContext(data)
	if err != nil {
		return nil, err
	}
	if context.ContentSHA256 != ref {
		return nil, fmt.Errorf("run collection context stored at ref %s actually digests to %s: content-addressed "+
			"identity mismatch", ref, context.ContentSHA256)
	}
	return context, nil
}

// contextAuthorizesScope confirms the context's own claimed Targets fully
// cover (host-for-host, and for each host every organization/enterprise
// claimed) the set of hosts/organizations/enterprises a candidate set of
// targets would require -- used both to confirm a report's own organization
// claims never exceed what its bound context actually authorized, and to
// confirm a CURRENT caller's own config-derived targets are not narrower
// than what verification is being asked to accept (RunVerifiedOfflineEvaluation's
// own scope-authorization gate). It is deliberately a coverage check, not
// an exact-set-equality check: a context may legitimately authorize a
// superset a given candidate narrows into (for example a caller choosing to
// evaluate only some of the organizations a run originally collected).
func contextAuthorizesScope(context *RunCollectionContext, candidates []Target) error {
	authority := make([]Target, 0, len(context.Targets))
	for _, target := range context.Targets {
		authority = append(authority, Target{
			Host: target.Host, Enterprise: target.Enterprise, Organizations: target.Organizations,
		})
	}
	if err := targetsAuthorizeScope(authority, candidates); err != nil {
		return fmt.Errorf("%w by the bound run collection context", err)
	}
	return nil
}

// targetsAuthorizeScope is the shared primitive behind
// contextAuthorizesScope (a context authorizing a report's own claims) and
// RunVerifiedOfflineEvaluation's own scope-authorization gate (the CURRENT
// caller's config authorizing what a report/context claims): authority's
// own Host-scoped organizations/enterprises must fully cover candidates',
// host for host. It is a coverage check, not exact-set equality: authority
// may legitimately be a superset a given candidate narrows into (for
// example a caller choosing to evaluate only some of the organizations a
// run originally collected).
func targetsAuthorizeScope(authority, candidates []Target) error {
	authorizedHosts := map[string]bool{}
	authorizedOrganizations := map[string]map[string]bool{}
	authorizedEnterprises := map[string]map[string]bool{}
	for _, target := range authority {
		host := strings.ToLower(target.Host)
		authorizedHosts[host] = true
		if authorizedOrganizations[host] == nil {
			authorizedOrganizations[host] = map[string]bool{}
		}
		for _, organization := range target.Organizations {
			authorizedOrganizations[host][organization] = true
		}
		if target.Enterprise != "" {
			if authorizedEnterprises[host] == nil {
				authorizedEnterprises[host] = map[string]bool{}
			}
			authorizedEnterprises[host][target.Enterprise] = true
		}
	}
	for _, candidate := range candidates {
		host := strings.ToLower(candidate.Host)
		// A bare host-only claim (zero organizations, zero enterprise --
		// for example a target-level operational fact with no org/
		// enterprise scope of its own) must still name an authority-
		// configured host: the loops below only ever check organization/
		// enterprise MEMBERSHIP for a host already known, so a host never
		// mentioned in authority at all previously passed this function
		// vacuously, authorizing an operational claim about a host that was
		// never actually configured.
		if !authorizedHosts[host] {
			return fmt.Errorf("host %s is not authorized", candidate.Host)
		}
		for _, organization := range candidate.Organizations {
			if !authorizedOrganizations[host][organization] {
				return fmt.Errorf("organization %s/%s is not authorized", candidate.Host, organization)
			}
		}
		if candidate.Enterprise != "" && !authorizedEnterprises[host][candidate.Enterprise] {
			return fmt.Errorf("enterprise %s/%s is not authorized", candidate.Host, candidate.Enterprise)
		}
	}
	return nil
}
