// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-github/v83/github"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// sigstorePublicGoodTrustedRootJSON embeds Sigstore's own public-good
// trusted_root.json (certificate authorities, transparency-log and
// certificate-transparency-log signing keys) at build time. Embedding a
// static copy -- rather than fetching root.FetchTrustedRoot()'s live TUF
// client during collection or replay -- means a run's trust material is
// always the exact bytes compiled into this binary: no network access, no
// risk of a replayed run resolving different trust material than the run
// that originally collected the evidence. Refer to the Sigstore trust root
// specification for the schema this file follows:
// https://github.com/sigstore/root-signing/blob/main/README.md
//
//go:embed sigstore_trusted_root.json
var sigstorePublicGoodTrustedRootJSON []byte

// DefaultSigstoreTrustedRoot parses the embedded Sigstore public-good trust
// root once per run. A parse failure is a programming error in this
// package's embedded resource, never a runtime/network condition.
func DefaultSigstoreTrustedRoot() (root.TrustedMaterial, error) {
	trustedRoot, err := root.NewTrustedRootFromJSON(sigstorePublicGoodTrustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parse embedded Sigstore trusted root: %w", err)
	}
	return trustedRoot, nil
}

// githubActionsOIDCIssuer is the only certificate issuer this collector
// accepts: GitHub Actions' own Fulcio-federated OIDC identity provider. A
// release-asset attestation signed through any other OIDC issuer (including
// a different CI provider, or a developer's personal Sigstore identity) is
// never accepted as "verified" for this metric, regardless of a matching
// digest -- see verify.NewShortCertificateIdentity's documented issuer
// parameter.
const githubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

// supportedArtifactDigestAlgorithms maps a documented digest algorithm name
// (as GitHub's REST API and the in-toto attestation specification both use
// it, for example "sha256") to its expected decoded byte length. A digest
// string is only ever compared against another digest of the identical,
// explicitly-typed algorithm -- two hex strings of unrelated algorithms (or
// truncated/extended hex) are never treated as a coincidental match.
var supportedArtifactDigestAlgorithms = map[string]int{
	"sha256": 32,
	"sha512": 64,
}

// parsedArtifactDigest is a typed (algorithm, raw bytes) artifact digest. It
// exists so every digest comparison in this file is explicitly
// algorithm-aware: comparing bare hex values without a confirmed, identical
// algorithm on both sides risks a digest-confusion false match between (for
// example) a truncated sha512 value and an unrelated sha256 value of
// coincidentally similar length.
type parsedArtifactDigest struct {
	Algorithm string
	Bytes     []byte
}

// parseArtifactDigest parses a release asset's documented "algorithm:hex"
// digest format (GitHub REST API docs: the ReleaseAsset digest field, for
// example "sha256:abcd..."). An unsupported algorithm, missing separator, or
// hex value of the wrong length for its named algorithm is rejected
// outright rather than silently truncated or reinterpreted.
func parseArtifactDigest(raw string) (parsedArtifactDigest, error) {
	algorithm, hexValue, found := strings.Cut(raw, ":")
	if !found || algorithm == "" || hexValue == "" {
		return parsedArtifactDigest{}, fmt.Errorf("digest %q is not in the documented \"algorithm:hex\" format", raw)
	}
	algorithm = strings.ToLower(algorithm)
	expectedLength, supported := supportedArtifactDigestAlgorithms[algorithm]
	if !supported {
		return parsedArtifactDigest{}, fmt.Errorf("digest algorithm %q is not a supported type", algorithm)
	}
	decoded, err := hex.DecodeString(strings.ToLower(hexValue))
	if err != nil || len(decoded) != expectedLength {
		return parsedArtifactDigest{}, fmt.Errorf("digest %q is not a valid %d-byte %s hex value", raw, expectedLength, algorithm)
	}
	return parsedArtifactDigest{Algorithm: algorithm, Bytes: decoded}, nil
}

// attestationEvidenceFeature builds a digest-qualified, per-asset evidence
// feature name (the evidence store's own identity pattern requires
// `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`, so the digest's algorithm and hex bytes --
// never its raw "algorithm:hex" string, which contains a disallowed colon --
// are used directly). Every asset in a release has its own distinct digest,
// so this keeps every asset's collected attestation pages under their own
// stable, non-colliding evidence identity.
func attestationEvidenceFeature(digest parsedArtifactDigest) string {
	return "attestation-" + digest.Algorithm + "-" + hex.EncodeToString(digest.Bytes)
}

// attestationAssetFallbackFeature names a not-configured outcome (no
// network request attempted) for an asset whose digest is missing or
// malformed -- there is no usable digest to qualify the feature name with,
// so the asset's own stable numeric ID is used instead, keeping the
// reported outcome attributable to a specific asset.
func attestationAssetFallbackFeature(asset *github.ReleaseAsset) string {
	return "attestation-asset-" + strconv.FormatInt(asset.GetID(), 10)
}

// RepositoryAttestationAssetResult is one release asset's attestation
// outcome. DigestSubjectObserved is a diagnostic-only signal (an in-toto
// statement subject naming this exact digest was present in at least one
// attestation entry); it is never, on its own, a substitute for Verified --
// a statement can name the right digest while being signed by an untrusted
// or wrongly-identified signer, and Verified is the only field this
// collector's consumers may treat as "genuinely authenticated provenance".
type RepositoryAttestationAssetResult struct {
	AssetName             string `json:"asset_name"`
	AssetDigest           string `json:"asset_digest"`
	AttestationsObserved  int    `json:"attestations_observed"`
	DigestSubjectObserved bool   `json:"digest_subject_observed"`
	Verified              bool   `json:"verified"`
	// Complete is false when this asset's attestation status could not be
	// confidently determined at all (digest absent/malformed, the
	// attestations lookup failed or was concealed, or every returned
	// attestation entry was structurally malformed) -- Verified stays
	// false in that case too, but Complete distinguishes "confidently not
	// attested" from "unknown".
	Complete bool `json:"complete"`
}

// RepositoryAttestationCoverageResult is one repository's
// critical_repos_with_attestations_pct contribution: whether its latest
// published release's assets include at least one genuinely Sigstore-verified
// attestation. Complete is false whenever the underlying release inventory,
// or any asset's attestation status, could not be confidently determined;
// a false Complete always means "excluded from this metric's cohort", never
// "confirmed not attested".
type RepositoryAttestationCoverageResult struct {
	HasReleases bool                               `json:"has_releases"`
	ReleaseTag  string                             `json:"release_tag,omitempty"`
	Assets      []RepositoryAttestationAssetResult `json:"assets,omitempty"`
	AnyVerified bool                               `json:"any_verified"`
	Complete    bool                               `json:"complete"`
}

// RepositoryAttestationSignal is this repository's contribution to the
// pooled critical_repos_with_attestations_pct cohort, following the exact
// same Known/value separation RepositoryFeatureSignal already established
// for CodeQL/Dependency coverage (see AggregateFeatureCoverage): an unknown
// critical-population membership, or an unknown attestation-coverage
// result, excludes the repository from the pooled numerator/denominator
// rather than silently counting it as a confirmed non-member or a
// confirmed non-attestation.
type RepositoryAttestationSignal struct {
	FullName string `json:"full_name"`

	CriticalKnown bool `json:"critical_known"`
	Critical      bool `json:"critical"`

	AttestationVerifiedKnown bool `json:"attestation_verified_known"`
	AttestationVerified      bool `json:"attestation_verified"`
}

// AggregateAttestationCoverage pools per-repository attestation signals into
// critical_repos_with_attestations_pct's explicit numerator/denominator,
// through the identical cohort-sensitive helper AggregateFeatureCoverage
// already uses: an unknown critical-population membership or an unknown
// attestation-verification result for any repository forces the pooled
// metric to MetricUnavailable rather than reporting a known subset's
// percentage as if no peer were unresolved.
func AggregateAttestationCoverage(signals []RepositoryAttestationSignal) FeatureCoverage {
	var numerator, denominator, unknownEligibility, unknownOperational int
	for _, signal := range signals {
		if !signal.CriticalKnown {
			unknownEligibility++
			continue
		}
		if !signal.Critical {
			continue
		}
		denominator++
		switch {
		case !signal.AttestationVerifiedKnown:
			unknownOperational++
		case signal.AttestationVerified:
			numerator++
		}
	}
	metric := cohortCoverageMetric(numerator, denominator, unknownEligibility, unknownOperational, len(signals),
		"confirmed critical-population repositories whose latest published release has at least one "+
			"release asset with a genuinely Sigstore-verified attestation (matching digest, trusted "+
			"certificate chain, GitHub Actions OIDC identity bound to this exact repository, and "+
			"authenticated transparency-log/SCT timestamp)")
	return FeatureCoverage{
		Feature: "critical_repos_with_attestations_pct", Numerator: numerator, Denominator: denominator, Metric: metric,
		Notes: "scope is exclusively the organization's confirmed critical-population repositories (never " +
			"every analyzed repository); verification uses the maintained sigstore-go library's full policy " +
			"(certificate identity, transparency-log inclusion, authenticated observer timestamps) -- a " +
			"digest match alone, or a structurally well-formed but untrusted/wrongly-identified bundle, is " +
			"never counted as verified",
		UnknownEligibilityCount: unknownEligibility, UnknownOperationalCount: unknownOperational,
	}
}

// FetchRepositoryAttestationCoverage determines critical_repos_with_attestations_pct's
// per-repository contribution: it collects the repository's latest
// published release (GET .../releases/latest) and genuinely verifies every
// asset's attestation(s). A non-2xx response from .../releases/latest --
// including a 404 -- is reported Complete:false (unknown), never a
// confident "no releases" result: GitHub's own REST API documents that this
// endpoint 404s both when a repository genuinely has no releases and when
// the caller's access is concealed (for example a private repository the
// credential cannot see), and these two cases are not distinguishable from
// the response alone.
//
// trustedMaterial being nil (an embedded-resource parse failure, see
// DefaultSigstoreTrustedRoot) means certificate-chain and transparency-log
// trust can never be established for this run; every asset in that case is
// reported Complete:false, never a confident "not attested" 0.
func FetchRepositoryAttestationCoverage(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string, trustedMaterial root.TrustedMaterial) (RepositoryAttestationCoverageResult, []CollectorOutcome, error) {
	result := RepositoryAttestationCoverageResult{}
	latest, outcome, err := collectJSONObject[github.RepositoryRelease](ctx, client, store, scope,
		"repo.releases_packages", "latest_release", "repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/releases/latest")
	if err != nil || latest == nil {
		// Never a confident "no releases" result: see this function's own
		// doc comment on .../releases/latest's documented 404 ambiguity.
		return result, []CollectorOutcome{outcome}, nil
	}
	result.HasReleases = true
	result.ReleaseTag = latest.GetTagName()
	outcomes := []CollectorOutcome{outcome}
	if latest.Assets == nil {
		// encoding/json leaves a slice field nil only when its JSON key was
		// entirely absent (an explicit "assets":[] decodes to a non-nil,
		// zero-length slice) -- GitHub's documented release object schema
		// always includes "assets" as an array, even when empty, so a
		// missing key here means the response itself is not a well-formed
		// release object. This is reported Complete:false (unknown), never
		// a confident "zero verifiable assets": the true asset list could
		// not be confirmed at all.
		outcomes = append(outcomes, CollectorOutcome{
			CollectorID: "repo.releases_packages", Feature: "latest_release_assets", Scope: scope,
			Readiness: Ready, Availability: outcome.Availability, Status: CollectionPartial,
			Complete: false, EvidenceRefs: []string{},
			Reason: "the latest release response has no \"assets\" array at all (not even an empty one); its asset inventory cannot be confirmed",
		})
		return result, outcomes, nil
	}
	anyIncomplete := false
	for _, asset := range latest.Assets {
		if asset == nil {
			// A null entry inside an otherwise well-formed assets array is
			// itself a malformed element: it is never silently skipped as
			// if it had never existed, since doing so would understate this
			// release's true asset count and could hide a genuine asset
			// whose record was merely corrupted in transit.
			anyIncomplete = true
			outcomes = append(outcomes, CollectorOutcome{
				CollectorID: "repo.releases_packages", Feature: "latest_release_assets", Scope: scope,
				Readiness: Ready, Availability: outcome.Availability, Status: CollectionPartial,
				Complete: false, EvidenceRefs: []string{},
				Reason: "the latest release's assets array contains a null element; that asset's identity and attestation status cannot be determined",
			})
			continue
		}
		assetResult, assetOutcome, _ := FetchReleaseAssetAttestation(ctx, client, store, scope, owner, repo, asset, trustedMaterial)
		outcomes = append(outcomes, assetOutcome)
		result.Assets = append(result.Assets, assetResult)
		if assetResult.Verified {
			result.AnyVerified = true
		}
		if !assetResult.Complete {
			anyIncomplete = true
		}
	}
	// A confirmed verified attestation is positive evidence regardless of
	// any other asset's incompleteness (the same "positive overrides
	// incomplete" contract RepositoryFeatureSignal's CodeQL/Dependency
	// operational checks already use); otherwise every asset must have
	// confidently completed (even a confident "zero attestations found") for
	// the overall result to be reported complete.
	result.Complete = result.AnyVerified || !anyIncomplete
	return result, outcomes, nil
}

// FetchReleaseAssetAttestation collects GET
// /repos/{owner}/{repo}/attestations/{subject_digest} for one release asset
// and genuinely verifies each returned bundle with the maintained
// sigstore-go verifier. A missing or malformed asset digest, or a
// non-2xx/concealed attestations response, is reported Complete:false
// (unknown) -- never a confident "not attested" result, since GitHub's own
// documentation states a 404 here covers both "no attestations exist" and
// "the caller lacks access", which are not distinguishable from the
// response alone. A missing digest is reported without attempting any
// network request at all: there is nothing a digest-addressed lookup could
// meaningfully be keyed on.
//
// The evidence feature name is digest-qualified (attestationEvidenceFeature),
// never a constant shared across every asset in a release: this endpoint is
// genuinely paginated (GitHub returns a Link header for more than one page
// of attestations for a single digest), and a release commonly has more
// than one asset, so collecting each asset's attestations under the SAME
// logical feature name would make every asset but the last overwrite the
// previous one's stored evidence pages under an identical identity.
func FetchReleaseAssetAttestation(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string, asset *github.ReleaseAsset, trustedMaterial root.TrustedMaterial) (RepositoryAttestationAssetResult, CollectorOutcome, error) {
	assetResult := RepositoryAttestationAssetResult{AssetName: asset.GetName(), AssetDigest: asset.GetDigest()}
	if asset.GetDigest() == "" {
		return assetResult, notConfiguredOutcome("repo.releases_packages", attestationAssetFallbackFeature(asset), scope,
			"release asset \""+asset.GetName()+"\" has no documented digest; attestation cannot be matched to it without one"), nil
	}
	digest, parseErr := parseArtifactDigest(asset.GetDigest())
	if parseErr != nil {
		return assetResult, notConfiguredOutcome("repo.releases_packages", attestationAssetFallbackFeature(asset), scope, parseErr.Error()), nil
	}
	attestations, outcome, err := collectJSONArray[*github.Attestation](ctx, client, store, scope,
		"repo.releases_packages", attestationEvidenceFeature(digest),
		"repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/attestations/"+url.PathEscape(asset.GetDigest()),
		"attestations", true)
	if err != nil {
		// err covers both a non-2xx/concealed response AND the documented
		// "attestations" array key being entirely absent from an otherwise
		// 2xx response (collectJSONArray's own required-array-field check,
		// shared with every other array-wrapped collector in this
		// package) -- neither is a confident "zero attestations", only an
		// explicit, successfully-decoded empty array is (see the zero-
		// length attestations case below, which is NOT an error here).
		return assetResult, outcome, nil
	}
	assetResult.AttestationsObserved = len(attestations)
	anyMalformed := false
	for _, attestation := range attestations {
		if attestation == nil {
			anyMalformed = true
			continue
		}
		verified, digestObserved, verifyErr := verifyAttestationBundle(attestation.Bundle, digest, owner, repo, trustedMaterial)
		if verifyErr != nil {
			anyMalformed = true
			continue
		}
		if digestObserved {
			assetResult.DigestSubjectObserved = true
		}
		if verified {
			assetResult.Verified = true
		}
	}
	assetResult.Complete = assetResult.Verified || !anyMalformed
	if anyMalformed {
		outcome = markOutcomeIncomplete(outcome, "one or more attestation entries were null, malformed or missing required trust evidence")
	}
	return assetResult, outcome, nil
}

// verifyAttestationBundle parses one Sigstore bundle (the raw JSON GitHub's
// attestations endpoint returned) and runs the maintained sigstore-go
// library's full verification policy against it: a trusted certificate
// chain rooted in the embedded Sigstore trust material, a GitHub Actions
// OIDC identity bound to this exact owner/repo, a matching artifact digest,
// and an authenticated transparency-log/SCT timestamp establishing the
// certificate was valid at signing time -- verify.VerifierConfig's
// documented default behavior derives that validity time from the
// transparency-log/SCT evidence itself, never this process's wall clock, so
// a historical attestation signed under a Fulcio certificate that has since
// expired (Fulcio-issued certificates are valid for roughly ten minutes)
// still verifies correctly.
//
// digestSubjectObserved is reported independently of verified: it reflects
// only whether the attestation's in-toto statement names a subject with
// this exact digest, parsed directly from the (unverified at this point)
// DSSE payload -- a diagnostic signal, never a substitute for verified.
//
// A non-nil error means either the bundle itself is malformed/unusable
// (invalid JSON, unsupported bundle shape, or no trusted material
// configured at all), or verification could not even be attempted for
// lack of sufficient transparency-log/timestamp evidence (see
// isStructuralTrustGap) -- both are reported unknown, never a confident
// result. This is distinct from a structurally valid bundle with
// sufficient trust evidence that simply fails policy (wrong identity,
// wrong digest, an untrusted certificate chain evaluated against an
// established authenticated time, or a tampered signature), which returns
// verified=false with a nil error: a confident, complete "not verified",
// not an unknown/malformed result.
func verifyAttestationBundle(rawBundle []byte, digest parsedArtifactDigest, owner, repo string,
	trustedMaterial root.TrustedMaterial) (verified, digestSubjectObserved bool, err error) {
	if len(rawBundle) == 0 {
		return false, false, fmt.Errorf("attestation entry has no bundle content")
	}
	var sigstoreBundle bundle.Bundle
	if err := sigstoreBundle.UnmarshalJSON(rawBundle); err != nil {
		return false, false, fmt.Errorf("attestation bundle is not a valid Sigstore bundle: %w", err)
	}
	digestSubjectObserved = bundleStatementHasDigestSubject(&sigstoreBundle, digest)
	if trustedMaterial == nil {
		return false, digestSubjectObserved, fmt.Errorf(
			"no trusted Sigstore root material is configured; certificate chain and transparency-log trust cannot be established")
	}
	sigstoreVerifier, err := verify.NewVerifier(trustedMaterial,
		verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return false, digestSubjectObserved, fmt.Errorf("construct Sigstore verifier: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity(githubActionsOIDCIssuer, "", "",
		"^https://github.com/"+regexp.QuoteMeta(owner)+"/"+regexp.QuoteMeta(repo)+"/")
	if err != nil {
		return false, digestSubjectObserved, fmt.Errorf("construct expected certificate identity: %w", err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest(digest.Algorithm, digest.Bytes), verify.WithCertificateIdentity(identity))
	result, verifyErr := sigstoreVerifier.Verify(&sigstoreBundle, policy)
	if verifyErr != nil {
		if isStructuralTrustGap(verifyErr) {
			// Verify() could not even establish enough transparency-log/
			// observer-timestamp evidence to evaluate this bundle's
			// certificate at all (for example zero tlog entries, or no
			// signed-timestamp/SCT source) -- this is insufficient
			// evidence to determine anything, not a confirmed mismatch:
			// the digest, identity, and signature might all genuinely be
			// correct, but there is no authenticated time to evaluate a
			// short-lived certificate's validity against. Reported
			// unknown (a non-nil error), never collapsed into the same
			// confident "not verified" a genuine digest/identity/signature
			// mismatch produces.
			return false, digestSubjectObserved, fmt.Errorf("insufficient trust evidence to evaluate this attestation: %w", verifyErr)
		}
		// Every other policy/trust failure (wrong issuer or repository,
		// digest mismatch, tampered signature, or an untrusted
		// certificate chain actually evaluated against an established
		// authenticated time) is a confident, complete "not verified" --
		// never treated as malformed/unknown.
		return false, digestSubjectObserved, nil
	}
	if result.Statement == nil || !recognizedProvenancePredicateTypes[result.Statement.PredicateType] {
		// A cryptographically valid, correctly identified attestation of an
		// unrecognized predicate type (for example a test-results or SBOM
		// attestation the same workflow also happened to sign) is not
		// "verified provenance" for this metric's purposes -- only a
		// recognized build-provenance predicate type counts.
		return false, digestSubjectObserved, nil
	}
	return true, digestSubjectObserved, nil
}

// isStructuralTrustGap reports whether a sigstore-go Verify() error means
// verification could not even be attempted for lack of sufficient
// transparency-log/timestamp evidence (as opposed to a completed check
// that confirmed a genuine mismatch). verify.Verifier.Verify's own two
// earliest steps -- VerifyTransparencyLogInclusion and
// VerifyObserverTimestamps -- wrap their errors with these exact literal
// prefixes before any identity/digest/signature check is even reached; no
// typed sentinel error is exposed for this distinction by the library
// (confirmed by reading verify.Verifier.Verify's own source), so matching
// on its own stable, documented wrapping text is the available mechanism.
func isStructuralTrustGap(err error) bool {
	message := err.Error()
	return strings.HasPrefix(message, "failed to verify log inclusion:") ||
		strings.HasPrefix(message, "failed to verify timestamps:")
}

// recognizedProvenancePredicateTypes is the in-toto statement predicate
// types this collector accepts as "build provenance" (as opposed to, for
// example, a cryptographically valid but unrelated test-results or SBOM
// attestation signed by the same workflow identity): SLSA Provenance, the
// predicate type GitHub's own actions/attest-build-provenance action
// produces. See https://slsa.dev/spec/v1.0/provenance and
// https://slsa.dev/provenance/v0.2.
var recognizedProvenancePredicateTypes = map[string]bool{
	"https://slsa.dev/provenance/v0.2": true,
	"https://slsa.dev/provenance/v1":   true,
}

// bundleStatementHasDigestSubject reports whether the bundle's in-toto
// statement names a subject whose recorded digest, for the same explicitly
// typed algorithm, matches digest exactly. This check runs over the DSSE
// payload only -- it is never, on its own, evidence of authenticity; it is
// purely a diagnostic signal kept separate from verifyAttestationBundle's
// cryptographic policy result.
func bundleStatementHasDigestSubject(sigstoreBundle *bundle.Bundle, digest parsedArtifactDigest) bool {
	envelope, err := sigstoreBundle.Envelope()
	if err != nil || envelope == nil {
		return false
	}
	statement, err := envelope.Statement()
	if err != nil || statement == nil {
		return false
	}
	want := hex.EncodeToString(digest.Bytes)
	for _, subject := range statement.GetSubject() {
		if subject == nil {
			continue
		}
		if value, ok := subject.GetDigest()[digest.Algorithm]; ok && strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
