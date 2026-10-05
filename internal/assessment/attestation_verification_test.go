// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-github/v83/github"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// realSigstoreBundlePath and its sibling constants describe a REAL,
// publicly published Sigstore attestation bundle embedded verbatim in
// testdata/ (sourced from the sigstore-go module's own examples/ directory,
// https://github.com/sigstore/sigstore-go -- a genuine GitHub Actions
// provenance attestation for sigstore/sigstore-js's v1.3.0 npm release).
// Its Fulcio leaf certificate is only valid for roughly ten minutes around
// 2023-04-18T17:45:11Z and has long since expired by wall-clock time; it
// verifies here purely through the bundle's own authenticated transparency-
// log timestamp, exactly the historical-attestation scenario this
// collector must support without ever trusting a live/raw-replay wall
// clock or a fabricated NotBefore/NotAfter midpoint.
const (
	realSigstoreBundlePath  = "testdata/sigstore-example-bundle-provenance.json"
	realSigstoreOwner       = "sigstore"
	realSigstoreRepo        = "sigstore-js"
	realSigstoreDigestValue = "sha512:76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751"
)

// loadRealSigstoreFixture reads the embedded production trust root and the
// real historical bundle fixture once per test.
func loadRealSigstoreFixture(t *testing.T) (trustedMaterial root.TrustedMaterial, rawBundle []byte, digest parsedArtifactDigest) {
	t.Helper()
	material, err := DefaultSigstoreTrustedRoot()
	if err != nil {
		t.Fatalf("parse embedded Sigstore trusted root: %v", err)
	}
	raw, err := os.ReadFile(realSigstoreBundlePath)
	if err != nil {
		t.Fatalf("read embedded real Sigstore bundle fixture: %v", err)
	}
	parsedDigest, err := parseArtifactDigest(realSigstoreDigestValue)
	if err != nil {
		t.Fatalf("parse the real fixture's own documented digest: %v", err)
	}
	return material, raw, parsedDigest
}

// TestDefaultSigstoreTrustedRootParsesEmbeddedResource confirms the
// embedded production trust root parses successfully and deterministically
// (a build-time resource, never a live network/TUF fetch).
func TestDefaultSigstoreTrustedRootParsesEmbeddedResource(t *testing.T) {
	first, err := DefaultSigstoreTrustedRoot()
	if err != nil {
		t.Fatalf("expected the embedded trust root to parse: %v", err)
	}
	if first == nil {
		t.Fatal("expected non-nil trusted material")
	}
	second, err := DefaultSigstoreTrustedRoot()
	if err != nil || second == nil {
		t.Fatalf("expected a repeat parse to succeed identically: %v", err)
	}
}

// TestVerifyAttestationBundleAcceptsGenuineHistoricalProvenance is the
// central positive case this round's rewrite exists to prove: a REAL
// GitHub Actions-signed attestation, whose Fulcio certificate expired (by
// wall-clock time) years ago, still verifies -- sigstore-go's documented
// default behavior derives certificate validity from the bundle's own
// authenticated transparency-log timestamp, never this process's wall
// clock or a fabricated NotBefore/NotAfter midpoint.
func TestVerifyAttestationBundleAcceptsGenuineHistoricalProvenance(t *testing.T) {
	trustedMaterial, raw, digest := loadRealSigstoreFixture(t)
	verified, digestSubjectObserved, err := verifyAttestationBundle(raw, digest, realSigstoreOwner, realSigstoreRepo, trustedMaterial)
	if err != nil {
		t.Fatalf("expected a genuine real bundle to be structurally valid, not malformed: %v", err)
	}
	if !digestSubjectObserved {
		t.Fatal("expected the real bundle's in-toto statement to name this exact digest")
	}
	if !verified {
		t.Fatal("expected the real historical attestation to verify via its authenticated transparency-log timestamp")
	}
}

// TestVerifyAttestationBundleStableOnFrozenReplay confirms repeat
// verification of the identical stored bundle bytes produces an identical
// result -- no hidden wall-clock dependency that could make a replayed run
// diverge from the run that originally collected this evidence.
func TestVerifyAttestationBundleStableOnFrozenReplay(t *testing.T) {
	trustedMaterial, raw, digest := loadRealSigstoreFixture(t)
	v1, d1, e1 := verifyAttestationBundle(raw, digest, realSigstoreOwner, realSigstoreRepo, trustedMaterial)
	v2, d2, e2 := verifyAttestationBundle(raw, digest, realSigstoreOwner, realSigstoreRepo, trustedMaterial)
	if v1 != v2 || d1 != d2 || (e1 == nil) != (e2 == nil) {
		t.Fatalf("expected identical results across repeat verification: (%v,%v,%v) vs (%v,%v,%v)", v1, d1, e1, v2, d2, e2)
	}
	if !v1 {
		t.Fatal("expected the baseline case itself to verify")
	}
}

// TestVerifyAttestationBundleRejectsWrongRepositoryIdentity proves identity
// binding is genuinely enforced: the exact same real, validly signed bundle
// fails when the expected repository does not match the certificate's
// GitHub Actions SAN. Before this round's rewrite, any valid Fulcio-issued
// certificate for ANY repository with a matching digest was incorrectly
// accepted; this is the regression guard for that gap.
func TestVerifyAttestationBundleRejectsWrongRepositoryIdentity(t *testing.T) {
	trustedMaterial, raw, digest := loadRealSigstoreFixture(t)
	verified, _, err := verifyAttestationBundle(raw, digest, realSigstoreOwner, "an-unrelated-repository", trustedMaterial)
	if err != nil {
		t.Fatalf("an identity mismatch is a policy failure, not malformed bundle content: %v", err)
	}
	if verified {
		t.Fatal("expected a mismatched repository identity to be rejected")
	}
}

// TestVerifyAttestationBundleRejectsWrongDigestAlgorithm proves digest
// comparisons are genuinely algorithm-typed: requesting verification
// against a sha256 digest against a bundle whose subject only records a
// sha512 digest must never coincidentally match on raw bytes/length.
func TestVerifyAttestationBundleRejectsWrongDigestAlgorithm(t *testing.T) {
	trustedMaterial, raw, _ := loadRealSigstoreFixture(t)
	wrongAlgorithm, err := parseArtifactDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	verified, digestSubjectObserved, verifyErr := verifyAttestationBundle(raw, wrongAlgorithm, realSigstoreOwner, realSigstoreRepo, trustedMaterial)
	if verifyErr != nil {
		t.Fatalf("a digest mismatch is a policy failure, not malformed bundle content: %v", verifyErr)
	}
	if digestSubjectObserved {
		t.Fatal("the diagnostic digest-subject check must also be algorithm-typed, not match across algorithms")
	}
	if verified {
		t.Fatal("expected a mismatched digest algorithm to be rejected")
	}
}

// TestVerifyAttestationBundleRejectsMissingAuthenticatedTime proves that
// stripping the bundle's transparency-log entries (its only source of
// authenticated signing time) is reported unknown, not a confident
// "not verified": this certificate genuinely IS expired by wall-clock
// time, and without an authenticated timestamp there is no trustworthy
// evidence either way about whether it was ever valid -- insufficient
// trust evidence to evaluate at all is not the same as a completed check
// that confirmed a genuine mismatch, so it must never collapse into the
// same confident false a wrong digest/identity/signature produces.
func TestVerifyAttestationBundleRejectsMissingAuthenticatedTime(t *testing.T) {
	trustedMaterial, raw, digest := loadRealSigstoreFixture(t)
	var bundleMap map[string]any
	if err := json.Unmarshal(raw, &bundleMap); err != nil {
		t.Fatal(err)
	}
	verificationMaterial, ok := bundleMap["verificationMaterial"].(map[string]any)
	if !ok {
		t.Fatal("expected the real fixture to have a verificationMaterial object")
	}
	verificationMaterial["tlogEntries"] = []any{}
	mutated, err := json.Marshal(bundleMap)
	if err != nil {
		t.Fatal(err)
	}
	verified, _, verifyErr := verifyAttestationBundle(mutated, digest, realSigstoreOwner, realSigstoreRepo, trustedMaterial)
	if verifyErr == nil {
		t.Fatal("expected insufficient transparency-log evidence to be reported unknown (non-nil error), not a confident policy result")
	}
	if verified {
		t.Fatal("expected a bundle with no authenticated timestamp source to never report verified")
	}
}

// TestVerifyAttestationBundleRejectsMalformedContent confirms a
// structurally invalid bundle is reported as malformed (a non-nil error,
// distinct from a confident policy-failure "not verified"), and that no
// trust material being configured is likewise reported malformed/unknown
// rather than a confident crypto-failure 0.
func TestVerifyAttestationBundleRejectsMalformedContent(t *testing.T) {
	_, raw, digest := loadRealSigstoreFixture(t)
	t.Run("empty object", func(t *testing.T) {
		trustedMaterial, _, _ := loadRealSigstoreFixture(t)
		verified, _, err := verifyAttestationBundle([]byte(`{}`), digest, realSigstoreOwner, realSigstoreRepo, trustedMaterial)
		if err == nil {
			t.Fatal("expected an empty bundle object to be reported malformed")
		}
		if verified {
			t.Fatal("a malformed bundle must never be reported verified")
		}
	})
	t.Run("empty bytes", func(t *testing.T) {
		trustedMaterial, _, _ := loadRealSigstoreFixture(t)
		if _, _, err := verifyAttestationBundle(nil, digest, realSigstoreOwner, realSigstoreRepo, trustedMaterial); err == nil {
			t.Fatal("expected zero-length bundle content to be reported malformed")
		}
	})
	t.Run("no trusted material configured", func(t *testing.T) {
		verified, _, err := verifyAttestationBundle(raw, digest, realSigstoreOwner, realSigstoreRepo, nil)
		if err == nil {
			t.Fatal("expected a nil trust root to be reported as an explicit unsupported/unknown condition, not silently verified")
		}
		if verified {
			t.Fatal("a nil trust root must never produce a confident verified result")
		}
	})
}

// TestRecognizedProvenancePredicateTypesRejectsUnrelatedClaims confirms the
// predicate-type allow-list genuinely distinguishes build provenance from
// an unrelated (but potentially validly signed) claim type: a
// cryptographically valid attestation of, say, test results or an SBOM is
// not "verified provenance" for this metric merely because the signer and
// digest both check out.
func TestRecognizedProvenancePredicateTypesRejectsUnrelatedClaims(t *testing.T) {
	if !recognizedProvenancePredicateTypes["https://slsa.dev/provenance/v0.2"] {
		t.Fatal("expected SLSA Provenance v0.2 (this round's real fixture's own predicate type) to be recognized")
	}
	if !recognizedProvenancePredicateTypes["https://slsa.dev/provenance/v1"] {
		t.Fatal("expected current SLSA Provenance v1 to be recognized")
	}
	if recognizedProvenancePredicateTypes["https://example.org/unrelated-claim-type"] {
		t.Fatal("expected an unrecognized predicate type to be rejected")
	}
}

// TestParseArtifactDigest covers the documented "algorithm:hex" format
// (GitHub REST API's ReleaseAsset.Digest field), rejecting anything that
// could risk a cross-algorithm or truncated-hex digest-confusion match.
func TestParseArtifactDigest(t *testing.T) {
	validSHA256 := "sha256:" + hex64("a")
	validSHA512 := "sha512:" + hex128("b")
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"valid sha256", validSHA256, false},
		{"valid sha512", validSHA512, false},
		{"uppercase algorithm and hex normalize", "SHA256:" + hex64("A"), false},
		{"missing separator", "sha256" + hex64("a"), true},
		{"empty algorithm", ":" + hex64("a"), true},
		{"empty hex", "sha256:", true},
		{"unsupported algorithm", "md5:" + hex64("a"), true},
		{"wrong length for algorithm", "sha256:" + hex128("a"), true},
		{"non-hex characters", "sha256:" + hex64("a")[:62] + "zz", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := parseArtifactDigest(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected %q to be rejected, got %+v", tc.raw, digest)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected %q to parse, got error: %v", tc.raw, err)
			}
		})
	}
}

func hex64(fill string) string {
	out := ""
	for len(out) < 64 {
		out += fill
	}
	return out[:64]
}

func hex128(fill string) string {
	out := ""
	for len(out) < 128 {
		out += fill
	}
	return out[:128]
}

// TestAggregateAttestationCoverageUnknownCriticalityCannotProduceKnownSubset
// mirrors AggregateFeatureCoverage's own established unknown-cohort-gate
// contract (see feature_coverage_test.go): a repository whose critical-
// population membership was never resolved must force the pooled metric
// to MetricUnavailable, never a confident percentage over only the known
// subset -- the unresolved peer could itself turn out critical.
func TestAggregateAttestationCoverageUnknownCriticalityCannotProduceKnownSubset(t *testing.T) {
	coverage := AggregateAttestationCoverage([]RepositoryAttestationSignal{
		{FullName: "fixture/known", CriticalKnown: true, Critical: true, AttestationVerifiedKnown: true, AttestationVerified: true},
		{FullName: "fixture/unknown"},
	})
	if coverage.Metric.Status == MetricKnown {
		t.Fatalf("an unresolved critical-population peer must not shrink the cohort into a known subset coverage: %+v", coverage.Metric)
	}
	if coverage.Metric.Number != nil {
		t.Fatalf("an unavailable metric must not carry a Number: %+v", coverage.Metric)
	}
	if coverage.Metric.Numerator == nil || coverage.Metric.Denominator == nil ||
		*coverage.Metric.Numerator != 1 || *coverage.Metric.Denominator != 1 {
		t.Fatalf("the confidently-known 1/1 subset must still be retained on the metric, not erased: %+v", coverage.Metric)
	}
	if coverage.UnknownEligibilityCount != 1 {
		t.Fatalf("expected the unresolved peer's uncertainty counted: %+v", coverage)
	}
}

// TestAggregateAttestationCoverageUnknownOperationalCannotBeKnownZero is the
// sibling gate: a confirmed-critical repository whose attestation coverage
// could not be confidently determined (AttestationVerifiedKnown false) must
// not be reported as a confident 0%.
func TestAggregateAttestationCoverageUnknownOperationalCannotBeKnownZero(t *testing.T) {
	coverage := AggregateAttestationCoverage([]RepositoryAttestationSignal{
		{FullName: "fixture/unresolved-coverage", CriticalKnown: true, Critical: true},
	})
	if coverage.Metric.Status == MetricKnown {
		t.Fatalf("unresolved attestation coverage must not be reported as a known zero: %+v", coverage.Metric)
	}
	if coverage.Metric.Number != nil {
		t.Fatalf("an unavailable metric must not carry a Number: %+v", coverage.Metric)
	}
	if coverage.UnknownOperationalCount != 1 {
		t.Fatalf("expected the unresolved coverage result counted: %+v", coverage)
	}
}

// TestAggregateAttestationCoverageExcludesNonCriticalAndFullyKnownIsConfident
// confirms non-critical repositories never dilute/inflate the pooled
// denominator, and that a fully-known cohort (no unknowns at all) reports a
// genuine confident percentage.
func TestAggregateAttestationCoverageExcludesNonCriticalAndFullyKnownIsConfident(t *testing.T) {
	coverage := AggregateAttestationCoverage([]RepositoryAttestationSignal{
		{FullName: "fixture/critical-verified", CriticalKnown: true, Critical: true, AttestationVerifiedKnown: true, AttestationVerified: true},
		{FullName: "fixture/critical-unverified", CriticalKnown: true, Critical: true, AttestationVerifiedKnown: true, AttestationVerified: false},
		{FullName: "fixture/non-critical", CriticalKnown: true, Critical: false},
	})
	if coverage.Metric.Status != MetricKnown {
		t.Fatalf("expected a fully-known cohort to report a confident percentage: %+v", coverage.Metric)
	}
	if coverage.Denominator != 2 {
		t.Fatalf("expected the non-critical repository excluded from the denominator entirely: %+v", coverage)
	}
	if coverage.Numerator != 1 {
		t.Fatalf("expected exactly one of the two critical repositories counted verified: %+v", coverage)
	}
	if coverage.Feature != "critical_repos_with_attestations_pct" {
		t.Fatalf("unexpected feature key: %q", coverage.Feature)
	}
}

// mainAttestationFixture migrates the exact helper main's own read-only
// review overlay used, so the three reproduction scenarios below are
// permanent, unmodified fixtures with identical semantics to what main
// independently confirmed failed against the prior round's implementation.
func mainAttestationFixture(t *testing.T, handler http.HandlerFunc) (*CollectionClient, *EvidenceStore, Scope) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	return client, evidenceFixtureStore(t, t.TempDir(), nil),
		Scope{Host: client.base.Hostname(), Kind: RepositoryScope, Name: "fixture/repo"}
}

// TestMainAttestationMissingDigestCannotProveAbsence is main's own
// confirmed reproduction, migrated verbatim as a permanent fixture: a
// release asset with no documented digest must not be treated as a
// complete, confidently "not attested" result, and must not even attempt a
// network lookup (there is nothing a digest-addressed endpoint could be
// keyed on).
func TestMainAttestationMissingDigestCannotProveAbsence(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("no digest is available; no network lookup should be attempted")
	})
	name, id := "fixture-asset", int64(1)
	result, outcome, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &id, Name: &name}, nil)
	if err == nil && result.Complete {
		t.Fatalf("missing required artifact digest cannot imply a complete known unattested asset: %+v / %+v", result, outcome)
	}
}

// TestMainAttestationConcealed404CannotProveNoRelease is main's own
// confirmed reproduction, migrated verbatim as a permanent fixture: GitHub's
// .../releases/latest endpoint returns an identical 404 whether a
// repository genuinely has no releases or the caller's access is
// concealed; this must never be collapsed into a confident "no releases"
// result.
func TestMainAttestationConcealed404CannotProveNoRelease(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(t, w, map[string]any{"message": "Not Found"})
	})
	result, outcomes, err := FetchRepositoryAttestationCoverage(context.Background(), client, store, scope, "fixture", "repo", nil)
	if err == nil && result.Complete {
		t.Fatalf("a concealed authorization 404 cannot prove complete release absence: %+v / %+v", result, outcomes)
	}
}

// TestMainAttestationMalformedBundleCannotBeComplete is main's own
// confirmed reproduction, migrated verbatim as a permanent fixture: every
// returned attestation entry being structurally malformed must leave the
// asset's result incomplete (unknown), never a confident "known absence".
func TestMainAttestationMalformedBundleCannotBeComplete(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"attestations": []map[string]any{{"bundle": map[string]any{}}}})
	})
	name, id, digest := "fixture-asset", int64(1), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result, _, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &id, Name: &name, Digest: &digest}, nil)
	if err == nil && result.Complete {
		t.Fatalf("all malformed attestation bundles must remain incomplete, not known absence: %+v", result)
	}
}

// TestFetchReleaseAssetAttestationMalformedDigestIsNotConfiguredNoNetwork
// confirms a digest that fails the documented "algorithm:hex" format is
// also rejected before any network attempt, the same as a wholly missing
// digest.
func TestFetchReleaseAssetAttestationMalformedDigestIsNotConfiguredNoNetwork(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("a malformed digest cannot be meaningfully keyed on; no network lookup should be attempted")
	})
	name, id, digest := "fixture-asset", int64(1), "not-a-documented-digest-format"
	result, outcome, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &id, Name: &name, Digest: &digest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatalf("a malformed digest cannot imply a complete known unattested asset: %+v", result)
	}
	if outcome.Status != NotRun {
		t.Fatalf("expected an explicit not-run outcome, not a network attempt: %+v", outcome)
	}
}

// TestFetchReleaseAssetAttestationZeroAttestationsIsConfidentlyComplete
// confirms the GitHub-documented "zero attestations for this digest"
// response shape (a 200 with an empty attestations array) is reported
// Complete:true, Verified:false -- a confident, genuine negative, distinct
// from every unknown case above.
func TestFetchReleaseAssetAttestationZeroAttestationsIsConfidentlyComplete(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"attestations": []map[string]any{}})
	})
	name, id, digest := "fixture-asset", int64(1), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result, _, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &id, Name: &name, Digest: &digest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Verified || result.AttestationsObserved != 0 {
		t.Fatalf("expected a confident, complete zero-attestations result: %+v", result)
	}
}

// TestFetchRepositoryAttestationCoverageGenuineVerificationEndToEnd runs
// FetchRepositoryAttestationCoverage's full collection path (latest-release
// lookup, then per-asset attestation lookup) against the REAL historical
// bundle fixture, confirming the whole collector -- not just
// verifyAttestationBundle in isolation -- reports a genuine verified
// result end to end.
func TestFetchRepositoryAttestationCoverageGenuineVerificationEndToEnd(t *testing.T) {
	trustedMaterial, raw, _ := loadRealSigstoreFixture(t)
	assetDigest := realSigstoreDigestValue
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + realSigstoreOwner + "/" + realSigstoreRepo + "/releases/latest":
			writeJSON(t, w, map[string]any{
				"tag_name": "v1.3.0",
				"assets":   []map[string]any{{"id": 1, "name": "sigstore-js-1.3.0.tgz", "digest": assetDigest}},
			})
		case "/repos/" + realSigstoreOwner + "/" + realSigstoreRepo + "/attestations/" + assetDigest:
			writeJSON(t, w, map[string]any{
				"attestations": []map[string]any{{"bundle": json.RawMessage(raw), "repository_id": 1}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	result, _, err := FetchRepositoryAttestationCoverage(context.Background(), client, store, scope,
		realSigstoreOwner, realSigstoreRepo, trustedMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || !result.AnyVerified || !result.HasReleases {
		t.Fatalf("expected the full collector to report a genuine end-to-end verified result: %+v", result)
	}
	if len(result.Assets) != 1 || !result.Assets[0].Verified || !result.Assets[0].Complete {
		t.Fatalf("expected the one real asset to be reported genuinely verified and complete: %+v", result.Assets)
	}
}

// TestFetchReleaseAssetAttestationPaginatesAndUsesUniquePerAssetEvidenceIdentity
// proves two things together: (1) the attestations endpoint is genuinely
// paginated -- a single asset's 101 attestation entries span two Link-
// header pages, both collected -- and (2) two DIFFERENT assets' (distinct
// digests) attestation pages are persisted under genuinely distinct
// evidence identities, never colliding/overwriting one another, by reading
// each asset's own page 1 back out of the evidence store directly and
// confirming their raw bytes differ and each contains only that asset's
// own served content.
func TestFetchReleaseAssetAttestationPaginatesAndUsesUniquePerAssetEvidenceIdentity(t *testing.T) {
	digestA, err := parseArtifactDigest("sha256:" + hex64("a"))
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := parseArtifactDigest("sha256:" + hex64("b"))
	if err != nil {
		t.Fatal(err)
	}
	const totalForAssetA = 101
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/fixture/repo/attestations/"+digestA.Algorithm+":"+hexOf(digestA):
			page := r.URL.Query().Get("page")
			var entries []map[string]any
			if page == "2" {
				entries = []map[string]any{{"bundle": map[string]any{"marker": "asset-a-page-2"}, "repository_id": 1}}
			} else {
				w.Header().Set("Link", "<https://"+r.Host+r.URL.Path+"?per_page=100&page=2>; rel=\"next\"")
				for i := 0; i < 100; i++ {
					entries = append(entries, map[string]any{"bundle": map[string]any{"marker": "asset-a-page-1"}, "repository_id": 1})
				}
			}
			writeJSON(t, w, map[string]any{"attestations": entries})
		case r.URL.Path == "/repos/fixture/repo/attestations/"+digestB.Algorithm+":"+hexOf(digestB):
			writeJSON(t, w, map[string]any{
				"attestations": []map[string]any{{"bundle": map[string]any{"marker": "asset-b-page-1"}, "repository_id": 1}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: client.base.Hostname(), Kind: RepositoryScope, Name: "fixture/repo"}

	nameA, idA := "asset-a", int64(1)
	digestAValue := digestA.Algorithm + ":" + hexOf(digestA)
	resultA, _, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &idA, Name: &nameA, Digest: &digestAValue}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resultA.AttestationsObserved != totalForAssetA {
		t.Fatalf("expected both of asset A's paginated pages collected (100+1=%d), got %d", totalForAssetA, resultA.AttestationsObserved)
	}

	nameB, idB := "asset-b", int64(2)
	digestBValue := digestB.Algorithm + ":" + hexOf(digestB)
	resultB, _, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &idB, Name: &nameB, Digest: &digestBValue}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resultB.AttestationsObserved != 1 {
		t.Fatalf("expected exactly asset B's own single entry, not asset A's count: %+v", resultB)
	}

	// Read each asset's own persisted page 1 directly back out of the
	// evidence store and confirm neither collided with (overwrote) the
	// other's.
	rawA, _, _, err := store.LoadJSON(scope, "repo.releases_packages", pageFeatureName(attestationEvidenceFeature(digestA), 1))
	if err != nil {
		t.Fatal(err)
	}
	rawB, _, _, err := store.LoadJSON(scope, "repo.releases_packages", pageFeatureName(attestationEvidenceFeature(digestB), 1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawA), "asset-b-page-1") || !strings.Contains(string(rawA), "asset-a-page-1") {
		t.Fatalf("asset A's persisted page 1 does not contain only asset A's own served content: %s", rawA)
	}
	if strings.Contains(string(rawB), "asset-a-page-1") || !strings.Contains(string(rawB), "asset-b-page-1") {
		t.Fatalf("asset B's persisted page 1 does not contain only asset B's own served content: %s", rawB)
	}
}

func hexOf(digest parsedArtifactDigest) string {
	return hex.EncodeToString(digest.Bytes)
}

// TestFetchReleaseAssetAttestationMissingAttestationsKeyIsNotConfidentlyEmpty
// confirms a 2xx response whose body omits the documented "attestations"
// array entirely (as opposed to an explicit, successfully-decoded empty
// array) is reported Complete:false -- a required-key omission is
// malformed, never a confident "zero attestations found".
func TestFetchReleaseAssetAttestationMissingAttestationsKeyIsNotConfidentlyEmpty(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{})
	})
	name, id, digest := "fixture-asset", int64(1), "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result, outcome, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{ID: &id, Name: &name, Digest: &digest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatalf("a missing \"attestations\" key must not be reported as a confident complete result: %+v / %+v", result, outcome)
	}
}

// TestFetchRepositoryAttestationCoverageMissingAssetsKeyIsUnknownNotZero
// confirms a latest-release response whose body omits the documented
// "assets" array entirely is reported Complete:false: GitHub's schema
// always includes "assets" (even as an empty array), so its total absence
// means the asset inventory itself could not be confirmed, never a
// confident "zero verifiable assets".
func TestFetchRepositoryAttestationCoverageMissingAssetsKeyIsUnknownNotZero(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"tag_name": "v1.0.0"})
	})
	result, outcomes, err := FetchRepositoryAttestationCoverage(context.Background(), client, store, scope, "fixture", "repo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatalf("a latest release with no \"assets\" array at all must not be reported complete: %+v / %+v", result, outcomes)
	}
	if !result.HasReleases {
		t.Fatal("a genuinely returned latest release object itself is still known, independent of its unknown asset inventory")
	}
}

// TestFetchRepositoryAttestationCoverageNullAssetEntryIsNotSilentlySkipped
// confirms a null element inside an otherwise well-formed assets array
// forces Complete:false, rather than being silently skipped as if it had
// never existed (which would understate the release's true asset count).
func TestFetchRepositoryAttestationCoverageNullAssetEntryIsNotSilentlySkipped(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"tag_name": "v1.0.0", "assets": []any{nil}})
	})
	result, outcomes, err := FetchRepositoryAttestationCoverage(context.Background(), client, store, scope, "fixture", "repo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete {
		t.Fatalf("a null asset entry must not be silently skipped into a confident complete result: %+v / %+v", result, outcomes)
	}
}

// TestFetchRepositoryAttestationCoverageExplicitEmptyAssetsIsConfidentlyComplete
// is the sibling confirming an EXPLICIT, successfully-decoded empty assets
// array ("assets":[]) -- as opposed to the key being entirely absent -- is
// still reported Complete:true, HasReleases:true: this is a genuine,
// confident "no assets to verify", not a missing/malformed response.
func TestFetchRepositoryAttestationCoverageExplicitEmptyAssetsIsConfidentlyComplete(t *testing.T) {
	client, store, scope := mainAttestationFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"tag_name": "v1.0.0", "assets": []any{}})
	})
	result, _, err := FetchRepositoryAttestationCoverage(context.Background(), client, store, scope, "fixture", "repo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || !result.HasReleases || len(result.Assets) != 0 {
		t.Fatalf("expected a genuine, confident zero-assets complete result: %+v", result)
	}
}
