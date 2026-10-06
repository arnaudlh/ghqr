// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evidenceFixtureMetadata(t *testing.T) EvidenceMetadata {
	t.Helper()
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	return EvidenceMetadata{
		SchemaVersion: "1", ProfileVersion: profile.Version, ProfileSHA256: profile.SHA256,
		CollectorID: "org.secret_scanning_alerts", Feature: "open-page-000001",
		Scope:       Scope{"github.com", OrganizationScope, "fixture-org"},
		CollectedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		Endpoint:    "import://fixture/alerts", SourceKind: ImportedEvidence,
		CredentialKind: NoCredential, Pages: 1, Complete: true,
	}
}

func evidenceFixtureStore(t *testing.T, directory string, redactor *Redactor) *EvidenceStore {
	t.Helper()
	store, err := OpenEvidenceStore(directory, redactor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestSecretAlertsSanitizedBeforeEveryPersistenceBoundary(t *testing.T) {
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, NewRedactor("configured-private-token"))
	raw := []byte(`{
		"already_redacted": true,
		"secret": "dummy-sensitive-value",
		"resolution_comment": "revoked dummy-sensitive-value",
		"resolved_by": {"email": "person@example.test"},
		"dummy-sensitive-value": "duplicated dummy-sensitive-value",
		"config": {"url": "https://webhook-user:webhook-password@hooks.example.test/private-path?token=destination-private-token"},
		"ldap": {"bind_password": "ldap-private-password"},
		"saml": {"private_key": "private-material"},
		"secret_type": "generic",
		"validity": "active",
		"state": "resolved",
		"created_at": "2026-01-01T00:00:00Z",
		"resolved_at": "2026-01-02T00:00:00Z",
		"enabled": false,
		"optional": null,
		"large_id": 9007199254740993
	}`)
	metadata := evidenceFixtureMetadata(t)
	ref, err := store.SaveJSON(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	restored, safeMetadata, restoredRef, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil {
		t.Fatal(err)
	}
	if ref != restoredRef || len(safeMetadata.Redactions) == 0 {
		t.Fatal("provenance or matching evidence reference was lost")
	}
	if !bytes.Contains(restored, []byte(`"secret_type": "generic"`)) ||
		!bytes.Contains(restored, []byte(`"enabled": false`)) ||
		!bytes.Contains(restored, []byte(`"optional": null`)) ||
		!bytes.Contains(restored, []byte(`9007199254740993`)) ||
		!bytes.Contains(restored, []byte(`"url": "hooks.example.test"`)) {
		t.Fatalf("redaction changed safe fields or numeric/null shape: %s", restored)
	}
	forbidden := []string{"dummy-sensitive-value", "person@example.test", "webhook-user", "webhook-password",
		"private-path", "destination-private-token", "ldap-private-password", "private-material", "configured-private-token"}
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, text := range forbidden {
			if bytes.Contains(data, []byte(text)) {
				t.Errorf("sensitive content survived in raw/sidecar/reference file: %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	second, err := store.SaveJSON(raw, metadata)
	if err != nil || second != ref {
		t.Fatalf("same-scope evidence is not idempotent: %+v %v", second, err)
	}
}

func TestEvidenceReferenceTamperingAndRootEscapeAreRejected(t *testing.T) {
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	metadata := evidenceFixtureMetadata(t)
	ref, err := store.SaveJSON([]byte(`[]`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(ref.DataPath)), []byte(`[{"secret":"tampered"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature); err == nil {
		t.Fatal("tampered evidence was accepted")
	}
	if err := os.WriteFile(filepath.Join(directory, evidenceManifest(metadata.Scope, metadata.CollectorID, metadata.Feature)),
		[]byte(`{"data_path":"../outside.json","metadata_path":"../outside.meta.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature); err == nil {
		t.Fatal("root-escaping evidence reference was accepted")
	}
}

func TestEvidenceFailureLeavesPreviousCompletePair(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	metadata := evidenceFixtureMetadata(t)
	ref, err := store.SaveJSON([]byte(`{"state":"open"}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveJSON([]byte(`not JSON; secret=do-not-store`), metadata); err == nil {
		t.Fatal("unsupported raw evidence was persisted")
	}
	_, _, latest, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil || latest != ref {
		t.Fatal("failed write replaced the previous raw/sidecar pair")
	}
}

// TestSaveJSONRedactionAppendIsIdempotentAcrossResaves proves the exact
// regression a parent-reported duplicate-EvidenceRefs finding root-caused:
// SaveJSON blindly appended this call's freshly-rediscovered redaction
// paths onto whatever Redactions a caller's metadata already carried
// forward (for example after round-tripping through LoadJSON before a
// genuine resave of identical content), so each additional resave of the
// SAME evidence grew Redactions -- and with it the content-addressed
// object identity/ref -- forever, even though nothing new was ever
// actually redacted.
func TestSaveJSONRedactionAppendIsIdempotentAcrossResaves(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	metadata := evidenceFixtureMetadata(t)
	raw := []byte(`{"description": "a free-text field that is always wholesale redacted"}`)

	first, err := store.SaveJSON(raw, metadata)
	if err != nil {
		t.Fatal(err)
	}
	_, firstMeta, _, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstMeta.Redactions) == 0 {
		t.Fatal("fixture raw was not genuinely redacted, so this test proves nothing")
	}

	// A genuine resave, carrying the already-saved metadata's own
	// Redactions forward exactly as a caller that round-trips metadata
	// through LoadJSON/an evidence ref before resaving the identical
	// content would.
	resave := metadata
	resave.Redactions = append([]string{}, firstMeta.Redactions...)
	second, err := store.SaveJSON(raw, resave)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("resaving identical content with carried-forward redactions changed its evidence reference: %+v vs %+v", first, second)
	}
	_, secondMeta, _, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondMeta.Redactions) != len(firstMeta.Redactions) {
		t.Fatalf("redaction history grew across an idempotent resave: first=%d second=%d", len(firstMeta.Redactions), len(secondMeta.Redactions))
	}

	// A third resave (a "client resave" after that) must still be a no-op.
	thirdResave := metadata
	thirdResave.Redactions = append([]string{}, secondMeta.Redactions...)
	third, err := store.SaveJSON(raw, thirdResave)
	if err != nil {
		t.Fatal(err)
	}
	if third != first {
		t.Fatalf("a third resave still changed the evidence reference: %+v vs %+v", first, third)
	}
}

// TestSaveJSONPreservesExistingDuplicatedRedactionHistoryVerbatim proves
// the idempotent-append fix is surgical: it never dedupes, reorders, or
// otherwise rewrites any entry already present in a caller-supplied
// Redactions history (including a legacy duplicate pair baked in before
// this safeguard existed) -- it only ever skips re-appending THIS call's
// own freshly-found paths when they already exactly match the array's own
// tail, and still appends a genuinely new path discovered on this save.
func TestSaveJSONPreservesExistingDuplicatedRedactionHistoryVerbatim(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	metadata := evidenceFixtureMetadata(t)
	metadata.Redactions = []string{"$.description", "$.description"}
	raw := []byte(`{"description": "a free-text field", "comment": "a different free-text field"}`)

	if _, err := store.SaveJSON(raw, metadata); err != nil {
		t.Fatal(err)
	}
	_, saved, _, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Redactions) < 2 || saved.Redactions[0] != "$.description" || saved.Redactions[1] != "$.description" {
		t.Fatalf("pre-existing legacy duplicate redaction history was altered: %v", saved.Redactions)
	}
	found := false
	for _, path := range saved.Redactions[2:] {
		if path == "$.comment" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a genuinely new redaction path on this save was not appended: %v", saved.Redactions)
	}
}

func TestKnownSecretTextAndBase64ContentAreSanitized(t *testing.T) {
	redactor := NewRedactor("dummy-sensitive-value")
	text := redactor.Text("authorization failure: dummy-sensitive-value for person@example.test\nAPI_TOKEN=another-private-value")
	if strings.Contains(text, "dummy-sensitive-value") || strings.Contains(text, "person@example.test") ||
		strings.Contains(text, "another-private-value") {
		t.Fatal("sensitive error/log text was not sanitized")
	}
	content := base64.StdEncoding.EncodeToString([]byte("env:\n  API_TOKEN: another-private-value\n# person@example.test\n"))
	raw, err := json.Marshal(map[string]string{"encoding": "base64", "content": content})
	if err != nil {
		t.Fatal(err)
	}
	safe, paths, err := redactor.JSON(raw)
	if err != nil || len(paths) == 0 {
		t.Fatalf("encoded content was not inspected: %v", err)
	}
	var result map[string]string
	if err := json.Unmarshal(safe, &result); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(result["content"])
	if err != nil || bytes.Contains(decoded, []byte("another-private-value")) || bytes.Contains(decoded, []byte("person@example.test")) {
		t.Fatal("base64 content concealed sensitive text")
	}
	if _, _, err := redactor.JSON([]byte(`{"secret":"same","same":"first","[REDACTED]":"second"}`)); err == nil {
		t.Fatal("redacted key collision was silently accepted")
	}
}
