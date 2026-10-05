// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v83/github"
)

func TestAttestationNullEntryPreservesUnknownAndOutcomeReason(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"attestations": []any{nil}})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{Host: client.base.Hostname(), Kind: RepositoryScope, Name: "fixture/repo"}
	name, id := "fixture-asset", int64(1)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	result, outcome, err := FetchReleaseAssetAttestation(context.Background(), client, store, scope,
		"fixture", "repo", &github.ReleaseAsset{Name: &name, ID: &id, Digest: &digest}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || result.Verified || outcome.Complete || outcome.Status != CollectionPartial ||
		outcome.Reason == "" || outcome.Pages != 1 || len(outcome.EvidenceRefs) != 2 {
		t.Fatalf("null attestation must retain evidence while marking the result and outcome incomplete: %+v / %+v", result, outcome)
	}
}
