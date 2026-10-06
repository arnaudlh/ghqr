// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReplayClientPreservesCredentialKindForGatedCollectors confirms a
// replay-mode CollectionClient (built via NewReplayCollectionClient; never
// dials the network; serves already-collected evidence) is not blocked by a
// live-collection credential gate that requires ClassicPAT (e.g.
// FetchEnterpriseSCIMUsers in remaining_collectors.go): the gate only
// exists to avoid a doomed live request, and a replay client's
// credentialKind is derived from the ORIGINAL collection's genuinely
// configured credential (preserved provenance), not forced to a different
// value for replay -- so a genuine prior ClassicPAT collection replays
// cleanly through that gate unmodified.
func TestReplayClientPreservesCredentialKindForGatedCollectors(t *testing.T) {
	liveServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(t, writer, map[string]any{"totalResults": 1, "startIndex": 1, "itemsPerPage": 1,
			"Resources": []map[string]any{{"id": "1", "active": true}}})
	}))
	t.Cleanup(liveServer.Close)
	liveClient := scimFixtureClient(t, liveServer, fixtureBudget(t), SystemClock{}) // credentialKind: ClassicPAT
	sourceDir := t.TempDir()
	sourceStore := evidenceFixtureStore(t, sourceDir, nil)
	scope := Scope{liveClient.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	// Populate genuine evidence via one real (fixture) collection pass.
	if _, _, err := FetchEnterpriseSCIMUsers(context.Background(), liveClient, sourceStore, scope, "fixture-enterprise", "emu", Cloud, nil); err != nil {
		t.Fatal(err)
	}
	if err := sourceStore.Close(); err != nil {
		t.Fatal(err)
	}
	replaySource := evidenceFixtureStore(t, sourceDir, nil)
	replayClient, err := NewReplayCollectionClient(
		Target{Host: liveClient.base.Hostname(), Deployment: Cloud, Credentials: CredentialReferences{Kind: ClassicPAT}},
		RESTEvidence, liveClient.profile, replaySource, SystemClock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	destinationStore := evidenceFixtureStore(t, t.TempDir(), nil)

	result, _, err := FetchEnterpriseSCIMUsers(context.Background(), replayClient, destinationStore, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.ResourcesReturnedCount != 1 {
		t.Fatalf("expected the replay to faithfully reproduce the genuinely collected evidence, not be blocked by the live-credential gate: %+v", result)
	}
}

// TestReplayClientDefaultsUnspecifiedCredentialKindToNoCredential confirms
// the complementary case: a replay target with no explicitly configured
// credential kind is NOT silently upgraded to ClassicPAT or any other value
// that might let a credential-gated collector attempt work the original
// collection never actually proved it had a credential for. Identity
// (NoCredential) is preserved exactly like any other explicitly configured
// kind -- replay never invents a stronger credential claim than the target
// it was given actually carries.
func TestReplayClientDefaultsUnspecifiedCredentialKindToNoCredential(t *testing.T) {
	replaySource := evidenceFixtureStore(t, t.TempDir(), nil)
	client, err := NewReplayCollectionClient(Target{Host: "github.com", Deployment: Cloud}, RESTEvidence,
		fixtureProfileWithDefault(t), replaySource, SystemClock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.credentialKind != NoCredential {
		t.Fatalf("an unspecified credential kind must default to NoCredential, not be invented as something stronger: %q", client.credentialKind)
	}
}

// TestReplayClientPreservesOAuthUserCredentialKind confirms OAuthUser
// (a GitHub OAuth App user-to-server `gho_` token, the same Bearer
// read-only transport as ClassicPAT/FineGrainedPAT, just its own distinct,
// truthfully labeled credential route) round-trips through
// NewReplayCollectionClient exactly like every other explicitly configured
// kind: replay never relabels it as ClassicPAT (which would falsely widen
// its claimed authorization to SCIM's own narrower, documented contract)
// nor silently defaults it away.
func TestReplayClientPreservesOAuthUserCredentialKind(t *testing.T) {
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	profile := fixtureProfileWithDefault(t)
	client, err := NewReplayCollectionClient(
		Target{Host: "github.com", Deployment: Cloud, Credentials: CredentialReferences{Kind: OAuthUser}},
		RESTEvidence, profile, store, SystemClock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.credentialKind != OAuthUser {
		t.Fatalf("replay must preserve OAuthUser exactly, never relabel it: got %q", client.credentialKind)
	}
}

// TestFetchEnterpriseSCIMUsersOAuthUserMakesNoRequest confirms SCIM stays
// ClassicPAT-only even for the new OAuthUser kind: FetchEnterpriseSCIMUsers'
// own exclusionary gate (credentialKind != ClassicPAT) is negative, not an
// allow-list, so it correctly continues to reject OAuthUser with zero
// changes needed to that gate itself.
func TestFetchEnterpriseSCIMUsersOAuthUserMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writeJSON(t, writer, map[string]any{})
	}))
	t.Cleanup(server.Close)
	client := collectionFixtureClient(t, server, fixtureBudget(t), SystemClock{})
	client.credentialKind = OAuthUser
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	scope := Scope{client.base.Hostname(), EnterpriseScope, "fixture-enterprise"}

	result, outcomes, err := FetchEnterpriseSCIMUsers(context.Background(), client, store, scope, "fixture-enterprise", "emu", Cloud, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatalf("SCIM must never be attempted with an OAuth user token (explicitly unsupported), got %d requests", requests)
	}
	if result.Complete || outcomes[0].Status != NotRun || outcomes[0].Reason == "" {
		t.Fatalf("expected a single explicit NotRun outcome: %+v / %+v", result, outcomes)
	}
}
