// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPreflightReportsRealProbesSeparatelyFromCatalogueReadiness(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/meta" {
			writer.WriteHeader(403)
			if _, err := writer.Write([]byte(`{"message":"permission denied"}`)); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := writer.Write([]byte(`{"two_factor_requirement_enabled":true}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	budget := fixtureBudget(t)
	client := collectionFixtureClient(t, server, budget, SystemClock{})
	directory := t.TempDir()
	store := evidenceFixtureStore(t, directory, nil)
	target := Target{Host: client.base.Hostname(), Deployment: Server, Organizations: []string{"fixture"}}
	report, err := preflightWithStore(context.Background(), client.profile, []Target{target}, store, SystemClock{},
		func(Target) (*CollectionClient, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Collectors) != 67 || !reflect.DeepEqual(report.ImplementedCollectors, ImplementedCollectorIDs()) ||
		!reflect.DeepEqual(report.ProbeCollectors, []string{"org.settings", "ghes.meta"}) ||
		len(report.ImplementedEvaluators) != 0 {
		t.Fatal("preflight confused catalogue and implemented IDs")
	}
	seen := map[string]bool{}
	for _, item := range report.Collectors {
		if seen[item.CollectorID] {
			t.Fatal("duplicate feasibility ID")
		}
		seen[item.CollectorID] = true
		switch item.CollectorID {
		case "org.settings":
			if len(item.Outcomes) != 1 || !item.Outcomes[0].Complete || item.Outcomes[0].Availability != Available {
				t.Fatal("successful explicit settings probe was not recorded")
			}
		case "ghes.meta":
			if len(item.Outcomes) != 1 || item.Outcomes[0].Complete || item.Outcomes[0].Availability != MissingPermission {
				t.Fatal("forbidden metadata probe was guessed as available")
			}
		default:
			switch {
			case importContractCollectorIDSet[item.CollectorID]:
				if item.Readiness != ImportOnly || len(item.Outcomes) != 0 || item.Reason == "" {
					t.Fatal("import-contract collector should report explicit ImportOnly readiness, no probe outcomes and a reason")
				}
			case runImplementedCollectorIDSet[item.CollectorID]:
				if item.Readiness != Ready || len(item.Outcomes) != 0 || item.Reason == "" {
					t.Fatalf("implemented collection adapter %q should report Ready with no probe outcomes and a reason: %+v",
						item.CollectorID, item)
				}
			default:
				if item.Readiness != Unimplemented || len(item.Outcomes) != 0 || item.Reason == "" {
					t.Fatal("unimplemented collector received a fake access probe")
				}
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "feasibility.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored FeasibilityReport
	if err := json.Unmarshal(data, &restored); err != nil || len(restored.Collectors) != 67 ||
		!reflect.DeepEqual(restored.ImplementedCollectors, report.ImplementedCollectors) ||
		!reflect.DeepEqual(restored.ProbeCollectors, report.ProbeCollectors) {
		t.Fatal("feasibility export missing its catalogue/outcome contract")
	}
}

func TestImportNeverTrustsAlreadyRedactedAndRejectsUnscopedData(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	config, err := ParseConfig([]byte("organizations: [fixture-org]"))
	if err != nil {
		t.Fatal(err)
	}
	config.EvidenceDir = t.TempDir()
	metadata := evidenceFixtureMetadata(t)
	metadata.SourceKind = RESTEvidence
	ref, err := ImportJSON(profile, config, []byte(`{"already_redacted":true,"secret":"dummy-sensitive-value","resolution_comment":"revoked dummy-sensitive-value","resolved_by":{"email":"person@example.test"}}`), metadata)
	if err != nil {
		t.Fatal(err)
	}
	store := evidenceFixtureStore(t, config.EvidenceDir, nil)
	raw, safeMetadata, restoredRef, err := store.LoadJSON(metadata.Scope, metadata.CollectorID, metadata.Feature)
	if err != nil || restoredRef != ref || safeMetadata.SourceKind != ImportedEvidence ||
		bytesContainAny(raw, "dummy-sensitive-value", "person@example.test") {
		t.Fatal("import claimed live provenance or persisted sensitive content")
	}
	metadata.Scope.Name = "not-authorized"
	if _, err := ImportJSON(profile, config, []byte(`[]`), metadata); err == nil {
		t.Fatal("import scope escaped explicit customer configuration")
	}
}

func TestDiscoveredLiteralSecretsAreRemovedFromLaterPagesAndLogs(t *testing.T) {
	redactor := NewRedactor()
	if _, _, err := redactor.JSON([]byte(`{"secret":"dummy-sensitive-value"}`)); err != nil {
		t.Fatal(err)
	}
	later, _, err := redactor.JSON([]byte(`{"unrelated_field":"duplicated dummy-sensitive-value"}`))
	if err != nil || bytesContainAny(later, "dummy-sensitive-value") ||
		bytesContainAny([]byte(redactor.Text("request failed with dummy-sensitive-value")), "dummy-sensitive-value") {
		t.Fatal("known literal secret leaked across a later page or error/log boundary")
	}
}

// TestPreflightDistinguishesImplementedAdaptersFromProbedAccess is a
// regression test: preflight previously defaulted every collector other
// than org.settings/ghes.meta to Unimplemented, even collectors with a real
// collection adapter already used by `ghqr assess run` (for example
// org.members), misreporting them as having zero implementation. An
// implemented-but-not-separately-probed collector must report Ready with an
// explicit "no probe attempted" reason and zero Outcomes (no network
// request), distinct from org.settings/ghes.meta's actually-probed Ready
// result and from a genuinely unimplemented collector's Unimplemented
// result.
func TestPreflightDistinguishesImplementedAdaptersFromProbedAccess(t *testing.T) {
	profile, err := LoadDefaultProfile()
	if err != nil {
		t.Fatal(err)
	}
	store := evidenceFixtureStore(t, t.TempDir(), nil)
	target := Target{Host: "github.example.test", Deployment: Cloud, Organizations: []string{"fixture-org"}}
	report, err := preflightWithStore(context.Background(), profile, []Target{target}, store, SystemClock{},
		func(Target) (*CollectionClient, error) {
			return nil, fmt.Errorf("no live credentials available in this fixture test")
		})
	if err != nil {
		t.Fatal(err)
	}

	byID := map[string]CollectorFeasibility{}
	for _, item := range report.Collectors {
		byID[item.CollectorID] = item
	}
	if len(report.ImplementedCollectors) != len(RunImplementedCollectorIDs())+1 ||
		!reflect.DeepEqual(report.ProbeCollectors, PreflightProbeCollectorIDs()) {
		t.Fatalf("adapter and probe registries were conflated: %+v", report)
	}
	seenImplementations := map[string]bool{}
	for _, id := range report.ImplementedCollectors {
		if seenImplementations[id] || byID[id].Readiness != Ready {
			t.Fatalf("implemented registry contains duplicate or non-ready ID %q", id)
		}
		seenImplementations[id] = true
	}

	members, ok := byID["org.members"]
	if !ok {
		t.Fatal("org.members missing from the feasibility report")
	}
	if members.Readiness != Ready {
		t.Fatalf("org.members has a real collection adapter; it must not report Unimplemented, got %q", members.Readiness)
	}
	if len(members.Outcomes) != 0 {
		t.Fatal("an implemented-but-unprobed collector must carry zero Outcomes (no network request)")
	}
	if members.Reason == "" || members.Reason == "collector implementation is not registered; access has not been probed" {
		t.Fatalf("org.members must carry the implemented-adapter reason, not the default unimplemented reason: %q", members.Reason)
	}

	readyNotProbed, importOnly, unimplemented := 0, 0, 0
	for id, item := range byID {
		switch {
		case id == "org.settings" || id == "ghes.meta":
			continue
		case importContractCollectorIDSet[id]:
			importOnly++
			if item.Readiness != ImportOnly {
				t.Fatalf("%q should be ImportOnly, got %q", id, item.Readiness)
			}
		case runImplementedCollectorIDSet[id]:
			readyNotProbed++
			if item.Readiness != Ready {
				t.Fatalf("%q has a real adapter and should be Ready, got %q", id, item.Readiness)
			}
		default:
			unimplemented++
			if item.Readiness != Unimplemented {
				t.Fatalf("%q should be Unimplemented, got %q", id, item.Readiness)
			}
		}
	}
	wantReadyNotProbed := len(RunImplementedCollectorIDs()) - 1 // org.settings is probed separately, not double-counted here
	if readyNotProbed != wantReadyNotProbed {
		t.Fatalf("expected %d implemented-adapter collectors besides org.settings, got %d", wantReadyNotProbed, readyNotProbed)
	}
	if importOnly != len(ImportContractCollectorIDs()) {
		t.Fatalf("expected %d import-contract collectors, got %d", len(ImportContractCollectorIDs()), importOnly)
	}
	wantTotal := len(profile.Collectors)
	wantUnimplemented := wantTotal - 2 - importOnly - readyNotProbed
	if unimplemented != wantUnimplemented {
		t.Fatalf("expected %d genuinely unimplemented collectors, got %d", wantUnimplemented, unimplemented)
	}
}
