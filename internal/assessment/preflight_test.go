// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
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
	if len(report.Collectors) != 67 || !reflect.DeepEqual(report.ImplementedCollectors, []string{"org.settings", "ghes.meta"}) ||
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
			if item.Readiness != Unimplemented || len(item.Outcomes) != 0 || item.Reason == "" {
				t.Fatal("unimplemented collector received a fake access probe")
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "feasibility.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored FeasibilityReport
	if err := json.Unmarshal(data, &restored); err != nil || len(restored.Collectors) != 67 {
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
