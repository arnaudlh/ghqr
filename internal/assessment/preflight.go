// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// CollectorFeasibility separates catalogue membership, implementation and observed access.
type CollectorFeasibility struct {
	CollectorID string             `json:"collector_id"`
	Readiness   Readiness          `json:"readiness"`
	Outcomes    []CollectorOutcome `json:"outcomes"`
	Reason      string             `json:"reason,omitempty"`
}

// FeasibilityReport records actual scoped probes, not inferred token-wide access.
type FeasibilityReport struct {
	Profile               ProfileSummary         `json:"profile"`
	CollectedAt           time.Time              `json:"collected_at"`
	ImplementedCollectors []string               `json:"implemented_collectors"`
	ImplementedEvaluators []string               `json:"implemented_evaluators"`
	Collectors            []CollectorFeasibility `json:"collectors"`
}

// ImplementedCollectorIDs reports implemented endpoint contracts separately from catalogue IDs.
func ImplementedCollectorIDs() []string {
	return []string{"org.settings", "ghes.meta"}
}

// RunPreflight executes only explicitly scoped implemented probes and saves all outcomes.
// Missing permissions and unimplemented collectors remain distinct in the report.
func RunPreflight(ctx context.Context, profile *Profile, config *CustomerConfig) (*FeasibilityReport, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, err
	}
	budget, err := NewRequestBudget(config.Concurrency)
	if err != nil {
		return nil, err
	}
	clock := SystemClock{}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		return nil, err
	}
	newClient := func(target Target) (*CollectionClient, error) {
		return NewCollectionClient(target, RESTEvidence, profile, budget, clock)
	}
	report, runErr := preflightWithStore(ctx, profile, targets, store, clock, newClient)
	closeErr := store.Close()
	if runErr != nil {
		return nil, runErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return report, nil
}

func preflightWithStore(ctx context.Context, profile *Profile, targets []Target, store *EvidenceStore, clock Clock,
	newClient func(Target) (*CollectionClient, error)) (*FeasibilityReport, error) {
	report := &FeasibilityReport{
		Profile: profile.Summary(), CollectedAt: clock.Now(), ImplementedCollectors: ImplementedCollectorIDs(),
		ImplementedEvaluators: []string{}, Collectors: []CollectorFeasibility{},
	}
	for _, collector := range profile.Collectors {
		item := CollectorFeasibility{CollectorID: collector.ID, Readiness: Unimplemented, Outcomes: []CollectorOutcome{},
			Reason: "collector implementation is not registered; access has not been probed"}
		if collector.ID == "org.settings" || collector.ID == "ghes.meta" {
			item.Readiness = Ready
			item.Reason = ""
			for _, target := range targets {
				if collector.ID == "ghes.meta" && target.Deployment != Server {
					continue
				}
				scopes := []Scope{}
				if collector.ID == "ghes.meta" {
					scopes = append(scopes, Scope{target.Host, InstanceScope, target.Host})
				} else {
					for _, organization := range target.Organizations {
						scopes = append(scopes, Scope{target.Host, OrganizationScope, organization})
					}
				}
				if len(scopes) == 0 {
					continue
				}
				client, setupErr := newClient(target)
				for _, scope := range scopes {
					if setupErr != nil {
						item.Outcomes = append(item.Outcomes, CollectorOutcome{
							CollectorID: collector.ID, Feature: "probe", Scope: scope, Readiness: Ready,
							Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{},
							Reason: "explicit credential route could not be initialized",
						})
						continue
					}
					endpoint := "meta"
					if collector.ID == "org.settings" {
						endpoint = "orgs/" + url.PathEscape(scope.Name)
					}
					outcome, probeErr := client.CollectGET(ctx, store, scope, collector.ID, "probe", endpoint, "", false)
					if probeErr != nil && outcome.Reason == "" {
						return nil, fmt.Errorf("preflight evidence pipeline failed: %w", probeErr)
					}
					item.Outcomes = append(item.Outcomes, outcome)
				}
			}
			if len(item.Outcomes) == 0 {
				item.Reason = "no applicable explicit scope object; no access probe attempted"
			}
		}
		report.Collectors = append(report.Collectors, item)
	}
	if err := store.WriteReport("feasibility.json", report); err != nil {
		return nil, err
	}
	if err := store.WriteReport("collection-log.json", report.Collectors); err != nil {
		return nil, err
	}
	if err := store.WriteReport("runs/"+clock.Now().Format("20060102T150405.000000000Z")+".json", report); err != nil {
		return nil, err
	}
	return report, nil
}

// WriteReport applies the same redaction and atomic boundary as raw evidence.
func (s *EvidenceStore) WriteReport(path string, report any) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode collection report: %w", err)
	}
	clean, _, err := s.redactor.JSON(data)
	if err != nil {
		return fmt.Errorf("sanitize collection report: %w", err)
	}
	return s.atomicWrite(path, clean)
}

// ImportJSON sanitizes caller-supplied evidence again and marks it as imported provenance.
func ImportJSON(profile *Profile, config *CustomerConfig, raw []byte, metadata EvidenceMetadata) (EvidenceRef, error) {
	if err := profile.Validate(); err != nil {
		return EvidenceRef{}, err
	}
	if err := config.Validate(); err != nil {
		return EvidenceRef{}, err
	}
	if metadata.ProfileVersion != profile.Version || metadata.ProfileSHA256 != profile.SHA256 {
		return EvidenceRef{}, fmt.Errorf("import profile identity does not match the selected profile")
	}
	if err := authorizeEvidenceScope(config, metadata.Scope); err != nil {
		return EvidenceRef{}, err
	}
	metadata.SourceKind = ImportedEvidence
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		return EvidenceRef{}, err
	}
	ref, saveErr := store.SaveJSON(raw, metadata)
	closeErr := store.Close()
	if saveErr != nil {
		return EvidenceRef{}, saveErr
	}
	return ref, closeErr
}
