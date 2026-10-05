// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
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
	ProbeCollectors       []string               `json:"probe_collectors"`
	ImplementedEvaluators []string               `json:"implemented_evaluators"`
	Collectors            []CollectorFeasibility `json:"collectors"`
}

// ImplementedCollectorIDs lists collection adapters and preflight-only probes.
// It excludes import-only contracts and does not establish access or completeness.
func ImplementedCollectorIDs() []string {
	ids := append([]string{}, RunImplementedCollectorIDs()...)
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	for _, id := range PreflightProbeCollectorIDs() {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	sort.Strings(ids)
	return ids
}

// PreflightProbeCollectorIDs lists the narrow set of pre-run access probes.
func PreflightProbeCollectorIDs() []string {
	return []string{"org.settings", "ghes.meta"}
}

// runImplementedCollectorIDSet mirrors RunImplementedCollectorIDs() for O(1)
// feasibility lookups, built once from the same registry the live run loop
// uses -- this is the actual adapter-implementation registry, never
// hand-maintained separately.
var runImplementedCollectorIDSet = buildRunImplementedCollectorIDSet()

func buildRunImplementedCollectorIDSet() map[string]bool {
	set := make(map[string]bool, len(RunImplementedCollectorIDs()))
	for _, id := range RunImplementedCollectorIDs() {
		set[id] = true
	}
	return set
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
		ProbeCollectors:       PreflightProbeCollectorIDs(),
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
		} else if importContractCollectorIDSet[collector.ID] {
			// These collectors have no live API/probe surface at all (customer-
			// run CLI/SSH output, Management Console screenshots, external
			// status feeds or assessor interviews/documents). Readiness is
			// explicitly ImportOnly, never Ready (no probe was or could be
			// attempted) and never the default Unimplemented reason (which
			// would wrongly suggest a future API probe is expected here).
			item.Readiness = ImportOnly
			item.Reason = "no live API surface exists for this collector; it accepts only an explicitly supplied, " +
				"schema-validated import payload (see ValidateImportContractPayload) and is never auto-probed"
		} else if runImplementedCollectorIDSet[collector.ID] {
			// This collector has a real collection adapter used by `ghqr
			// assess run` (for example org.members), but this preflight pass
			// only issues an explicit pre-run access probe for org.settings/
			// ghes.meta above. Ready here means "an implementation exists",
			// not "this probe verified live access" -- Outcomes stays empty
			// and no request is made, so this must never be confused with a
			// probed, Outcome-backed Ready result.
			item.Readiness = Ready
			item.Reason = "implemented collection adapter; no preflight probe attempted/availability not checked"
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
	// A recognized import-contract collector ID (ghes.cli/ghes.backup, every
	// ui.*/ext.* capture, manual.interview/manual.document) must satisfy its
	// typed, schema-validated shape before any evidence store is even
	// opened: these 16 collector IDs have no live API surface at all, so
	// this import is their ONLY acceptance gate. An ordinary scoped-API
	// collector ID (anything outside this 16-member set) is unaffected and
	// keeps accepting any well-scoped JSON payload exactly as before.
	if importContractCollectorIDSet[metadata.CollectorID] {
		if _, err := ValidateImportContractPayload(metadata.CollectorID, raw); err != nil {
			return EvidenceRef{}, fmt.Errorf("import payload for %q failed its contract validation: %w", metadata.CollectorID, err)
		}
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
