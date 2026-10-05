// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import "fmt"

// CollectorPlan records implementation readiness without claiming a live access probe.
type CollectorPlan struct {
	CollectorID  string       `json:"collector_id"`
	Readiness    Readiness    `json:"readiness"`
	Availability Availability `json:"availability"`
	Reason       string       `json:"reason"`
}

// Plan is an offline foundation inventory, not a feasibility report or scored assessment.
type Plan struct {
	Kind       string             `json:"kind"`
	Profile    ProfileSummary     `json:"profile"`
	Sources    []SourceReference  `json:"sources"`
	Targets    []Target           `json:"targets"`
	Collectors []CollectorPlan    `json:"collectors"`
	Results    []ControlResult    `json:"results"`
	Metrics    map[string]Metric  `json:"metrics"`
	Thresholds map[string]float64 `json:"threshold_overrides"`
}

// BuildPlan lists all profile controls and metrics with honest unimplemented states.
func BuildPlan(profile *Profile, config *CustomerConfig) (*Plan, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate planning profile: %w", err)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate planning configuration: %w", err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, fmt.Errorf("resolve planning targets: %w", err)
	}
	plan := &Plan{
		Kind: "offline-plan", Profile: profile.Summary(), Sources: profile.Sources(),
		Targets: targets, Collectors: []CollectorPlan{}, Results: []ControlResult{},
		Metrics: map[string]Metric{}, Thresholds: config.Thresholds,
	}
	for _, collector := range profile.Collectors {
		readiness := Unimplemented
		reason := "collector and import contracts are not implemented; access has not been probed"
		for _, implemented := range ImplementedCollectorIDs() {
			if collector.ID == implemented {
				readiness = Ready
				reason = "collector implementation is registered; access has not been probed by this offline plan"
			}
		}
		plan.Collectors = append(plan.Collectors, CollectorPlan{
			CollectorID: collector.ID, Readiness: readiness, Availability: NotChecked, Reason: reason,
		})
	}
	for _, control := range profile.Controls {
		keys, err := control.MetricKeys()
		if err != nil {
			return nil, fmt.Errorf("read planning metric keys for %s: %w", control.ID, err)
		}
		result := initialResult(control, targets)
		for _, key := range keys {
			if _, exists := plan.Metrics[key]; !exists {
				plan.Metrics[key] = unknownMetric(key, targets)
			}
			result.Metrics[key] = plan.Metrics[key]
		}
		plan.Results = append(plan.Results, result)
	}
	for key := range config.Thresholds {
		if _, exists := plan.Metrics[key]; !exists {
			return nil, fmt.Errorf("threshold override references unknown profile metric %q", key)
		}
	}
	return plan, nil
}

func initialResult(control Control, targets []Target) ControlResult {
	result := ControlResult{
		ControlID: control.ID, Sheet: "Controls", Pillar: control.Pillar,
		Origin: control.Origin, Automation: control.Automation,
		ProposedState: NotAssessed, Confidence: LowConfidence,
		Flags: []ResultFlag{}, RequiresConfirmation: control.RequiresInterview(),
		Metrics: map[string]Metric{}, EvidenceRefs: []string{},
		Notes: "collector, metric and evaluator implementation pending; no assessment performed",
	}
	if control.Automation == Partial || control.ID == "PRD-041" {
		result.Flags = append(result.Flags, Confirm)
	}
	applicable := false
	for _, target := range targets {
		if control.Scope == "All" || control.Scope == "GHE (Cloud & Server)" ||
			(control.Scope == "GHE Cloud" && target.Deployment == Cloud) ||
			(control.Scope == "GHE Server" && target.Deployment == Server) {
			applicable = true
		}
	}
	if !applicable {
		result.ProposedState = NotApplicable
		result.Notes = "control deployment scope is excluded by the explicit customer targets"
	}
	return result
}

func unknownMetric(key string, targets []Target) Metric {
	value := MetricValue{
		Status: MetricUnavailable, Population: "not established",
		EvidenceRefs: []string{}, Reason: "metric computation and required evidence are not implemented",
	}
	metric := Metric{Key: key, Overall: value, PerOrganization: map[string]MetricValue{}}
	for _, target := range targets {
		for _, organization := range target.Organizations {
			metric.PerOrganization[(Scope{target.Host, OrganizationScope, organization}).Key()] = value
		}
	}
	return metric
}
