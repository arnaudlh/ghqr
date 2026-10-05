// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"unicode"
)

var resultsCSVHeader = []string{
	"control_id", "sheet", "pillar", "automation", "proposed_state",
	"confidence", "flag", "metrics_json", "evidence_refs", "notes",
}

// RenderResultsCSV exports exactly one proposed result per profile control.
// Inputs must have been sanitized by the evidence and assessor-input layers.
func RenderResultsCSV(profile *Profile, results []ControlResult) ([]byte, error) {
	index, err := indexExportResults(profile, results)
	if err != nil {
		return nil, err
	}
	rows := [][]string{resultsCSVHeader}
	for _, control := range profile.Controls {
		result := index[control.ID]
		metrics, err := json.Marshal(result.Metrics)
		if err != nil {
			return nil, fmt.Errorf("encode result metrics for %s: %w", control.ID, err)
		}
		flags := make([]string, 0, len(result.Flags))
		for _, flag := range result.Flags {
			flags = append(flags, string(flag))
		}
		sort.Strings(flags)
		rows = append(rows, []string{
			control.ID, result.Sheet, control.Pillar, string(control.Automation),
			string(result.ProposedState), string(result.Confidence),
			strings.Join(flags, ";"), string(metrics),
			strings.Join(result.EvidenceRefs, ";"), result.Notes,
		})
	}
	return encodeExportCSV(rows)
}

// RenderInterviewGuide groups required questions by pillar, principle and area.
// It includes the profile's explicitly required PRD-041 confirmation.
func RenderInterviewGuide(profile *Profile, results []ControlResult) ([]byte, error) {
	index, err := indexExportResults(profile, results)
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteString("# Assessment interview guide\n\n")
	output.WriteString("Proposed states are not final assessor confirmations. Deployment exclusions remain visible.\n\n")
	for _, pillar := range exportPillars(profile) {
		fmt.Fprintf(&output, "## %s\n\n", exportMarkdown(pillar))
		for _, principle := range exportGroups(profile, pillar, "", true) {
			fmt.Fprintf(&output, "### %s\n\n", exportMarkdown(principle))
			for _, area := range exportGroups(profile, pillar, principle, true) {
				fmt.Fprintf(&output, "#### %s\n\n", exportMarkdown(area))
				for _, control := range profile.Controls {
					if control.Pillar != pillar || control.DesignPrinciple != principle ||
						control.Area != area || !control.RequiresInterview() {
						continue
					}
					result := index[control.ID]
					fmt.Fprintf(&output, "**%s (%s)**\n\n%s\n\n",
						control.ID, control.Automation, exportMarkdown(*control.InterviewQuestion))
					fmt.Fprintf(&output, "Proposed state: %s. %s\n\n",
						result.ProposedState, exportMarkdown(result.Notes))
					if control.Automation == Partial || control.ID == "PRD-041" {
						metrics, err := json.MarshalIndent(result.Metrics, "", "  ")
						if err != nil {
							return nil, fmt.Errorf("encode interview metrics for %s: %w", control.ID, err)
						}
						output.WriteString("Computed metrics (including explicit unavailable values):\n\n")
						for _, line := range strings.Split(string(metrics), "\n") {
							fmt.Fprintf(&output, "    %s\n", line)
						}
						output.WriteString("\n")
					}
					if result.Decision != nil {
						fmt.Fprintf(&output, "Assessor decision: %s. Rationale: %s\n\n",
							result.Decision.State, exportMarkdown(result.Decision.Rationale))
					}
				}
			}
		}
	}
	return []byte(output.String()), nil
}

// RenderWorkbookUpdateCSV produces a non-destructive update proposal, not a workbook edit.
// Existing evidence is appended when supplied; otherwise evidence cells are append fragments.
// Manual controls are never included in automatic update rows.
func RenderWorkbookUpdateCSV(profile *Profile, results []ControlResult, existingEvidence map[string]string) ([]byte, error) {
	index, err := indexExportResults(profile, results)
	if err != nil {
		return nil, err
	}
	rows := [][]string{{"sheet", "control_id", "current_state", "finding", "evidence"}}
	for _, control := range profile.Controls {
		if control.Automation == Manual {
			continue
		}
		result := index[control.ID]
		state := result.ProposedState
		finding := result.Notes
		refs := append([]string{}, result.EvidenceRefs...)
		if result.Decision != nil {
			state = result.Decision.State
			finding = "Assessor decision: " + result.Decision.Rationale
			refs = append(refs, result.Decision.EvidenceRefs...)
		} else if result.RequiresConfirmation {
			metrics, err := json.Marshal(result.Metrics)
			if err != nil {
				return nil, fmt.Errorf("encode workbook metrics for %s: %w", control.ID, err)
			}
			finding = "Agent proposal \u2014 confirm in interview: " + string(metrics)
			if result.Notes != "" {
				finding += " | " + result.Notes
			}
		}
		evidence := existingEvidence[control.ID]
		addition := strings.Join(uniqueExportStrings(refs), ";")
		if addition != "" {
			if evidence != "" {
				evidence += " | "
			}
			evidence += addition
		}
		rows = append(rows, []string{
			result.Sheet, control.ID, workbookState(state), finding, evidence,
		})
	}
	return encodeExportCSV(rows)
}

// RenderAssessmentSummary reports proposed states, gaps and limitations without inferring compliance.
func RenderAssessmentSummary(profile *Profile, results []ControlResult, outcomes []CollectorOutcome, thresholds map[string]float64) ([]byte, error) {
	index, err := indexExportResults(profile, results)
	if err != nil {
		return nil, err
	}
	var output strings.Builder
	output.WriteString("# Assessment summary\n\n")
	fmt.Fprintf(&output, "Profile: %s. Source digest: %s.\n\n", exportMarkdown(profile.Version), exportMarkdown(profile.SHA256))
	output.WriteString("Counts below describe proposed states, not certification or proof that unobserved controls are implemented.\n\n")
	output.WriteString("| Pillar / design principle | IMPLEMENTED | PARTIAL | NOT_IMPLEMENTED | N/A | NOT_ASSESSED |\n")
	output.WriteString("| --- | ---: | ---: | ---: | ---: | ---: |\n")
	for _, pillar := range exportPillars(profile) {
		writeExportCounts(&output, pillar, exportStateCounts(profile, index, pillar, ""))
		for _, principle := range exportGroups(profile, pillar, "", false) {
			writeExportCounts(&output, pillar+" / "+principle, exportStateCounts(profile, index, pillar, principle))
		}
	}
	output.WriteString("\n## Top 20 fully automated gaps\n\n")
	gaps := 0
	for _, pillar := range exportPillars(profile) {
		for _, control := range profile.Controls {
			if control.Pillar != pillar || control.Automation != Full ||
				index[control.ID].ProposedState != NotImplemented || gaps == 20 {
				continue
			}
			fmt.Fprintf(&output, "- %s (%s): %s\n", control.ID, exportMarkdown(pillar), exportMarkdown(control.Control))
			gaps++
		}
	}
	if gaps == 0 {
		output.WriteString("No fully automated NOT_IMPLEMENTED gaps were proposed. This does not imply unavailable controls passed.\n")
	}
	output.WriteString("\n## Infeasible or incomplete collection\n\n")
	incomplete := 0
	for _, outcome := range outcomes {
		if outcome.Readiness == Ready && outcome.Availability == Available &&
			outcome.Status == CollectionOK && outcome.Complete {
			continue
		}
		fmt.Fprintf(&output, "- %s (%s): %s / %s / %s. %s\n", exportMarkdown(outcome.CollectorID),
			exportMarkdown(outcome.Scope.Key()), exportMarkdown(string(outcome.Readiness)),
			exportMarkdown(string(outcome.Availability)), exportMarkdown(string(outcome.Status)),
			exportMarkdown(outcome.Reason))
		incomplete++
	}
	if incomplete == 0 {
		output.WriteString("No incomplete outcomes supplied. An empty outcome list is not proof of collector coverage.\n")
	}
	output.WriteString("\n## Threshold overrides\n\n")
	for _, key := range sortedExportKeys(thresholds) {
		fmt.Fprintf(&output, "- %s: %g\n", exportMarkdown(key), thresholds[key])
	}
	if len(thresholds) == 0 {
		output.WriteString("None.\n")
	}
	output.WriteString("\n## Unavailable or inapplicable metrics\n\n")
	for _, control := range profile.Controls {
		result := index[control.ID]
		for _, key := range sortedExportKeys(result.Metrics) {
			metric := result.Metrics[key]
			if metric.Overall.Status != MetricKnown {
				fmt.Fprintf(&output, "- %s / %s: %s. %s\n", control.ID, exportMarkdown(key),
					exportMarkdown(string(metric.Overall.Status)), exportMarkdown(metric.Overall.Reason))
			}
			for _, organization := range sortedExportKeys(metric.PerOrganization) {
				observation := metric.PerOrganization[organization]
				if observation.Status != MetricKnown {
					fmt.Fprintf(&output, "- %s / %s / %s: %s. %s\n", control.ID, exportMarkdown(key),
						exportMarkdown(organization), exportMarkdown(string(observation.Status)), exportMarkdown(observation.Reason))
				}
			}
		}
	}
	return []byte(output.String()), nil
}

func indexExportResults(profile *Profile, results []ControlResult) (map[string]ControlResult, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate export profile: %w", err)
	}
	if len(results) != len(profile.Controls) {
		return nil, fmt.Errorf("assessment export requires exactly %d control results", len(profile.Controls))
	}
	controls := make(map[string]Control, len(profile.Controls))
	for _, control := range profile.Controls {
		controls[control.ID] = control
	}
	index := make(map[string]ControlResult, len(results))
	for _, result := range results {
		control, known := controls[result.ControlID]
		if _, duplicate := index[result.ControlID]; !known || duplicate {
			return nil, fmt.Errorf("assessment export contains an unknown or duplicate control ID")
		}
		if err := validateExportResult(control, result); err != nil {
			return nil, fmt.Errorf("validate export result %s: %w", control.ID, err)
		}
		index[control.ID] = result
	}
	return index, nil
}

func validateExportResult(control Control, result ControlResult) error {
	if result.Sheet != "Controls" || result.Pillar != control.Pillar ||
		result.Origin != control.Origin || result.Automation != control.Automation {
		return fmt.Errorf("result taxonomy does not match its profile control")
	}
	if err := result.ProposedState.Validate(); err != nil {
		return err
	}
	switch result.Confidence {
	case HighConfidence, MediumConfidence, LowConfidence:
	default:
		return fmt.Errorf("result confidence is outside the export contract")
	}
	if (result.ProposedState == NotAssessed || result.ProposedState == NotApplicable) && strings.TrimSpace(result.Notes) == "" {
		return fmt.Errorf("unassessed or inapplicable result requires an explanation")
	}
	seenFlags := map[ResultFlag]bool{}
	for _, flag := range result.Flags {
		if (flag != Confirm && flag != VerifyEndpoint) || seenFlags[flag] {
			return fmt.Errorf("result contains an unknown or duplicate flag")
		}
		seenFlags[flag] = true
	}
	if control.RequiresInterview() && result.Decision == nil && !result.RequiresConfirmation {
		return fmt.Errorf("required assessor confirmation is missing")
	}
	if (control.Automation == Partial || control.ID == "PRD-041") && result.Decision == nil && !seenFlags[Confirm] {
		return fmt.Errorf("pending proposal is missing its confirmation flag")
	}
	if result.Decision != nil {
		if err := result.Decision.State.Validate(); err != nil {
			return fmt.Errorf("assessor decision: %w", err)
		}
		if strings.TrimSpace(result.Decision.Assessor) == "" || result.Decision.ConfirmedAt.IsZero() ||
			strings.TrimSpace(result.Decision.Rationale) == "" {
			return fmt.Errorf("assessor decision requires an assessor, timestamp and rationale")
		}
	}
	keys, err := control.MetricKeys()
	if err != nil {
		return err
	}
	for _, key := range keys {
		metric, exists := result.Metrics[key]
		if !exists || metric.Key != key {
			return fmt.Errorf("required result metric %s is missing or mismatched", key)
		}
		if err := metric.Overall.Validate(); err != nil {
			return fmt.Errorf("metric %s overall observation: %w", key, err)
		}
		for _, observation := range metric.PerOrganization {
			if err := observation.Validate(); err != nil {
				return fmt.Errorf("metric %s organization observation: %w", key, err)
			}
		}
	}
	return nil
}

func encodeExportCSV(rows [][]string) ([]byte, error) {
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	for _, row := range rows {
		cells := make([]string, len(row))
		for index, value := range row {
			cells[index] = exportCSVText(value)
		}
		if err := writer.Write(cells); err != nil {
			return nil, fmt.Errorf("write assessment CSV row: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush assessment CSV: %w", err)
	}
	return output.Bytes(), nil
}

func exportCSVText(value string) string {
	trimmed := strings.TrimLeftFunc(value, unicode.IsSpace)
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func workbookState(state State) string {
	switch state {
	case Implemented:
		return "Implemented"
	case PartiallyImplemented:
		return "Partially Implemented"
	case NotImplemented:
		return "Not Implemented"
	case NotApplicable:
		return "Not Applicable"
	default:
		return "Not Assessed"
	}
}

func exportMarkdown(value string) string {
	value = html.EscapeString(value)
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", " ")
}

func exportPillars(profile *Profile) []string {
	values := make([]string, 0, len(controlFamilies))
	for _, control := range profile.Controls {
		values = append(values, control.Pillar)
	}
	return uniqueExportStrings(values)
}

func exportGroups(profile *Profile, pillar, principle string, interviewsOnly bool) []string {
	values := []string{}
	for _, control := range profile.Controls {
		if control.Pillar != pillar || (interviewsOnly && !control.RequiresInterview()) {
			continue
		}
		if principle == "" {
			values = append(values, control.DesignPrinciple)
		} else if control.DesignPrinciple == principle {
			values = append(values, control.Area)
		}
	}
	return uniqueExportStrings(values)
}

func uniqueExportStrings(values []string) []string {
	result := []string{}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	return result
}

func sortedExportKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func exportStateCounts(profile *Profile, index map[string]ControlResult, pillar, principle string) map[State]int {
	counts := map[State]int{}
	for _, control := range profile.Controls {
		if control.Pillar == pillar && (principle == "" || control.DesignPrinciple == principle) {
			counts[index[control.ID].ProposedState]++
		}
	}
	return counts
}

func writeExportCounts(output *strings.Builder, label string, counts map[State]int) {
	fmt.Fprintf(output, "| %s | %d | %d | %d | %d | %d |\n", exportMarkdown(label),
		counts[Implemented], counts[PartiallyImplemented], counts[NotImplemented],
		counts[NotApplicable], counts[NotAssessed])
}
