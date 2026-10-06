// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

//go:embed profile/simple-checks.v1.json
var defaultSimpleChecks []byte

// SimpleComparison is a whitelisted scalar comparison, never executable code.
type SimpleComparison struct {
	Operator       string `json:"operator"`
	ExpectedValues []any  `json:"expected_values"`
}

// SimpleCheck maps an existing control to a typed field in a collected metric.
type SimpleCheck struct {
	ControlID   string           `json:"control_id"`
	QuestionRef string           `json:"question_ref"`
	MetricKey   string           `json:"metric_key"`
	FieldPath   string           `json:"field_path"`
	Type        string           `json:"type"`
	Implemented SimpleComparison `json:"implemented"`
	Partial     SimpleComparison `json:"partial"`
}

// ScalarExtraction selects a typed configuration fact from an existing repo.details response.
type ScalarExtraction struct {
	CollectorID string           `json:"collector_id"`
	Fact        string           `json:"fact"`
	FieldPath   string           `json:"field_path"`
	Type        string           `json:"type"`
	KnownValues []any            `json:"known_values"`
	Enabled     SimpleComparison `json:"enabled"`
}

// SimpleChecks versions the bounded declarative policy for ARC-005 and GOV-001.
type SimpleChecks struct {
	SchemaVersion  string             `json:"schema_version"`
	ProfileVersion string             `json:"profile_version"`
	Checks         []SimpleCheck      `json:"checks"`
	Extractions    []ScalarExtraction `json:"extractions"`
	SHA256         string             `json:"-"`
	sourceJSON     []byte
}

// LoadSimpleChecks loads the bundled policy or a strict explicit JSON override.
func LoadSimpleChecks(profile *Profile, path string) (*SimpleChecks, error) {
	data := defaultSimpleChecks
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read simple checks: %w", err)
		}
	}
	return ParseSimpleChecks(profile, data)
}

// ParseSimpleChecks rejects unknown fields, unsupported controls and untyped predicates.
func ParseSimpleChecks(profile *Profile, data []byte) (*SimpleChecks, error) {
	if len(data) > 64*1024 {
		return nil, fmt.Errorf("simple checks exceed the 64 KiB policy limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var checks SimpleChecks
	if err := decoder.Decode(&checks); err != nil {
		return nil, fmt.Errorf("decode simple checks: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("simple checks require exactly one JSON object")
	}
	checks.SHA256 = digestBytes(data)
	checks.sourceJSON = bytes.Clone(data)
	if err := checks.Validate(profile); err != nil {
		return nil, err
	}
	return &checks, nil
}

// Validate confines mappings to existing simple controls and declared metric payloads.
func (c *SimpleChecks) Validate(profile *Profile) error {
	if c == nil || profile == nil || c.SchemaVersion != "1" || c.ProfileVersion != profile.Version || len(c.Checks) != 2 {
		return fmt.Errorf("simple checks require schema 1, the current profile version and exactly two existing controls")
	}
	if len(c.sourceJSON) == 0 || c.SHA256 == "" || digestBytes(c.sourceJSON) != c.SHA256 {
		return fmt.Errorf("simple checks require loaded exact source bytes and their matching digest")
	}
	if len(c.Extractions) != 1 {
		return fmt.Errorf("simple checks require exactly one existing repo.details scalar extraction")
	}
	extraction := c.Extractions[0]
	if extraction.CollectorID != "repo.details" || extraction.Fact != "dependency_operational" ||
		!strings.HasPrefix(extraction.FieldPath, "/") || len(extraction.FieldPath) > 256 ||
		len(strings.Split(extraction.FieldPath, "/")) > 9 ||
		(extraction.Enabled.Operator != "eq" && extraction.Enabled.Operator != "in") ||
		len(extraction.Enabled.ExpectedValues) == 0 || len(extraction.Enabled.ExpectedValues) > 32 ||
		(extraction.Enabled.Operator == "eq" && len(extraction.Enabled.ExpectedValues) != 1) ||
		len(extraction.KnownValues) == 0 || len(extraction.KnownValues) > 32 {
		return fmt.Errorf("scalar extraction must use the existing repo.details fact and a bounded object-field path/enum predicate")
	}
	for _, segment := range strings.Split(strings.TrimPrefix(extraction.FieldPath, "/"), "/") {
		if !metricKeyPattern.MatchString(segment) {
			return fmt.Errorf("scalar extraction paths support named JSON object fields only")
		}
	}
	for _, value := range append(append([]any{}, extraction.KnownValues...), extraction.Enabled.ExpectedValues...) {
		if !simpleScalarType(value, extraction.Type) {
			return fmt.Errorf("scalar extraction requires typed known and expected values")
		}
		if text, ok := value.(string); ok && (len(text) > 256 || NewRedactor().Text(text) != text) {
			return fmt.Errorf("scalar extraction enum contains sensitive or oversized text")
		}
	}
	for _, expected := range extraction.Enabled.ExpectedValues {
		if !simpleCompare(expected, SimpleComparison{Operator: "in", ExpectedValues: extraction.KnownValues}) {
			return fmt.Errorf("scalar enabled predicates must reference explicitly known enum values")
		}
	}
	if len(c.sourceJSON) > 0 {
		var original SimpleChecks
		decoder := json.NewDecoder(bytes.NewReader(c.sourceJSON))
		decoder.UseNumber()
		if err := decoder.Decode(&original); err != nil {
			return fmt.Errorf("decode original check definitions: %w", err)
		}
		current, err := json.Marshal(c)
		if err != nil {
			return fmt.Errorf("encode current check definitions: %w", err)
		}
		source, err := json.Marshal(original)
		if err != nil {
			return fmt.Errorf("encode original check definitions: %w", err)
		}
		if !bytes.Equal(current, source) || digestBytes(c.sourceJSON) != c.SHA256 {
			return fmt.Errorf("check definitions changed after loading; load the explicit JSON policy again")
		}
	}
	controls := map[string]Control{}
	for _, control := range profile.Controls {
		controls[control.ID] = control
	}
	seen := map[string]bool{}
	for _, check := range c.Checks {
		if (check.ControlID != "ARC-005" && check.ControlID != "GOV-001") || seen[check.ControlID] ||
			check.QuestionRef != check.ControlID {
			return fmt.Errorf("simple checks require unique ARC-005/GOV-001 IDs and their unchanged question references")
		}
		seen[check.ControlID] = true
		control, exists := controls[check.ControlID]
		if !exists {
			return fmt.Errorf("simple check references an absent control")
		}
		keys, err := control.MetricKeys()
		if err != nil {
			return err
		}
		declared := false
		for _, key := range keys {
			declared = declared || key == check.MetricKey
		}
		if !declared || (check.FieldPath != "/overall/number" && check.FieldPath != "/overall/boolean" &&
			check.FieldPath != "/overall/text") {
			return fmt.Errorf("simple check %s requires a declared metric and a scalar overall payload field", check.ControlID)
		}
		if check.Type != "number" && check.Type != "boolean" && check.Type != "string" {
			return fmt.Errorf("simple check %s has an unsupported scalar type", check.ControlID)
		}
		for _, comparison := range []SimpleComparison{check.Implemented, check.Partial} {
			if len(comparison.ExpectedValues) == 0 || len(comparison.ExpectedValues) > 32 {
				return fmt.Errorf("simple comparison requires 1 to 32 expected values")
			}
			switch comparison.Operator {
			case "eq", "in":
			case "gte", "gt", "lte", "lt":
				if check.Type != "number" {
					return fmt.Errorf("ordered comparisons require a number")
				}
			default:
				return fmt.Errorf("unsupported simple comparison operator")
			}
			if comparison.Operator != "in" && len(comparison.ExpectedValues) != 1 {
				return fmt.Errorf("scalar comparison requires exactly one expected value")
			}
			for _, value := range comparison.ExpectedValues {
				if !simpleScalarType(value, check.Type) {
					return fmt.Errorf("simple check %s has an expected value with the wrong type", check.ControlID)
				}
				if text, ok := value.(string); ok && (len(text) > 256 || NewRedactor().Text(text) != text) {
					return fmt.Errorf("simple string values must be bounded and contain no sensitive material")
				}
			}
		}
	}
	return nil
}

func simpleScalarType(value any, kind string) bool {
	switch kind {
	case "number":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := number.Float64()
		return err == nil
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	default:
		return false
	}
}

func simpleField(data []byte, pointer string) (any, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode metric field: %w", err)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("field %s does not resolve to an object", pointer)
		}
		value, ok = object[segment]
		if !ok || value == nil {
			return nil, fmt.Errorf("field %s is missing or null", pointer)
		}
	}
	return value, nil
}

func simpleCompare(value any, comparison SimpleComparison) bool {
	for _, expected := range comparison.ExpectedValues {
		matches := value == expected
		if number, ok := value.(json.Number); ok {
			actual, err := number.Float64()
			expectedNumber, expectedOK := expected.(json.Number)
			if err != nil || !expectedOK {
				return false
			}
			target, err := expectedNumber.Float64()
			if err != nil {
				return false
			}
			switch comparison.Operator {
			case "gte":
				matches = actual >= target
			case "gt":
				matches = actual > target
			case "lte":
				matches = actual <= target
			case "lt":
				matches = actual < target
			default:
				matches = actual == target
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func evaluateSimpleCheck(control Control, input *EvaluationInput, result ControlResult, complete bool) ControlResult {
	checks := input.Checks
	if checks == nil {
		var err error
		checks, err = LoadSimpleChecks(input.Profile, "")
		if err != nil {
			result.ProposedState, result.Confidence, result.Notes = NotAssessed, LowConfidence, err.Error()
			return result
		}
	}
	var check SimpleCheck
	for _, candidate := range checks.Checks {
		if candidate.ControlID == control.ID {
			check = candidate
		}
	}
	result.RuleDefinitionSHA256 = checks.SHA256
	metric, exists := result.Metrics[check.MetricKey]
	result.EvidenceRefs = append([]string{}, metric.Overall.EvidenceRefs...)
	if !exists || metric.Overall.Status != MetricKnown {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = "NOT_ASSESSED: selected metric is missing or unavailable. " + metric.Overall.Reason
		return result
	}

	if err := metric.Overall.Validate(); err != nil {
		result.ProposedState, result.Confidence, result.Notes = NotAssessed, LowConfidence, "NOT_ASSESSED: "+err.Error()
		return result
	}
	data, err := json.Marshal(metric)
	if err != nil {
		result.ProposedState, result.Confidence, result.Notes = NotAssessed, LowConfidence, err.Error()
		return result
	}
	value, err := simpleField(data, check.FieldPath)
	if err != nil || !simpleScalarType(value, check.Type) {
		result.ProposedState, result.Confidence = NotAssessed, LowConfidence
		result.Notes = fmt.Sprintf("NOT_ASSESSED: field %s is missing, null or has the wrong type", check.FieldPath)
		return result
	}
	if floor, ok := input.Thresholds[check.MetricKey]; ok && check.Type == "number" && check.Implemented.Operator == "gte" {
		check.Implemented.ExpectedValues = []any{json.Number(fmt.Sprintf("%g", floor))}
	}
	result.ProposedState, result.Confidence = NotImplemented, MediumConfidence
	if simpleCompare(value, check.Implemented) {
		result.ProposedState = Implemented
	} else if simpleCompare(value, check.Partial) {
		result.ProposedState = PartiallyImplemented
	}
	if check.Type == "number" && check.Implemented.Operator == "gte" && check.Partial.Operator == "gte" {
		actual, actualErr := value.(json.Number).Float64()
		implemented, implementedErr := check.Implemented.ExpectedValues[0].(json.Number).Float64()
		partial, partialErr := check.Partial.ExpectedValues[0].(json.Number).Float64()
		if actualErr != nil || implementedErr != nil || partialErr != nil {
			result.ProposedState, result.Confidence, result.Notes = NotAssessed, LowConfidence, "NOT_ASSESSED: numeric comparison could not be decoded"
			return result
		}
		result.Confidence = confidenceFor(actual, partial, implemented, complete && !metric.Overall.Sampled, anySampled(input.Report))
	} else if !complete || metric.Overall.Sampled || anySampled(input.Report) {
		result.Confidence = LowConfidence
	}
	result.Notes = fmt.Sprintf("Declarative settings-facts proposal: %s%s = %v; implemented %s %v; partial %s %v. "+
		"Policy schema %s, SHA-256 %s; this is assessment policy, not a universal GitHub requirement.",
		check.MetricKey, check.FieldPath, value, check.Implemented.Operator, check.Implemented.ExpectedValues,
		check.Partial.Operator, check.Partial.ExpectedValues, checks.SchemaVersion, checks.SHA256)
	if result.RequiresConfirmation {
		result.Notes += " The interview half is separate and still requires explicit assessor confirmation; no answer is inferred."
	}
	if floor, ok := input.Thresholds[check.MetricKey]; ok {
		result.Notes += fmt.Sprintf(" Customer policy applies a customer-accepted threshold override: implemented floor %.1f%%.", floor)
	}
	return result
}

func extractRepositoryConfiguration(data []byte, checks *SimpleChecks) (*bool, error) {
	extraction := checks.Extractions[0]
	value, err := simpleField(data, extraction.FieldPath)
	if err != nil {
		return nil, err
	}
	if !simpleScalarType(value, extraction.Type) ||
		!simpleCompare(value, SimpleComparison{Operator: "in", ExpectedValues: extraction.KnownValues}) {
		return nil, fmt.Errorf("configuration field %s has an unknown type or enum value", extraction.FieldPath)
	}
	enabled := simpleCompare(value, extraction.Enabled)
	return &enabled, nil
}
