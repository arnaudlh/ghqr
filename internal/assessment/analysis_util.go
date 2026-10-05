// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"strings"
)

// safeFeatureName builds an evidence-store-safe feature identifier from a
// label (for example a prefix) and a repository-relative path, which may
// contain "/" and leading "." segments that the evidence store's feature name
// pattern does not permit on their own.
func safeFeatureName(label, path string) string {
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			return r
		default:
			return '-'
		}
	}, path)
	return fmt.Sprintf("%s-%s", label, sanitized)
}

// appendUnique appends value to list only when it is not already present and is
// non-empty, preserving first-seen order for deterministic, readable output.
func appendUnique(list []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return list
	}
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

// markCoverageUncertain converts an already-computed coverage MetricValue
// (typically from Percentage) into an explicit unavailable result when its
// population contains observations that cannot be confidently resolved either
// way (for example a dynamic/unresolvable action ref, or a repository whose
// effective protection could not be fully assessed). The ratio's numerator and
// denominator are preserved for audit, matching Percentage's own zero-
// denominator contract; only the computed percentage number is cleared, since
// a known number and an unavailable status cannot coexist on one MetricValue.
// This never silently narrows a population to its confidently known subset.
func markCoverageUncertain(value MetricValue, reason string) MetricValue {
	value.Status = MetricUnavailable
	value.Number = nil
	value.Reason = reason
	return value
}
