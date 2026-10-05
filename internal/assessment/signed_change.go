// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"math"
)

// SignedPercentageChange computes (current-baseline)/baseline*100 for nonnegative counts.
// A zero baseline is undefined, not zero change; increases can exceed 100 percent.
func SignedPercentageChange(baseline, current float64, population string) (MetricValue, error) {
	if math.IsNaN(baseline) || math.IsNaN(current) || math.IsInf(baseline, 0) || math.IsInf(current, 0) ||
		baseline < 0 || current < 0 {
		return MetricValue{}, fmt.Errorf("signed change observations must be finite and nonnegative")
	}
	value := MetricValue{
		Baseline: &baseline, Current: &current, Population: population, EvidenceRefs: []string{},
	}
	if baseline == 0 {
		value.Status = MetricUnavailable
		value.Reason = "signed relative change has a zero baseline"
		return value, nil
	}
	change := (current - baseline) / baseline * 100
	if math.IsInf(change, 0) || math.IsNaN(change) {
		return MetricValue{}, fmt.Errorf("signed change result exceeds finite numeric range")
	}
	value.Status = MetricKnown
	value.Number = &change
	return value, nil
}
