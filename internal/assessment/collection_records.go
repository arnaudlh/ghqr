// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"encoding/json"
	"fmt"
)

// collectJSONObject collects a single-object REST endpoint and decodes its sanitized,
// replay-verified evidence into T. A non-2xx or network outcome is surfaced to the
// caller without attempting to decode an error body as the requested type; callers
// must inspect the returned CollectorOutcome (HTTP status, Availability) to tell a
// confirmed absence (for example HTTP 404 on a documented "not configured" endpoint)
// from a concealed or missing-permission response.
func collectJSONObject[T any](ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	collectorID, feature, endpoint string) (*T, CollectorOutcome, error) {
	outcome, err := client.CollectGET(ctx, store, scope, collectorID, feature, endpoint, "", false)
	if err != nil {
		return nil, outcome, err
	}
	if outcome.Pages == 0 {
		return nil, outcome, fmt.Errorf("collection produced no evidence for %s/%s", collectorID, feature)
	}
	raw, _, _, loadErr := store.LoadJSON(scope, collectorID, pageFeatureName(feature, 1))
	if loadErr != nil {
		return nil, outcome, fmt.Errorf("reload collected evidence for %s/%s: %w", collectorID, feature, loadErr)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, outcome, fmt.Errorf("decode collected evidence for %s/%s: %w", collectorID, feature, err)
	}
	return &value, outcome, nil
}

// collectJSONArray collects a possibly paginated array-typed REST endpoint and
// decodes every stored page into a concatenated slice of T. arrayField unwraps a
// named array property (for example "workflows") when the endpoint returns an
// envelope object instead of a bare JSON array.
//
// A collection error on the final page does not discard successfully collected
// prior pages: the partial slice and the original error are both returned so a
// caller can decide whether partial population data remains usable, with reduced
// confidence, or must be treated as entirely unavailable.
func collectJSONArray[T any](ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	collectorID, feature, endpoint, arrayField string, paginate bool) ([]T, CollectorOutcome, error) {
	outcome, collectErr := client.CollectGET(ctx, store, scope, collectorID, feature, endpoint, arrayField, paginate)
	all := make([]T, 0, outcome.Pages)
	for page := 1; page <= outcome.Pages; page++ {
		raw, _, _, loadErr := store.LoadJSON(scope, collectorID, pageFeatureName(feature, page))
		if loadErr != nil {
			if page == outcome.Pages && collectErr != nil {
				break
			}
			return all, outcome, fmt.Errorf("reload collected evidence for %s/%s page %d: %w", collectorID, feature, page, loadErr)
		}
		value := json.RawMessage(raw)
		if arrayField != "" {
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(raw, &envelope); err != nil {
				if page == outcome.Pages && collectErr != nil {
					break
				}
				return all, outcome, fmt.Errorf("decode %s/%s page %d envelope: %w", collectorID, feature, page, err)
			}
			value = envelope[arrayField]
		}
		var items []T
		if err := json.Unmarshal(value, &items); err != nil {
			if page == outcome.Pages && collectErr != nil {
				break
			}
			return all, outcome, fmt.Errorf("decode %s/%s page %d: %w", collectorID, feature, page, err)
		}
		all = append(all, items...)
	}
	return all, outcome, collectErr
}

func pageFeatureName(feature string, page int) string {
	return fmt.Sprintf("%s-page-%06d", feature, page)
}

// boolPtr returns a pointer to a bool literal, for EvidenceMetadata's
// tri-state PaginationContinues field (true/false/nil are all distinct and
// meaningful there, so a plain bool cannot express it).
func boolPtr(value bool) *bool {
	return &value
}
