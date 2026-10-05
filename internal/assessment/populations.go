// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"hash/fnv"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v83/github"
)

// activeRepositoryWindowDays is the automation profile's fixed "active repository"
// recency window (org.repos collector notes: "pushed_at within 365 days"). It is a
// collector-domain constant, independent of the customer configuration's
// LookbackDays, which instead governs alert-trend windows elsewhere.
const activeRepositoryWindowDays = 365

// criticalFallbackRecentCount is the profile's documented fallback critical
// population size when no criticality custom property is defined.
const criticalFallbackRecentCount = 20

// FetchOrganizationRepositoryInventory collects the complete, paginated repository
// inventory for one organization using the org.repos collector contract.
// A collection failure returns whatever pages were already gathered alongside the
// error so callers can decide whether a partial inventory remains usable.
func FetchOrganizationRepositoryInventory(ctx context.Context, client *CollectionClient, store *EvidenceStore,
	scope Scope, organization string) ([]*github.Repository, CollectorOutcome, error) {
	endpoint := "orgs/" + url.PathEscape(organization) + "/repos?type=all&sort=pushed"
	return collectJSONArray[*github.Repository](ctx, client, store, scope, "org.repos", "repos", endpoint, "", true)
}

// FetchRepositoryDetails collects the single-repository repo.details record,
// the authoritative per-repository source for default_branch and
// security_and_analysis used by downstream effective-rules and feature-coverage
// analysis.
func FetchRepositoryDetails(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (*github.Repository, CollectorOutcome, error) {
	return collectJSONObject[github.Repository](ctx, client, store, scope, "repo.details", "details",
		"repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo))
}

// ActiveRepositories returns repositories that are not archived, not a fork and
// pushed within the profile's 365-day window. A repository with no recorded
// pushed_at is excluded rather than assumed recently active.
func ActiveRepositories(repos []*github.Repository, now time.Time) []*github.Repository {
	cutoff := now.AddDate(0, 0, -activeRepositoryWindowDays)
	active := make([]*github.Repository, 0, len(repos))
	for _, repo := range repos {
		if repo == nil || repo.GetArchived() || repo.GetFork() {
			continue
		}
		pushed := repo.GetPushedAt()
		if pushed.IsZero() || pushed.Before(cutoff) {
			continue
		}
		active = append(active, repo)
	}
	return active
}

// SampleResult records a deterministic stratified sample's seed, population size,
// selected repositories and per-stratum allocation so a run can be reproduced and
// audited. A nil *SampleResult means the full active population was in scope.
type SampleResult struct {
	Seed              string         `json:"seed"`
	Cap               int            `json:"cap"`
	PopulationSize    int            `json:"population_size"`
	SelectedFullNames []string       `json:"selected_full_names"`
	Strata            map[string]int `json:"strata"`
	Reason            string         `json:"reason"`
}

// EligibleRepositories returns active repositories up to the configured cap.
// Populations at or under the cap return every active repository unsampled;
// larger populations are reduced via a deterministic stratified sample.
func EligibleRepositories(active []*github.Repository, cap int, seed string) ([]*github.Repository, *SampleResult) {
	if cap <= 0 || len(active) <= cap {
		return active, nil
	}
	sample := stratifiedSample(active, cap, seed)
	selected := make(map[string]bool, len(sample.SelectedFullNames))
	for _, name := range sample.SelectedFullNames {
		selected[name] = true
	}
	eligible := make([]*github.Repository, 0, len(sample.SelectedFullNames))
	for _, repo := range active {
		if selected[repo.GetFullName()] {
			eligible = append(eligible, repo)
		}
	}
	return eligible, sample
}

func stratifiedSample(active []*github.Repository, cap int, seed string) *SampleResult {
	type entry struct {
		repo *github.Repository
		hash uint64
	}
	strata := map[string][]entry{}
	var order []string
	for _, repo := range active {
		key := sampleStratumKey(repo)
		if _, exists := strata[key]; !exists {
			order = append(order, key)
		}
		strata[key] = append(strata[key], entry{repo, sampleHash(seed, repo.GetFullName())})
	}
	sort.Strings(order)
	total := len(active)
	allocation := make(map[string]int, len(order))
	allocated := 0
	type remainder struct {
		key  string
		frac float64
	}
	remainders := make([]remainder, 0, len(order))
	for _, key := range order {
		exact := float64(len(strata[key])) * float64(cap) / float64(total)
		base := int(math.Floor(exact))
		allocation[key] = base
		allocated += base
		remainders = append(remainders, remainder{key, exact - float64(base)})
	}
	sort.Slice(remainders, func(i, j int) bool {
		if remainders[i].frac != remainders[j].frac {
			return remainders[i].frac > remainders[j].frac
		}
		return remainders[i].key < remainders[j].key
	})
	for i := 0; allocated < cap && i < len(remainders); i++ {
		allocation[remainders[i].key]++
		allocated++
	}
	selected := make([]string, 0, cap)
	strataCounts := make(map[string]int, len(order))
	for _, key := range order {
		bucket := strata[key]
		sort.Slice(bucket, func(i, j int) bool {
			if bucket[i].hash != bucket[j].hash {
				return bucket[i].hash < bucket[j].hash
			}
			return bucket[i].repo.GetFullName() < bucket[j].repo.GetFullName()
		})
		take := allocation[key]
		if take > len(bucket) {
			take = len(bucket)
		}
		for i := 0; i < take; i++ {
			selected = append(selected, bucket[i].repo.GetFullName())
		}
		strataCounts[key] = take
	}
	sort.Strings(selected)
	return &SampleResult{
		Seed: seed, Cap: cap, PopulationSize: total, SelectedFullNames: selected, Strata: strataCounts,
		Reason: "active population exceeds the repository cap; selection is a deterministic stratified sample by visibility and primary language",
	}
}

func sampleStratumKey(repo *github.Repository) string {
	visibility := repo.GetVisibility()
	if visibility == "" {
		if repo.GetPrivate() {
			visibility = "private"
		} else {
			visibility = "public"
		}
	}
	language := repo.GetLanguage()
	if language == "" {
		language = "unspecified"
	}
	return visibility + "|" + language
}

func sampleHash(seed, fullName string) uint64 {
	digest := fnv.New64a()
	_, _ = digest.Write([]byte(seed))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(fullName))
	return digest.Sum64()
}

// CriticalPopulationResult preserves how the critical population was determined.
// A "recent-fallback" result is explicitly flagged rather than silently treated as
// exhaustive: production-environment evidence is not collected by this phase, so
// the fallback can undercount repositories with a production-like environment.
type CriticalPopulationResult struct {
	Method       string   `json:"method"`
	PropertyName string   `json:"property_name,omitempty"`
	FullNames    []string `json:"full_names"`
	Caveat       string   `json:"caveat,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// ComputeCriticalPopulation uses the configured custom property when the
// organization's property schema confirms it exists; otherwise it falls back to
// the profile's documented 20-most-recently-pushed active repositories. Schema
// access failures do not silently assume the property is absent.
func ComputeCriticalPopulation(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	organization string, active []*github.Repository, config *CustomerConfig) (*CriticalPopulationResult, []CollectorOutcome, error) {
	outcomes := []CollectorOutcome{}
	propertyName := ""
	if config.CriticalProperty != nil {
		propertyName = strings.TrimSpace(*config.CriticalProperty)
	}
	if propertyName == "" {
		return recentFallbackCriticalPopulation(active, ""), outcomes, nil
	}
	schema, schemaOutcome, err := collectJSONArray[github.CustomProperty](ctx, client, store, scope,
		"org.properties", "schema", "orgs/"+url.PathEscape(organization)+"/properties/schema", "", false)
	outcomes = append(outcomes, schemaOutcome)
	if err != nil {
		return &CriticalPopulationResult{
			Method: "unknown", PropertyName: propertyName,
			Reason: "organization custom property schema could not be confirmed; critical population was not determined",
		}, outcomes, nil
	}
	defined := false
	for _, property := range schema {
		if property.GetPropertyName() == propertyName {
			defined = true
			break
		}
	}
	if !defined {
		return recentFallbackCriticalPopulation(active, "configured critical property is not defined in the organization's custom property schema"), outcomes, nil
	}
	values, valuesOutcome, valuesErr := collectJSONArray[github.RepoCustomPropertyValue](ctx, client, store, scope,
		"org.properties", "values", "orgs/"+url.PathEscape(organization)+"/properties/values", "", true)
	outcomes = append(outcomes, valuesOutcome)
	criticalValues := make(map[string]bool, len(config.CriticalValues))
	for _, value := range config.CriticalValues {
		criticalValues[strings.ToLower(strings.TrimSpace(value))] = true
	}
	byFullName := make(map[string]bool, len(values))
	for _, value := range values {
		for _, property := range value.Properties {
			if property == nil || property.PropertyName != propertyName {
				continue
			}
			if propertyMatchesCriticalValues(property.Value, criticalValues) {
				byFullName[value.RepositoryFullName] = true
			}
		}
	}
	var names []string
	for _, repo := range active {
		if byFullName[repo.GetFullName()] {
			names = append(names, repo.GetFullName())
		}
	}
	sort.Strings(names)
	result := &CriticalPopulationResult{Method: "custom-property", PropertyName: propertyName, FullNames: names}
	if valuesErr != nil {
		result.Reason = "repository property values were only partially collected; the critical population may be incomplete"
	}
	return result, outcomes, nil
}

func propertyMatchesCriticalValues(value any, criticalValues map[string]bool) bool {
	switch typed := value.(type) {
	case string:
		return criticalValues[strings.ToLower(strings.TrimSpace(typed))]
	case []string:
		for _, item := range typed {
			if criticalValues[strings.ToLower(strings.TrimSpace(item))] {
				return true
			}
		}
	}
	return false
}

func recentFallbackCriticalPopulation(active []*github.Repository, reason string) *CriticalPopulationResult {
	sorted := make([]*github.Repository, len(active))
	copy(sorted, active)
	sort.Slice(sorted, func(i, j int) bool {
		left, right := sorted[i].GetPushedAt().Time, sorted[j].GetPushedAt().Time
		if !left.Equal(right) {
			return left.After(right)
		}
		return sorted[i].GetFullName() < sorted[j].GetFullName()
	})
	count := criticalFallbackRecentCount
	if len(sorted) < count {
		count = len(sorted)
	}
	names := make([]string, 0, count)
	for _, repo := range sorted[:count] {
		names = append(names, repo.GetFullName())
	}
	sort.Strings(names)
	return &CriticalPopulationResult{
		Method: "recent-fallback", FullNames: names, Reason: reason,
		Caveat: "production environment evidence is not collected by this phase; the fallback critical population " +
			"may undercount repositories with a production-like environment that lack recent pushes",
	}
}

// OrganizationPopulation aggregates the inventory, active/eligible filtering,
// sampling and critical-repository determination for one organization scope.
type OrganizationPopulation struct {
	Scope                 Scope                     `json:"scope"`
	TotalRepositories     int                       `json:"total_repositories"`
	ActiveRepositoryCount int                       `json:"active_repository_count"`
	ActiveFullNames       []string                  `json:"active_full_names"`
	EligibleFullNames     []string                  `json:"eligible_full_names"`
	Sample                *SampleResult             `json:"sample,omitempty"`
	Critical              *CriticalPopulationResult `json:"critical"`
}

// BuildOrganizationPopulation runs the full population pipeline for one organization
// and returns both the reportable summary and the resolved eligible repository
// objects for downstream per-repository collection.
func BuildOrganizationPopulation(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	organization string, config *CustomerConfig, now time.Time) (*OrganizationPopulation, []*github.Repository, []CollectorOutcome, error) {
	repos, inventoryOutcome, err := FetchOrganizationRepositoryInventory(ctx, client, store, scope, organization)
	outcomes := []CollectorOutcome{inventoryOutcome}
	if err != nil && len(repos) == 0 {
		return nil, nil, outcomes, err
	}
	active := ActiveRepositories(repos, now)
	eligible, sample := EligibleRepositories(active, config.RepositoryCap, scope.Key())
	critical, criticalOutcomes, criticalErr := ComputeCriticalPopulation(ctx, client, store, scope, organization, active, config)
	if criticalErr != nil {
		return nil, nil, outcomes, criticalErr
	}
	outcomes = append(outcomes, criticalOutcomes...)
	activeNames := make([]string, 0, len(active))
	for _, repo := range active {
		activeNames = append(activeNames, repo.GetFullName())
	}
	sort.Strings(activeNames)
	eligibleNames := make([]string, 0, len(eligible))
	for _, repo := range eligible {
		eligibleNames = append(eligibleNames, repo.GetFullName())
	}
	sort.Strings(eligibleNames)
	population := &OrganizationPopulation{
		Scope: scope, TotalRepositories: len(repos), ActiveRepositoryCount: len(active),
		ActiveFullNames: activeNames, EligibleFullNames: eligibleNames, Sample: sample, Critical: critical,
	}
	return population, eligible, outcomes, nil
}
