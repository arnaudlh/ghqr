// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"math"
	"strings"
)

const minimumCodeScanningLanguageShare = 5.0

// CodeScanningEligibility uses the complete language-byte inventory, not its primary language.
// The caller supplies the versioned set of supported CodeQL languages.
func CodeScanningEligibility(languages map[string]int64, supportedLanguages []string, complete bool) (MetricValue, error) {
	if !complete || languages == nil {
		return unavailableObservation("language-byte inventory is unavailable or incomplete", "CodeQL-supported languages"), nil
	}
	if len(supportedLanguages) == 0 {
		return MetricValue{}, fmt.Errorf("code scanning eligibility requires the supported-language policy")
	}
	supported := make(map[string]bool, len(supportedLanguages))
	for _, language := range supportedLanguages {
		name := strings.ToLower(strings.TrimSpace(language))
		if name == "" {
			return MetricValue{}, fmt.Errorf("supported-language names must not be empty")
		}
		supported[name] = true
	}
	var total int64
	for language, count := range languages {
		if strings.TrimSpace(language) == "" || count < 0 || count > math.MaxInt64-total {
			return MetricValue{}, fmt.Errorf("language inventory requires named languages and valid byte counts")
		}
		total += count
	}
	eligible := false
	if total > 0 {
		for language, count := range languages {
			if supported[strings.ToLower(strings.TrimSpace(language))] &&
				float64(count)/float64(total)*100 >= minimumCodeScanningLanguageShare {
				eligible = true
				break
			}
		}
	}
	return securityBoolean(eligible, "supported language occupies at least 5% of repository bytes"), nil
}

// DependencyEligibility uses confirmed supported manifests or actual dependency packages.
// dependencyPackages excludes a repository-only SPDX root package.
func DependencyEligibility(supportedManifests, dependencyPackages *int, complete bool) (MetricValue, error) {
	if supportedManifests != nil && *supportedManifests < 0 ||
		dependencyPackages != nil && *dependencyPackages < 0 {
		return MetricValue{}, fmt.Errorf("dependency eligibility counts must not be negative")
	}
	if !complete {
		return unavailableObservation("dependency/manifest evidence is incomplete", "supported dependency manifests"), nil
	}
	if supportedManifests != nil && *supportedManifests > 0 ||
		dependencyPackages != nil && *dependencyPackages > 0 {
		return securityBoolean(true, "confirmed supported manifests or dependency packages"), nil
	}
	if supportedManifests == nil || dependencyPackages == nil {
		return unavailableObservation("manifest or dependency population was not observed", "supported dependency manifests"), nil
	}
	return securityBoolean(false, "no supported manifest or dependency package observed"), nil
}

// SecurityRepositoryObservation keeps eligibility separate from feature enablement.
// A nil observation is unknown, never disabled or automatically eligible.
type SecurityRepositoryObservation struct {
	Scope          Scope
	Eligible       *bool
	FeatureEnabled *bool
	EvidenceRefs   []string
}

// SecurityFeatureCoverage computes coverage only over a known feature-specific denominator.
func SecurityFeatureCoverage(repositories []SecurityRepositoryObservation, complete bool) (MetricValue, error) {
	if err := validateSecurityRepositories(repositories); err != nil {
		return MetricValue{}, err
	}
	if !complete {
		return unavailableObservation("security feature population is incomplete", "feature-eligible repositories"), nil
	}
	numerator, denominator := 0.0, 0.0
	refs := []string{}
	for _, repository := range repositories {
		refs = append(refs, repository.EvidenceRefs...)
		if repository.Eligible == nil {
			return unavailableObservation("feature eligibility is unknown for a repository", "feature-eligible repositories"), nil
		}
		if !*repository.Eligible {
			continue
		}
		denominator++
		if repository.FeatureEnabled == nil {
			return unavailableObservation("feature enablement is unknown for an eligible repository", "feature-eligible repositories"), nil
		}
		if *repository.FeatureEnabled {
			numerator++
		}
	}
	value, err := securityCoverage(numerator, denominator, "feature-eligible repositories")
	if err != nil {
		return MetricValue{}, err
	}
	value.EvidenceRefs = uniqueExportStrings(refs)
	return value, nil
}

// SecurityConfigurationObservation records observed configuration settings without treating defaults as attachments.
type SecurityConfigurationObservation struct {
	Host        string
	ID          int64
	Enforcement string
	Features    map[string]*bool
}

// SecurityAttachmentObservation records a repository's actual configuration attachment status.
type SecurityAttachmentObservation struct {
	Repository      Scope
	ConfigurationID int64
	Status          string
	EvidenceRefs    []string
}

// SecurityConfigurationCoverage counts attached/enforced full-feature configurations.
// Transitional/failed attachments are unavailable, not silently detached.
func SecurityConfigurationCoverage(repositories []SecurityRepositoryObservation, configurations []SecurityConfigurationObservation,
	attachments []SecurityAttachmentObservation, requiredFeatures []string, complete bool) (MetricValue, error) {
	if err := validateSecurityRepositories(repositories); err != nil {
		return MetricValue{}, err
	}
	configs, err := indexSecurityConfigurations(configurations, requiredFeatures)
	if err != nil {
		return MetricValue{}, err
	}
	byRepository := make(map[string]SecurityAttachmentObservation, len(attachments))
	for _, attachment := range attachments {
		if err := attachment.Repository.Validate(); err != nil || attachment.Repository.Kind != RepositoryScope {
			return MetricValue{}, fmt.Errorf("configuration attachment requires a valid repository scope")
		}
		key := attachment.Repository.Key()
		if _, duplicate := byRepository[key]; duplicate {
			return MetricValue{}, fmt.Errorf("repository configuration attachment is duplicated")
		}
		switch attachment.Status {
		case "attached", "enforced", "detached", "removed", "attaching", "updating", "failed":
		default:
			return MetricValue{}, fmt.Errorf("configuration attachment has an unsupported status")
		}
		byRepository[key] = attachment
	}
	if !complete {
		return unavailableObservation("configuration or attachment inventory is incomplete", "configuration-eligible repositories"), nil
	}
	numerator, denominator := 0.0, 0.0
	refs := []string{}
	for _, repository := range repositories {
		if repository.Eligible == nil {
			return unavailableObservation("configuration population eligibility is unknown", "configuration-eligible repositories"), nil
		}
		if !*repository.Eligible {
			continue
		}
		denominator++
		refs = append(refs, repository.EvidenceRefs...)
		attachment, exists := byRepository[repository.Scope.Key()]
		if !exists {
			continue
		}
		refs = append(refs, attachment.EvidenceRefs...)
		switch attachment.Status {
		case "detached", "removed":
			continue
		case "attaching", "updating", "failed":
			return unavailableObservation("configuration attachment is not in a confirmed final state", "configuration-eligible repositories"), nil
		}
		configuration, exists := configs[securityConfigurationKey(repository.Scope.Host, attachment.ConfigurationID)]
		if !exists {
			return unavailableObservation("attached configuration settings are unavailable", "configuration-eligible repositories"), nil
		}
		enabled, known := configurationHasFeatures(configuration, requiredFeatures)
		if !known {
			return unavailableObservation("attached configuration feature settings are unknown", "configuration-eligible repositories"), nil
		}
		if enabled {
			numerator++
		}
	}
	value, err := securityCoverage(numerator, denominator, "configuration-eligible repositories")
	if err != nil {
		return MetricValue{}, err
	}
	value.EvidenceRefs = uniqueExportStrings(refs)
	return value, nil
}

func validateSecurityRepositories(repositories []SecurityRepositoryObservation) error {
	seen := make(map[string]bool, len(repositories))
	for _, repository := range repositories {
		if err := repository.Scope.Validate(); err != nil || repository.Scope.Kind != RepositoryScope {
			return fmt.Errorf("security population requires valid repository scopes")
		}
		key := repository.Scope.Key()
		if seen[key] {
			return fmt.Errorf("security population contains a duplicate repository scope")
		}
		seen[key] = true
	}
	return nil
}

func indexSecurityConfigurations(configurations []SecurityConfigurationObservation, features []string) (map[string]SecurityConfigurationObservation, error) {
	if len(features) == 0 {
		return nil, fmt.Errorf("configuration coverage requires the feature policy")
	}
	seenFeatures := map[string]bool{}
	for _, feature := range features {
		if feature == "" || seenFeatures[feature] {
			return nil, fmt.Errorf("configuration policy features must be nonempty and unique")
		}
		seenFeatures[feature] = true
	}
	index := make(map[string]SecurityConfigurationObservation, len(configurations))
	for _, configuration := range configurations {
		if err := validateHost(configuration.Host); err != nil {
			return nil, fmt.Errorf("security configuration requires its observed host")
		}
		if configuration.ID <= 0 {
			return nil, fmt.Errorf("security configuration requires a positive ID")
		}
		key := securityConfigurationKey(configuration.Host, configuration.ID)
		if _, duplicate := index[key]; duplicate {
			return nil, fmt.Errorf("security configuration ID is duplicated")
		}
		if configuration.Enforcement != "enforced" && configuration.Enforcement != "unenforced" {
			return nil, fmt.Errorf("security configuration enforcement was not observed")
		}
		index[key] = configuration
	}
	return index, nil
}

func securityConfigurationKey(host string, id int64) string {
	return fmt.Sprintf("%s/%d", strings.ToLower(host), id)
}

func configurationHasFeatures(configuration SecurityConfigurationObservation, required []string) (bool, bool) {
	unknown := false
	for _, feature := range required {
		value := configuration.Features[feature]
		if value == nil {
			unknown = true
		} else if !*value {
			return false, true
		}
	}
	return !unknown, !unknown
}

func securityCoverage(numerator, denominator float64, population string) (MetricValue, error) {
	value, err := Percentage(numerator, denominator, population)
	if err != nil {
		return MetricValue{}, err
	}
	if denominator == 0 {
		value.Status = MetricInapplicable
		value.Reason = "complete population contains no eligible repositories"
	}
	return value, nil
}

func securityBoolean(eligible bool, population string) MetricValue {
	return MetricValue{
		Status: MetricKnown, Boolean: &eligible, Population: population, EvidenceRefs: []string{},
	}
}
