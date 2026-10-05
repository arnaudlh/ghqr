// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/go-github/v83/github"
	"gopkg.in/yaml.v3"
)

// SecurityCollectorIDs lists the catalogue collector IDs this file
// implements: the three organization-wide alert lifecycles, organization code
// security configurations and the per-repository code-scanning default-setup
// enablement signal. It is additive to RunImplementedCollectorIDs.
func SecurityCollectorIDs() []string {
	return []string{
		"org.dependabot_alerts", "org.code_scanning_alerts", "org.secret_scanning_alerts",
		"org.code_security_configs", "repo.code_scanning", "repo.contents_probe",
	}
}

// alertLifecycleWindowDays is the profile's fixed 180-day fixed-alert MTTR
// window (org.*_alerts collector notes: "MTTR ... over the last 180 days").
// It is independent of the customer configuration's LookbackDays, which
// governs other windows (PR/actions-run lookback) elsewhere.
const alertLifecycleWindowDays = 180

// OrgAlertLifecycleResult is one organization's collected alert population for
// one alert kind (Dependabot, code scanning or secret scanning), already
// normalized into the shared AlertObservation shape so the published
// AlertLifecycleMetrics helper can compute median open-alert age and MTTR
// without any duplicate arithmetic in this file.
type OrgAlertLifecycleResult struct {
	Kind         string             `json:"kind"`
	Observations []AlertObservation `json:"observations"`
	Complete     bool               `json:"complete"`
}

// FetchOrgDependabotAlerts collects every open and every fixed/dismissed/
// auto_dismissed Dependabot alert for the organization (each state fully
// paginated). Dismissed/auto_dismissed alerts are preserved in the observation
// set but the published AlertLifecycleMetrics helper excludes them from MTTR
// (median uses fixed alerts only, never dismissals).
func FetchOrgDependabotAlerts(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgAlertLifecycleResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	open, openOutcome, openErr := collectJSONArray[*github.DependabotAlert](ctx, client, store, orgScope,
		"org.dependabot_alerts", "open", "orgs/"+organizationPath+"/dependabot/alerts?state=open", "", true)
	closed, closedOutcome, closedErr := collectJSONArray[*github.DependabotAlert](ctx, client, store, orgScope,
		"org.dependabot_alerts", "closed",
		"orgs/"+organizationPath+"/dependabot/alerts?state=fixed,dismissed,auto_dismissed&sort=updated", "", true)
	result := OrgAlertLifecycleResult{Kind: "dependabot", Observations: []AlertObservation{}, Complete: openErr == nil && closedErr == nil}
	for _, alert := range open {
		result.Observations = append(result.Observations, dependabotAlertObservation(alert))
	}
	for _, alert := range closed {
		result.Observations = append(result.Observations, dependabotAlertObservation(alert))
	}
	return result, []CollectorOutcome{openOutcome, closedOutcome}, nil
}

func dependabotAlertObservation(alert *github.DependabotAlert) AlertObservation {
	if alert == nil {
		return AlertObservation{}
	}
	observation := AlertObservation{Number: alert.GetNumber(), State: alert.GetState(), CreatedAt: alert.GetCreatedAt().Time}
	if advisory := alert.GetSecurityAdvisory(); advisory != nil {
		observation.Severity = advisory.GetSeverity()
	}
	if alert.FixedAt != nil {
		fixedAt := alert.GetFixedAt().Time
		observation.FixedAt = &fixedAt
	}
	return observation
}

// FetchOrgCodeScanningAlerts collects every open, dismissed and fixed
// code-scanning alert for the organization (each state fully paginated).
func FetchOrgCodeScanningAlerts(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgAlertLifecycleResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	result := OrgAlertLifecycleResult{Kind: "code_scanning", Observations: []AlertObservation{}, Complete: true}
	outcomes := make([]CollectorOutcome, 0, 3)
	for _, state := range []string{"open", "dismissed", "fixed"} {
		alerts, outcome, err := collectJSONArray[*github.Alert](ctx, client, store, orgScope,
			"org.code_scanning_alerts", state, "orgs/"+organizationPath+"/code-scanning/alerts?state="+state, "", true)
		outcomes = append(outcomes, outcome)
		if err != nil {
			result.Complete = false
		}
		for _, alert := range alerts {
			result.Observations = append(result.Observations, codeScanningAlertObservation(alert))
		}
	}
	return result, outcomes, nil
}

func codeScanningAlertObservation(alert *github.Alert) AlertObservation {
	if alert == nil {
		return AlertObservation{}
	}
	observation := AlertObservation{Number: alert.GetNumber(), State: alert.GetState(), CreatedAt: alert.GetCreatedAt().Time}
	if rule := alert.GetRule(); rule != nil {
		observation.Severity = rule.GetSecuritySeverityLevel()
	}
	if alert.FixedAt != nil {
		fixedAt := alert.GetFixedAt().Time
		observation.FixedAt = &fixedAt
	}
	return observation
}

// FetchOrgSecretScanningAlerts collects every open and every resolved secret-
// scanning alert for the organization (each state fully paginated). The
// shared read transport already forces `hide_secret=true` on every
// secret-scanning request, and the shared Redactor independently strips any
// literal `secret` field regardless of that query parameter, so this
// defense-in-depth holds even if a future endpoint variant omits the
// parameter.
func FetchOrgSecretScanningAlerts(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string) (OrgAlertLifecycleResult, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	open, openOutcome, openErr := collectJSONArray[*github.SecretScanningAlert](ctx, client, store, orgScope,
		"org.secret_scanning_alerts", "open", "orgs/"+organizationPath+"/secret-scanning/alerts?state=open", "", true)
	resolved, resolvedOutcome, resolvedErr := collectJSONArray[*github.SecretScanningAlert](ctx, client, store, orgScope,
		"org.secret_scanning_alerts", "resolved", "orgs/"+organizationPath+"/secret-scanning/alerts?state=resolved", "", true)
	result := OrgAlertLifecycleResult{Kind: "secret_scanning", Observations: []AlertObservation{}, Complete: openErr == nil && resolvedErr == nil}
	for _, alert := range open {
		result.Observations = append(result.Observations, secretScanningAlertObservation(alert))
	}
	for _, alert := range resolved {
		result.Observations = append(result.Observations, secretScanningAlertObservation(alert))
	}
	return result, []CollectorOutcome{openOutcome, resolvedOutcome}, nil
}

// secretScanningAlertObservation maps GitHub's open/resolved state vocabulary
// and its resolution taxonomy (revoked/false_positive/wont_fix/used_in_tests/
// pattern_edited/pattern_deleted) onto the shared AlertObservation shape.
// Secret scanning has no dedicated "fixed_at" field, so a resolved alert's
// closure time is carried in ClosedAt (from resolved_at); the published
// AlertLifecycleMetrics helper already falls back to ClosedAt for a
// "resolved" state and already excludes false_positive/wont_fix/used_in_tests
// from MTTR while treating any other resolution (including the documented
// pattern_edited/pattern_deleted values) as an unknown/incomplete fix rather
// than silently counting or excluding it.
func secretScanningAlertObservation(alert *github.SecretScanningAlert) AlertObservation {
	if alert == nil {
		return AlertObservation{}
	}
	observation := AlertObservation{
		Number: alert.GetNumber(), State: alert.GetState(), Resolution: alert.GetResolution(), CreatedAt: alert.GetCreatedAt().Time,
	}
	if alert.ResolvedAt != nil {
		resolvedAt := alert.GetResolvedAt().Time
		observation.ClosedAt = &resolvedAt
	}
	return observation
}

// requiredCodeSecurityConfigurationFeatures is the full-feature policy this
// adapter requires for a repository's attached configuration to count as
// "enabled": every one of these settings must be "enabled" (not merely
// attached/enforced with some features off). This is an adapter choice, not a
// profile-declared metric key.
var requiredCodeSecurityConfigurationFeatures = []string{
	"secret_scanning", "secret_scanning_push_protection", "dependabot_alerts", "code_scanning_default_setup",
}

// codeSecurityConfigurationCoveragePopulation documents this invented (not an
// existing automation-profile metric name) key's denominator.
const codeSecurityConfigurationCoveragePopulationKey = "code_security_configuration_full_coverage_pct"

// FetchOrgCodeSecurityConfigurations collects the organization's code security
// configuration catalogue, its default-for-new-repos assignments and, for
// every configuration, its complete (paginated) repository attachment list,
// then pools them with the already-known active/eligible repository
// population into the published SecurityConfigurationCoverage helper. A
// repository's configuration coverage is "enabled" only when every feature in
// requiredCodeSecurityConfigurationFeatures reports "enabled" on its attached,
// final-state (attached/enforced) configuration.
func FetchOrgCodeSecurityConfigurations(ctx context.Context, client *CollectionClient, store *EvidenceStore, orgScope Scope,
	organization string, eligibleRepositoryFullNames []string) (MetricValue, []CollectorOutcome, error) {
	organizationPath := url.PathEscape(organization)
	configs, listOutcome, listErr := collectJSONArray[*github.CodeSecurityConfiguration](ctx, client, store, orgScope,
		"org.code_security_configs", "configurations", "orgs/"+organizationPath+"/code-security/configurations", "", true)
	outcomes := []CollectorOutcome{listOutcome}
	defaults, defaultsOutcome, defaultsErr := collectJSONArray[*github.CodeSecurityConfigurationWithDefaultForNewRepos](ctx, client, store, orgScope,
		"org.code_security_configs", "defaults", "orgs/"+organizationPath+"/code-security/configurations/defaults", "", false)
	outcomes = append(outcomes, defaultsOutcome)
	_ = defaults // defaults inform default-for-new-repos policy; not yet folded into a pooled metric.

	observations := make([]SecurityConfigurationObservation, 0, len(configs))
	attachments := make([]SecurityAttachmentObservation, 0)
	complete := listErr == nil && defaultsErr == nil
	for _, config := range configs {
		if config == nil || config.ID == nil {
			continue
		}
		observations = append(observations, SecurityConfigurationObservation{
			Host: orgScope.Host, ID: config.GetID(), Enforcement: codeSecurityEnforcementValue(config.Enforcement),
			Features: map[string]*bool{
				"secret_scanning":                 codeSecurityFeatureState(config.SecretScanning),
				"secret_scanning_push_protection": codeSecurityFeatureState(config.SecretScanningPushProtection),
				"dependabot_alerts":               codeSecurityFeatureState(config.DependabotAlerts),
				"code_scanning_default_setup":     codeSecurityFeatureState(config.CodeScanningDefaultSetup),
			},
		})
		repositories, repositoriesOutcome, repositoriesErr := collectJSONArray[*github.RepositoryAttachment](ctx, client, store, orgScope,
			"org.code_security_configs", repositoriesFeatureName(config.GetID()),
			"orgs/"+organizationPath+"/code-security/configurations/"+strconv.FormatInt(config.GetID(), 10)+"/repositories?status=all", "", true)
		outcomes = append(outcomes, repositoriesOutcome)
		if repositoriesErr != nil {
			complete = false
			continue
		}
		for _, attachment := range repositories {
			if attachment == nil || attachment.Repository == nil || attachment.Repository.GetFullName() == "" {
				continue
			}
			attachments = append(attachments, SecurityAttachmentObservation{
				Repository:      Scope{Host: orgScope.Host, Kind: RepositoryScope, Name: attachment.Repository.GetFullName()},
				ConfigurationID: config.GetID(), Status: attachment.GetStatus(),
			})
		}
	}

	repositories := make([]SecurityRepositoryObservation, 0, len(eligibleRepositoryFullNames))
	eligible := true
	for _, fullName := range eligibleRepositoryFullNames {
		repositories = append(repositories, SecurityRepositoryObservation{
			Scope: Scope{Host: orgScope.Host, Kind: RepositoryScope, Name: fullName}, Eligible: &eligible, EvidenceRefs: []string{},
		})
	}

	metric, err := SecurityConfigurationCoverage(repositories, observations, attachments, requiredCodeSecurityConfigurationFeatures, complete)
	if err != nil {
		return MetricValue{}, outcomes, err
	}
	return metric, outcomes, nil
}

func codeSecurityEnforcementValue(enforcement *string) string {
	if enforcement == nil || (*enforcement != "enforced" && *enforcement != "unenforced") {
		return "unenforced"
	}
	return *enforcement
}

func codeSecurityFeatureState(value *string) *bool {
	if value == nil {
		return nil
	}
	switch *value {
	case "enabled":
		enabled := true
		return &enabled
	case "disabled":
		disabled := false
		return &disabled
	default:
		return nil
	}
}

func repositoriesFeatureName(configurationID int64) string {
	return safeFeatureName("repositories", strconv.FormatInt(configurationID, 10))
}

// FetchRepositoryCodeScanningDefaultSetup reports whether GitHub's native
// code-scanning default setup is configured for this repository, distinct
// from a custom `github/codeql-action` workflow step (AnalyzeRepositoryWorkflows'
// CodeQLOperational signal). A concealed/failed probe leaves enablement
// unknown rather than assuming disabled.
func FetchRepositoryCodeScanningDefaultSetup(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (*bool, CollectorOutcome, error) {
	setup, outcome, err := collectJSONObject[github.DefaultSetupConfiguration](ctx, client, store, scope,
		"repo.code_scanning", "default-setup", "repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/code-scanning/default-setup")
	if err != nil || setup == nil {
		return nil, outcome, nil
	}
	configured := setup.GetState() == "configured"
	return &configured, outcome, nil
}

// supportedManifestFilenames mirrors the repo.contents_probe collector's
// documented dependency-manifest detection set (a subset of its full probe
// list, scoped to files that indicate a supported dependency-graph manifest
// ecosystem). Matching is by exact filename, not path prefix, so a manifest
// nested in a subdirectory (for example a monorepo package) is still found.
var supportedManifestFilenames = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.mod": true, "go.sum": true,
	"requirements.txt": true, "pipfile": true, "pipfile.lock": true, "pyproject.toml": true, "setup.py": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
	"gemfile": true, "gemfile.lock": true, "cargo.toml": true, "cargo.lock": true, "composer.json": true, "composer.lock": true,
}

var supportedManifestExtensions = map[string]bool{".csproj": true, ".fsproj": true, ".vbproj": true}

func isSupportedManifestPath(path string) bool {
	segments := strings.Split(path, "/")
	name := strings.ToLower(segments[len(segments)-1])
	if supportedManifestFilenames[name] {
		return true
	}
	for extension := range supportedManifestExtensions {
		if strings.HasSuffix(name, extension) {
			return true
		}
	}
	return false
}

// RepositoryContentsProbeResult is the repo.contents_probe collector's
// dependency-manifest-relevant subset: a direct file inventory, not the
// repo.sbom-endpoint-availability proxy Phase 3 used as a stand-in for
// "supported manifest present", plus a parsed .github/dependabot.yml's
// update-group and ecosystem signals (SEC-043's
// repos_with_grouped_version_updates_pct, SEC-099's
// repos_with_actions_ecosystem_updates_pct). The full catalogue descriptor
// additionally covers CODEOWNERS/SECURITY.md/community-profile signals,
// which remain unimplemented this phase.
type RepositoryContentsProbeResult struct {
	Repository              string   `json:"repository"`
	ManifestPaths           []string `json:"manifest_paths"`
	SupportedManifestCount  int      `json:"supported_manifest_count"`
	UsedRootOnlyFallback    bool     `json:"used_root_only_fallback"`
	Complete                bool     `json:"complete"`
	DependabotConfigFound   bool     `json:"dependabot_config_found"`
	HasGroupedVersionUpdate bool     `json:"has_grouped_version_update"`
	HasActionsEcosystem     bool     `json:"has_actions_ecosystem_update"`
	DependabotConfigKnown   bool     `json:"dependabot_config_known"`
}

// dependabotConfig is the minimal .github/dependabot.yml shape this adapter
// parses: each update entry's package-ecosystem and whether it declares any
// version-update group.
type dependabotConfig struct {
	Updates []struct {
		PackageEcosystem string         `yaml:"package-ecosystem"`
		Groups           map[string]any `yaml:"groups"`
	} `yaml:"updates"`
}

// FetchRepositoryContentsProbe inventories a repository's actual dependency
// manifest files by walking its complete default-branch file tree
// (recursive, matching the profile's own documented cap/fallback: "git/trees
// recursive is capped at 100,000 entries — fall back to top-level listing").
// A truncated or failed recursive tree falls back to a root-level listing
// only, which is explicitly flagged (UsedRootOnlyFallback) rather than
// silently presented as an exhaustive inventory. It also fetches and parses
// .github/dependabot.yml when present.
func FetchRepositoryContentsProbe(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo, defaultBranch string) (RepositoryContentsProbeResult, []CollectorOutcome, error) {
	ownerPath, repoPath := url.PathEscape(owner), url.PathEscape(repo)
	result := RepositoryContentsProbeResult{Repository: owner + "/" + repo, ManifestPaths: []string{}}
	if defaultBranch == "" {
		return result, []CollectorOutcome{{CollectorID: "repo.contents_probe", Feature: "tree", Scope: scope,
			Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{}, Reason: "default branch is unknown"}}, nil
	}
	outcomes := make([]CollectorOutcome, 0, 2)
	tree, outcome, err := collectJSONObject[github.Tree](ctx, client, store, scope,
		"repo.contents_probe", "tree", "repos/"+ownerPath+"/"+repoPath+"/git/trees/"+url.PathEscape(defaultBranch)+"?recursive=1")
	outcomes = append(outcomes, outcome)
	if err == nil && tree != nil && !tree.GetTruncated() {
		for _, entry := range tree.Entries {
			if entry == nil || entry.GetType() != "blob" || entry.GetPath() == "" {
				continue
			}
			if isSupportedManifestPath(entry.GetPath()) {
				result.ManifestPaths = appendUnique(result.ManifestPaths, entry.GetPath())
			}
		}
		result.SupportedManifestCount = len(result.ManifestPaths)
		result.Complete = true
	} else {
		// Recursive tree unavailable or truncated: fall back to a root-level
		// listing only, explicitly flagged as non-exhaustive.
		result.UsedRootOnlyFallback = true
		root, rootOutcome, rootErr := collectJSONArray[*github.RepositoryContent](ctx, client, store, scope,
			"repo.contents_probe", "root", "repos/"+ownerPath+"/"+repoPath+"/contents", "", false)
		outcomes = append(outcomes, rootOutcome)
		if rootErr != nil {
			result.Complete = false
		} else {
			for _, entry := range root {
				if entry == nil || entry.GetType() != "file" || entry.GetName() == "" {
					continue
				}
				if isSupportedManifestPath(entry.GetName()) {
					result.ManifestPaths = appendUnique(result.ManifestPaths, entry.GetName())
				}
			}
			result.SupportedManifestCount = len(result.ManifestPaths)
			result.Complete = true
		}
	}

	dependabotOutcome := fetchDependabotConfig(ctx, client, store, scope, ownerPath, repoPath, &result)
	outcomes = append(outcomes, dependabotOutcome)
	return result, outcomes, nil
}

// fetchDependabotConfig fetches and parses .github/dependabot.yml. A missing
// (404) or unparseable file leaves DependabotConfigKnown false (not "no
// groups"/"no actions ecosystem"), distinguishing a confirmed absence from
// an unknown one for SEC-043/SEC-099.
func fetchDependabotConfig(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	ownerPath, repoPath string, result *RepositoryContentsProbeResult) CollectorOutcome {
	content, outcome, err := collectJSONObject[github.RepositoryContent](ctx, client, store, scope,
		"repo.contents_probe", "dependabot-config", "repos/"+ownerPath+"/"+repoPath+"/contents/.github/dependabot.yml")
	if err != nil || content == nil {
		return outcome
	}
	result.DependabotConfigFound = true
	text, decodeErr := content.GetContent()
	if decodeErr != nil {
		return outcome
	}
	var config dependabotConfig
	if yamlErr := yaml.Unmarshal([]byte(text), &config); yamlErr != nil {
		return outcome
	}
	result.DependabotConfigKnown = true
	for _, update := range config.Updates {
		if len(update.Groups) > 0 {
			result.HasGroupedVersionUpdate = true
		}
		if strings.EqualFold(update.PackageEcosystem, "github-actions") {
			result.HasActionsEcosystem = true
		}
	}
	return outcome
}

// FetchRepositorySBOMPackageCount decodes the dependency-graph SBOM response
// (when available) and counts actual dependency packages, excluding the
// SPDX document's own "describes" package(s) — typically the repository
// itself, not a dependency. A nil result (as opposed to a known zero) means
// the SBOM endpoint was unavailable (404/403/etc.), which this phase cannot
// yet distinguish from "dependency graph genuinely disabled" (documented
// repo.sbom collector limitation, unchanged from Phase 3).
func FetchRepositorySBOMPackageCount(ctx context.Context, client *CollectionClient, store *EvidenceStore, scope Scope,
	owner, repo string) (*int, CollectorOutcome, error) {
	document, outcome, err := collectJSONObject[github.SBOM](ctx, client, store, scope,
		"repo.sbom", "packages", "repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/dependency-graph/sbom")
	if err != nil || document == nil || document.SBOM == nil {
		return nil, outcome, nil
	}
	described := make(map[string]bool, len(document.SBOM.DocumentDescribes))
	for _, id := range document.SBOM.DocumentDescribes {
		described[id] = true
	}
	count := 0
	for _, pkg := range document.SBOM.Packages {
		if pkg == nil || described[pkg.GetSPDXID()] {
			continue
		}
		count++
	}
	return &count, outcome, nil
}

// severityFilter reports whether an AlertObservation's severity matches one
// of the given (case-insensitive) severity labels.
func severityFilter(observations []AlertObservation, severities ...string) []AlertObservation {
	wanted := make(map[string]bool, len(severities))
	for _, severity := range severities {
		wanted[strings.ToLower(severity)] = true
	}
	filtered := make([]AlertObservation, 0, len(observations))
	for _, observation := range observations {
		if wanted[strings.ToLower(observation.Severity)] {
			filtered = append(filtered, observation)
		}
	}
	return filtered
}
