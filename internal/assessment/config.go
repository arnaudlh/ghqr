// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Deployment identifies a GitHub platform, independently of its authentication mode.
type Deployment string

// Supported deployment values never infer EMU from the presence of SAML.
const (
	Cloud  Deployment = "ghec"
	Server Deployment = "ghes"
	Both   Deployment = "both"
)

// ScopeKind identifies a host-qualified object.
type ScopeKind string

// Supported scope kinds avoid collisions across Cloud and Server instances.
const (
	EnterpriseScope   ScopeKind = "enterprise"
	OrganizationScope ScopeKind = "organization"
	RepositoryScope   ScopeKind = "repository"
	InstanceScope     ScopeKind = "instance"
	ExternalScope     ScopeKind = "external"
)

var (
	dnsLabelPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	scopeNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	envNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Scope is a stable identity; repository names must include their organization.
type Scope struct {
	Host string    `json:"host"`
	Kind ScopeKind `json:"kind"`
	Name string    `json:"name"`
}

// Key returns a stable identity after the scope has been validated.
func (s Scope) Key() string {
	return strings.ToLower(s.Host) + "/" + string(s.Kind) + "/" + strings.ToLower(s.Name)
}

// Validate rejects ambiguous hosts and traversal-shaped object names.
func (s Scope) Validate() error {
	if err := validateHost(s.Host); err != nil {
		return err
	}
	parts := strings.Split(s.Name, "/")
	switch s.Kind {
	case RepositoryScope:
		if len(parts) != 2 {
			return fmt.Errorf("repository scope must be owner/repo")
		}
	case EnterpriseScope, OrganizationScope, InstanceScope, ExternalScope:
		if len(parts) != 1 {
			return fmt.Errorf("non-repository scope must have one name")
		}
	default:
		return fmt.Errorf("unsupported scope kind %q", s.Kind)
	}
	for _, part := range parts {
		if !scopeNamePattern.MatchString(part) || part == "." || part == ".." {
			return fmt.Errorf("invalid scope object name")
		}
	}
	return nil
}

func validateHost(host string) error {
	if len(host) > 253 || host == "" {
		return fmt.Errorf("host must be an explicit DNS hostname")
	}
	for _, label := range strings.Split(strings.ToLower(host), ".") {
		if !dnsLabelPattern.MatchString(label) {
			return fmt.Errorf("host must be a DNS hostname without scheme, port or path")
		}
	}
	return nil
}

// CredentialReferences contains environment variable names, never secret values.
type CredentialReferences struct {
	Kind                  CredentialKind `yaml:"kind" json:"kind"`
	TokenEnv              string         `yaml:"token_env" json:"token_env,omitempty"`
	ManagementUsernameEnv string         `yaml:"management_username_env" json:"management_username_env,omitempty"`
	ManagementPasswordEnv string         `yaml:"management_password_env" json:"management_password_env,omitempty"`
}

// Target explicitly binds organizations and credential references to one host.
type Target struct {
	Host          string               `yaml:"host" json:"host"`
	Deployment    Deployment           `yaml:"deployment" json:"deployment"`
	Enterprise    string               `yaml:"enterprise" json:"enterprise,omitempty"`
	Organizations []string             `yaml:"organizations" json:"organizations"`
	Credentials   CredentialReferences `yaml:"credentials" json:"credentials"`
}

// CustomerConfig supports the brief's single-host form and explicit mixed-host targets.
type CustomerConfig struct {
	Enterprise         string               `yaml:"enterprise" json:"enterprise,omitempty"`
	GHESHost           string               `yaml:"ghes_host" json:"ghes_host,omitempty"`
	Hostname           string               `yaml:"hostname" json:"hostname,omitempty"`
	Organizations      []string             `yaml:"organizations" json:"organizations,omitempty"`
	Deployment         Deployment           `yaml:"deployment" json:"deployment,omitempty"`
	Credentials        CredentialReferences `yaml:"credentials" json:"credentials"`
	Targets            []Target             `yaml:"targets" json:"targets,omitempty"`
	RepositoryCap      int                  `yaml:"repository_cap" json:"repository_cap"`
	LookbackDays       int                  `yaml:"lookback_days" json:"lookback_days"`
	Concurrency        int                  `yaml:"concurrency" json:"concurrency"`
	CriticalProperty   *string              `yaml:"critical_property" json:"critical_property"`
	CriticalValues     []string             `yaml:"critical_values" json:"critical_values"`
	ProductionEnvRegex string               `yaml:"production_env_regex" json:"production_env_regex"`
	Thresholds         map[string]float64   `yaml:"thresholds" json:"thresholds"`
	EvidenceDir        string               `yaml:"evidence_dir" json:"evidence_dir"`
}

// LoadConfig reads strict YAML without resolving credentials or contacting GitHub.
func LoadConfig(path string) (*CustomerConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("customer configuration is required: specify --config")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read customer configuration: %w", err)
	}
	return ParseConfig(data)
}

// ParseConfig applies documented defaults and rejects unknown fields and extra documents.
func ParseConfig(data []byte) (*CustomerConfig, error) {
	property := "criticality"
	config := CustomerConfig{
		RepositoryCap: 300, LookbackDays: 90, Concurrency: 4,
		CriticalProperty: &property, CriticalValues: []string{"critical", "high", "tier-0", "tier-1"},
		ProductionEnvRegex: "prod|production|live|release",
		Thresholds:         map[string]float64{}, EvidenceDir: "./evidence",
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode customer configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("read customer configuration trailer: %w", err)
		}
		return nil, fmt.Errorf("customer configuration must contain exactly one YAML document")
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validate customer configuration: %w", err)
	}
	return &config, nil
}

// Validate checks explicit scope, numeric limits, safe references and expressions.
func (c *CustomerConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("customer configuration is nil")
	}
	if c.RepositoryCap < 1 || c.LookbackDays < 1 || c.Concurrency < 1 || c.Concurrency > 4 {
		return fmt.Errorf("repository cap and lookback must be positive; concurrency must be between 1 and 4")
	}
	if c.EvidenceDir == "" {
		return fmt.Errorf("evidence directory is required")
	}
	if c.ProductionEnvRegex == "" {
		return fmt.Errorf("production environment expression is required")
	}
	if _, err := regexp.Compile("(?i)" + c.ProductionEnvRegex); err != nil {
		return fmt.Errorf("invalid production environment expression: %w", err)
	}
	for key, threshold := range c.Thresholds {
		if !metricKeyPattern.MatchString(key) || threshold < 0 || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
			return fmt.Errorf("threshold %q requires a valid metric key and a finite nonnegative value", key)
		}
		if strings.HasSuffix(key, "_pct") && threshold > 100 {
			return fmt.Errorf("percentage threshold %q must not exceed 100", key)
		}
	}
	_, err := c.ResolvedTargets()
	return err
}

// ResolvedTargets converts the single-host form without inferring cross-host membership.
func (c *CustomerConfig) ResolvedTargets() ([]Target, error) {
	if c == nil {
		return nil, fmt.Errorf("customer configuration is nil")
	}
	targets := c.Targets
	if len(targets) != 0 {
		if c.Enterprise != "" || c.GHESHost != "" || c.Hostname != "" || len(c.Organizations) != 0 ||
			c.Deployment != "" || c.Credentials != (CredentialReferences{}) {
			return nil, fmt.Errorf("targets cannot be combined with single-host scope or credential fields")
		}
	} else {
		deployment := c.Deployment
		if deployment == "" {
			deployment = Cloud
		}
		host := c.Hostname
		if deployment == Both {
			return nil, fmt.Errorf("deployment both requires explicit targets with per-host organizations")
		}
		if deployment == Server {
			if c.Hostname != "" {
				return nil, fmt.Errorf("server deployment uses ghes_host, not hostname")
			}
			host = c.GHESHost
		} else if c.GHESHost != "" {
			return nil, fmt.Errorf("ghes_host requires server deployment")
		}
		if host == "" && deployment == Cloud {
			host = "github.com"
		}
		targets = []Target{{host, deployment, c.Enterprise, c.Organizations, c.Credentials}}
	}
	seen := map[string]bool{}
	resolved := make([]Target, 0, len(targets))
	for _, target := range targets {
		target.Host = strings.ToLower(target.Host)
		if err := validateTarget(target); err != nil {
			return nil, err
		}
		if seen[target.Host] {
			return nil, fmt.Errorf("duplicate target host %q; combine its organizations", target.Host)
		}
		seen[target.Host] = true
		resolved = append(resolved, target)
	}
	return resolved, nil
}

func validateTarget(target Target) error {
	if err := validateHost(target.Host); err != nil {
		return fmt.Errorf("invalid target host: %w", err)
	}
	if target.Deployment != Cloud && target.Deployment != Server {
		return fmt.Errorf("target deployment must be ghec or ghes")
	}
	if target.Deployment == Cloud && target.Host != "github.com" && !strings.HasSuffix(target.Host, ".ghe.com") {
		return fmt.Errorf("cloud host must be github.com or a data residency subdomain of ghe.com")
	}
	if target.Deployment == Cloud && target.Enterprise == "" && len(target.Organizations) == 0 {
		return fmt.Errorf("cloud target requires an explicit enterprise or organization")
	}
	if target.Enterprise != "" {
		if err := (Scope{target.Host, EnterpriseScope, target.Enterprise}).Validate(); err != nil {
			return fmt.Errorf("invalid enterprise scope: %w", err)
		}
	}
	seen := map[string]bool{}
	for _, organization := range target.Organizations {
		if strings.EqualFold(organization, "all") {
			return fmt.Errorf("organizations must be explicit; all-organization discovery is not implemented")
		}
		scope := Scope{target.Host, OrganizationScope, organization}
		if err := scope.Validate(); err != nil {
			return fmt.Errorf("invalid organization scope: %w", err)
		}
		if seen[scope.Key()] {
			return fmt.Errorf("duplicate organization scope %q", scope.Key())
		}
		seen[scope.Key()] = true
	}
	return validateCredentials(target.Credentials)
}

func validateCredentials(refs CredentialReferences) error {
	switch refs.Kind {
	case "", NoCredential, ClassicPAT, FineGrainedPAT, AppInstallation:
	default:
		return fmt.Errorf("API credential kind must be none, classic-pat, fine-grained-pat or app-installation")
	}
	if (refs.Kind == "" || refs.Kind == NoCredential) && refs.TokenEnv != "" {
		return fmt.Errorf("token reference requires an explicit credential kind")
	}
	for _, name := range []string{refs.TokenEnv, refs.ManagementUsernameEnv, refs.ManagementPasswordEnv} {
		if name != "" && !envNamePattern.MatchString(name) {
			return fmt.Errorf("credential references must be environment variable names, not secret values")
		}
	}
	if (refs.ManagementUsernameEnv == "") != (refs.ManagementPasswordEnv == "") {
		return fmt.Errorf("management credentials require both username and password references")
	}
	return nil
}
