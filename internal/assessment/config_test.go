// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"strings"
	"testing"
)

func TestCustomerConfig(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"explicit cloud organization", "organizations: [acme]", ""},
		{"explicit cloud enterprise", "enterprise: acme", ""},
		{"explicit server", "deployment: ghes\nghes_host: github.example.com\norganizations: [acme]", ""},
		{"empty scope", "thresholds: {}", "explicit enterprise or organization"},
		{"all organizations", "organizations: all", "decode customer configuration"},
		{"all in list", "organizations: [all]", "must be explicit"},
		{"over concurrency", "organizations: [acme]\nconcurrency: 5", "between 1 and 4"},
		{"zero concurrency", "organizations: [acme]\nconcurrency: 0", "between 1 and 4"},
		{"zero cap", "organizations: [acme]\nrepository_cap: 0", "must be positive"},
		{"bad lookback", "organizations: [acme]\nlookback_days: -1", "must be positive"},
		{"bad regex", "organizations: [acme]\nproduction_env_regex: '['", "environment expression"},
		{"bad threshold", "organizations: [acme]\nthresholds: {coverage_pct: 101}", "must not exceed 100"},
		{"nonfinite threshold", "organizations: [acme]\nthresholds: {coverage_pct: .nan}", "finite value"},
		{"negative coverage", "organizations: [acme]\nthresholds: {coverage_pct: -1}", "nonnegative"},
		{"signed reduction threshold", "organizations: [acme]\nthresholds: {open_alerts_trend_90d_pct: -20}", ""},
		{"signed lower boundary", "organizations: [acme]\nthresholds: {open_alerts_trend_90d_pct: -100}", ""},
		{"signed increase threshold", "organizations: [acme]\nthresholds: {open_alerts_trend_90d_pct: 300}", ""},
		{"signed impossible reduction", "organizations: [acme]\nthresholds: {open_alerts_trend_90d_pct: -100.01}", "at least -100"},
		{"inline secret", "organizations: [acme]\ncredentials: {token: sensitive-placeholder}", "decode customer configuration"},
		{"secret as reference", "organizations: [acme]\ncredentials: {kind: classic-pat, token_env: 'not/an/env'}", "variable names"},
		{"partial management reference", "organizations: [acme]\ncredentials: {management_password_env: GHES_PASSWORD}", "both username and password"},
		{"management token confusion", "organizations: [acme]\ncredentials: {kind: management-console}", "API credential kind"},
		{"mixed implicit hosts", "deployment: both\norganizations: [acme]", "requires explicit targets"},
		{"host URL", "deployment: ghes\nghes_host: https://github.example.com", "without scheme"},
		{"duplicate organizations", "organizations: [Acme, acme]", "duplicate organization"},
		{"unknown option", "organizations: [acme]\nunknown: true", "decode customer configuration"},
		{"multiple documents", "organizations: [acme]\n---\norganizations: [other]", "exactly one YAML"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseConfig([]byte(tt.yaml))
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("config error = %v, want %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.RepositoryCap != 300 || config.LookbackDays != 90 || config.Concurrency != 4 {
				t.Fatalf("unexpected defaults: %+v", config)
			}
		})
	}
}

func TestMixedHostScopeIdentity(t *testing.T) {
	config, err := ParseConfig([]byte(`
targets:
  - host: github.com
    deployment: ghec
    organizations: [acme]
    credentials: {kind: app-installation, token_env: CLOUD_APP_TOKEN}
  - host: github.example.com
    deployment: ghes
    organizations: [acme]
    credentials:
      kind: classic-pat
      token_env: SERVER_API_TOKEN
      management_username_env: GHES_MANAGE_USER
      management_password_env: GHES_MANAGE_PASSWORD
`))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		t.Fatal(err)
	}
	first := (Scope{targets[0].Host, OrganizationScope, "acme"}).Key()
	second := (Scope{targets[1].Host, OrganizationScope, "acme"}).Key()
	if first == second || first != "github.com/organization/acme" || second != "github.example.com/organization/acme" {
		t.Fatalf("host-qualified scopes collide: %s %s", first, second)
	}
}

func TestScopeValidation(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		valid bool
	}{
		{"repository", Scope{"github.com", RepositoryScope, "acme/repo"}, true},
		{"server organization", Scope{"github.example.com", OrganizationScope, "acme"}, true},
		{"missing owner", Scope{"github.com", RepositoryScope, "repo"}, false},
		{"traversal", Scope{"github.com", RepositoryScope, "acme/.."}, false},
		{"nested path", Scope{"github.com", RepositoryScope, "acme/repo/extra"}, false},
		{"host path", Scope{"github.com/api/v3", OrganizationScope, "acme"}, false},
		{"host credentials", Scope{"user@github.com", OrganizationScope, "acme"}, false},
		{"unknown kind", Scope{"github.com", "unknown", "acme"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.scope.Validate(); (err == nil) != tt.valid {
				t.Fatalf("scope validity = %v, want %v: %v", err == nil, tt.valid, err)
			}
		})
	}
}
