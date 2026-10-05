// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// ProfileVersion is the supplied assessment offering profile, not the framework version.
const ProfileVersion = "2.0"

// FrameworkURL identifies the governing normative framework.
const FrameworkURL = "https://learn.github.com/well-architected"

// PlatformDocsURL identifies the authority for GitHub platform capabilities.
const PlatformDocsURL = "https://docs.github.com"

var metricKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

var controlFamilies = []struct {
	prefix string
	pillar string
	count  int
}{
	{"PRD", "Productivity", 76},
	{"COL", "Collaboration", 31},
	{"SEC", "Application Security", 139},
	{"GOV", "Governance", 87},
	{"ARC", "Architecture", 123},
}

var collectorIDs = strings.Fields(`
ent.info ent.policies ent.actions_permissions ent.audit_log ent.audit_log_streams
ent.billing ent.scim_users ent.code_security_configs ent.copilot
ghes.meta ghes.manage_api ghes.cli ghes.backup
org.settings org.repos org.members org.outside_collaborators org.teams
org.installations org.hooks org.pat_governance org.rulesets org.properties org.roles
org.code_security_configs org.dependabot_alerts org.code_scanning_alerts
org.secret_scanning_alerts org.secret_scanning_settings org.bypass_requests
org.campaigns org.actions_permissions org.runners org.audit_log org.api_insights
org.copilot org.packages org.billing org.projects
repo.details repo.rules repo.workflows repo.actions_runs repo.secrets_env
repo.contents_probe repo.languages repo.sbom repo.code_scanning repo.commits
repo.access repo.prs repo.releases_packages repo.discussions_projects
ui.ent_policies ui.ent_auth ui.ent_audit_settings ui.org_pat_policy
ui.org_third_party ui.org_code_security_settings ui.org_copilot_policies
ui.org_security_overview ui.org_actions_settings
ext.github_status ext.ghes_releases ext.siem_rules manual.interview manual.document
`)

// Collector retains the complete supplied catalogue descriptor without executing its text.
type Collector struct {
	ID         string `json:"id"`
	Level      string `json:"level"`
	Method     string `json:"method"`
	Endpoint   string `json:"endpoint"`
	Auth       string `json:"auth"`
	Pagination string `json:"pagination"`
	Fields     string `json:"fields"`
	GHES       string `json:"ghes"`
	Evidence   string `json:"evidence"`
	Notes      string `json:"notes"`
	Verify     bool   `json:"verify,omitempty"`
}

// Control preserves local identity, wording, origin and non-executable rule text.
type Control struct {
	ID                string     `json:"id"`
	Origin            Origin     `json:"origin"`
	Pillar            string     `json:"pillar"`
	DesignPrinciple   string     `json:"design_principle"`
	Area              string     `json:"area"`
	Control           string     `json:"control"`
	Scope             string     `json:"scope"`
	CollectionMethod  string     `json:"collection_method"`
	Automation        Automation `json:"automation"`
	Collectors        []string   `json:"collectors"`
	Rule              string     `json:"rule"`
	Metrics           string     `json:"metrics"`
	Evidence          []string   `json:"evidence"`
	InterviewQuestion *string    `json:"interview_question"`
}

// Profile is the versioned source catalogue; SHA256 fingerprints the original bytes.
type Profile struct {
	Name             string                        `json:"name"`
	Version          string                        `json:"version"`
	Generated        string                        `json:"generated"`
	APIVersionHeader string                        `json:"api_version_header"`
	States           map[State]*int                `json:"states"`
	Definitions      map[string]string             `json:"definitions"`
	AutomationLevels map[Automation]string         `json:"automation_levels"`
	Collectors       []Collector                   `json:"collectors"`
	Controls         []Control                     `json:"controls"`
	Stats            map[string]map[Automation]int `json:"stats"`
	SHA256           string                        `json:"-"`
}

// SourceReference maps a local control back to its versioned source and authority.
// Authority URLs are entry points, not claims of an exact live wording match.
type SourceReference struct {
	ControlID      string `json:"control_id"`
	Origin         Origin `json:"origin"`
	ProfileVersion string `json:"profile_version"`
	ProfileSHA256  string `json:"profile_sha256"`
	AuthorityURL   string `json:"authority_url"`
	MappingNote    string `json:"mapping_note"`
}

// ProfileSummary reports identity and counts without calling them completion percentages.
type ProfileSummary struct {
	Version        string             `json:"version"`
	SHA256         string             `json:"sha256"`
	ControlCount   int                `json:"control_count"`
	CollectorCount int                `json:"collector_count"`
	ByAutomation   map[Automation]int `json:"by_automation"`
	ByOrigin       map[Origin]int     `json:"by_origin"`
	ByPillar       map[string]int     `json:"by_pillar"`
}

// LoadProfile reads an explicit profile, or the bundled default when path is empty.
// An invalid explicit override returns an error rather than falling back.
func LoadProfile(path string) (*Profile, error) {
	if path == "" {
		return LoadDefaultProfile()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read assessment profile: %w", err)
	}
	return ParseProfile(data)
}

// ParseProfile validates the exact version-2 catalogue contract.
func ParseProfile(data []byte) (*Profile, error) {
	var profile Profile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode assessment profile: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("read assessment profile trailer: %w", err)
		}
		return nil, fmt.Errorf("assessment profile must contain exactly one JSON object")
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate assessment profile: %w", err)
	}
	digest := sha256.Sum256(data)
	profile.SHA256 = hex.EncodeToString(digest[:])
	return &profile, nil
}

// Validate enforces exact identities, taxonomy, counts and collector references.
func (p *Profile) Validate() error {
	if p == nil {
		return fmt.Errorf("assessment profile is nil")
	}
	if p.Version != ProfileVersion || p.Name == "" || p.APIVersionHeader != "2022-11-28" {
		return fmt.Errorf("expected named profile version %s with API version 2022-11-28", ProfileVersion)
	}
	if _, err := time.Parse(time.DateOnly, p.Generated); err != nil {
		return fmt.Errorf("invalid profile generation date: %w", err)
	}
	if err := p.validateStates(); err != nil {
		return err
	}
	if len(p.Controls) != 456 || len(p.Collectors) != len(collectorIDs) {
		return fmt.Errorf("profile requires 456 controls and 67 collectors, got %d and %d", len(p.Controls), len(p.Collectors))
	}
	collectors, err := p.validateCollectors()
	if err != nil {
		return err
	}
	expected := expectedControls()
	seen := make(map[string]bool, len(p.Controls))
	for _, control := range p.Controls {
		identity, ok := expected[control.ID]
		if !ok || seen[control.ID] {
			return fmt.Errorf("unknown or duplicate control ID %q", control.ID)
		}
		seen[control.ID] = true
		if control.Pillar != identity.pillar || control.Origin != identity.origin {
			return fmt.Errorf("control %s has inconsistent pillar or origin", control.ID)
		}
		if err := validateControl(control, collectors); err != nil {
			return fmt.Errorf("control %s: %w", control.ID, err)
		}
	}
	summary := p.Summary()
	if summary.ByAutomation[Full] != 150 || summary.ByAutomation[Partial] != 109 || summary.ByAutomation[Manual] != 197 {
		return fmt.Errorf("profile requires Full=150, Partial=109 and Manual=197")
	}
	return p.validateStats()
}

func (p *Profile) validateStats() error {
	if len(p.Stats) != len(controlFamilies) {
		return fmt.Errorf("profile statistics require the five supplied pillars")
	}
	actual := make(map[string]map[Automation]int, len(controlFamilies))
	for _, control := range p.Controls {
		if actual[control.Pillar] == nil {
			actual[control.Pillar] = map[Automation]int{}
		}
		actual[control.Pillar][control.Automation]++
	}
	for _, family := range controlFamilies {
		stats, ok := p.Stats[family.pillar]
		if !ok || len(stats) != 3 {
			return fmt.Errorf("profile statistics for %s require Full, Partial and Manual counts", family.pillar)
		}
		for _, automation := range []Automation{Full, Partial, Manual} {
			count, ok := stats[automation]
			if !ok || count != actual[family.pillar][automation] {
				return fmt.Errorf("profile statistics for %s/%s do not match the controls", family.pillar, automation)
			}
		}
	}
	return nil
}

func (p *Profile) validateStates() error {
	expected := map[State]*int{NotAssessed: nil, NotApplicable: nil}
	for state, score := range map[State]int{Implemented: 2, PartiallyImplemented: 1, NotImplemented: 0} {
		value := score
		expected[state] = &value
	}
	if len(p.States) != len(expected) {
		return fmt.Errorf("profile requires the five contractual assessment states")
	}
	for state, score := range expected {
		actual, ok := p.States[state]
		if !ok || (score == nil) != (actual == nil) || (score != nil && *score != *actual) {
			return fmt.Errorf("invalid score mapping for state %s", state)
		}
	}
	return nil
}

func (p *Profile) validateCollectors() (map[string]bool, error) {
	expected := make(map[string]bool, len(collectorIDs))
	for _, id := range collectorIDs {
		expected[id] = true
	}
	seen := make(map[string]bool, len(p.Collectors))
	for _, collector := range p.Collectors {
		if !expected[collector.ID] || seen[collector.ID] {
			return nil, fmt.Errorf("unknown or duplicate collector ID %q", collector.ID)
		}
		seen[collector.ID] = true
		if collector.Endpoint == "" || collector.Evidence == "" {
			return nil, fmt.Errorf("collector %s requires endpoint and evidence descriptors", collector.ID)
		}
		switch collector.Method {
		case "REST", "GraphQL", "UI", "CLI", "Document", "Interview":
		default:
			return nil, fmt.Errorf("collector %s has unsupported method %q", collector.ID, collector.Method)
		}
	}
	return seen, nil
}

type controlIdentity struct {
	pillar string
	origin Origin
}

func expectedControls() map[string]controlIdentity {
	expected := make(map[string]controlIdentity, 456)
	for _, family := range controlFamilies {
		for number := 1; number <= family.count; number++ {
			origin := FrameworkChecklist
			if (family.prefix == "SEC" && number >= 98) || (family.prefix == "GOV" && number >= 58) {
				origin = SecurityDeepDive
			}
			expected[fmt.Sprintf("%s-%03d", family.prefix, number)] = controlIdentity{family.pillar, origin}
		}
	}
	return expected
}

func validateControl(control Control, collectors map[string]bool) error {
	if control.Control == "" || control.Rule == "" || control.DesignPrinciple == "" || control.Area == "" {
		return fmt.Errorf("wording, rule, design principle and area are required")
	}
	switch control.Automation {
	case Full, Partial, Manual:
	default:
		return fmt.Errorf("unsupported automation %q", control.Automation)
	}
	switch control.Scope {
	case "All", "GHE (Cloud & Server)", "GHE Cloud", "GHE Server":
	default:
		return fmt.Errorf("unsupported scope %q", control.Scope)
	}
	if control.RequiresInterview() && (control.InterviewQuestion == nil || strings.TrimSpace(*control.InterviewQuestion) == "") {
		return fmt.Errorf("mandatory interview question is missing")
	}
	for _, id := range control.CollectorIDs() {
		if !collectors[id] {
			return fmt.Errorf("unknown collector reference %q", id)
		}
	}
	_, err := control.MetricKeys()
	return err
}

// CollectorIDs returns stable unique dependencies without changing raw profile references.
func (c Control) CollectorIDs() []string {
	ids := make([]string, 0, len(c.Collectors))
	seen := make(map[string]bool, len(c.Collectors))
	for _, id := range c.Collectors {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids
}

// MetricKeys removes descriptive type annotations while preserving exact metric keys.
func (c Control) MetricKeys() ([]string, error) {
	keys := []string{}
	for _, entry := range strings.Split(c.Metrics, ";") {
		key := strings.TrimSpace(strings.SplitN(entry, "(", 2)[0])
		if !metricKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("invalid metric descriptor %q", entry)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// Summary computes catalogue counts, not implementation coverage.
func (p *Profile) Summary() ProfileSummary {
	summary := ProfileSummary{
		Version: p.Version, SHA256: p.SHA256,
		ControlCount: len(p.Controls), CollectorCount: len(p.Collectors),
		ByAutomation: map[Automation]int{}, ByOrigin: map[Origin]int{}, ByPillar: map[string]int{},
	}
	for _, control := range p.Controls {
		summary.ByAutomation[control.Automation]++
		summary.ByOrigin[control.Origin]++
		summary.ByPillar[control.Pillar]++
	}
	return summary
}

// Sources preserves origin mapping and known reconciliation exceptions without expanding the catalogue.
func (p *Profile) Sources() []SourceReference {
	checklists := map[string]string{
		"Productivity": "productivity", "Collaboration": "collaboration",
		"Application Security": "application-security", "Governance": "governance", "Architecture": "architecture",
	}
	references := make([]SourceReference, 0, len(p.Controls))
	for _, control := range p.Controls {
		ref := SourceReference{
			ControlID: control.ID, Origin: control.Origin, ProfileVersion: p.Version,
			ProfileSHA256: p.SHA256, AuthorityURL: FrameworkURL + "/" + checklists[control.Pillar] + "/checklist",
			MappingNote: "framework-derived profile wording; not a claim of live exact wording parity",
		}
		if control.Origin == SecurityDeepDive {
			ref.AuthorityURL = PlatformDocsURL
			ref.MappingNote = "offering security extension; specific platform documentation mapping requires review"
		}
		switch control.ID {
		case "PRD-058", "PRD-064", "ARC-004", "ARC-015":
			ref.MappingNote = "editorial or annotation variant recorded in the 2026-10-05 framework reconciliation"
		}
		references = append(references, ref)
	}
	return references
}
