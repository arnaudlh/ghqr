// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ImportContractCollectorIDs lists the 16 catalogue collector IDs that have
// no live API or UI-automatable probe surface at all: customer-run GHES
// CLI/SSH output (ghes.cli), customer-run backup-utils host output
// (ghes.backup), Management Console / Settings-page screenshots or manual
// transcriptions (ui.*), external status/release/SIEM feeds this offering
// does not operate (ext.*), and assessor interviews/document review
// (manual.*). None of these is, or ever will be, auto-probed by
// RunVerticalSlice or RunPreflight; each instead defines a typed JSON import
// contract (see ValidateImportContractPayload) so a customer-supplied
// payload is validated against the collector's actual expected shape before
// ImportJSON persists it as evidence, rather than silently accepting and
// aliasing arbitrary JSON as "fully implemented" collection.
func ImportContractCollectorIDs() []string {
	return []string{
		"ghes.cli", "ghes.backup",
		"ui.ent_policies", "ui.ent_auth", "ui.ent_audit_settings", "ui.org_pat_policy",
		"ui.org_third_party", "ui.org_code_security_settings", "ui.org_copilot_policies",
		"ui.org_security_overview", "ui.org_actions_settings",
		"ext.github_status", "ext.ghes_releases", "ext.siem_rules",
		"manual.interview", "manual.document",
	}
}

var importContractCollectorIDSet = buildImportContractCollectorIDSet()

func buildImportContractCollectorIDSet() map[string]bool {
	set := make(map[string]bool, len(ImportContractCollectorIDs()))
	for _, id := range ImportContractCollectorIDs() {
		set[id] = true
	}
	return set
}

// GHESCLIReplicationEntry is one parsed service line from `ghe-repl-status`
// (per the ghes.cli collector's documented evidence: "Store command output
// verbatim; the agent parses OK/WARN/ERR lines from ghe-repl-status"). The
// import contract is the already-parsed structured result, not the raw
// terminal transcript, so the status taxonomy is validated at import time.
type GHESCLIReplicationEntry struct {
	Service           string   `json:"service"`
	Status            string   `json:"status"`
	ReplicaLagSeconds *float64 `json:"replica_lag_seconds,omitempty"`
}

// GHESCLIImport is the ghes.cli collector's full import contract: replication
// status plus the other documented ghe-* command outputs this offering
// understands as structured fields (disk usage, cluster health, maintenance
// mode). Fields this offering does not yet parse are explicitly omitted
// rather than accepted as an arbitrary blob.
type GHESCLIImport struct {
	CapturedAt      time.Time                 `json:"captured_at"`
	Replication     []GHESCLIReplicationEntry `json:"replication"`
	DiskUsagePct    *float64                  `json:"disk_usage_pct,omitempty"`
	ClusterHealthy  *bool                     `json:"cluster_healthy,omitempty"`
	MaintenanceMode *bool                     `json:"maintenance_mode,omitempty"`
}

func (i GHESCLIImport) validate() error {
	if i.CapturedAt.IsZero() {
		return fmt.Errorf("ghes.cli import requires captured_at")
	}
	for index, entry := range i.Replication {
		if entry.Service == "" {
			return fmt.Errorf("ghes.cli replication[%d] requires a service name", index)
		}
		switch entry.Status {
		case "OK", "WARN", "ERR":
		default:
			return fmt.Errorf("ghes.cli replication[%d] status must be OK, WARN or ERR, got %q", index, entry.Status)
		}
	}
	return nil
}

// GHESBackupImport is the ghes.backup collector's import contract: the
// customer's backup-utils host state (backup.config fields, retained
// snapshot count, latest snapshot outcome). storage_location/encrypted are
// collected as plain descriptive fields, never credentials. RetainedSnapshots
// is a pointer so an omitted field is preserved as unknown rather than
// collapsing to the same zero value as an explicitly reported "0 retained
// snapshots" -- a meaningfully different, and more alarming, signal.
type GHESBackupImport struct {
	CapturedAt             time.Time  `json:"captured_at"`
	ScheduleCronExpression string     `json:"schedule_cron_expression"`
	RetainedSnapshots      *int       `json:"retained_snapshots"`
	LatestSnapshotAt       *time.Time `json:"latest_snapshot_at,omitempty"`
	LatestSnapshotStatus   string     `json:"latest_snapshot_status"`
	StorageLocation        string     `json:"storage_location,omitempty"`
	Encrypted              *bool      `json:"encrypted,omitempty"`
}

func (i GHESBackupImport) validate() error {
	if i.CapturedAt.IsZero() {
		return fmt.Errorf("ghes.backup import requires captured_at")
	}
	if i.RetainedSnapshots == nil {
		return fmt.Errorf("ghes.backup import requires retained_snapshots (explicitly, not omitted)")
	}
	if *i.RetainedSnapshots < 0 {
		return fmt.Errorf("ghes.backup retained_snapshots must not be negative")
	}
	switch i.LatestSnapshotStatus {
	case "success", "failed", "unknown":
	default:
		return fmt.Errorf("ghes.backup latest_snapshot_status must be success, failed or unknown, got %q", i.LatestSnapshotStatus)
	}
	return nil
}

// UISettingCapture is the shared import contract for every ui.* collector:
// a manual Management-Console/Settings-page transcription. It intentionally
// does not store a screenshot image (out of this offering's evidence model);
// Fields holds the specific named settings the assessor actually read off
// the page, keyed by the exact setting name the catalogue descriptor
// documents for that collector (for example "two_factor_required" for
// ui.org_security_overview). An empty Fields map is rejected: a UI capture
// with nothing read is not a valid import, it is a missed capture.
//
// This contract validates only the shared outer envelope (collector_id
// matches the target collector, captured_by/captured_at are present, and
// Fields is non-empty) -- it deliberately does NOT validate the individual
// setting names or value types inside Fields against any per-collector
// schema (Fields remains an arbitrary map[string]any). "Schema-validated
// import contract" describes this non-empty, identity-matched envelope
// guarantee; it must never be read or documented as "every ui.* collector's
// individual settings are field-normalized/complete", which this contract
// does not provide.
type UISettingCapture struct {
	CollectorID string         `json:"collector_id"`
	CapturedBy  string         `json:"captured_by"`
	CapturedAt  time.Time      `json:"captured_at"`
	Fields      map[string]any `json:"fields"`
}

func (i UISettingCapture) validate(expectedCollectorID string) error {
	if i.CollectorID != expectedCollectorID {
		return fmt.Errorf("ui capture collector_id %q does not match the target collector %q", i.CollectorID, expectedCollectorID)
	}
	if i.CapturedBy == "" {
		return fmt.Errorf("ui capture requires captured_by")
	}
	if i.CapturedAt.IsZero() {
		return fmt.Errorf("ui capture requires captured_at")
	}
	if len(i.Fields) == 0 {
		return fmt.Errorf("ui capture requires at least one captured field")
	}
	return nil
}

// ExternalFeedImport is the shared import contract for the three ext.*
// external data sources (GitHub status, GHES release feed, SIEM detection
// rule inventory). This offering never polls these feeds itself; Source
// records the retrieval method so "offering-collected" is never conflated
// with "customer-supplied".
//
// Like UISettingCapture, this contract validates only the shared outer
// envelope (a non-empty Source description, a present RetrievedAt and a
// non-empty Payload) -- Payload's actual feed content remains an arbitrary,
// non-field-normalized map[string]any, not a per-feed-source schema. The
// same honesty requirement applies: this is a non-empty-envelope guarantee,
// not proof that a given ext.* collector's content is complete or typed.
type ExternalFeedImport struct {
	Source      string         `json:"source"`
	RetrievedAt time.Time      `json:"retrieved_at"`
	Payload     map[string]any `json:"payload"`
}

func (i ExternalFeedImport) validate() error {
	if strings.TrimSpace(i.Source) == "" {
		return fmt.Errorf("external feed import requires a source description")
	}
	if i.RetrievedAt.IsZero() {
		return fmt.Errorf("external feed import requires retrieved_at")
	}
	if len(i.Payload) == 0 {
		return fmt.Errorf("external feed import requires a non-empty payload")
	}
	return nil
}

// ManualInterviewImport is the manual.interview collector's import contract:
// one control's assessor interview response, distinct from an
// AssessorDecision (which records a confirmed/overridden state, not raw
// interview content).
type ManualInterviewImport struct {
	ControlID    string    `json:"control_id"`
	Assessor     string    `json:"assessor"`
	AnsweredAt   time.Time `json:"answered_at"`
	Question     string    `json:"question"`
	Response     string    `json:"response"`
	EvidenceRefs []string  `json:"evidence_refs,omitempty"`
}

func (i ManualInterviewImport) validate() error {
	if i.ControlID == "" || i.Assessor == "" || i.Response == "" {
		return fmt.Errorf("manual interview import requires control_id, assessor and response")
	}
	if i.AnsweredAt.IsZero() {
		return fmt.Errorf("manual interview import requires answered_at")
	}
	return nil
}

// ManualDocumentImport is the manual.document collector's import contract:
// one control's supporting document reference (policy, runbook, architecture
// diagram) reviewed by an assessor, never the document's raw bytes.
type ManualDocumentImport struct {
	ControlID     string    `json:"control_id"`
	DocumentTitle string    `json:"document_title"`
	DocumentURL   string    `json:"document_url,omitempty"`
	ReviewedBy    string    `json:"reviewed_by"`
	ReviewedAt    time.Time `json:"reviewed_at"`
	Summary       string    `json:"summary,omitempty"`
}

func (i ManualDocumentImport) validate() error {
	if i.ControlID == "" || i.DocumentTitle == "" || i.ReviewedBy == "" {
		return fmt.Errorf("manual document import requires control_id, document_title and reviewed_by")
	}
	if i.ReviewedAt.IsZero() {
		return fmt.Errorf("manual document import requires reviewed_at")
	}
	return nil
}

// ValidateImportContractPayload decodes and validates a customer-supplied
// import payload against the named collector's actual typed contract,
// rejecting both malformed JSON and a structurally valid document that is
// missing required fields. It never accepts an arbitrary/unvalidated JSON
// blob as satisfying one of these 16 collectors: a payload that fails
// validation must be corrected and re-submitted, not silently stored as if
// it were complete evidence. The returned value is the decoded, validated
// contract struct (or a typed slice/map for the shared ui.*/ext.*
// contracts), ready for the caller to pass to ImportJSON alongside
// unmodified, schema-appropriate EvidenceMetadata.
func ValidateImportContractPayload(collectorID string, raw []byte) (any, error) {
	if !importContractCollectorIDSet[collectorID] {
		return nil, fmt.Errorf("%q is not an import-contract collector; see ImportContractCollectorIDs", collectorID)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	switch collectorID {
	case "ghes.cli":
		var payload GHESCLIImport
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode ghes.cli import: %w", err)
		}
		if err := payload.validate(); err != nil {
			return nil, err
		}
		return payload, nil
	case "ghes.backup":
		var payload GHESBackupImport
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode ghes.backup import: %w", err)
		}
		if err := payload.validate(); err != nil {
			return nil, err
		}
		return payload, nil
	case "ext.github_status", "ext.ghes_releases", "ext.siem_rules":
		var payload ExternalFeedImport
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode %s import: %w", collectorID, err)
		}
		if err := payload.validate(); err != nil {
			return nil, err
		}
		return payload, nil
	case "manual.interview":
		var payload ManualInterviewImport
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode manual.interview import: %w", err)
		}
		if err := payload.validate(); err != nil {
			return nil, err
		}
		return payload, nil
	case "manual.document":
		var payload ManualDocumentImport
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode manual.document import: %w", err)
		}
		if err := payload.validate(); err != nil {
			return nil, err
		}
		return payload, nil
	default:
		// Every remaining import-contract ID is a ui.* Management-Console/
		// Settings-page capture, sharing one contract shape.
		var payload UISettingCapture
		if err := decoder.Decode(&payload); err != nil {
			return nil, fmt.Errorf("decode %s import: %w", collectorID, err)
		}
		if err := payload.validate(collectorID); err != nil {
			return nil, err
		}
		return payload, nil
	}
}

// uiCaptureBool/uiCaptureString/uiCaptureFloat are typed accessors for
// UISettingCapture.Fields (a generic map[string]any by design -- see
// UISettingCapture's own doc comment): a named field that is absent, or
// present with a JSON type other than the one requested, is reported
// unknown (a nil pointer) -- never silently coerced to false/""/0. This is
// the same Known/value separation this package uses everywhere a field can
// be genuinely unobserved rather than confirmed negative/empty.
func uiCaptureBool(fields map[string]any, key string) *bool {
	value, exists := fields[key]
	if !exists {
		return nil
	}
	boolValue, ok := value.(bool)
	if !ok {
		return nil
	}
	return &boolValue
}

func uiCaptureString(fields map[string]any, key string) *string {
	value, exists := fields[key]
	if !exists {
		return nil
	}
	stringValue, ok := value.(string)
	if !ok {
		return nil
	}
	return &stringValue
}

func uiCaptureFloat(fields map[string]any, key string) *float64 {
	value, exists := fields[key]
	if !exists {
		return nil
	}
	// encoding/json always decodes a JSON number into Go's float64 when the
	// target is `any` (map[string]any), never int -- this is the one
	// numeric Go type a captured field can actually arrive as.
	floatValue, ok := value.(float64)
	if !ok {
		return nil
	}
	return &floatValue
}

// GHESBackupNormalizedObservation is ghes.backup's typed, profile-exact-key
// normalization of an already-validated GHESBackupImport. Its four fields
// are the metric keys multiple catalogue controls independently and
// consistently name for this collector (backup_schedule/snapshots_retained
// in SEC-073 and ARC-121; latest_snapshot_age_h in SEC-073, ARC-024 and
// ARC-121; backup_encrypted in SEC-074 and ARC-123). Every OTHER metric key
// these same controls also reference against ghes.backup --
// restore_test_last_12m, backup_host_separate, backup_access_restricted,
// restore_time_h, backup_automated, backup_strategy -- requires evidence
// this import contract does not capture at all (restore testing, physical/
// network host placement, access-control specifics): they are never
// fabricated here and remain a disclosed gap for manual.document/
// manual.interview to supply instead, not a silently assumed false/zero.
type GHESBackupNormalizedObservation struct {
	BackupSchedule     *string  `json:"backup_schedule,omitempty"`
	LatestSnapshotAgeH *float64 `json:"latest_snapshot_age_h,omitempty"`
	SnapshotsRetained  *int     `json:"snapshots_retained,omitempty"`
	BackupEncrypted    *bool    `json:"backup_encrypted,omitempty"`
}

// NormalizeGHESBackupImport derives GHESBackupNormalizedObservation from an
// already-validated GHESBackupImport. latest_snapshot_age_h is computed
// relative to the import's own CapturedAt (when the customer-run command
// output was actually captured), never this process's live wall clock at
// evaluation time -- a report generated days after collection must not
// silently inflate the apparent snapshot age. A LatestSnapshotAt after
// CapturedAt (a logically impossible, malformed capture) reports the age
// unknown rather than a confident negative number.
func NormalizeGHESBackupImport(payload GHESBackupImport) GHESBackupNormalizedObservation {
	observation := GHESBackupNormalizedObservation{}
	if payload.ScheduleCronExpression != "" {
		schedule := payload.ScheduleCronExpression
		observation.BackupSchedule = &schedule
	}
	if payload.LatestSnapshotAt != nil {
		hours := payload.CapturedAt.Sub(*payload.LatestSnapshotAt).Hours()
		if hours >= 0 {
			observation.LatestSnapshotAgeH = &hours
		}
	}
	if payload.RetainedSnapshots != nil {
		retained := *payload.RetainedSnapshots
		observation.SnapshotsRetained = &retained
	}
	observation.BackupEncrypted = payload.Encrypted
	return observation
}

// uiEntAuthRecognizedSSOModes is ui.ent_auth's documented sso_mode enum
// (SEC-070/GOV-058/ARC-095/ARC-106 all consistently name
// "sso_mode (saml|oidc|emu|ldap|cas|builtin)"), plus "none" for a confirmed
// absence of SSO. A captured value outside this enum is reported unknown,
// never silently accepted as a fabricated new mode.
var uiEntAuthRecognizedSSOModes = map[string]bool{
	"saml": true, "oidc": true, "emu": true, "ldap": true, "cas": true, "builtin": true, "none": true,
}

// UIEntAuthNormalizedObservation is ui.ent_auth's typed, profile-exact-key
// normalization of an already-validated UISettingCapture: sso_mode,
// sso_enforced and ip_allow_list_enabled are the three metric keys multiple
// catalogue controls consistently and independently name for this
// collector. Every other metric key these same controls also reference
// (sso_last_review_months, idp_issuer, recovery_codes_custody_doc,
// private_mode, admin_ports_restricted) is outside this collector's own
// documented field set and is never fabricated here.
type UIEntAuthNormalizedObservation struct {
	SSOMode            *string `json:"sso_mode,omitempty"`
	SSOEnforced        *bool   `json:"sso_enforced,omitempty"`
	IPAllowListEnabled *bool   `json:"ip_allow_list_enabled,omitempty"`
}

// NormalizeUIEntAuthCapture derives UIEntAuthNormalizedObservation from an
// already-validated UISettingCapture. An error is returned only when the
// capture's own CollectorID does not match ui.ent_auth (a caller error, not
// an evidence-quality finding); a recognized field simply absent, or an
// sso_mode value outside its documented enum, is reported unknown (nil) on
// the observation itself, never an error.
func NormalizeUIEntAuthCapture(capture UISettingCapture) (UIEntAuthNormalizedObservation, error) {
	if capture.CollectorID != "ui.ent_auth" {
		return UIEntAuthNormalizedObservation{}, fmt.Errorf("normalize ui.ent_auth requires a ui.ent_auth capture, got %q", capture.CollectorID)
	}
	observation := UIEntAuthNormalizedObservation{
		SSOEnforced:        uiCaptureBool(capture.Fields, "sso_enforced"),
		IPAllowListEnabled: uiCaptureBool(capture.Fields, "ip_allow_list_enabled"),
	}
	if mode := uiCaptureString(capture.Fields, "sso_mode"); mode != nil {
		normalized := strings.ToLower(strings.TrimSpace(*mode))
		if uiEntAuthRecognizedSSOModes[normalized] {
			observation.SSOMode = &normalized
		}
	}
	return observation, nil
}

// UIOrgPATPolicyNormalizedObservation is ui.org_pat_policy's typed,
// profile-exact-key normalization of an already-validated UISettingCapture:
// fine_grained_requires_approval, classic_restricted and max_lifetime_days
// are the three metric keys both SEC-086 and GOV-063 consistently and
// independently name for this collector. pending_pat_requests/
// pending_requests_over_7d (named differently by each of those two
// controls, and sourced from org.pat_governance's own pat-requests.json
// evidence per both controls' documented evidence lists, not this
// collector's own capture) are never fabricated here.
type UIOrgPATPolicyNormalizedObservation struct {
	FineGrainedRequiresApproval *bool    `json:"fine_grained_requires_approval,omitempty"`
	ClassicRestricted           *bool    `json:"classic_restricted,omitempty"`
	MaxLifetimeDays             *float64 `json:"max_lifetime_days,omitempty"`
}

// NormalizeUIOrgPATPolicyCapture derives UIOrgPATPolicyNormalizedObservation
// from an already-validated UISettingCapture, with the same CollectorID
// cross-check and unknown-on-absent/wrong-type contract as
// NormalizeUIEntAuthCapture.
func NormalizeUIOrgPATPolicyCapture(capture UISettingCapture) (UIOrgPATPolicyNormalizedObservation, error) {
	if capture.CollectorID != "ui.org_pat_policy" {
		return UIOrgPATPolicyNormalizedObservation{}, fmt.Errorf("normalize ui.org_pat_policy requires a ui.org_pat_policy capture, got %q", capture.CollectorID)
	}
	return UIOrgPATPolicyNormalizedObservation{
		FineGrainedRequiresApproval: uiCaptureBool(capture.Fields, "fine_grained_requires_approval"),
		ClassicRestricted:           uiCaptureBool(capture.Fields, "classic_restricted"),
		MaxLifetimeDays:             uiCaptureFloat(capture.Fields, "max_lifetime_days"),
	}, nil
}

// loadImportedPayload reads a previously imported collector's evidence back
// out of the evidence store at the caller-supplied scope/feature identity
// (ImportJSON lets each import choose its own feature name; this package
// defines no "latest import" convention to infer it from, so the caller
// must supply the exact identity its own import used) and decodes it into
// an already-validated Go value. A missing import, or one that no longer
// decodes against the target type, is reported through outcome/err -- never
// silently treated as a confident empty/zero result.
//
// Every outcome that cites evidence (EvidenceRefs non-empty) sets Pages:1:
// an import is always a single, non-paginated record (never a REST
// Link-paginated collection), and exact-ref replay verification elsewhere
// in this package cross-checks len(EvidenceRefs) == Pages*2 uniformly
// across every collector's outcomes, import-sourced or not.
// loadImportedPayload reads a previously imported collector's evidence back
// out of the evidence store at the caller-supplied scope/feature identity
// (ImportJSON lets each import choose its own feature name; this package
// defines no "latest import" convention to infer it from, so the caller
// must supply the exact identity its own import used) and decodes it into
// an already-validated Go value. A missing import, or one that no longer
// decodes against the target type, is reported through outcome/err -- never
// silently treated as a confident empty/zero result.
//
// This reuses ValidateImportContractPayload (the SAME gate ImportJSON
// itself enforces at import time) rather than a bare json.Unmarshal: stored
// evidence that no longer satisfies its own contract (a required field
// since gone missing, or any other structural drift) is rejected here too,
// not silently accepted just because it once passed validation at import
// time. It also cross-checks metadata.SourceKind is genuinely
// ImportedEvidence and, when a profile is supplied, that the stored
// evidence's own profile identity still matches the active profile --
// stored evidence belonging to a different profile generation is never
// silently reinterpreted against the current one.
//
// A source recorded Complete:false at import time (the customer's own
// capture was itself partial) is reported CollectionPartial, never
// CollectionOK -- callers must treat this exactly like any other
// not-fully-successful outcome, never a confident known result.
//
// Every outcome that cites evidence (EvidenceRefs non-empty) sets Pages:1:
// an import is always a single, non-paginated record (never a REST
// Link-paginated collection), and exact-ref replay verification elsewhere
// in this package cross-checks len(EvidenceRefs) == Pages*2 uniformly
// across every collector's outcomes, import-sourced or not.
func loadImportedPayload[T any](store *EvidenceStore, profile *Profile, scope Scope, collectorID, feature string) (T, CollectorOutcome, error) {
	var zero T
	raw, metadata, ref, loadErr := store.LoadJSON(scope, collectorID, feature)
	if loadErr != nil {
		return zero, CollectorOutcome{
			CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
			Availability: NotChecked, Status: NotRun, EvidenceRefs: []string{},
			Reason: fmt.Sprintf("no previously imported %s evidence found at this scope/feature: %s", collectorID, loadErr),
		}, nil
	}
	refs := []string{ref.DataPath, ref.MetadataPath}
	if metadata.SourceKind != ImportedEvidence {
		return zero, CollectorOutcome{
			CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
			Availability: Available, Status: CollectionFailed, Pages: 1, EvidenceRefs: refs,
			Reason: fmt.Sprintf("stored evidence at this identity is not imported provenance (source_kind=%q)", metadata.SourceKind),
		}, fmt.Errorf("stored evidence for %s is not ImportedEvidence", collectorID)
	}
	if profile != nil && (metadata.ProfileVersion != profile.Version || metadata.ProfileSHA256 != profile.SHA256) {
		return zero, CollectorOutcome{
			CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
			Availability: Available, Status: CollectionFailed, Pages: 1, EvidenceRefs: refs,
			Reason: "stored evidence's profile identity does not match the active profile",
		}, fmt.Errorf("profile identity mismatch for imported %s evidence", collectorID)
	}
	validated, validateErr := ValidateImportContractPayload(collectorID, raw)
	if validateErr != nil {
		return zero, CollectorOutcome{
			CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
			Availability: Available, Status: CollectionFailed, Pages: 1, EvidenceRefs: refs,
			Reason: fmt.Sprintf("stored evidence no longer satisfies its import contract: %s", validateErr),
		}, fmt.Errorf("revalidate imported %s evidence: %w", collectorID, validateErr)
	}
	payload, ok := validated.(T)
	if !ok {
		return zero, CollectorOutcome{
			CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
			Availability: Available, Status: CollectionFailed, Pages: 1, EvidenceRefs: refs,
			Reason: "decoded import contract type does not match the expected normalizer",
		}, fmt.Errorf("decoded import contract type mismatch for %s", collectorID)
	}
	if !metadata.Complete {
		return payload, CollectorOutcome{
			CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
			Availability: Available, Status: CollectionPartial, Complete: false, Pages: 1,
			CredentialKind: metadata.CredentialKind, EvidenceRefs: refs,
			Reason: "imported evidence was itself recorded incomplete at import time",
		}, nil
	}
	return payload, CollectorOutcome{
		CollectorID: collectorID, Feature: feature, Scope: scope, Readiness: ImportOnly,
		Availability: Available, Status: CollectionOK, Complete: true, Pages: 1,
		CredentialKind: metadata.CredentialKind, EvidenceRefs: refs,
	}, nil
}

// LoadNormalizedGHESBackupImport reads a previously imported ghes.backup
// evidence record back out of the evidence store and normalizes it via
// NormalizeGHESBackupImport. profile may be nil to skip the profile-identity
// cross-check (for example in tests using a throwaway store); production
// callers should always supply the active profile.
func LoadNormalizedGHESBackupImport(store *EvidenceStore, profile *Profile, scope Scope, feature string) (GHESBackupNormalizedObservation, CollectorOutcome, error) {
	payload, outcome, err := loadImportedPayload[GHESBackupImport](store, profile, scope, "ghes.backup", feature)
	if err != nil || outcome.Status != CollectionOK {
		return GHESBackupNormalizedObservation{}, outcome, err
	}
	return NormalizeGHESBackupImport(payload), outcome, nil
}

// LoadNormalizedUIEntAuthCapture reads a previously imported ui.ent_auth
// evidence record back out of the evidence store and normalizes it via
// NormalizeUIEntAuthCapture.
func LoadNormalizedUIEntAuthCapture(store *EvidenceStore, profile *Profile, scope Scope, feature string) (UIEntAuthNormalizedObservation, CollectorOutcome, error) {
	payload, outcome, err := loadImportedPayload[UISettingCapture](store, profile, scope, "ui.ent_auth", feature)
	if err != nil || outcome.Status != CollectionOK {
		return UIEntAuthNormalizedObservation{}, outcome, err
	}
	observation, normalizeErr := NormalizeUIEntAuthCapture(payload)
	if normalizeErr != nil {
		return UIEntAuthNormalizedObservation{}, outcome, normalizeErr
	}
	return observation, outcome, nil
}

// LoadNormalizedUIOrgPATPolicyCapture reads a previously imported
// ui.org_pat_policy evidence record back out of the evidence store and
// normalizes it via NormalizeUIOrgPATPolicyCapture.
func LoadNormalizedUIOrgPATPolicyCapture(store *EvidenceStore, profile *Profile, scope Scope, feature string) (UIOrgPATPolicyNormalizedObservation, CollectorOutcome, error) {
	payload, outcome, err := loadImportedPayload[UISettingCapture](store, profile, scope, "ui.org_pat_policy", feature)
	if err != nil || outcome.Status != CollectionOK {
		return UIOrgPATPolicyNormalizedObservation{}, outcome, err
	}
	observation, normalizeErr := NormalizeUIOrgPATPolicyCapture(payload)
	if normalizeErr != nil {
		return UIOrgPATPolicyNormalizedObservation{}, outcome, normalizeErr
	}
	return observation, outcome, nil
}

// ImportSource names one previously-imported collector's evidence to merge
// into a VerticalSliceReport via ApplyNormalizedImports: an explicit
// (collector ID, scope, feature) identity, never inferred from a "latest"
// pointer -- the same deliberate-context-binding contract
// loadImportedPayload already requires of every LoadNormalized* function.
//
// This logical identity resolves through the evidence store's own current
// manifest for (scope, collector ID, feature) (see EvidenceStore.LoadJSON):
// it is the CURRENT import recorded under that identity, not a frozen
// point-in-time snapshot -- if that identity is ever re-imported, a later
// ApplyNormalizedImports call resolves the newer evidence, not historically
// pinned to whatever was current when an earlier report was produced. A
// genuinely historical, byte-exact re-merge (reproducing precisely what an
// earlier report actually observed, regardless of any later re-import under
// the same logical identity) is not yet supported; that would require an
// exact content-addressed selector (EvidenceRef) bypassing the mutable
// manifest entirely, which this round does not add -- disclosed as a
// remaining gap, not silently assumed solved.
type ImportSource struct {
	CollectorID string `json:"collector_id"`
	Scope       Scope  `json:"scope"`
	Feature     string `json:"feature"`
}

// ValidateImportSourceAuthorization confirms profile/config validity and
// that source's own scope is authorized by config's configured targets --
// the SAME gate ImportJSON itself already enforces at import time -- before
// any evidence store is opened. Callers that accept a caller-supplied list
// of ImportSource values from outside this package (the apply-imports CLI
// command, in particular) must call this for every source before merging
// anything: an out-of-scope source is rejected deterministically here,
// never discovered only after partially opening/reading the evidence store
// or merging a foreign-scope value into the report.
func ValidateImportSourceAuthorization(profile *Profile, config *CustomerConfig, source ImportSource) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	return authorizeEvidenceScope(config, source.Scope)
}

// normalizedImportMetricKeys documents, for each collector this round
// normalizes, the exact profile metric keys ApplyNormalizedImports
// populates -- cross-referenced directly from the automation-spec.v2.json
// catalogue's own per-control "metrics" declarations (see
// GHESBackupNormalizedObservation/UIEntAuthNormalizedObservation/
// UIOrgPATPolicyNormalizedObservation's own doc comments for the specific
// controls each key comes from), never invented.
var normalizedImportMetricKeys = map[string][]string{
	"ghes.backup":       {"backup_schedule", "latest_snapshot_age_h", "snapshots_retained", "backup_encrypted"},
	"ui.ent_auth":       {"sso_mode", "sso_enforced", "ip_allow_list_enabled"},
	"ui.org_pat_policy": {"fine_grained_requires_approval", "classic_restricted", "max_lifetime_days"},
}

// NormalizedImportMetricKeys returns the exact profile metric keys
// ApplyNormalizedImports can populate for a given import-contract collector
// ID, or false if this package does not yet normalize that collector's
// captured fields at all (the generic, interior-unread outer-envelope
// contract from ValidateImportContractPayload still applies to every other
// import-contract collector; it is never silently claimed as "normalized").
func NormalizedImportMetricKeys(collectorID string) ([]string, bool) {
	keys, ok := normalizedImportMetricKeys[collectorID]
	return keys, ok
}

// stageNormalizedImportSource loads and normalizes one import source,
// always returning a MetricValue for EVERY one of its documented metric
// keys (normalizedImportMetricKeys[source.CollectorID]) -- a source whose
// evidence is missing, incomplete, no longer satisfies its import contract,
// or carries a mismatched profile/source-kind still returns an explicit
// MetricUnavailable (with a semantic Reason and the outcome's own retained
// EvidenceRefs when it has any) for each of its keys, never omits them: a
// failed/missing source must never be indistinguishable from "this metric
// was never requested at all".
func stageNormalizedImportSource(store *EvidenceStore, profile *Profile, source ImportSource) (map[string]MetricValue, []CollectorOutcome) {
	unavailableAll := func(population string, outcome CollectorOutcome, err error) map[string]MetricValue {
		reason := outcome.Reason
		if reason == "" && err != nil {
			reason = err.Error()
		}
		if reason == "" {
			reason = "imported evidence for this collector could not be confirmed"
		}
		values := map[string]MetricValue{}
		for _, key := range normalizedImportMetricKeys[source.CollectorID] {
			value := unavailableObservation(reason, population)
			value.EvidenceRefs = append([]string{}, outcome.EvidenceRefs...)
			values[key] = value
		}
		return values
	}
	switch source.CollectorID {
	case "ghes.backup":
		observation, outcome, err := LoadNormalizedGHESBackupImport(store, profile, source.Scope, source.Feature)
		population := "ghes.backup capture"
		if err != nil || outcome.Status != CollectionOK {
			return unavailableAll(population, outcome, err), []CollectorOutcome{outcome}
		}
		return map[string]MetricValue{
			"backup_schedule":       importedStringMetric(observation.BackupSchedule, population, outcome.EvidenceRefs),
			"latest_snapshot_age_h": importedNumberMetric(observation.LatestSnapshotAgeH, population, outcome.EvidenceRefs),
			"snapshots_retained":    importedIntMetric(observation.SnapshotsRetained, population, outcome.EvidenceRefs),
			"backup_encrypted":      importedBoolMetric(observation.BackupEncrypted, population, outcome.EvidenceRefs),
		}, []CollectorOutcome{outcome}
	case "ui.ent_auth":
		observation, outcome, err := LoadNormalizedUIEntAuthCapture(store, profile, source.Scope, source.Feature)
		population := "ui.ent_auth capture"
		if err != nil || outcome.Status != CollectionOK {
			return unavailableAll(population, outcome, err), []CollectorOutcome{outcome}
		}
		return map[string]MetricValue{
			"sso_mode":              importedStringMetric(observation.SSOMode, population, outcome.EvidenceRefs),
			"sso_enforced":          importedBoolMetric(observation.SSOEnforced, population, outcome.EvidenceRefs),
			"ip_allow_list_enabled": importedBoolMetric(observation.IPAllowListEnabled, population, outcome.EvidenceRefs),
		}, []CollectorOutcome{outcome}
	case "ui.org_pat_policy":
		observation, outcome, err := LoadNormalizedUIOrgPATPolicyCapture(store, profile, source.Scope, source.Feature)
		population := "ui.org_pat_policy capture"
		if err != nil || outcome.Status != CollectionOK {
			return unavailableAll(population, outcome, err), []CollectorOutcome{outcome}
		}
		return map[string]MetricValue{
			"fine_grained_requires_approval": importedBoolMetric(observation.FineGrainedRequiresApproval, population, outcome.EvidenceRefs),
			"classic_restricted":             importedBoolMetric(observation.ClassicRestricted, population, outcome.EvidenceRefs),
			"max_lifetime_days":              importedNumberMetric(observation.MaxLifetimeDays, population, outcome.EvidenceRefs),
		}, []CollectorOutcome{outcome}
	}
	return nil, nil
}

// ApplyNormalizedImports merges zero or more previously-imported,
// already-validated collector captures into report.Metrics (under exactly
// the keys NormalizedImportMetricKeys documents) and report.Outcomes, so
// the SAME EvaluateReport/reportedMetricValue path every live-collected
// metric already goes through also observes these values -- this is never
// a separate, evaluator-bypassing output, and it never overwrites a metric
// key any live collector (or an earlier merge) already populated: every
// source's own keys are checked against report.Metrics BEFORE anything is
// loaded, and the whole call is rejected if any would collide.
//
// All sources are validated and loaded first; report is mutated only after
// every source has been confirmed structurally acceptable (a known
// collector, no conflicting duplicate, no metric-key collision) -- a
// rejected call (an unsupported collector, or a second, DIFFERENT source
// naming an already-merged collector ID) never leaves report partially
// mutated. An identical duplicate source (the exact same collector ID,
// scope and feature appearing more than once in sources) is treated as an
// idempotent no-op, not an error or a double-counted merge.
//
// This round supports exactly one source per collector ID: pooling
// multiple organizations' ui.org_pat_policy captures (for example) into one
// metric key is NOT yet implemented -- a disclosed scope boundary.
//
// A source whose import cannot be loaded, is incomplete, or no longer
// satisfies its contract still contributes an explicit MetricUnavailable
// for every one of its documented keys (see stageNormalizedImportSource),
// never a silently absent metric that could be mistaken for "never
// requested".
func ApplyNormalizedImports(report *VerticalSliceReport, store *EvidenceStore, profile *Profile, sources []ImportSource) error {
	if report.Metrics == nil {
		return fmt.Errorf("report does not have a metrics object to merge into")
	}
	type stagedEntry struct {
		key             string
		organizationKey string
		value           MetricValue
	}
	seenSources := map[string]ImportSource{}
	claimedKeys := map[string]bool{}
	var stagedEntries []stagedEntry
	var stagedOutcomes []CollectorOutcome

	for _, source := range sources {
		keys, known := normalizedImportMetricKeys[source.CollectorID]
		if !known {
			return fmt.Errorf("%q has no normalized-import merge support yet", source.CollectorID)
		}
		if existing, seen := seenSources[source.CollectorID]; seen {
			if existing == source {
				continue // an identical duplicate source is an idempotent no-op, not an error.
			}
			return fmt.Errorf("%q is already merged from a different source (%+v vs %+v) in this call; this round "+
				"supports only one source per collector (multi-organization pooling is not yet implemented)",
				source.CollectorID, existing, source)
		}
		seenSources[source.CollectorID] = source
		for _, key := range keys {
			if _, exists := report.Metrics[key]; exists {
				return fmt.Errorf("metric key %q is already populated; refusing to silently overwrite it with an imported value", key)
			}
			if claimedKeys[key] {
				return fmt.Errorf("metric key %q would be set by more than one source in this call", key)
			}
			claimedKeys[key] = true
		}
		organizationKey := source.Scope.Key()
		values, outcomes := stageNormalizedImportSource(store, profile, source)
		stagedOutcomes = append(stagedOutcomes, outcomes...)
		for _, key := range keys {
			stagedEntries = append(stagedEntries, stagedEntry{key: key, organizationKey: organizationKey, value: values[key]})
		}
	}

	// Every source has been validated, loaded and normalized without a
	// structural rejection: commit every staged entry together. Nothing
	// above this point touched report.Metrics/report.Outcomes.
	for _, entry := range stagedEntries {
		setMetric(report.Metrics, entry.key, entry.value)
		setMetricPerOrganization(report.Metrics, entry.key, entry.organizationKey, entry.value)
	}
	report.Outcomes = append(report.Outcomes, stagedOutcomes...)
	return nil
}

func importedBoolMetric(value *bool, population string, refs []string) MetricValue {
	if value == nil {
		result := unavailableObservation("field was not captured, or was not the documented boolean type", population)
		result.EvidenceRefs = append([]string{}, refs...)
		return result
	}
	return MetricValue{Status: MetricKnown, Boolean: value, Population: population, EvidenceRefs: append([]string{}, refs...)}
}

func importedStringMetric(value *string, population string, refs []string) MetricValue {
	if value == nil {
		result := unavailableObservation("field was not captured, or was not the documented string type/enum value", population)
		result.EvidenceRefs = append([]string{}, refs...)
		return result
	}
	return MetricValue{Status: MetricKnown, Text: value, Population: population, EvidenceRefs: append([]string{}, refs...)}
}

func importedNumberMetric(value *float64, population string, refs []string) MetricValue {
	if value == nil {
		result := unavailableObservation("field was not captured, or was not the documented numeric type", population)
		result.EvidenceRefs = append([]string{}, refs...)
		return result
	}
	return MetricValue{Status: MetricKnown, Number: value, Population: population, EvidenceRefs: append([]string{}, refs...)}
}

func importedIntMetric(value *int, population string, refs []string) MetricValue {
	if value == nil {
		result := unavailableObservation("field was not captured, or was not the documented integer type", population)
		result.EvidenceRefs = append([]string{}, refs...)
		return result
	}
	number := float64(*value)
	return MetricValue{Status: MetricKnown, Number: &number, Population: population, EvidenceRefs: append([]string{}, refs...)}
}
