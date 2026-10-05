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
