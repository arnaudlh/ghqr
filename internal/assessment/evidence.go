// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

var evidenceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// EvidenceRef identifies a sanitized raw object and its matching provenance sidecar.
type EvidenceRef struct {
	DataPath     string `json:"data_path"`
	MetadataPath string `json:"metadata_path"`
	SHA256       string `json:"sha256"`
}

// EvidenceStore uses immutable object pairs and an atomic latest-reference manifest.
// A partial write cannot replace the previous complete evidence pair.
type EvidenceStore struct {
	root     *os.Root
	redactor *Redactor
}

// OpenEvidenceStore confines all reads and writes to the customer-selected evidence root.
func OpenEvidenceStore(directory string, redactor *Redactor) (*EvidenceStore, error) {
	if directory == "" {
		return nil, fmt.Errorf("evidence directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open evidence root: %w", err)
	}
	if redactor == nil {
		redactor = NewRedactor()
	}
	return &EvidenceStore{root: root, redactor: redactor}, nil
}

// Close releases the evidence root descriptor.
func (s *EvidenceStore) Close() error {
	if err := s.root.Close(); err != nil {
		return fmt.Errorf("close evidence root: %w", err)
	}
	return nil
}

// SaveJSON sanitizes raw and metadata before writing either, including imported payloads.
func (s *EvidenceStore) SaveJSON(raw []byte, metadata EvidenceMetadata) (EvidenceRef, error) {
	if err := validateEvidenceMetadata(metadata); err != nil {
		return EvidenceRef{}, err
	}
	clean, redactions, err := s.redactor.JSON(raw)
	if err != nil {
		return EvidenceRef{}, fmt.Errorf("sanitize raw evidence: %w", err)
	}
	metadata.ContentSHA256 = digestBytes(clean)
	if !redactionsAlreadyRecorded(metadata.Redactions, redactions) {
		metadata.Redactions = append(metadata.Redactions, redactions...)
	}
	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return EvidenceRef{}, fmt.Errorf("encode evidence metadata: %w", err)
	}
	metaBytes, _, err = s.redactor.JSON(metaBytes)
	if err != nil {
		return EvidenceRef{}, fmt.Errorf("sanitize evidence metadata: %w", err)
	}
	var safeMetadata EvidenceMetadata
	if err := json.Unmarshal(metaBytes, &safeMetadata); err != nil {
		return EvidenceRef{}, fmt.Errorf("decode sanitized evidence metadata: %w", err)
	}
	if err := validateEvidenceMetadata(safeMetadata); err != nil {
		return EvidenceRef{}, fmt.Errorf("validate sanitized evidence metadata: %w", err)
	}
	if safeMetadata.Scope != metadata.Scope || safeMetadata.ContentSHA256 != digestBytes(clean) {
		return EvidenceRef{}, fmt.Errorf("redaction invalidated evidence identity")
	}
	objectID := digestBytes(append(append([]byte{}, clean...), metaBytes...))
	ref := EvidenceRef{
		DataPath:     filepath.ToSlash(filepath.Join("objects", objectID+".json")),
		MetadataPath: filepath.ToSlash(filepath.Join("objects", objectID+".meta.json")),
		SHA256:       safeMetadata.ContentSHA256,
	}
	if err := s.writeObject(ref.DataPath, clean); err != nil {
		return EvidenceRef{}, err
	}
	if err := s.writeObject(ref.MetadataPath, metaBytes); err != nil {
		return EvidenceRef{}, err
	}
	manifest, err := json.Marshal(ref)
	if err != nil {
		return EvidenceRef{}, fmt.Errorf("encode evidence reference: %w", err)
	}
	if err := s.atomicWrite(evidenceManifest(metadata.Scope, metadata.CollectorID, metadata.Feature), manifest); err != nil {
		return EvidenceRef{}, err
	}
	return ref, nil
}

// LoadJSON verifies the complete pair and sanitizes replay input again before returning it.
func (s *EvidenceStore) LoadJSON(scope Scope, collectorID, feature string) ([]byte, EvidenceMetadata, EvidenceRef, error) {
	if err := validateEvidenceIdentity(scope, collectorID, feature); err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, err
	}
	manifest, err := s.root.ReadFile(evidenceManifest(scope, collectorID, feature))
	if err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("read evidence reference: %w", err)
	}
	var ref EvidenceRef
	if err := json.Unmarshal(manifest, &ref); err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("decode evidence reference: %w", err)
	}
	if !filepath.IsLocal(ref.DataPath) || !filepath.IsLocal(ref.MetadataPath) {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("evidence reference escapes its root")
	}
	raw, err := s.root.ReadFile(ref.DataPath)
	if err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("read raw evidence: %w", err)
	}
	metaBytes, err := s.root.ReadFile(ref.MetadataPath)
	if err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("read evidence sidecar: %w", err)
	}
	var metadata EvidenceMetadata
	if err := json.Unmarshal(metaBytes, &metadata); err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("decode evidence sidecar: %w", err)
	}
	if err := validateEvidenceMetadata(metadata); err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, err
	}
	if metadata.Scope != scope || metadata.CollectorID != collectorID || metadata.Feature != feature ||
		digestBytes(raw) != metadata.ContentSHA256 || ref.SHA256 != metadata.ContentSHA256 {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("evidence identity or digest mismatch")
	}
	objectID := digestBytes(append(append([]byte{}, raw...), metaBytes...))
	if ref.DataPath != "objects/"+objectID+".json" || ref.MetadataPath != "objects/"+objectID+".meta.json" {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("evidence pair reference does not match its contents")
	}
	// Do not trust an imported or edited bundle to have been redacted already.
	clean, _, err := s.redactor.JSON(raw)
	if err != nil {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("sanitize replayed evidence: %w", err)
	}
	if !bytes.Equal(clean, raw) {
		return nil, EvidenceMetadata{}, EvidenceRef{}, fmt.Errorf("replay bundle needs sanitized re-import before use")
	}
	return clean, metadata, ref, nil
}

// redactionsAlreadyRecorded reports whether fresh (already sorted,
// deterministic for identical raw bytes) redaction paths are already the
// trailing entries of metadata's existing Redactions history, so SaveJSON
// can skip re-appending them. Redactor.JSON always recomputes the complete
// redaction-path set for its input from scratch and sorts it, so saving the
// exact same raw content twice (for example a genuine re-collection whose
// metadata round-tripped forward a prior save's own Redactions) yields the
// identical fresh slice both times; without this check, each such resave
// would append a duplicate copy, growing Redactions (and with it the
// content-addressed object identity) forever even though nothing new was
// ever actually redacted. This only ever recognizes an EXACT, in-order
// repeat of the full fresh slice as the array's own tail -- it never
// dedupes, reorders, or otherwise rewrites any entry already present
// earlier in Redactions, so legacy history containing its own genuine
// pre-existing duplicate entries (from before this safeguard existed) is
// preserved byte-for-byte on every future save.
func redactionsAlreadyRecorded(existing, fresh []string) bool {
	if len(fresh) == 0 {
		return true
	}
	if len(existing) < len(fresh) {
		return false
	}
	tail := existing[len(existing)-len(fresh):]
	for index, path := range fresh {
		if tail[index] != path {
			return false
		}
	}
	return true
}

func validateEvidenceIdentity(scope Scope, collectorID, feature string) error {
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("invalid evidence scope: %w", err)
	}
	known := false
	for _, id := range collectorIDs {
		if id == collectorID {
			known = true
		}
	}
	if !known || !evidenceNamePattern.MatchString(feature) || feature == "." || feature == ".." {
		return fmt.Errorf("evidence requires a known collector and a safe feature name")
	}
	return nil
}

func validateEvidenceMetadata(metadata EvidenceMetadata) error {
	if err := validateEvidenceIdentity(metadata.Scope, metadata.CollectorID, metadata.Feature); err != nil {
		return err
	}
	if metadata.SchemaVersion != "1" || metadata.ProfileVersion != ProfileVersion ||
		len(metadata.ProfileSHA256) != 64 || metadata.CollectedAt.IsZero() || metadata.Endpoint == "" ||
		metadata.Pages < 1 || (metadata.RecordCount != nil && *metadata.RecordCount < 0) {
		return fmt.Errorf("evidence metadata requires schema/profile identity, time, endpoint and valid page/count provenance")
	}
	if _, err := hex.DecodeString(metadata.ProfileSHA256); err != nil {
		return fmt.Errorf("evidence profile digest is invalid")
	}
	endpoint, err := url.Parse(metadata.Endpoint)
	if err != nil || endpoint.User != nil || endpoint.Scheme == "" {
		return fmt.Errorf("evidence endpoint must have a scheme and no embedded credentials")
	}
	switch metadata.SourceKind {
	case RESTEvidence, GraphQLEvidence, ManagementEvidence:
		if metadata.APIVersion == "" || metadata.HTTPStatus == nil || *metadata.HTTPStatus < 100 || *metadata.HTTPStatus > 599 {
			return fmt.Errorf("API evidence requires version and observed HTTP status")
		}
	case ImportedEvidence:
	default:
		return fmt.Errorf("evidence source provenance is required")
	}
	switch metadata.CredentialKind {
	case NoCredential, ClassicPAT, FineGrainedPAT, AppInstallation, OAuthUser, ManagementConsole:
	default:
		return fmt.Errorf("unknown evidence credential kind")
	}
	return nil
}

func evidenceManifest(scope Scope, collectorID, feature string) string {
	return filepath.Join("scopes", filepath.FromSlash(scope.Key()), collectorID, feature+".ref.json")
}

func digestBytes(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func (s *EvidenceStore) writeObject(path string, data []byte) error {
	existing, err := s.root.ReadFile(path)
	if err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("immutable evidence object collision")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect evidence object: %w", err)
	}
	return s.atomicWrite(path, data)
}

func (s *EvidenceStore) atomicWrite(path string, data []byte) (err error) {
	if !filepath.IsLocal(path) {
		return fmt.Errorf("evidence path escapes its root")
	}
	directory := filepath.Dir(path)
	if err := s.root.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create evidence object directory: %w", err)
	}
	temporary := filepath.Join(directory, ".tmp-"+rand.Text())
	file, err := s.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary evidence file: %w", err)
	}
	closed, renamed := false, false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
		if !renamed {
			err = errors.Join(err, s.root.Remove(temporary))
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write evidence file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync evidence file: %w", err)
	}
	if err := file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close evidence file: %w", err)
	}
	closed = true
	if err := s.root.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish evidence file: %w", err)
	}
	renamed = true
	return nil
}
