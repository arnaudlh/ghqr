// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

const (
	portableFileLimit  = 32 * 1024 * 1024
	portableTotalLimit = 512 * 1024 * 1024
	portableEntryLimit = 20000
)

// PortableMember fingerprints an exact relative file, not a claim of trusted provenance.
type PortableMember struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// PortableManifest identifies the captured data and the selected analysis definitions.
type PortableManifest struct {
	SchemaVersion string           `json:"schema_version"`
	EngineVersion string           `json:"engine_version"`
	Profile       ProfileSummary   `json:"profile"`
	Scopes        []Scope          `json:"scopes"`
	ChecksSHA256  string           `json:"checks_sha256"`
	Evaluators    []string         `json:"evaluators"`
	Analysis      string           `json:"analysis"`
	Files         []PortableMember `json:"files"`
}

// PortableAnalysisOptions requires explicit scope authority and separates discussion inputs.
type PortableAnalysisOptions struct {
	OutputDirectory   string
	Config            *CustomerConfig
	AcceptBundleScope bool
	ChecksPath        string
	AnswersPath       string
}

func readBoundedFile(name string, limit int64) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds its supported size limit")
	}
	return data, nil
}

func decodePortableJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON document")
	}
	return nil
}

func portablePath(name string) bool {
	return name != "" && path.Clean(name) == name && filepath.IsLocal(name) &&
		!strings.ContainsAny(name, "\\:\x00") && !strings.HasSuffix(name, "/")
}

func portableSafeJSON(data []byte) error {
	if !json.Valid(data) || tokenPattern.Match(data) || emailPattern.Match(data) || privateMaterialPattern.Match(data) {
		return fmt.Errorf("portable files must be valid sanitized JSON without credentials or personal email")
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var inspect func(any, int) error
	inspect = func(value any, depth int) error {
		if depth > 64 {
			return fmt.Errorf("portable JSON nesting exceeds the supported limit")
		}
		switch item := value.(type) {
		case map[string]any:
			for key, child := range item {
				if text, ok := child.(string); ok && sensitiveKey(key) && text != "" &&
					text != "[REDACTED]" && text != "[REDACTED_EMAIL]" && text != "[REDACTED_TOKEN]" {
					return fmt.Errorf("portable JSON contains an unredacted sensitive field")
				}
				if err := inspect(child, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range item {
				if err := inspect(child, depth+1); err != nil {
					return err
				}
			}
		case string:
			if tokenPattern.MatchString(item) || emailPattern.MatchString(item) || privateMaterialPattern.MatchString(item) {
				return fmt.Errorf("portable JSON contains escaped sensitive material")
			}
		}
		return nil
	}
	return inspect(value, 0)
}

func capturedChecks(profile *Profile, report *VerticalSliceReport, directory string) (*SimpleChecks, error) {
	if report.ContextRef == "" {
		return nil, fmt.Errorf("portable data requires an explicit bound collection context")
	}
	store, err := OpenEvidenceStore(directory, NewRedactor())
	if err != nil {
		return nil, err
	}
	context, loadErr := LoadRunCollectionContextByRef(store, report.ContextRef)
	closeErr := store.Close()
	if loadErr != nil {
		return nil, loadErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if context.ProfileSHA256 != profile.SHA256 {
		return nil, fmt.Errorf("captured profile digest differs from the portable profile")
	}
	if len(context.CheckDefinitions) > 0 {
		return ParseSimpleChecks(profile, context.CheckDefinitions)
	}
	return LoadSimpleChecks(profile, "")
}

func validateExtractionContract(profile *Profile, report *VerticalSliceReport, directory string, selected *SimpleChecks) error {
	original, err := capturedChecks(profile, report, directory)
	if err != nil {
		return fmt.Errorf("load captured extraction contract: %w", err)
	}
	if !reflect.DeepEqual(original.Extractions, selected.Extractions) {
		return fmt.Errorf("analysis cannot change captured configuration extraction; recollect with the explicit new policy")
	}
	return selected.Validate(profile)
}

func portableScopes(targets []Target) []Scope {
	var scopes []Scope
	for _, target := range targets {
		if target.Enterprise != "" {
			scopes = append(scopes, Scope{target.Host, EnterpriseScope, target.Enterprise})
		}
		for _, organization := range target.Organizations {
			scopes = append(scopes, Scope{target.Host, OrganizationScope, organization})
		}
	}
	return scopes
}

func portableBudget(memberSize, expandedTotal int64) error {
	if memberSize < 0 || memberSize > portableFileLimit || expandedTotal < 0 || expandedTotal > portableTotalLimit {
		return fmt.Errorf("portable data exceeds the expanded member or total size limit")
	}
	return nil
}

// ExportPortableBundle packages exact saved bytes without analysis, credential resolution or network access.
func ExportPortableBundle(profile *Profile, config *CustomerConfig, runData []byte, evidenceDirectory, outputPath string, explicitProfile ...[]byte) (*PortableManifest, error) {
	if outputPath == "" {
		return nil, fmt.Errorf("portable export requires an explicit output file")
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	profileData := defaultProfileData
	if len(explicitProfile) > 1 {
		return nil, fmt.Errorf("portable export accepts exactly one explicit profile source")
	}
	if len(explicitProfile) == 1 {
		profileData = explicitProfile[0]
	}
	if len(profileData) == 0 || digestBytes(profileData) != profile.SHA256 {
		return nil, fmt.Errorf("portable export requires the exact loaded profile bytes")
	}
	var report VerticalSliceReport
	if err := decodePortableJSON(runData, &report); err != nil {
		return nil, fmt.Errorf("decode portable run: %w", err)
	}
	if report.Profile.SHA256 != profile.SHA256 {
		return nil, fmt.Errorf("run and portable profile digests differ")
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return nil, err
	}
	if err := targetsAuthorizeScope(targets, deriveClaimedScope(&report)); err != nil {
		return nil, fmt.Errorf("portable export scope: %w", err)
	}
	evidenceRoot, err := os.OpenRoot(evidenceDirectory)
	if err != nil {
		return nil, fmt.Errorf("open existing portable evidence: %w", err)
	}
	defer func() { _ = evidenceRoot.Close() }()
	checks := config.CheckDefinitions
	if checks == nil {
		checks, err = capturedChecks(profile, &report, evidenceDirectory)
		if err != nil {
			return nil, err
		}
	}
	if err := validateExtractionContract(profile, &report, evidenceDirectory, checks); err != nil {
		return nil, err
	}
	portableConfig := *config
	portableConfig.EvidenceDir = "./evidence"
	configData, err := json.Marshal(portableConfig)
	if err != nil {
		return nil, fmt.Errorf("encode portable configuration: %w", err)
	}
	dataFiles := map[string][]byte{
		"run.json": runData, "profile.json": profileData,
		"config.json": configData, "checks.json": checks.sourceJSON,
	}
	selectedNames := map[string]bool{runCollectionContextObjectPath(report.ContextRef): true}
	sourceStore, err := OpenEvidenceStore(evidenceDirectory, NewRedactor())
	if err != nil {
		return nil, err
	}
	selectionErr := func() error {
		for _, outcome := range report.Outcomes {
			if len(outcome.EvidenceRefs) != outcome.Pages*2 {
				return fmt.Errorf("portable export requires exact immutable references for every recorded page")
			}
			if _, failures := verifyOutcomeEvidenceRefs(sourceStore, profile, outcome); len(failures) > 0 {
				return fmt.Errorf("portable export cannot include unbound or wrong-scope source pages: %s", failures[0])
			}
			for _, name := range outcome.EvidenceRefs {
				selectedNames[name] = true
			}
		}
		return nil
	}()
	closeErr := sourceStore.Close()
	if selectionErr != nil {
		return nil, selectionErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	evidenceNames := sortedExportKeys(selectedNames)
	if len(evidenceNames)+len(dataFiles)+1 > portableEntryLimit {
		return nil, fmt.Errorf("portable evidence exceeds the member limit")
	}
	for _, name := range evidenceNames {
		info, err := evidenceRoot.Lstat(name)
		if err != nil {
			return nil, fmt.Errorf("inspect selected portable evidence: %w", err)
		}
		if !info.Mode().IsRegular() || !portablePath(name) || !strings.HasSuffix(name, ".json") || info.Size() > portableFileLimit {
			return nil, fmt.Errorf("selected portable evidence must be bounded regular JSON, not links or unsafe paths")
		}
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return nil, fmt.Errorf("create portable output parent: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(outputPath), ".ghqr-bundle-*.tmp")
	if err != nil {
		return nil, err
	}
	defer func() { _ = temporary.Close(); _ = os.Remove(temporary.Name()) }()
	writer := zip.NewWriter(temporary)
	manifest := &PortableManifest{SchemaVersion: "1", EngineVersion: collectionEngineVersion, Profile: profile.Summary(),
		ChecksSHA256: checks.SHA256, Evaluators: ImplementedEvaluatorIDs(), Analysis: "not performed by export"}
	manifest.Scopes = portableScopes(targets)
	var total int64
	writeMember := func(name string, data []byte) error {
		total += int64(len(data))
		if err := portableBudget(int64(len(data)), total); err != nil {
			return err
		}
		if err := portableSafeJSON(data); err != nil {
			return fmt.Errorf("validate portable member %s: %w", name, err)
		}
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0o600)
		member, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := member.Write(data); err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, PortableMember{name, int64(len(data)), digestBytes(data)})
		return nil
	}
	for _, name := range sortedExportKeys(dataFiles) {
		if err := writeMember(name, dataFiles[name]); err != nil {
			return nil, err
		}
	}
	sort.Strings(evidenceNames)
	for _, name := range evidenceNames {
		file, err := evidenceRoot.Open(name)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, portableFileLimit+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err := writeMember("evidence/"+name, data); err != nil {
			return nil, err
		}
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if err := portableBudget(int64(len(manifestData)), total+int64(len(manifestData))); err != nil {
		return nil, fmt.Errorf("include portable manifest in archive budget: %w", err)
	}
	member, err := writer.Create("manifest.json")
	if err != nil {
		return nil, err
	}
	if _, err := member.Write(manifestData); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(temporary.Name(), outputPath); err != nil {
		return nil, fmt.Errorf("publish private portable file without overwriting existing data: %w", err)
	}
	return manifest, nil
}

func unpackPortableBundle(bundlePath string, directory string) (*PortableManifest, error) {
	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("open portable file: %w", err)
	}
	defer func() { _ = reader.Close() }()
	if len(reader.File) > portableEntryLimit {
		return nil, fmt.Errorf("portable file exceeds the member limit")
	}
	files := map[string]*zip.File{}
	folded := map[string]bool{}
	var total uint64
	for _, file := range reader.File {
		total += file.UncompressedSize64
		key := strings.ToLower(file.Name)
		if !portablePath(file.Name) || !file.Mode().IsRegular() || folded[key] ||
			file.UncompressedSize64 > portableFileLimit || total > portableTotalLimit {
			return nil, fmt.Errorf("portable file contains unsafe, duplicate, linked or oversized members")
		}
		folded[key] = true
		files[file.Name] = file
	}
	readMember := func(file *zip.File) ([]byte, error) {
		if file == nil {
			return nil, fmt.Errorf("portable file is missing a required member")
		}
		member, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = member.Close() }()
		data, err := io.ReadAll(io.LimitReader(member, portableFileLimit+1))
		if err != nil || uint64(len(data)) != file.UncompressedSize64 || len(data) > portableFileLimit {
			return nil, fmt.Errorf("portable member data length or checksum is invalid")
		}
		return data, nil
	}
	manifestData, err := readMember(files["manifest.json"])
	if err != nil {
		return nil, err
	}
	var manifest PortableManifest
	if err := decodePortableJSON(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode portable manifest: %w", err)
	}
	if manifest.SchemaVersion != "1" || manifest.EngineVersion != collectionEngineVersion ||
		len(manifest.Files)+1 != len(files) || !reflect.DeepEqual(manifest.Evaluators, ImplementedEvaluatorIDs()) {
		return nil, fmt.Errorf("portable manifest version, engine, rules or member inventory is incompatible")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	listed := map[string]bool{}
	for _, entry := range manifest.Files {
		if !portablePath(entry.Path) || entry.Path == "manifest.json" || listed[entry.Path] ||
			(entry.Path != "run.json" && entry.Path != "profile.json" && entry.Path != "config.json" &&
				entry.Path != "checks.json" && !strings.HasPrefix(entry.Path, "evidence/")) {
			return nil, fmt.Errorf("portable manifest contains duplicate or unexpected paths")
		}
		listed[entry.Path] = true
		data, err := readMember(files[entry.Path])
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != entry.Size || digestBytes(data) != entry.SHA256 {
			return nil, fmt.Errorf("portable member %s failed its manifest digest", entry.Path)
		}
		if err := portableSafeJSON(data); err != nil {
			return nil, err
		}
		if err := root.MkdirAll(path.Dir(entry.Path), 0o700); err != nil {
			return nil, err
		}
		if err := root.WriteFile(entry.Path, data, 0o600); err != nil {
			return nil, err
		}
	}
	for _, name := range []string{"run.json", "profile.json", "config.json", "checks.json"} {
		if !listed[name] {
			return nil, fmt.Errorf("portable manifest is missing %s", name)
		}
	}
	return &manifest, nil
}

// AnalysePortableBundle verifies and replays saved data offline before scoring it.
func AnalysePortableBundle(bundlePath string, options PortableAnalysisOptions) (*EvaluationOutputSummary, error) {
	if options.OutputDirectory == "" || (options.Config == nil && !options.AcceptBundleScope) {
		return nil, fmt.Errorf("portable analysis requires --out and explicit --config or --accept-bundle-scope consent")
	}
	directory, err := os.MkdirTemp("", "ghqr-portable-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(directory) }()
	manifest, err := unpackPortableBundle(bundlePath, directory)
	if err != nil {
		return nil, err
	}
	profile, err := LoadProfile(filepath.Join(directory, "profile.json"))
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(profile.Summary(), manifest.Profile) {
		return nil, fmt.Errorf("portable profile digest does not match the manifest")
	}
	config, err := LoadConfig(filepath.Join(directory, "config.json"))
	if err != nil {
		return nil, err
	}
	bundleTargets, err := config.ResolvedTargets()
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(portableScopes(bundleTargets), manifest.Scopes) {
		return nil, fmt.Errorf("portable scope differs from its recorded configuration")
	}
	if options.Config != nil {
		config = options.Config
		currentTargets, err := config.ResolvedTargets()
		if err != nil {
			return nil, err
		}
		if err := targetsAuthorizeScope(currentTargets, bundleTargets); err != nil {
			return nil, fmt.Errorf("portable file exceeds the current configured scope: %w", err)
		}
	}
	var report VerticalSliceReport
	data, err := readBoundedFile(filepath.Join(directory, "run.json"), portableFileLimit)
	if err != nil {
		return nil, err
	}
	if err := decodePortableJSON(data, &report); err != nil {
		return nil, err
	}
	checks, err := LoadSimpleChecks(profile, filepath.Join(directory, "checks.json"))
	if err != nil {
		return nil, err
	}
	if checks.SHA256 != manifest.ChecksSHA256 || report.Profile.SHA256 != profile.SHA256 {
		return nil, fmt.Errorf("portable definition/run digests do not match their manifest")
	}
	if options.ChecksPath != "" {
		checks, err = LoadSimpleChecks(profile, options.ChecksPath)
		if err != nil {
			return nil, err
		}
	}
	evidenceDirectory := filepath.Join(directory, "evidence")
	if err := validateExtractionContract(profile, &report, evidenceDirectory, checks); err != nil {
		return nil, err
	}
	configCopy := *config
	configCopy.CheckDefinitions = checks
	configCopy.InterviewAnswers, err = ReadInterviewAnswers(options.AnswersPath)
	if err != nil {
		return nil, err
	}
	return RunVerifiedOfflineEvaluation(profile, &report, &configCopy, options.OutputDirectory, evidenceDirectory)
}
