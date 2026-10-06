// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestPortableExplicitProfileKeepsExactWhitespaceAndDigest(t *testing.T) {
	directory := t.TempDir()
	_, config, runData := syntheticPortableSource(t, filepath.Join(directory, "source"))
	profileData := append(bytes.Clone(defaultProfileData), '\n', '\n')
	profile, err := ParseProfile(profileData)
	if err != nil {
		t.Fatal(err)
	}
	var report VerticalSliceReport
	if err := json.Unmarshal(runData, &report); err != nil {
		t.Fatal(err)
	}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		t.Fatal(err)
	}
	report.ContextRef, err = WriteRunCollectionContextWithOutcomes(store, profile, config, []Target{}, report.CollectedAt, report.Outcomes)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	report.Profile = profile.Summary()
	runData, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(directory, "custom-profile.zip")
	if _, err := ExportPortableBundle(profile, config, runData, config.EvidenceDir, bundle, profileData); err != nil {
		t.Fatal(err)
	}
	members := portableTestMembers(t, bundle)
	if !bytes.Equal(members["profile.json"], profileData) || digestBytes(members["profile.json"]) != profile.SHA256 {
		t.Fatal("explicit profile was re-encoded or lost its exact source digest")
	}
	if _, err := ExportPortableBundle(profile, config, runData, config.EvidenceDir, filepath.Join(directory, "wrong.zip")); err == nil {
		t.Fatal("different explicit profile silently fell back to embedded bytes")
	}
}
