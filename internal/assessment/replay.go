// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ReplayedEvidence returns sanitized raw data and original provenance without network access.
type ReplayedEvidence struct {
	Raw       json.RawMessage  `json:"raw"`
	Metadata  EvidenceMetadata `json:"metadata"`
	Reference EvidenceRef      `json:"reference"`
}

// ReplayEvidence verifies scoped content and profile identity instead of trusting imported flags.
func ReplayEvidence(profile *Profile, config *CustomerConfig, scope Scope, collectorID, feature string) (*ReplayedEvidence, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := authorizeEvidenceScope(config, scope); err != nil {
		return nil, err
	}
	store, err := OpenEvidenceStore(config.EvidenceDir, NewRedactor())
	if err != nil {
		return nil, err
	}
	raw, metadata, ref, loadErr := store.LoadJSON(scope, collectorID, feature)
	closeErr := store.Close()
	if loadErr != nil {
		return nil, loadErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if metadata.ProfileVersion != profile.Version || metadata.ProfileSHA256 != profile.SHA256 {
		return nil, fmt.Errorf("replay profile identity does not match the selected profile")
	}
	return &ReplayedEvidence{Raw: raw, Metadata: metadata, Reference: ref}, nil
}

func authorizeEvidenceScope(config *CustomerConfig, scope Scope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	targets, err := config.ResolvedTargets()
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target.Host != strings.ToLower(scope.Host) {
			continue
		}
		switch scope.Kind {
		case EnterpriseScope:
			if target.Enterprise != "" && strings.EqualFold(target.Enterprise, scope.Name) {
				return nil
			}
		case OrganizationScope, RepositoryScope:
			organization := strings.Split(scope.Name, "/")[0]
			for _, name := range target.Organizations {
				if strings.EqualFold(name, organization) {
					return nil
				}
			}
		case InstanceScope:
			if target.Deployment == Server && strings.EqualFold(scope.Name, target.Host) {
				return nil
			}
		}
	}
	return fmt.Errorf("evidence scope is not explicitly authorized by customer configuration")
}
