// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	_ "embed"
	"fmt"
)

//go:embed profile/automation-spec.v2.json
var defaultProfileData []byte

// LoadDefaultProfile validates a fresh copy of the exact profile bundled in the binary.
func LoadDefaultProfile() (*Profile, error) {
	profile, err := ParseProfile(defaultProfileData)
	if err != nil {
		return nil, fmt.Errorf("load bundled assessment profile: %w", err)
	}
	return profile, nil
}
