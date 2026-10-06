// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"fmt"
	"strings"
	"time"
)

// InterviewAnswer is discussion evidence, not an automatic score or assessor decision.
type InterviewAnswer struct {
	ControlID    string    `json:"control_id"`
	Answer       string    `json:"answer"`
	Respondent   string    `json:"respondent"`
	AnsweredAt   time.Time `json:"answered_at"`
	EvidenceRefs []string  `json:"evidence_refs"`
}

// ReadInterviewAnswers reads a separate strict JSON answer file without contacting GitHub.
func ReadInterviewAnswers(path string) ([]InterviewAnswer, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readBoundedFile(path, 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("read interview answers: %w", err)
	}
	var answers []InterviewAnswer
	if err := decodePortableJSON(data, &answers); err != nil {
		return nil, fmt.Errorf("decode interview answers: %w", err)
	}
	return answers, nil
}

// ApplyInterviewAnswers keeps discussion evidence separate from unchanged GitHub proposals.
func ApplyInterviewAnswers(profile *Profile, results []ControlResult, answers []InterviewAnswer, now time.Time) ([]ControlResult, error) {
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	if len(results) != len(profile.Controls) {
		return nil, fmt.Errorf("interview answers require the complete canonical result inventory")
	}
	controls := map[string]Control{}
	for _, control := range profile.Controls {
		controls[control.ID] = control
	}
	seen := map[string]bool{}
	for _, answer := range answers {
		control, exists := controls[answer.ControlID]
		if !exists || control.InterviewQuestion == nil || seen[answer.ControlID] {
			return nil, fmt.Errorf("interview answers require unique known control IDs with profile questions")
		}
		seen[answer.ControlID] = true
		if strings.TrimSpace(answer.Answer) == "" || len(answer.Answer) > 8192 ||
			strings.TrimSpace(answer.Respondent) == "" || len(answer.Respondent) > 256 ||
			answer.AnsweredAt.IsZero() || answer.AnsweredAt.After(now) || len(answer.EvidenceRefs) == 0 {
			return nil, fmt.Errorf("interview answer %s requires bounded text, respondent, a genuine date and evidence", answer.ControlID)
		}
		for _, ref := range answer.EvidenceRefs {
			if strings.TrimSpace(ref) == "" || len(ref) > 1024 {
				return nil, fmt.Errorf("interview answer %s has an empty or oversized evidence reference", answer.ControlID)
			}
		}
	}
	updated := append([]ControlResult(nil), results...)
	for index := range updated {
		for _, answer := range answers {
			if updated[index].ControlID == answer.ControlID {
				copyAnswer := answer
				copyAnswer.EvidenceRefs = append([]string(nil), answer.EvidenceRefs...)
				updated[index].Discussion = &copyAnswer
			}
		}
	}
	return updated, nil
}
