// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package assessment

import (
	"testing"
	"time"
)

func TestInterviewAnswerNeverInventsConfirmationOrGitHubFacts(t *testing.T) {
	profile := fixtureProfileWithDefault(t)
	config := fixtureEvaluationConfig(t)
	results, err := EvaluateReport(profile, fixtureReport(), config)
	if err != nil {
		t.Fatal(err)
	}
	answer := InterviewAnswer{ControlID: "GOV-001", Answer: "Synthetic discussion: the fixture team owns the rules.",
		Respondent: "fixture-reviewer", AnsweredAt: time.Now().UTC().Add(-time.Hour), EvidenceRefs: []string{"interview:synthetic-1"}}
	updated, err := ApplyInterviewAnswers(profile, results, []InterviewAnswer{answer}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range updated {
		if result.ProposedState != results[index].ProposedState || result.Decision != nil {
			t.Fatal("answer presence invented a grade or assessor confirmation")
		}
		if result.ControlID == answer.ControlID && (result.Discussion == nil || !result.RequiresConfirmation) {
			t.Fatal("discussion evidence was not kept separately from mandatory confirmation")
		}
	}
	if _, err := ApplyInterviewAnswers(profile, results, []InterviewAnswer{answer, answer}, time.Now().UTC()); err == nil {
		t.Fatal("duplicate discussion answer was accepted")
	}
	for _, mutate := range []func(*InterviewAnswer){
		func(a *InterviewAnswer) { a.ControlID = "unknown" },
		func(a *InterviewAnswer) { a.Answer = "" },
		func(a *InterviewAnswer) { a.AnsweredAt = time.Now().Add(time.Hour) },
		func(a *InterviewAnswer) { a.EvidenceRefs = nil },
	} {
		invalid := answer
		mutate(&invalid)
		if _, err := ApplyInterviewAnswers(profile, results, []InterviewAnswer{invalid}, time.Now().UTC()); err == nil {
			t.Fatal("incomplete/invalid discussion evidence was accepted")
		}
	}
}
