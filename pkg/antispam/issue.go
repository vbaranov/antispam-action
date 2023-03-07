package antispam

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-github/v50/github"
)

func (a *Antispam) ProcessIssue(payload []byte) error {
	var event github.IssuesEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	if event.GetAction() == "closed" || event.GetIssue().GetState() == "closed" {
		return nil
	}

	var detections []Detection
	detections = append(detections, checkText(event.GetIssue().GetTitle())...)
	detections = append(detections, checkText(event.GetIssue().GetBody())...)

	if len(strings.Split(event.GetIssue().GetTitle(), " ")) <= 1 {
		detections = append(detections, Detection{
			Location:       "issue title",
			DebugInfo:      "Title is too short",
			AuthorFeedback: "Please provide a longer title and reopen the issue.",
		})
	}

	if len(event.GetIssue().GetBody()) <= 32 || len(strings.Split(event.GetIssue().GetBody(), " ")) <= 5 {
		detections = append(detections, Detection{
			Location:       "issue body",
			DebugInfo:      "Body is too short or lacks detail",
			AuthorFeedback: "Please provide a longer description and reopen the issue.",
		})
	}

	if len(detections) == 0 {
		return nil
	}

	body := "This issue has been automatically marked as spam and has been closed.\n"

	for _, detection := range detections {
		fmt.Printf("Detected spam in %s: %s\n", detection.Location, detection.DebugInfo)
		if detection.AuthorFeedback != "" {
			body += "\n- " + detection.AuthorFeedback
		}
	}

	labels := []string{"spam"}
	if _, _, err := a.client.Issues.Edit(a.ctx, event.GetRepo().GetOwner().GetLogin(), event.GetRepo().GetName(), event.GetIssue().GetNumber(), &github.IssueRequest{
		State:  github.String("closed"),
		Labels: &labels,
	}); err != nil {
		return err
	}

	if _, _, err := a.client.Issues.CreateComment(
		a.ctx,
		event.GetRepo().GetOwner().GetLogin(),
		event.GetRepo().GetName(),
		event.GetIssue().GetNumber(),
		&github.IssueComment{
			Body: &body,
		},
	); err != nil {
		return err
	}

	return nil
}
