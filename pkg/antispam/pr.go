package antispam

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/go-github/v50/github"
)

func (a *Antispam) ProcessPullRequest(payload []byte) error {
	var event github.PullRequestEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return err
	}

	if event.GetAction() == "closed" || event.GetPullRequest().GetState() == "closed" {
		return nil
	}

	var detections []Detection
	detections = append(detections, checkText(event.GetPullRequest().GetTitle())...)
	detections = append(detections, checkText(event.GetPullRequest().GetBody())...)

	if len(strings.Split(event.GetPullRequest().GetTitle(), " ")) <= 1 {
		detections = append(detections, Detection{
			Location:       "pr title",
			DebugInfo:      "Title is too short",
			AuthorFeedback: "Please provide a longer title and reopen the pull request.",
		})
	}

	if len(detections) == 0 {
		return nil
	}

	body := "This pull request has been automatically marked as spam and has been closed.\n"

	for _, detection := range detections {
		fmt.Printf("Detected spam in %s: %s\n", detection.Location, detection.DebugInfo)
		if detection.AuthorFeedback != "" {
			body += "\n- " + detection.AuthorFeedback
		}
	}

	if _, _, err := a.client.Issues.CreateComment(
		a.ctx,
		event.GetRepo().GetOwner().GetLogin(),
		event.GetRepo().GetName(),
		event.GetPullRequest().GetNumber(),
		&github.IssueComment{
			Body: &body,
		},
	); err != nil {
		return err
	}

	if _, _, err := a.client.PullRequests.Edit(a.ctx, event.GetRepo().GetOwner().GetLogin(), event.GetRepo().GetName(), event.GetPullRequest().GetNumber(), &github.PullRequest{
		State: github.String("closed"),
	}); err != nil {
		return err
	}

	return nil
}
