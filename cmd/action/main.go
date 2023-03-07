package main

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-github/v50/github"
	"github.com/liamg/antispam-action/pkg/antispam"
)

func main() {
	eventType := os.Getenv("GITHUB_EVENT_NAME")
	var eventData []byte
	if path := os.Getenv("GITHUB_EVENT_PATH"); path != "" {
		var err error
		eventData, err = os.ReadFile(path)
		if err != nil {
			fail(fmt.Errorf("failed to read event data: %w", err))
		}
	} else {
		fail(fmt.Errorf("event data is required"))
	}

	ctx := context.Background()
	client := github.NewTokenClient(ctx, os.Getenv("ACTIONS_RUNTIME_TOKEN"))
	a := antispam.New(ctx, client)

	switch eventType {
	case "pull_request":
		if err := a.ProcessPullRequest(eventData); err != nil {
			fail(err)
		}
	case "issues":
		if err := a.ProcessIssue(eventData); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "Action failed: %s\n", err)
	os.Exit(1)
}
