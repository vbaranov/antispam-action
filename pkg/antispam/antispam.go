package antispam

import (
	"context"

	"github.com/google/go-github/v50/github"
)

type Antispam struct {
	ctx    context.Context
	client *github.Client
}

func New(ctx context.Context, client *github.Client) *Antispam {
	return &Antispam{
		ctx:    ctx,
		client: client,
	}
}
