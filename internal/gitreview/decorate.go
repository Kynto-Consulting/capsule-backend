package gitreview

import (
	"context"
	"time"

	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// AutoMergeOut is the API schema MergeRequest as shown in Pull.auto_merge.
type AutoMergeOut struct {
	Style        string `json:"style"`
	Title        string `json:"title,omitempty"`
	Message      string `json:"message,omitempty"`
	DeleteBranch bool   `json:"delete_branch"`
	HeadSHA      string `json:"head_sha"`
}

// Out maps a row to the API shape.
func (a AutoMerge) Out() AutoMergeOut {
	return AutoMergeOut{Style: string(a.Style), Title: a.Title, Message: a.Message, DeleteBranch: a.DeleteBranch, HeadSHA: a.HeadSHA}
}

// decorate fills Pull.auto_merge (gitapi.PullDecorator has no context: it uses a short one).
func (s *Service) decorate(ref gitcore.RepoRef, p gitcore.Pull, out *gitapi.PullOut) {
	if p.State != gitcore.PullOpen {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	proj, err := s.Projects.ByRef(ctx, ref)
	if err != nil {
		return
	}
	if a := s.Active(ctx, proj.ID, p.Number); a != nil {
		out.AutoMerge = a.Out()
	}
}
