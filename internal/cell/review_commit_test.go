package cell

import (
	"context"
	"testing"

	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/review"
)

type recordingCommitter struct {
	requests []review.CommitRequest
}

func (c *recordingCommitter) Commit(_ context.Context, request review.CommitRequest) (string, error) {
	c.requests = append(c.requests, request)
	return "commit:accepted-entities", nil
}

func TestEntityApprovalsCommitOnlyAfterEveryCurrentEntityIsAccepted(t *testing.T) {
	committer := &recordingCommitter{}
	store := NewStoreWithOptions(Options{Committer: committer})
	store.mu.Lock()
	store.cells["cell-demo"].cell.Reviews = []model.Review{
		{ID: "review-a", Entity: "func:A", Status: "pending", CommitReady: true, Files: []string{"cmd/hello/main.go"}},
		{ID: "review-b", Entity: "func:B", Status: "pending", CommitReady: true, Files: []string{"cmd/hello/main.go"}},
	}
	store.mu.Unlock()

	first, err := store.ApproveReview("cell-demo", "review-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(committer.requests) != 0 || first.Reviews[0].Status != "accepted" || first.Reviews[1].Status != "pending" {
		t.Fatalf("partial entity approval committed worktree: requests=%d reviews=%+v", len(committer.requests), first.Reviews)
	}

	second, err := store.ApproveReview("cell-demo", "review-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(committer.requests) != 1 {
		t.Fatalf("accepted entity set produced %d commits", len(committer.requests))
	}
	request := committer.requests[0]
	if len(request.Review.Files) != 1 || request.Review.Files[0] != "cmd/hello/main.go" {
		t.Fatalf("aggregate commit paths=%v", request.Review.Files)
	}
	for _, item := range second.Reviews {
		if item.Status != "approved" || item.Receipt != "commit:accepted-entities" {
			t.Fatalf("entity approval not finalized atomically: %+v", second.Reviews)
		}
	}
}
