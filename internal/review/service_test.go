package review

import (
	"context"
	"testing"

	"m31labs.dev/mercutio/internal/model"
)

func TestGenerateMarksSecretShapedChangesBlocked(t *testing.T) {
	service := NewService(nil)
	reviews := service.Generate(
		[]model.File{{Path: "config.yaml", Language: "yaml", Content: "token: old-value\n"}},
		[]model.File{{Path: "config.yaml", Language: "yaml", Content: "token: ghp_abcdefghijklmnopqrstuvwxyz\n"}},
	)
	if len(reviews) == 0 {
		t.Fatal("no review generated")
	}
	if reviews[0].Status != "blocked" || reviews[0].CommitReady || reviews[0].Patch == "" || reviews[0].Patch == "- token: old-value\n+ token: ghp_abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("secret review = %+v", reviews[0])
	}
	if reviews[0].SecretScanStatus == "" || len(reviews[0].SecretFindings) == 0 {
		t.Fatalf("structural scan missing: %+v", reviews[0])
	}
}

func TestAgentCommitterDelegatesApprovalToCellTransport(t *testing.T) {
	called := false
	committer := NewAgentCommitter(func(_ context.Context, request CommitRequest) (string, error) {
		called = request.CellID == "cell-1" && request.Review.ID == "review-1"
		return "agent-receipt", nil
	})
	receipt, err := committer.Commit(context.Background(), CommitRequest{CellID: "cell-1", Review: model.Review{ID: "review-1"}})
	if err != nil || receipt != "agent-receipt" || !called {
		t.Fatalf("agent commit = %q, %v, called=%v", receipt, err, called)
	}
}
