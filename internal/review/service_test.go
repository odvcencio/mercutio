package review

import (
	"context"
	"strings"
	"testing"

	"m31labs.dev/mercutio/internal/model"
)

func TestGenerateUsesGraftReceiverIdentity(t *testing.T) {
	service := NewService(nil)
	before := "package demo\n\ntype A struct{}\ntype B struct{}\nfunc (A) Run() int { return 1 }\nfunc (B) Run() int { return 2 }\n"
	after := "package demo\n\ntype A struct{}\ntype B struct{}\nfunc (A) Run() int { return 3 }\nfunc (B) Run() int { return 2 }\n"
	reviews := service.Generate([]model.File{{Path: "demo.go", Language: "go", Content: before}}, []model.File{{Path: "demo.go", Language: "go", Content: after}})
	if len(reviews) != 1 {
		t.Fatalf("reviews=%+v", reviews)
	}
	if !strings.HasPrefix(reviews[0].Entity, "decl:") || !strings.Contains(reviews[0].Entity, ":A:Run:") || !strings.Contains(reviews[0].Summary, "A.Run") {
		t.Fatalf("review did not use receiver-qualified Graft identity: %+v", reviews[0])
	}
}

func TestGenerateKeepsIdentityAcrossSignatureChangeAndFlagsIt(t *testing.T) {
	service := NewService(nil)
	before := "package demo\n\nfunc Transform(value int) int { return value }\n"
	after := "package demo\n\nfunc Transform(value int, scale int) int { return value * scale }\n"
	reviews := service.Generate([]model.File{{Path: "demo.go", Language: "go", Content: before}}, []model.File{{Path: "demo.go", Language: "go", Content: after}})
	if len(reviews) != 1 || !reviews[0].SignatureChanged || !strings.Contains(reviews[0].Entity, ":Transform:") {
		t.Fatalf("signature-changing entity review=%+v", reviews)
	}
}

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

func TestGenerateBlocksSecretShapedContentRemovedByDiff(t *testing.T) {
	service := NewService(nil)
	reviews := service.Generate(
		[]model.File{{Path: "config.yaml", Language: "yaml", Content: "token: ghp_abcdefghijklmnopqrstuvwxyz\n"}},
		[]model.File{{Path: "config.yaml", Language: "yaml", Content: "token: brokered\n"}},
	)
	if len(reviews) == 0 || reviews[0].Status != "blocked" || reviews[0].CommitReady || len(reviews[0].SecretFindings) == 0 {
		t.Fatalf("removed secret was not blocked: %+v", reviews)
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
