package cell

import (
	"testing"

	"m31labs.dev/mercutio/internal/model"
)

func TestSecretReviewRequiresExplicitAcknowledgmentAndRejectReason(t *testing.T) {
	store := NewStore()
	reviews := store.reviews.Generate(
		[]model.File{{Path: "config.yaml", Language: "yaml", Content: "token: brokered\n"}},
		[]model.File{{Path: "config.yaml", Language: "yaml", Content: "token: ghp_abcdefghijklmnopqrstuvwxyz\n"}},
	)
	store.mu.Lock()
	store.cells["cell-demo"].cell.Reviews = reviews
	snapshot := snapshotLocked(store.cells["cell-demo"])
	store.mu.Unlock()
	var id string
	for _, review := range snapshot.Reviews {
		if len(review.SecretFindings) > 0 {
			id = review.ID
			break
		}
	}
	if id == "" {
		t.Fatal("no secret-blocked review")
	}
	if _, err := store.ApproveReview("cell-demo", id); err == nil {
		t.Fatal("blocked review approved")
	}
	if _, err := store.AcknowledgeReview("cell-demo", id, "operator", "", true, false); err == nil {
		t.Fatal("empty acknowledgment accepted")
	}
	snapshot, err := store.AcknowledgeReview("cell-demo", id, "operator", "accepted test fixture", true, false)
	if err != nil {
		t.Fatal(err)
	}
	ready := false
	for _, review := range snapshot.Reviews {
		if review.ID == id {
			ready = review.CommitReady
		}
	}
	if !ready {
		t.Fatal("acknowledged review not ready")
	}
	if _, _, err = store.RejectReview("cell-demo", id, "operator", ""); err == nil {
		t.Fatal("empty rejection accepted")
	}
	snapshot, prompt, err := store.RejectReview("cell-demo", id, "operator", "use broker instead")
	if err != nil || prompt == "" {
		t.Fatalf("reject=%q %v", prompt, err)
	}
}
