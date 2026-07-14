package cell

import "testing"

func TestResolveCursorAnchorsUsesStableElementIDsAndUTF16(t *testing.T) {
	store := NewStore()
	snapshot, err := store.Snapshot("cell-demo")
	if err != nil || len(snapshot.Files) == 0 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	path := snapshot.Files[0].Path
	if _, err := store.ApplyEdit("cell-demo", path, "a🙂b", "operator"); err != nil {
		t.Fatal(err)
	}
	start, end, err := store.ResolveCursorAnchors("cell-demo", path, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if start.ElemID == "" || start.Affinity != "before" || end.ElemID == "" || end.Affinity != "before" || start.ElemID == end.ElemID {
		t.Fatalf("start=%+v end=%+v", start, end)
	}
	if _, _, err := store.ResolveCursorAnchors("cell-demo", path, 2, 3); err == nil {
		t.Fatal("cursor offset splitting a UTF-16 surrogate pair was accepted")
	}
	_, eof, err := store.ResolveCursorAnchors("cell-demo", path, 0, 4)
	if err != nil || eof.ElemID == "" || eof.Affinity != "after" {
		t.Fatalf("eof=%+v err=%v", eof, err)
	}
}
