package actions

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/transport"
)

func TestBrowserActionsCreateAndEditWithoutJSONClient(t *testing.T) {
	store := cell.NewStore()
	hub := transport.NewCellHub(store)
	registry := New(store, hub)

	create := formRequest("/gosx/action/create-cell", url.Values{
		"repoURL": {"https://github.com/example/repo"},
		"branch":  {"main"},
		"profile": {"standard"},
	})
	created := httptest.NewRecorder()
	registry.ServeHTTP(created, create)
	if created.Code != http.StatusSeeOther {
		t.Fatalf("create status = %d, body=%s", created.Code, created.Body.String())
	}
	location, err := url.Parse(created.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cellID := location.Query().Get("cell")
	if cellID == "" {
		t.Fatalf("create redirect missing cell identity: %q", created.Header().Get("Location"))
	}

	edit := formRequest("/gosx/action/edit-file", url.Values{
		"cellID":  {cellID},
		"path":    {"README.md"},
		"content": {"package changed\n"},
	})
	edited := httptest.NewRecorder()
	registry.ServeHTTP(edited, edit)
	if edited.Code != http.StatusSeeOther {
		t.Fatalf("edit status = %d, body=%s", edited.Code, edited.Body.String())
	}
	file, err := store.File(cellID, "README.md")
	if err != nil || file.Content != "package changed\n" {
		t.Fatalf("edited file = %#v, err=%v", file, err)
	}
}

func TestBrowserPolicyChangeIsPreviewThenCapabilityAuthorizedApply(t *testing.T) {
	store := cell.NewStore()
	registry := New(store, transport.NewCellHub(store))
	previewed := httptest.NewRecorder()
	registry.ServeHTTP(previewed, formRequest("/gosx/action/preview-policy", url.Values{
		"cellID": {"cell-demo"}, "path": {"policy/sandbox.yaml"}, "content": {"profile: strict\n"},
	}))
	if previewed.Code != http.StatusSeeOther || !strings.Contains(previewed.Header().Get("Location"), "policyPreview=1") {
		t.Fatalf("preview=%d location=%q body=%s", previewed.Code, previewed.Header().Get("Location"), previewed.Body.String())
	}
	snapshot, _ := store.Snapshot("cell-demo")
	if snapshot.SandboxProfile != "standard" {
		t.Fatalf("preview mutated enforcement profile: %s", snapshot.SandboxProfile)
	}
	applied := httptest.NewRecorder()
	registry.ServeHTTP(applied, formRequest("/gosx/action/apply-policy", url.Values{
		"cellID": {"cell-demo"}, "path": {"policy/sandbox.yaml"}, "content": {"profile: strict\n"},
	}))
	if applied.Code != http.StatusSeeOther {
		t.Fatalf("apply=%d body=%s", applied.Code, applied.Body.String())
	}
	snapshot, _ = store.Snapshot("cell-demo")
	if snapshot.SandboxProfile != "strict" {
		t.Fatalf("authorized apply profile=%s", snapshot.SandboxProfile)
	}
}

func formRequest(path string, values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}
