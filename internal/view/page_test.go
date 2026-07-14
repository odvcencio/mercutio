package view

import (
	"strings"
	"testing"

	"m31labs.dev/gosx"
	"m31labs.dev/mercutio/internal/model"
)

func TestPageUsesGoSXActionsWithoutApplicationScripts(t *testing.T) {
	state := model.State{Cells: []model.CellSnapshot{{Cell: model.Cell{
		ID: "cell-1", Status: model.CellReady, Files: []model.File{{Path: "main.go", Language: "go", Content: "package main\n"}},
	}}}}
	html := gosx.RenderHTML(Page(state, "cell-1", "main.go", "csrf-token"))
	for _, want := range []string{
		`data-gosx-code-surface="true"`,
		`action="/gosx/action/edit-file"`,
		`action="/gosx/action/prompt"`,
		`name="content"`,
		`data-collaboration-hub="/gosx/hub/cells?cellID=cell-1"`,
		`data-collaboration-capability-url="/api/cells/cell-1/capability"`,
		`/editor/collaborative-editor.js`,
		`/editor/code-intelligence.js`,
		`data-code-intelligence-runtime="/intelligence/gotreesitter.wasm"`,
		`name="csrf_token" value="csrf-token"`,
		`package main`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("viewport missing %q in %s", want, html)
		}
	}
	for _, forbidden := range []string{"app.js", "login.js", "initial-state"} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("viewport contains application script contract %q", forbidden)
		}
	}
}

func TestLoginUsesGoSXAuthenticationContract(t *testing.T) {
	html := gosx.RenderHTML(LoginPage("csrf-token"))
	for _, want := range []string{
		`action="/auth/magic-link"`,
		`data-gosx-webauthn-action="login"`,
		`data-gosx-webauthn-action="register"`,
		`data-gosx-webauthn="true"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("login missing %q", want)
		}
	}
	if strings.Contains(html, "login.js") {
		t.Fatal("login references application-authored JavaScript")
	}
}

func TestLayoutServesApplicationStylesFromPublicRoot(t *testing.T) {
	html := gosx.RenderHTML(Layout("Mercutio", gosx.Text("body")))
	if !strings.Contains(html, `href="/app.css"`) {
		t.Fatalf("layout missing public-root stylesheet: %s", html)
	}
}
