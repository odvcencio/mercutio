package view

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"m31labs.dev/gosx"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/policy"
)

func TestPageUsesGoSXActionsWithoutApplicationScripts(t *testing.T) {
	state := model.State{Cells: []model.CellSnapshot{{Cell: model.Cell{
		ID: "cell-1", Status: model.CellReady, Files: []model.File{{Path: "main.go", Language: "go", Content: "package main\n"}},
	}}}}
	html := gosx.RenderHTML(Page(state, "cell-1", "main.go", "csrf-token"))
	for _, want := range []string{
		`data-gosx-code-surface="true"`,
		`data-code-tab-width="4"`,
		`data-code-highlight-source="external"`,
		`data-code-insert-spaces`,
		`data-code-gutter`,
		`data-code-external-undo`,
		`action="/gosx/action/edit-file"`,
		`action="/gosx/action/prompt"`,
		`name="content"`,
		`aria-label="Repository files"`,
		`class="file-tree-file active"`,
		`data-collaboration-hub="/gosx/hub/cells?cellID=cell-1"`,
		`data-collaboration-capability-url="/api/cells/cell-1/capability"`,
		`/editor/collaborative-editor.js`,
		`/editor/code-intelligence.js`,
		`data-code-intelligence-runtime="/intelligence/gotreesitter.wasm"`,
		`data-code-intelligence-server="/api/cells/cell-1/analyze"`,
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

func TestPolicyEditorRequiresPreviewBeforeApplyAndRendersBlastRadius(t *testing.T) {
	state := model.State{Cells: []model.CellSnapshot{{Cell: model.Cell{
		ID: "cell-policy", Status: model.CellReady, SandboxProfile: "standard",
		Files: []model.File{{Path: "policy/sandbox.yaml", Language: "yaml", Content: "profile: strict\n"}},
	}}}}
	without := gosx.RenderHTML(Page(state, "cell-policy", "policy/sandbox.yaml", "csrf-token"))
	if !strings.Contains(without, `action="/gosx/action/preview-policy"`) || strings.Contains(without, `action="/gosx/action/apply-policy"`) {
		t.Fatalf("policy editor bypasses preview: %s", without)
	}
	preview := policy.PreviewResult{
		Before: policy.Manifest{Profile: "standard"}, After: policy.Manifest{Profile: "strict"},
		Classes: []policy.ClassImpact{{Class: "standard", Narrows: 2, Rules: []policy.RuleImpact{{Action: "net", Domain: "dependency", Operation: "connect", BeforeVerdict: "allow", AfterVerdict: "deny", Direction: "narrows"}}}},
		Cells:   []policy.CellImpact{{CellID: "cell-policy", RequiresRearm: true, Narrows: 1, Replay: []policy.ReplayImpact{{EventID: "k1", Action: "net/dependency/connect", BeforeVerdict: "allow", AfterVerdict: "deny", Direction: "narrows"}}}},
	}
	with := gosx.RenderHTML(PageWithPolicyPreview(state, "cell-policy", "policy/sandbox.yaml", "csrf-token", &preview))
	for _, want := range []string{`aria-label="Policy impact preview"`, `static EPS diff + recorded kernel replay`, `0 widens`, `2 narrows`, `cell-policy`, `verdict flips`, `action="/gosx/action/apply-policy"`, `Apply reviewed policy &amp; re-arm`} {
		if !strings.Contains(with, want) {
			t.Fatalf("policy preview missing %q in %s", want, with)
		}
	}
}

func TestMobileShellIsWatchSteerApproveWithoutAuthoringSurfaces(t *testing.T) {
	state := model.State{Cells: []model.CellSnapshot{{Cell: model.Cell{
		ID: "cell-mobile", Status: model.CellReady, SandboxProfile: "strict", EvidenceHealth: "healthy",
		Files:   []model.File{{Path: "policy/sandbox.yaml", Language: "yaml", Content: "profile: strict\n"}},
		Reviews: []model.Review{{ID: "review-1", Title: "Entity change", Summary: "Function changed", Status: "pending", CommitReady: true, EvidenceHealth: "healthy", SecretScanStatus: "clean"}},
		Shadows: []model.ShadowRevision{{ID: "shadow-1", URI: "shadow://cell-mobile/a.go/shadow-1", Path: "a.go", Author: "agent", Status: "open", Before: "old", After: "new"}},
	}, Events: []model.Event{{Kind: model.EventIntent, Action: "test.run", Summary: "Agent claims tests passed"}, {Kind: model.EventKernel, Action: "process.exec", Summary: "Observed test runner"}}}}}
	html := gosx.RenderHTML(MobilePage(state, "cell-mobile", "csrf-token"))
	for _, want := range []string{`data-shell="mobile"`, `data-typing-first="false"`, `aria-label="Cell fleet"`, `AGENT REPORTED / INTENT`, `KERNEL / HORIZON`, `action="/gosx/action/prompt"`, `action="/gosx/action/approve-review"`, `action="/gosx/action/reject-review"`, `action="/gosx/action/adopt-shadow"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("mobile shell missing %q in %s", want, html)
		}
	}
	for _, forbidden := range []string{`data-gosx-code-surface`, `/editor/`, `/intelligence/`, `name="content"`, `apply-policy`, `preview-policy`, `merge-shadow`, `discard-shadow`, `secret:read`} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("mobile shell exposes forbidden authoring surface %q in %s", forbidden, html)
		}
	}
}

func TestConfigAndDSLFilesUseServerCodeIntelligence(t *testing.T) {
	for _, file := range []model.File{
		{Path: "config.yaml", Language: "yaml", Content: "enabled: true\n"},
		{Path: "policy.arb", Language: "arbiter", Content: "rule Allow {}\n"},
		{Path: "program.hzn", Language: "horizon", Content: "package demo\n"},
	} {
		state := model.State{Cells: []model.CellSnapshot{{Cell: model.Cell{ID: "cell-1", Status: model.CellReady, Files: []model.File{file}}}}}
		html := gosx.RenderHTML(Page(state, "cell-1", file.Path, "csrf-token"))
		for _, want := range []string{`data-code-intelligence-language="` + file.Language + `"`, `data-code-intelligence-server="/api/cells/cell-1/analyze"`} {
			if !strings.Contains(html, want) {
				t.Fatalf("%s editor missing %q in %s", file.Path, want, html)
			}
		}
		if strings.Contains(html, `data-code-intelligence-runtime=`) {
			t.Fatalf("%s should use the server lane directly", file.Path)
		}
	}
}

func TestFileTreeRendersSortedDirectoriesAndSelectedFile(t *testing.T) {
	cell := &model.CellSnapshot{Cell: model.Cell{ID: "cell-tree", Files: []model.File{
		{Path: "z.go", Language: "go"},
		{Path: "internal/config/load.go", Language: "go"},
		{Path: "cmd/mercutio/main.go", Language: "go"},
		{Path: "README.md", Language: "markdown"},
	}}}
	html := gosx.RenderHTML(renderFileTree(cell, "internal/config/load.go"))
	for _, want := range []string{`aria-label="Repository files"`, `>cmd</summary>`, `>internal</summary>`, `>config</summary>`, `class="file-tree-file active"`, `file=internal%2Fconfig%2Fload.go`} {
		if !strings.Contains(html, want) {
			t.Fatalf("file tree missing %q in %s", want, html)
		}
	}
	if strings.Index(html, ">cmd</summary>") > strings.Index(html, ">internal</summary>") || strings.Index(html, ">README.md</a>") > strings.Index(html, ">z.go</a>") {
		t.Fatalf("file tree is not sorted: %s", html)
	}
}

func TestOrreryRendersFiftyCellsWithinServerBudget(t *testing.T) {
	state := model.State{Cells: make([]model.CellSnapshot, 50)}
	for i := range state.Cells {
		state.Cells[i] = model.CellSnapshot{Cell: model.Cell{
			ID: fmt.Sprintf("cell-%02d", i), RepoURL: fmt.Sprintf("https://example.invalid/repo-%02d", i%5),
			Branch: "main", Status: model.CellReady, SandboxProfile: "standard", EvidenceHealth: "healthy",
			Files: []model.File{{Path: "main.go", Language: "go", Content: "package main\n"}},
		}}
	}
	durations := make([]time.Duration, 25)
	var html string
	for i := range durations {
		started := time.Now()
		html = gosx.RenderHTML(renderOrrery(state))
		durations[i] = time.Since(started)
	}
	if count := strings.Count(html, `class="orrery-node `); count != 50 {
		t.Fatalf("orrery cards = %d, want 50", count)
	}
	if strings.Contains(html, "<button") || strings.Contains(html, "<form") {
		t.Fatal("orrery exposes a bulk action surface")
	}
	sortedDurations := append([]time.Duration(nil), durations...)
	slices.Sort(sortedDurations)
	if p95 := sortedDurations[23]; p95 > 50*time.Millisecond {
		t.Fatalf("50-cell Orrery server render p95 = %s, budget 50ms", p95)
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
