package view

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"m31labs.dev/gosx"
	gosxauth "m31labs.dev/gosx/auth"
	gosxeditor "m31labs.dev/gosx/editor"
	"m31labs.dev/gosx/server"
	"m31labs.dev/mercutio/internal/model"
)

const actionBase = "/gosx/action/"

// Page renders the operator viewport entirely from GoSX nodes. Browser
// mutations use GoSX server actions and retain native HTML form behavior.
func Page(state model.State, selectedCellID, selectedPath, csrfToken string) gosx.Node {
	cell := activeCell(state, selectedCellID)
	file := activeFile(cell, selectedPath)
	return gosx.El("main", gosx.Attrs(gosx.Attr("class", "app-shell")),
		renderTopbar(state.Connected),
		gosx.El("section", gosx.Attrs(gosx.Attr("class", "workspace")),
			renderSidebar(state, cell, csrfToken),
			renderEditor(cell, file, csrfToken),
			renderObservability(cell, file, csrfToken),
		),
		renderOrrery(state),
	)
}

func renderTopbar(connected int) gosx.Node {
	return gosx.El("header", gosx.Attrs(gosx.Attr("class", "topbar")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "brand")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "brand-mark")), gosx.Text("M")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "brand-name")), gosx.Text("mercutio"))),
		gosx.El("span", gosx.Attrs(gosx.Attr("class", "eyebrow")), gosx.Text("observe-first control plane")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "topbar-right")),
			gosx.El("span", gosx.Attrs(gosx.Attr("class", "connection-dot"))),
			gosx.El("span", gosx.Text(strconv.Itoa(connected)+" online")),
			gosx.El("a", gosx.Attrs(gosx.Attr("class", "ghost-button"), gosx.Attr("href", "#orrery-panel")), gosx.Text("Orrery view")),
		),
	)
}

func renderSidebar(state model.State, selected *model.CellSnapshot, csrfToken string) gosx.Node {
	const visibleCellLimit = 12
	indices := make([]int, 0, min(len(state.Cells), visibleCellLimit))
	for i := 0; i < len(state.Cells) && len(indices) < visibleCellLimit; i++ {
		indices = append(indices, i)
	}
	if selected != nil && len(state.Cells) > visibleCellLimit {
		for i := visibleCellLimit; i < len(state.Cells); i++ {
			if state.Cells[i].ID == selected.ID {
				indices[len(indices)-1] = i
				break
			}
		}
	}
	cards := make([]gosx.Node, 0, len(indices)+1)
	for _, i := range indices {
		cell := &state.Cells[i]
		className := "cell-card"
		if selected != nil && selected.ID == cell.ID {
			className += " active"
		}
		children := []gosx.Node{
			gosx.El("a", gosx.Attrs(gosx.Attr("class", "cell-name"), gosx.Attr("href", viewPath(cell.ID, firstFile(cell)))), gosx.El("span", gosx.Attrs(gosx.Attr("class", "cell-state "+string(cell.Status)))), gosx.Text(cell.ID)),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "cell-meta")), gosx.Text(cell.RepoURL+" @ "+cell.Branch)),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "cell-agent")), gosx.Text("◉ "+defaultText(cell.Agent.Name, "agent detached")+" · "+defaultText(cell.Agent.Status, "offline"))),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "cell-runtime")), gosx.Text(string(cell.Sandbox.Phase)+" · "+containmentLabel(cell)+" · rung "+defaultText(cell.Sandbox.Enforcement, "unarmed"))),
		}
		if cell.Status != model.CellStopped {
			children = append(children, actionForm(csrfToken, "destroy-cell", "cell-stop", hidden("cellID", cell.ID), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Stop cell"))))
		}
		cards = append(cards, gosx.El("article", gosx.Attrs(gosx.Attr("class", className)), gosx.Fragment(children...)))
	}
	if hidden := len(state.Cells) - len(indices); hidden > 0 {
		cards = append(cards, gosx.El("a", gosx.Attrs(gosx.Attr("class", "cell-overflow"), gosx.Attr("href", "#orrery-panel")), gosx.Text(fmt.Sprintf("%d more cells in Orrery", hidden))))
	}
	if len(cards) == 0 {
		cards = append(cards, gosx.El("div", gosx.Attrs(gosx.Attr("class", "empty-feed")), gosx.Text("No cells yet. Create one from a repository.")))
	}
	return gosx.El("aside", gosx.Attrs(gosx.Attr("class", "sidebar")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "side-heading")), gosx.El("span", gosx.Text("CELLS")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "count-pill")), gosx.Text(strconv.Itoa(len(state.Cells))))),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "cell-list")), gosx.Fragment(cards...)),
		actionForm(csrfToken, "create-cell", "create-cell",
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "form-label")), gosx.Text("NEW SANDBOX CELL")),
			gosx.El("input", gosx.Attrs(gosx.Attr("name", "repoURL"), gosx.Attr("placeholder", "github.com/org/repo"), gosx.Attr("autocomplete", "off"), gosx.BoolAttr("required"))),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "form-row")),
				gosx.El("input", gosx.Attrs(gosx.Attr("name", "branch"), gosx.Attr("value", "main"), gosx.Attr("placeholder", "branch"))),
				gosx.El("select", gosx.Attrs(gosx.Attr("name", "profile")), option("standard"), option("strict"), option("open")),
			),
			gosx.El("button", gosx.Attrs(gosx.Attr("class", "primary-button"), gosx.Attr("type", "submit")), gosx.Text("Create cell")),
			gosx.El("p", gosx.Attrs(gosx.Attr("class", "form-help")), gosx.Text("Creates a sandbox cell with a selected capability profile.")),
		),
	)
}

func renderEditor(cell *model.CellSnapshot, file *model.File, csrfToken string) gosx.Node {
	if cell == nil {
		return gosx.El("section", gosx.Attrs(gosx.Attr("class", "editor-column")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "empty-feed")), gosx.Text("Create or select a cell to begin.")))
	}
	tabs := make([]gosx.Node, 0, len(cell.Files))
	for i := range cell.Files {
		item := &cell.Files[i]
		className := "file-tab"
		if file != nil && file.Path == item.Path {
			className += " active"
		}
		tabs = append(tabs, gosx.El("a", gosx.Attrs(gosx.Attr("class", className), gosx.Attr("href", viewPath(cell.ID, item.Path))), gosx.Text(item.Path)))
	}
	if file == nil {
		return gosx.El("section", gosx.Attrs(gosx.Attr("class", "editor-column")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "file-tabs")), gosx.Fragment(tabs...)), gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-workbench")), renderFileTree(cell, ""), gosx.El("div", gosx.Attrs(gosx.Attr("class", "empty-feed")), gosx.Text("This cell has no files."))))
	}
	codeEditor := gosxeditor.New("mercutio-code-editor", gosxeditor.Options{
		Surface:          gosxeditor.SurfaceCode,
		Content:          file.Content,
		Title:            file.Path,
		Label:            "Code editor for " + file.Path,
		Language:         editorLanguage(file.Language),
		FormAction:       actionBase + editorAction(file.Path),
		AutoSaveURL:      actionBase + editorAction(file.Path),
		CSRFToken:        csrfToken,
		ExtraFields:      map[string]string{"cellID": cell.ID, "path": file.Path},
		Buttons:          []gosxeditor.FormButton{{Name: "editor_action", Value: "save", Label: editorSubmitLabel(file.Path), Class: "save-button"}},
		Collaboration:    &gosxeditor.Collaboration{HubURL: "/gosx/hub/cells?cellID=" + url.QueryEscape(cell.ID), CapabilityURL: "/api/cells/" + url.PathEscape(cell.ID) + "/capability", CellID: cell.ID, Path: file.Path, BinarySplices: true},
		CodeIntelligence: editorIntelligence(cell.ID, file.Language),
	})
	return gosx.El("section", gosx.Attrs(gosx.Attr("class", "editor-column"), gosx.Attr("data-gosx-code-surface", "true"), gosx.Attr("data-language", file.Language)),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-toolbar")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "file-tabs")), gosx.Fragment(tabs...)), gosx.El("span", gosx.Attrs(gosx.Attr("class", "revision")), gosx.Text(fmt.Sprintf("rev %d", cell.Revision)))),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-workbench")),
			renderFileTree(cell, file.Path),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-main")),
				gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-meta")), gosx.El("div", gosx.El("span", gosx.Attrs(gosx.Attr("class", "file-icon")), gosx.Text("▧")), gosx.El("strong", gosx.Text(file.Path)), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text(file.Language)))),
				codeEditor.Render(),
				gosx.El("div", gosx.Attrs(gosx.Attr("class", "buffer-actions")),
					actionForm(csrfToken, "undo-edit", "buffer-action", hidden("cellID", cell.ID), hidden("path", file.Path), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Undo my edit"))),
					actionForm(csrfToken, "revert-agent-edit", "buffer-action", hidden("cellID", cell.ID), hidden("path", file.Path), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Revert agent edit"))),
					actionForm(csrfToken, "delete-file", "delete-file-form", hidden("cellID", cell.ID), hidden("path", file.Path), gosx.El("button", gosx.Attrs(gosx.Attr("class", "delete-button"), gosx.Attr("type", "submit")), gosx.Text("Delete file"))),
				),
				actionForm(csrfToken, "prompt", "prompt-bar", hidden("cellID", cell.ID), hidden("path", file.Path), gosx.El("div", gosx.Attrs(gosx.Attr("class", "prompt-icon")), gosx.Text("↗")), gosx.El("input", gosx.Attrs(gosx.Attr("name", "prompt"), gosx.Attr("placeholder", "Steer the agent in this cell…"), gosx.Attr("autocomplete", "off"), gosx.BoolAttr("required"))), gosx.El("button", gosx.Attrs(gosx.Attr("class", "prompt-button"), gosx.Attr("type", "submit")), gosx.Text("Send prompt"))),
			),
		),
	)
}

type fileTreeNode struct {
	dirs  map[string]*fileTreeNode
	files []string
}

func renderFileTree(cell *model.CellSnapshot, selectedPath string) gosx.Node {
	root := &fileTreeNode{dirs: map[string]*fileTreeNode{}}
	for _, file := range cell.Files {
		parts := strings.Split(strings.Trim(file.Path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		node := root
		for _, part := range parts[:len(parts)-1] {
			if node.dirs[part] == nil {
				node.dirs[part] = &fileTreeNode{dirs: map[string]*fileTreeNode{}}
			}
			node = node.dirs[part]
		}
		node.files = append(node.files, parts[len(parts)-1])
	}
	return gosx.El("nav", gosx.Attrs(gosx.Attr("class", "file-tree"), gosx.Attr("aria-label", "Repository files")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "file-tree-heading")), gosx.Text("FILES")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "file-tree-root")), gosx.Fragment(renderFileTreeNode(root, "", cell.ID, selectedPath)...)),
	)
}

func renderFileTreeNode(node *fileTreeNode, prefix, cellID, selectedPath string) []gosx.Node {
	dirs := make([]string, 0, len(node.dirs))
	for name := range node.dirs {
		dirs = append(dirs, name)
	}
	sort.Strings(dirs)
	sort.Strings(node.files)
	children := make([]gosx.Node, 0, len(dirs)+len(node.files))
	for _, name := range dirs {
		path := strings.TrimPrefix(prefix+"/"+name, "/")
		children = append(children, gosx.El("details", gosx.Attrs(gosx.Attr("class", "file-tree-directory"), gosx.BoolAttr("open")),
			gosx.El("summary", gosx.Text(name)),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "file-tree-children")), gosx.Fragment(renderFileTreeNode(node.dirs[name], path, cellID, selectedPath)...)),
		))
	}
	for _, name := range node.files {
		path := strings.TrimPrefix(prefix+"/"+name, "/")
		className := "file-tree-file"
		if path == selectedPath {
			className += " active"
		}
		children = append(children, gosx.El("a", gosx.Attrs(gosx.Attr("class", className), gosx.Attr("href", viewPath(cellID, path)), gosx.Attr("title", path)), gosx.Text(name)))
	}
	return children
}

func editorIntelligence(cellID, language string) *gosxeditor.CodeIntelligence {
	language = strings.ToLower(language)
	switch language {
	case "go", "yaml", "toml", "json", "hcl", "markdown", "arbiter", "horizon":
	default:
		return nil
	}
	intelligence := &gosxeditor.CodeIntelligence{
		Language:  language,
		ServerURL: "/api/cells/" + url.PathEscape(cellID) + "/analyze",
	}
	if language == "go" {
		intelligence.WasmExecURL = "/intelligence/wasm_exec.js"
		intelligence.RuntimeURL = "/intelligence/gotreesitter.wasm"
		intelligence.GrammarURL = "/intelligence/go.bin"
		intelligence.HighlightQueryURL = "/intelligence/go-highlights.scm"
		intelligence.TagsQueryURL = "/intelligence/go-tags.scm"
	}
	return intelligence
}

func editorLanguage(language string) gosxeditor.Lang {
	switch strings.ToLower(language) {
	case "go":
		return gosxeditor.Go
	case "gosx":
		return gosxeditor.GoSX
	case "javascript":
		return gosxeditor.JavaScript
	case "typescript":
		return gosxeditor.TypeScript
	case "json":
		return gosxeditor.JSON
	case "yaml":
		return gosxeditor.YAML
	case "markdown":
		return gosxeditor.Markdown
	default:
		return gosxeditor.PlainText
	}
}

func editorAction(path string) string {
	if path == "policy/sandbox.yaml" {
		return "apply-policy"
	}
	return "edit-file"
}
func editorSubmitLabel(path string) string {
	if path == "policy/sandbox.yaml" {
		return "Apply policy & re-arm"
	}
	return "Save buffer"
}

func renderObservability(cell *model.CellSnapshot, file *model.File, csrfToken string) gosx.Node {
	if cell == nil {
		return gosx.El("aside", gosx.Attrs(gosx.Attr("class", "observability")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "empty-feed")), gosx.Text("No active cell.")))
	}
	path := ""
	if file != nil {
		path = file.Path
	}
	children := []gosx.Node{
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "obs-heading")), gosx.El("div", gosx.Text("OBSERVABILITY"))),
	}
	if cell.Capabilities.RecordedOnly {
		children = append(children, gosx.El("div", gosx.Attrs(gosx.Attr("class", "evidence-warning")), gosx.Text("OPEN PROFILE · recorded, not contained")))
	}
	if cell.EvidenceHealth != "healthy" {
		children = append(children, gosx.El("div", gosx.Attrs(gosx.Attr("class", "evidence-warning")), gosx.Text("EVIDENCE DEGRADED · clean assertions are suppressed")))
	}
	for _, finding := range cell.Divergences {
		children = append(children, gosx.El("div", gosx.Attrs(gosx.Attr("class", "divergence"), gosx.Attr("data-rule", finding.RuleID)), gosx.El("strong", gosx.Text(finding.RuleID+" · "+finding.Rule)), gosx.El("span", gosx.Text(finding.Summary)), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text(finding.Severity+" · evidence "+evidenceLabel(finding.Evidence)))))
	}
	children = append(children, eventFeed(cell.Events, model.EventIntent, "AGENT REPORTED / INTENT", defaultText(cell.Agent.ID, "agent")+" · untrusted claims"), eventFeed(cell.Events, model.EventKernel, "KERNEL / HORIZON", "trusted observations · loss-accounted"), renderReview(cell, path, csrfToken))
	for _, request := range cell.SecretRequests {
		if request.Status == "pending" {
			children = append(children, actionForm(csrfToken, "approve-secret-grant", "secret-ask-human", hidden("cellID", cell.ID), hidden("requestID", request.ID), hidden("path", path), gosx.El("strong", gosx.Text("Credential approval required")), gosx.El("span", gosx.Text(request.Credential+" · "+request.Purpose)), gosx.El("code", gosx.Text(strings.Join(request.Command, " "))), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit"), gosx.Attr("class", "approve-button")), gosx.Text("Approve Tier-2 grant"))))
		}
	}
	for _, request := range cell.ActionApprovals {
		if request.Status != "pending" {
			continue
		}
		children = append(children, actionForm(csrfToken, "decide-action", "kernel-ask-human",
			hidden("cellID", cell.ID), hidden("requestID", request.ID), hidden("path", path),
			gosx.El("strong", gosx.Text("Kernel action blocked for approval")),
			gosx.El("span", gosx.Text(request.Kind+" · pid "+fmt.Sprint(request.PID)+" · "+request.NodeID)),
			gosx.El("code", gosx.Text(defaultText(request.Resource, "resource unavailable"))),
			gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit"), gosx.Attr("name", "decision"), gosx.Attr("value", "approve"), gosx.Attr("class", "approve-button")), gosx.Text("Approve once")),
			gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit"), gosx.Attr("name", "decision"), gosx.Attr("value", "reject"), gosx.Attr("class", "danger-button")), gosx.Text("Reject")),
		))
	}
	for _, shadow := range cell.Shadows {
		shadowChildren := []gosx.Node{gosx.El("strong", gosx.Text("Shadow Revision · "+shadow.Author)), gosx.El("code", gosx.Text(shadow.URI)), gosx.El("span", gosx.Text(shadow.Path+" · "+shadow.Reason)), gosx.El("span", gosx.Text("status: "+shadow.Status)), gosx.El("span", gosx.Text("conflicts: "+strings.Join(shadow.Conflicts, ", "))), gosx.El("details", gosx.El("summary", gosx.Text("View before / after")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "shadow-diff")), gosx.El("pre", gosx.Text(shadow.Before)), gosx.El("pre", gosx.Text(shadow.After))))}
		if shadow.Status == "open" {
			shadowChildren = append(shadowChildren, actionForm(csrfToken, "merge-shadow", "shadow-action", hidden("cellID", cell.ID), hidden("shadowID", shadow.ID), hidden("path", path), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Structural merge"))), actionForm(csrfToken, "adopt-shadow", "shadow-action", hidden("cellID", cell.ID), hidden("shadowID", shadow.ID), hidden("path", path), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Adopt agent version"))), actionForm(csrfToken, "discard-shadow", "shadow-action", hidden("cellID", cell.ID), hidden("shadowID", shadow.ID), hidden("path", path), gosx.El("input", gosx.Attrs(gosx.Attr("name", "reason"), gosx.Attr("placeholder", "Required discard reason"), gosx.BoolAttr("required"))), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Discard with receipt"))))
		}
		children = append(children, gosx.El("section", gosx.Attrs(gosx.Attr("class", "shadow-card")), gosx.Fragment(shadowChildren...)))
	}
	return gosx.El("aside", gosx.Attrs(gosx.Attr("class", "observability")), gosx.Fragment(children...))
}

func evidenceLabel(status model.DivergenceEvidence) string {
	if status.Healthy {
		return "healthy"
	}
	return "degraded"
}

func eventFeed(events []model.Event, kind model.EventKind, title, subtitle string) gosx.Node {
	items := make([]gosx.Node, 0)
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind != kind {
			continue
		}
		meta := events[i].Action
		if events[i].DangerAxes != (model.DangerAxes{}) {
			meta += " · Action danger " + dangerTriple(events[i].DangerAxes)
		}
		if events[i].ProgramDanger != (model.DangerAxes{}) {
			meta += " · Program danger " + dangerTriple(events[i].ProgramDanger)
		}
		children := []gosx.Node{gosx.El("strong", gosx.Text(events[i].Summary)), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text(meta))}
		if events[i].PathTruncated || events[i].ArgvTruncated {
			children = append(children, gosx.El("span", gosx.Attrs(gosx.Attr("class", "truncation-warning")), gosx.Text("TRUNCATED PATH/ARGV · prefix-only policy evidence")))
		}
		items = append(items, gosx.El("article", gosx.Attrs(gosx.Attr("class", "feed-item")), gosx.Fragment(children...)))
	}
	if len(items) == 0 {
		items = append(items, gosx.El("div", gosx.Attrs(gosx.Attr("class", "empty-feed")), gosx.Text("No events recorded.")))
	}
	return gosx.El("section", gosx.Attrs(gosx.Attr("class", "feed")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "feed-heading")), gosx.El("div", gosx.Text(title)), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text(subtitle))), gosx.El("div", gosx.Attrs(gosx.Attr("class", "feed-items")), gosx.Fragment(items...)))
}

func renderReview(cell *model.CellSnapshot, path, csrfToken string) gosx.Node {
	var review *model.Review
	for i := len(cell.Reviews) - 1; i >= 0; i-- {
		if cell.Reviews[i].Status == "pending" || cell.Reviews[i].Status == "blocked" {
			review = &cell.Reviews[i]
			break
		}
	}
	if review == nil {
		return gosx.El("div", gosx.Attrs(gosx.Attr("class", "review-card")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "section-heading")), gosx.Text("STRUCTURAL REVIEW")), gosx.El("div", gosx.Text("No pending entity diff.")))
	}
	children := []gosx.Node{
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "section-heading")), gosx.Text("STRUCTURAL REVIEW")),
		gosx.El("strong", gosx.Text(review.Title)), gosx.El("p", gosx.Text(review.Summary)),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "review-evidence")), gosx.Text(fmt.Sprintf("evidence %s · divergences %d · secret scan %s", review.EvidenceHealth, len(review.DivergenceIDs), review.SecretScanStatus))),
	}
	if len(review.OutstandingShadowIDs) > 0 {
		children = append(children, gosx.El("div", gosx.Attrs(gosx.Attr("class", "evidence-warning")), gosx.Text("Outstanding Shadow Revisions block commit: "+strings.Join(review.OutstandingShadowIDs, ", "))))
	}
	if review.Patch != "" {
		children = append(children, gosx.El("details", gosx.Attrs(gosx.Attr("class", "line-diff")), gosx.El("summary", gosx.Text("Expand line-level diff")), gosx.El("pre", gosx.Text(review.Patch))))
	}
	if review.SignatureChanged {
		children = append(children, gosx.El("strong", gosx.Attrs(gosx.Attr("class", "signature-change")), gosx.Text("Signature changed")))
	}
	for _, finding := range review.SecretFindings {
		children = append(children, gosx.El("div", gosx.Attrs(gosx.Attr("class", "secret-finding")), gosx.Text("Critical secret finding · "+finding.Kind+" · "+finding.Redacted)))
	}
	if review.CommitReady {
		children = append(children, actionForm(csrfToken, "approve-review", "approve-review", hidden("cellID", cell.ID), hidden("reviewID", review.ID), hidden("path", path), gosx.El("button", gosx.Attrs(gosx.Attr("class", "approve-button"), gosx.Attr("type", "submit")), gosx.Text("Approve entity diff"))))
	} else {
		children = append(children, actionForm(csrfToken, "acknowledge-review", "acknowledge-review", hidden("cellID", cell.ID), hidden("reviewID", review.ID), hidden("path", path), gosx.El("label", gosx.El("input", gosx.Attrs(gosx.Attr("type", "checkbox"), gosx.Attr("name", "ackSecret"))), gosx.Text(" Acknowledge secret finding")), gosx.El("label", gosx.El("input", gosx.Attrs(gosx.Attr("type", "checkbox"), gosx.Attr("name", "ackEvidence"))), gosx.Text(" Acknowledge degraded evidence")), gosx.El("input", gosx.Attrs(gosx.Attr("name", "reason"), gosx.Attr("placeholder", "Required acknowledgment reason"), gosx.BoolAttr("required"))), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit")), gosx.Text("Acknowledge risk"))))
	}
	children = append(children, actionForm(csrfToken, "reject-review", "reject-review", hidden("cellID", cell.ID), hidden("reviewID", review.ID), hidden("path", path), gosx.El("input", gosx.Attrs(gosx.Attr("name", "reason"), gosx.Attr("placeholder", "Required rejection reason"), gosx.BoolAttr("required"))), gosx.El("button", gosx.Attrs(gosx.Attr("type", "submit"), gosx.Attr("class", "delete-button")), gosx.Text("Reject and send feedback"))))
	return gosx.El("div", gosx.Attrs(gosx.Attr("class", "review-card")), gosx.Fragment(children...))
}

func renderOrrery(state model.State) gosx.Node {
	cards := make([]gosx.Node, 0, len(state.Cells))
	repos := map[string]int{}
	agents := make([]gosx.Node, 0, len(state.Cells))
	now := time.Now().UTC()
	for i := range state.Cells {
		cell := &state.Cells[i]
		repos[cell.RepoURL]++
		openShadows, pendingApprovals, recentKernel, lastTickAge := 0, 0, 0, "never"
		for _, shadow := range cell.Shadows {
			if shadow.Status == "open" {
				openShadows++
			}
		}
		for _, request := range cell.SecretRequests {
			if request.Status == "pending" {
				pendingApprovals++
			}
		}
		for _, event := range cell.Events {
			if event.Kind == model.EventKernel && event.Timestamp.After(now.Add(-time.Minute)) {
				recentKernel++
			}
			if event.Kind == model.EventIntent && !event.Timestamp.IsZero() {
				lastTickAge = ageLabel(now.Sub(event.Timestamp))
			}
		}
		axes := maxActionDanger(cell.Divergences)
		className := "orrery-node danger-" + dangerClass(axes)
		if cell.EvidenceHealth != "healthy" {
			className += " evidence-degraded"
		}
		cards = append(cards, gosx.El("a", gosx.Attrs(gosx.Attr("class", className), gosx.Attr("href", viewPath(cell.ID, firstFile(cell))), gosx.Attr("data-cell-class", cell.SandboxProfile), gosx.Attr("data-evidence", cell.EvidenceHealth)), gosx.El("div", gosx.Attrs(gosx.Attr("class", "orrery-node-title")), gosx.El("strong", gosx.Text(cell.ID)), gosx.El("span", gosx.Text(containmentLabel(cell)))), gosx.El("div", gosx.Attrs(gosx.Attr("class", "orrery-node-meta")), gosx.Text(cell.RepoURL+" @ "+cell.Branch), gosx.El("br"), gosx.Text(string(cell.Status)+" · "+string(cell.Sandbox.Phase)), gosx.El("br"), gosx.Text(fmt.Sprintf("divergences %d · evidence %s", len(cell.Divergences), cell.EvidenceHealth)), gosx.El("br"), gosx.Text(fmt.Sprintf("shadows %d · approvals %d", openShadows, pendingApprovals)), gosx.El("br"), gosx.Text(fmt.Sprintf("kernel/min %d · last report %s", recentKernel, lastTickAge)), gosx.El("br"), gosx.Text("Action danger "+dangerTriple(axes))), gosx.El("div", gosx.Attrs(gosx.Attr("class", "orrery-bar")), gosx.El("span"))))
		agents = append(agents, gosx.El("li", gosx.Text(defaultText(cell.Agent.ID, "detached")+" · "+cell.ID+" · "+defaultText(cell.Agent.Status, "offline"))))
	}
	repoNames := make([]string, 0, len(repos))
	for repo := range repos {
		repoNames = append(repoNames, repo)
	}
	sort.Strings(repoNames)
	repoItems := make([]gosx.Node, 0, len(repoNames))
	for _, repo := range repoNames {
		repoItems = append(repoItems, gosx.El("li", gosx.Text(fmt.Sprintf("%s · %d cells", repo, repos[repo]))))
	}
	return gosx.El("section", gosx.Attrs(gosx.Attr("id", "orrery-panel"), gosx.Attr("class", "orrery-panel")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "section-heading")), gosx.El("div", gosx.Text("Orrery / fleet view")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text("evidence · divergence · activity"))), gosx.El("p", gosx.Attrs(gosx.Attr("class", "danger-legend")), gosx.Text("Action danger precedence: reversibility > scope > mode. Program danger is shown separately in the kernel feed.")), gosx.El("div", gosx.Attrs(gosx.Attr("class", "orrery-grid")), gosx.Fragment(cards...)), gosx.El("div", gosx.Attrs(gosx.Attr("class", "orrery-index")), gosx.El("section", gosx.El("strong", gosx.Text("REPOSITORIES")), gosx.El("ul", gosx.Fragment(repoItems...))), gosx.El("section", gosx.El("strong", gosx.Text("AGENTS")), gosx.El("ul", gosx.Fragment(agents...)))))
}

func containmentLabel(cell *model.CellSnapshot) string {
	if cell.Capabilities.RecordedOnly || cell.SandboxProfile == "open" {
		return "open · recorded, not contained"
	}
	return defaultText(cell.SandboxProfile, "unclassified") + " · contained"
}

func dangerTriple(axes model.DangerAxes) string {
	return defaultText(axes.Mode, "none") + " / " + defaultText(axes.Scope, "none") + " / " + defaultText(axes.Reversibility, "none")
}
func maxActionDanger(values []model.DivergenceRecord) model.DangerAxes {
	var best model.DangerAxes
	for _, value := range values {
		if dangerRank(value.ActionDanger) > dangerRank(best) {
			best = value.ActionDanger
		}
	}
	return best
}
func dangerRank(axes model.DangerAxes) int {
	return axisRank(axes.Reversibility, []string{"none", "ephemeral", "restart", "reversible", "persistent"})*100 + axisRank(axes.Scope, []string{"none", "event", "process", "cell", "filesystem", "workspace", "system", "network", "external", "global"})*10 + axisRank(axes.Mode, []string{"none", "observe", "read", "mutate", "write", "execute", "control", "admin"})
}
func axisRank(value string, ordered []string) int {
	for i, candidate := range ordered {
		if strings.EqualFold(value, candidate) {
			return i
		}
	}
	return 0
}
func dangerClass(axes model.DangerAxes) string {
	rank := dangerRank(axes)
	if rank >= 400 {
		return "critical"
	}
	if rank >= 250 {
		return "high"
	}
	if rank > 0 {
		return "medium"
	}
	return "low"
}
func ageLabel(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	if duration < time.Minute {
		return fmt.Sprintf("%ds", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	}
	return fmt.Sprintf("%dh", int(duration.Hours()))
}

func activeCell(state model.State, id string) *model.CellSnapshot {
	if id == "" {
		id = state.ActiveCellID
	}
	for i := range state.Cells {
		if state.Cells[i].ID == id {
			return &state.Cells[i]
		}
	}
	if len(state.Cells) > 0 {
		return &state.Cells[0]
	}
	return nil
}

func activeFile(cell *model.CellSnapshot, path string) *model.File {
	if cell == nil {
		return nil
	}
	for i := range cell.Files {
		if cell.Files[i].Path == path {
			return &cell.Files[i]
		}
	}
	if len(cell.Files) > 0 {
		return &cell.Files[0]
	}
	return nil
}

func firstFile(cell *model.CellSnapshot) string {
	if cell != nil && len(cell.Files) > 0 {
		return cell.Files[0].Path
	}
	return ""
}

func viewPath(cellID, path string) string {
	values := url.Values{}
	values.Set("cell", cellID)
	if path != "" {
		values.Set("file", path)
	}
	return "/?" + values.Encode()
}

func actionForm(csrfToken, name, className string, children ...gosx.Node) gosx.Node {
	children = append([]gosx.Node{hidden("csrf_token", csrfToken)}, children...)
	return gosx.El("form", gosx.Attrs(gosx.Attr("method", "post"), gosx.Attr("action", actionBase+name), gosx.Attr("class", className), gosx.Attr("data-gosx-form", "true"), gosx.Attr("data-gosx-enhance", "form"), gosx.Attr("data-gosx-fallback", "native-form")), gosx.Fragment(children...))
}

func hidden(name, value string) gosx.Node {
	return gosx.El("input", gosx.Attrs(gosx.Attr("type", "hidden"), gosx.Attr("name", name), gosx.Attr("value", value)))
}

func option(value string) gosx.Node {
	return gosx.El("option", gosx.Attrs(gosx.Attr("value", value)), gosx.Text(value))
}

func defaultText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func Layout(title string, body gosx.Node) gosx.Node {
	return server.HTMLDocument(title, gosx.Fragment(
		gosx.El("meta", gosx.Attrs(gosx.Attr("name", "theme-color"), gosx.Attr("content", "#07111f"))),
		gosx.El("link", gosx.Attrs(gosx.Attr("rel", "stylesheet"), gosx.Attr("href", "/app.css"))),
	), body)
}

func LoginPage(csrfToken string) gosx.Node {
	return Layout("Mercutio / sign in", gosx.El("main", gosx.Attrs(gosx.Attr("class", "auth-shell")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "auth-card")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "brand")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "brand-mark")), gosx.Text("M")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "brand-name")), gosx.Text("mercutio"))),
			gosx.El("p", gosx.Attrs(gosx.Attr("class", "eyebrow")), gosx.Text("single-operator access")),
			gosx.El("h1", gosx.Text("Sign in to your viewport")),
			gosx.El("p", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text("Use a one-time link or a registered passkey.")),
			gosx.El("form", gosx.Attrs(gosx.Attr("method", "post"), gosx.Attr("action", "/auth/magic-link"), gosx.Attr("data-gosx-form", "true")), hidden("csrf_token", csrfToken), gosx.El("label", gosx.Text("Email")), gosx.El("input", gosx.Attrs(gosx.Attr("id", "operator-email"), gosx.Attr("name", "email"), gosx.Attr("type", "email"), gosx.BoolAttr("required"), gosx.Attr("autocomplete", "email"))), gosx.El("button", gosx.Attrs(gosx.Attr("class", "primary-button"), gosx.Attr("type", "submit")), gosx.Text("Send magic link"))),
			passkeyButton("login", "Use passkey", "/auth/passkey/login/options", "/auth/passkey/login", csrfToken),
			passkeyButton("register", "Register passkey", "/auth/passkey/register/options", "/auth/passkey/register", csrfToken),
			gosx.El("p", gosx.Attrs(gosx.Attr("id", "auth-status"), gosx.Attr("class", "form-help"), gosx.Attr("aria-live", "polite"))),
		),
		gosxauth.WebAuthnScript(),
	))
}

func passkeyButton(action, label, optionsURL, finishURL, csrfToken string) gosx.Node {
	payload := fmt.Sprintf(`{"csrfToken":%q}`, csrfToken)
	attrs := gosx.Attrs(gosx.Attr("class", "ghost-button"), gosx.Attr("type", "button"), gosx.Attr("data-gosx-webauthn-action", action), gosx.Attr("data-gosx-webauthn-options", optionsURL), gosx.Attr("data-gosx-webauthn-finish", finishURL), gosx.Attr("data-gosx-webauthn-status", "#auth-status"), gosx.Attr("data-gosx-webauthn-success", "/"), gosx.Attr("data-gosx-webauthn-payload", payload))
	if action == "register" {
		attrs = append(attrs, gosx.Attr("data-gosx-webauthn-email", "#operator-email"))
	}
	return gosx.El("button", attrs, gosx.Text(label))
}
