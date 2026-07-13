package view

import (
	"fmt"

	"m31labs.dev/gosx"
	"m31labs.dev/gosx/server"
)

func Page(stateJSON string) gosx.Node {
	return gosx.El("main",
		gosx.Attrs(gosx.Attr("class", "app-shell")),
		gosx.El("header",
			gosx.Attrs(gosx.Attr("class", "topbar")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "brand")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "brand-mark")), gosx.Text("M")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "brand-name")), gosx.Text("mercutio"))),
			gosx.El("span", gosx.Attrs(gosx.Attr("class", "eyebrow")), gosx.Text("observe-first control plane")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "topbar-right")),
				gosx.El("span", gosx.Attrs(gosx.Attr("class", "connection-dot"), gosx.Attr("id", "connection-dot")), gosx.Text("")),
				gosx.El("span", gosx.Attrs(gosx.Attr("id", "connection-label")), gosx.Text("connecting")),
				gosx.El("button", gosx.Attrs(gosx.Attr("class", "ghost-button"), gosx.Attr("id", "fleet-toggle")), gosx.Text("Orrery view")),
			),
		),
		gosx.El("section",
			gosx.Attrs(gosx.Attr("class", "workspace")),
			renderSidebar(),
			renderEditor(),
			renderObservability(),
		),
		gosx.El("section", gosx.Attrs(gosx.Attr("id", "orrery-panel"), gosx.Attr("class", "orrery-panel is-hidden")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "section-heading")), gosx.El("div", gosx.Text("Orrery / fleet view")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text("cells · agents · repos"))),
			gosx.El("div", gosx.Attrs(gosx.Attr("id", "orrery-grid"))),
		),
		gosx.RawHTML(fmt.Sprintf(`<script id="initial-state" type="application/json">%s</script>`, stateJSON)),
		gosx.El("script", gosx.Attrs(gosx.Attr("src", "/assets/app.js"))),
	)
}

func renderSidebar() gosx.Node {
	return gosx.El("aside", gosx.Attrs(gosx.Attr("class", "sidebar")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "side-heading")), gosx.El("span", gosx.Text("CELLS")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "count-pill"), gosx.Attr("id", "cell-count")), gosx.Text("0"))),
		gosx.El("div", gosx.Attrs(gosx.Attr("id", "cell-list"), gosx.Attr("class", "cell-list"))),
		gosx.El("form", gosx.Attrs(gosx.Attr("id", "create-cell"), gosx.Attr("class", "create-cell")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "form-label")), gosx.Text("NEW SANDBOX CELL")),
			gosx.El("input", gosx.Attrs(gosx.Attr("name", "repoURL"), gosx.Attr("placeholder", "github.com/org/repo"), gosx.Attr("autocomplete", "off"))),
			gosx.El("div", gosx.Attrs(gosx.Attr("form-row", "")),
				gosx.El("input", gosx.Attrs(gosx.Attr("name", "branch"), gosx.Attr("value", "main"), gosx.Attr("placeholder", "branch"))),
				gosx.El("select", gosx.Attrs(gosx.Attr("name", "profile")), gosx.El("option", gosx.Attrs(gosx.Attr("value", "standard")), gosx.Text("standard")), gosx.El("option", gosx.Attrs(gosx.Attr("value", "strict")), gosx.Text("strict")), gosx.El("option", gosx.Attrs(gosx.Attr("value", "open")), gosx.Text("open"))),
			),
			gosx.El("button", gosx.Attrs(gosx.Attr("class", "primary-button")), gosx.Text("Create cell")),
			gosx.El("p", gosx.Attrs(gosx.Attr("class", "form-help")), gosx.Text("Creates a reviewable local cell. Kubernetes reconciliation is the next adapter.")),
		),
	)
}

func renderEditor() gosx.Node {
	return gosx.El("section", gosx.Attrs(gosx.Attr("class", "editor-column")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-toolbar")),
			gosx.El("div", gosx.Attrs(gosx.Attr("id", "file-tabs"), gosx.Attr("class", "file-tabs"))),
			gosx.El("span", gosx.Attrs(gosx.Attr("class", "revision"), gosx.Attr("id", "revision")), gosx.Text("rev —")),
		),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-meta")),
			gosx.El("div", gosx.El("span", gosx.Attrs(gosx.Attr("class", "file-icon")), gosx.Text("▧")), gosx.El("strong", gosx.Attrs(gosx.Attr("id", "active-file")), gosx.Text("—")), gosx.El("span", gosx.Attrs(gosx.Attr("id", "active-language"), gosx.Attr("class", "muted")), gosx.Text("text"))),
			gosx.El("button", gosx.Attrs(gosx.Attr("class", "save-button"), gosx.Attr("id", "save-edit")), gosx.Text("Save buffer")),
		),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "editor-surface")),
			gosx.El("div", gosx.Attrs(gosx.Attr("id", "line-numbers"), gosx.Attr("class", "line-numbers"))),
			gosx.El("textarea", gosx.Attrs(gosx.Attr("id", "code-editor"), gosx.Attr("spellcheck", "false"), gosx.Attr("aria-label", "Code editor"))),
		),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "outline-bar")),
			gosx.El("span", gosx.Attrs(gosx.Attr("class", "form-label")), gosx.Text("OUTLINE")),
			gosx.El("div", gosx.Attrs(gosx.Attr("id", "outline"), gosx.Attr("class", "outline")), gosx.Text("Select a file to inspect its symbols.")),
		),
		gosx.El("form", gosx.Attrs(gosx.Attr("id", "prompt-form"), gosx.Attr("class", "prompt-bar")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "prompt-icon")), gosx.Text("↗")),
			gosx.El("input", gosx.Attrs(gosx.Attr("id", "prompt-input"), gosx.Attr("placeholder", "Steer the agent in this cell…"), gosx.Attr("autocomplete", "off"))),
			gosx.El("button", gosx.Attrs(gosx.Attr("class", "prompt-button")), gosx.Text("Send prompt")),
		),
	)
}

func renderObservability() gosx.Node {
	return gosx.El("aside", gosx.Attrs(gosx.Attr("class", "observability")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "obs-heading")), gosx.El("div", gosx.Text("OBSERVABILITY")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "count-pill"), gosx.Attr("id", "presence-count")), gosx.Text("0 online"))),
		gosx.El("div", gosx.Attrs(gosx.Attr("id", "divergence"), gosx.Attr("class", "divergence is-hidden")), gosx.El("strong", gosx.Text("Divergence")), gosx.El("span", gosx.Text("Intent and kernel truth are out of step."))),
		feed("intent-feed", "INTENT / TRACE", "intent", "What the agent claims"),
		feed("kernel-feed", "KERNEL / HORIZON", "kernel", "What the sandbox observed"),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "review-card")),
			gosx.El("div", gosx.Attrs(gosx.Attr("class", "section-heading")), gosx.El("span", gosx.Text("STRUCTURAL REVIEW")), gosx.El("span", gosx.Attrs(gosx.Attr("class", "count-pill"), gosx.Attr("id", "review-status")), gosx.Text("pending"))),
			gosx.El("div", gosx.Attrs(gosx.Attr("id", "review-content")), gosx.Text("No pending entity diff.")),
			gosx.El("button", gosx.Attrs(gosx.Attr("class", "approve-button"), gosx.Attr("id", "approve-review")), gosx.Text("Approve entity diff")),
		),
	)
}

func feed(id, title, kind, subtitle string) gosx.Node {
	return gosx.El("section", gosx.Attrs(gosx.Attr("class", "feed")),
		gosx.El("div", gosx.Attrs(gosx.Attr("class", "feed-heading")), gosx.El("div", gosx.El("span", gosx.Attrs(gosx.Attr("class", "feed-dot"), gosx.Attr("data-kind", kind)), gosx.Text("●")), gosx.El("span", gosx.Text(title))), gosx.El("span", gosx.Attrs(gosx.Attr("class", "muted")), gosx.Text(subtitle))),
		gosx.El("div", gosx.Attrs(gosx.Attr("id", id), gosx.Attr("class", "feed-items"))),
	)
}

func Layout(title string, body gosx.Node) gosx.Node {
	return server.HTMLDocument(title, gosx.Fragment(
		gosx.El("meta", gosx.Attrs(gosx.Attr("name", "theme-color"), gosx.Attr("content", "#07111f"))),
		gosx.El("link", gosx.Attrs(gosx.Attr("rel", "stylesheet"), gosx.Attr("href", "/assets/app.css"))),
	), body)
}
