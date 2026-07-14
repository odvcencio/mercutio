package e2e

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func TestGoSXEditorIntelligence(t *testing.T) {
	target := os.Getenv("MERCUTIO_E2E_URL")
	if target == "" {
		t.Skip("set MERCUTIO_E2E_URL to an authenticated Go file editor page")
	}
	cellID := envOr("MERCUTIO_E2E_CELL_ID", "cell-demo")
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(envOr("MERCUTIO_CHROME", "/usr/bin/google-chrome")),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocator, cancelAllocator := chromedp.NewExecAllocator(context.Background(), options...)
	defer cancelAllocator()
	browser, cancelBrowser := chromedp.NewContext(allocator)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browser, 45*time.Second)
	defer cancel()
	viewportWidth := envInt("MERCUTIO_E2E_WIDTH", 1600)
	viewportHeight := envInt("MERCUTIO_E2E_HEIGHT", 900)

	var mutex sync.Mutex
	var browserErrors []string
	chromedp.ListenTarget(ctx, func(event any) {
		switch typed := event.(type) {
		case *runtime.EventConsoleAPICalled:
			parts := make([]string, 0, len(typed.Args))
			for _, argument := range typed.Args {
				parts = append(parts, argument.Description)
			}
			if typed.Type == runtime.APITypeError || typed.Type == runtime.APITypeWarning {
				mutex.Lock()
				browserErrors = append(browserErrors, "console: "+strings.Join(parts, " "))
				mutex.Unlock()
			}
		case *runtime.EventExceptionThrown:
			mutex.Lock()
			browserErrors = append(browserErrors, typed.ExceptionDetails.Error())
			mutex.Unlock()
		case *network.EventLoadingFailed:
			mutex.Lock()
			browserErrors = append(browserErrors, "network: "+typed.ErrorText)
			mutex.Unlock()
		}
	})

	if err := chromedp.Run(ctx,
		chromedp.EmulateViewport(int64(viewportWidth), int64(viewportHeight)),
		chromedp.Navigate(target),
		chromedp.WaitVisible("#editor-content", chromedp.ByQuery),
		chromedp.Poll(`document.querySelectorAll("#editor-highlight-content [class^=syntax-]").length > 0`, nil, chromedp.WithPollingTimeout(15*time.Second)),
		chromedp.Poll(`document.querySelector("#editor-outline-headings")?.textContent.includes("main")`, nil, chromedp.WithPollingTimeout(5*time.Second)),
		chromedp.Poll(`document.querySelector(".editor-collaboration-status")?.textContent.includes("connected")`, nil, chromedp.WithPollingTimeout(5*time.Second)),
		chromedp.Sleep(250*time.Millisecond),
	); err != nil {
		var debug any
		_ = chromedp.Run(ctx,
			chromedp.Evaluate(`(() => { window.__wasmProbe = {stage:"starting"}; (async () => { try { const response = await fetch("/intelligence/gotreesitter.wasm"); window.__wasmProbe.stage = "fetched"; const go = new Go(); const built = await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject); window.__wasmProbe.stage = "instantiated"; const running = go.run(built.instance); window.__wasmProbe.stage = "run-returned"; running.then(code => { window.__wasmProbe.stage = "exited"; window.__wasmProbe.code = code; }).catch(error => { window.__wasmProbe.stage = "rejected"; window.__wasmProbe.error = String(error); }); } catch (error) { window.__wasmProbe.stage = "threw"; window.__wasmProbe.error = String(error); } })(); return true; })()`, nil),
			chromedp.Sleep(2*time.Second),
		)
		_ = chromedp.Run(ctx, chromedp.Evaluate(`({go:typeof window.Go, runtime:typeof window.gotreesitter, probe:window.__wasmProbe, diagnostic:document.querySelector("#editor-diagnostics")?.textContent, scripts:Array.from(document.scripts).map(s=>({src:s.src, complete:s.dataset.gosxRuntime||""})), resources:performance.getEntriesByType("resource").map(r=>r.name).filter(n=>n.includes("intelligence"))})`, &debug))
		t.Fatalf("initial editor intelligence: %v; browser errors: %s; debug: %+v", err, joinedErrors(&mutex, browserErrors), debug)
	}
	var viewport struct {
		InnerWidth  float64 `json:"innerWidth"`
		InnerHeight float64 `json:"innerHeight"`
		ScrollWidth float64 `json:"scrollWidth"`
		EditorLeft  float64 `json:"editorLeft"`
		EditorRight float64 `json:"editorRight"`
		EditorTop   float64 `json:"editorTop"`
		EditorWidth float64 `json:"editorWidth"`
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => { const editor = document.querySelector(".editor-column").getBoundingClientRect(); return {innerWidth, innerHeight, scrollWidth:document.documentElement.scrollWidth, editorLeft:editor.left, editorRight:editor.right, editorTop:editor.top, editorWidth:editor.width}; })()`, &viewport)); err != nil {
		t.Fatal(err)
	}
	if viewport.ScrollWidth > viewport.InnerWidth || viewport.EditorLeft < 0 || viewport.EditorRight > viewport.InnerWidth || viewport.EditorTop < 0 || viewport.EditorWidth < 400 {
		t.Fatalf("editor does not fit viewport: %+v", viewport)
	}
	if screenshotPath := os.Getenv("MERCUTIO_E2E_SCREENSHOT"); screenshotPath != "" {
		var screenshot []byte
		if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&screenshot)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(screenshotPath, screenshot, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := chromedp.Run(ctx,
		chromedp.Focus("#editor-content", chromedp.ByQuery),
		chromedp.Evaluate(`document.querySelector("#editor-content").setSelectionRange(document.querySelector("#editor-content").value.length, document.querySelector("#editor-content").value.length)`, nil),
	); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(ctx,
		chromedp.SendKeys("#editor-content", "func helper() {}\n", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector("#editor-outline-headings")?.textContent.includes("helper")`, nil, chromedp.WithPollingTimeout(5*time.Second)),
	); err != nil {
		var debug any
		_ = chromedp.Run(ctx, chromedp.Evaluate(`({source:document.querySelector("#editor-content")?.value, outline:document.querySelector("#editor-outline-headings")?.textContent, diagnostic:document.querySelector("#editor-diagnostics")?.textContent, highlights:document.querySelectorAll("#editor-highlight-content [class^=syntax-]").length})`, &debug))
		t.Fatalf("incremental edit: %v; browser errors: %s; debug: %+v", err, joinedErrors(&mutex, browserErrors), debug)
	}
	if err := chromedp.Run(ctx,
		chromedp.SendKeys("#editor-content", "func use() { helper() }\n\nfunc pair() {\n\tfirst()\n\tsecond()\n}\n", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector("#editor-outline-headings")?.textContent.includes("use")`, nil, chromedp.WithPollingTimeout(5*time.Second)),
		chromedp.Poll(`fetch("/api/cells/" + `+strconv.Quote(cellID)+`).then(r => r.json()).then(cell => cell.files.some(file => file.path === "cmd/hello/main.go" && file.content.includes("func pair()")))`, nil, chromedp.WithPollingTimeout(5*time.Second)),
	); err != nil {
		t.Fatalf("binary collaboration splice: %v; browser errors: %s", err, joinedErrors(&mutex, browserErrors))
	}
	var navigation struct {
		Definition int `json:"definition"`
		Cursor     int `json:"cursor"`
		Start      int `json:"start"`
		End        int `json:"end"`
	}
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`(() => { const source = document.querySelector("#editor-content"); const reference = source.value.lastIndexOf("helper()"); source.setSelectionRange(reference + 2, reference + 2); source.dispatchEvent(new KeyboardEvent("keydown", {key:"F12", bubbles:true, cancelable:true})); const cursor = source.selectionStart; source.dispatchEvent(new KeyboardEvent("keydown", {key:"ArrowUp", altKey:true, shiftKey:true, bubbles:true, cancelable:true})); return {definition:source.value.indexOf("helper"), cursor, start:source.selectionStart, end:source.selectionEnd}; })()`, &navigation),
	); err != nil {
		t.Fatal(err)
	}
	if navigation.Cursor != navigation.Definition || navigation.End <= navigation.Start {
		t.Fatalf("structural navigation=%+v", navigation)
	}
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(`(() => { const source = document.querySelector("#editor-content"); const first = source.value.indexOf("\tfirst()"); source.focus(); source.setSelectionRange(first, first); source.dispatchEvent(new KeyboardEvent("keydown", {key:"ArrowDown", ctrlKey:true, altKey:true, bubbles:true, cancelable:true})); })()`, nil),
		chromedp.SendKeys("#editor-content", "// ", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector("form[data-editor-native]")?.dataset.multiCursorCount === "2"`, nil, chromedp.WithPollingTimeout(2*time.Second)),
	); err != nil {
		t.Fatalf("multi-cursor edit: %v", err)
	}
	var multiCursorSource string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector("#editor-content").value`, &multiCursorSource)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(multiCursorSource, "// \tfirst()") || !strings.Contains(multiCursorSource, "// \tsecond()") {
		t.Fatalf("multi-cursor source did not update both lines: %q", multiCursorSource)
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => { const source = document.querySelector("#editor-content"); source.dispatchEvent(new KeyboardEvent("keydown", {key:"Escape", bubbles:true, cancelable:true})); source.setSelectionRange(source.value.length, source.value.length); })()`, nil)); err != nil {
		t.Fatal(err)
	}

	if err := chromedp.Run(ctx,
		chromedp.SendKeys("#editor-content", "func (", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector("#editor-diagnostics")?.textContent.includes("error node")`, nil, chromedp.WithPollingTimeout(5*time.Second)),
	); err != nil {
		t.Fatalf("malformed source diagnostic: %v; browser errors: %s", err, joinedErrors(&mutex, browserErrors))
	}
	if errors := joinedErrors(&mutex, browserErrors); errors != "" {
		t.Fatalf("browser errors: %s", errors)
	}
}

func joinedErrors(mutex *sync.Mutex, errors []string) string {
	mutex.Lock()
	defer mutex.Unlock()
	return strings.Join(errors, "; ")
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
