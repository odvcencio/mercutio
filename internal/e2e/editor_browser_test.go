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
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
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
		chromedp.WaitVisible(".file-tree", chromedp.ByQuery),
		chromedp.Poll(`document.querySelector(".file-tree-file.active")?.title === "cmd/hello/main.go" && Array.from(document.querySelectorAll(".file-tree-directory > summary")).some(node => node.textContent === "cmd")`, nil, chromedp.WithPollingTimeout(2*time.Second)),
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

	var checklist struct {
		FindReplaced    bool `json:"findReplaced"`
		Commented       bool `json:"commented"`
		Indented        bool `json:"indented"`
		BracketMatched  bool `json:"bracketMatched"`
		UndoDepth       int  `json:"undoDepth"`
		UndoRestored    bool `json:"undoRestored"`
		RedoRestored    bool `json:"redoRestored"`
		Lines           int  `json:"lines"`
		PastedLines     int  `json:"pastedLines"`
		LargeFileEdited bool `json:"largeFileEdited"`
	}
	const editorChecklist = `(() => {
		const source = document.querySelector("#editor-content");
		const form = source.closest("form[data-editor-native]");
		const key = options => source.dispatchEvent(new KeyboardEvent("keydown", {bubbles:true,cancelable:true,...options}));

		const oldName = "first";
		const oldCount = source.value.split(oldName).length - 1;
		document.querySelector('[data-code-command="find"]').click();
		const query = document.querySelector('[data-code-find="query"]');
		const replacement = document.querySelector('[data-code-find="replacement"]');
		query.value = oldName;
		query.dispatchEvent(new Event("input", {bubbles:true}));
		replacement.value = "alpha";
		document.querySelector('[data-code-find-action="replace-all"]').click();
		const findReplaced = oldCount > 0 && !source.value.includes(oldName) && source.value.includes("alpha");
		source.setSelectionRange(source.value.length, source.value.length);
		source.setRangeText("\nfunc checklist() {\n\tcheckOne()\n\tcheckTwo()\n}\n", source.selectionStart, source.selectionEnd, "end");
		source.dispatchEvent(new InputEvent("input", {bubbles:true,inputType:"insertText"}));

		const commentStart = source.value.indexOf("\tcheckOne()");
		const commentEnd = source.value.indexOf("\n", source.value.indexOf("checkTwo()", commentStart));
		source.setSelectionRange(commentStart, commentEnd);
		key({key:"/",ctrlKey:true});
		const commented = source.value.slice(commentStart, commentEnd + 6).split("\n").every(line => line.trimStart().startsWith("//"));
		key({key:"/",ctrlKey:true});

		const indentStart = source.value.indexOf("\tcheckOne()");
		const indentEnd = source.value.indexOf("\n", source.value.indexOf("checkTwo()", indentStart));
		source.setSelectionRange(indentStart, indentEnd);
		key({key:"Tab"});
		const indented = source.value.slice(indentStart, indentEnd + 2).split("\n").every(line => line.startsWith("\t\t"));

		const bracket = source.value.indexOf("{", source.value.indexOf("func pair"));
		source.setSelectionRange(bracket, bracket);
		key({key:"\\",ctrlKey:true,shiftKey:true});
		const bracketMatched = Boolean(form.dataset.bracketMatch) && source.value.slice(source.selectionStart, source.selectionEnd) === "}";

		source.setSelectionRange(source.value.length, source.value.length);
		const beforeHistory = source.value;
		for (let i=0; i<50; i++) {
			source.dispatchEvent(new InputEvent("beforeinput", {bubbles:true,cancelable:true,inputType:"insertText",data:String(i%10)}));
			source.setRangeText(String(i%10), source.selectionStart, source.selectionEnd, "end");
			source.dispatchEvent(new InputEvent("input", {bubbles:true,inputType:"insertText",data:String(i%10)}));
		}
		const afterHistory = source.value;
		const undoDepth = Number(form.dataset.undoDepth || 0);
		for (let i=0; i<50; i++) key({key:"z",ctrlKey:true});
		const undoRestored = source.value === beforeHistory;
		for (let i=0; i<50; i++) key({key:"y",ctrlKey:true});
		const redoRestored = source.value === afterHistory;

		const seed = Array.from({length:4500}, (_, i) => "// seed-" + i).join("\n") + "\n";
		const pasted = Array.from({length:500}, (_, i) => "// paste-" + i).join("\n") + "\n";
		source.value = seed;
		source.setSelectionRange(source.value.length, source.value.length);
		source.dispatchEvent(new InputEvent("beforeinput", {bubbles:true,cancelable:true,inputType:"insertFromPaste",data:pasted}));
		source.setRangeText(pasted, source.selectionStart, source.selectionEnd, "end");
		source.dispatchEvent(new InputEvent("input", {bubbles:true,inputType:"insertFromPaste",data:pasted}));
		source.dispatchEvent(new InputEvent("beforeinput", {bubbles:true,cancelable:true,inputType:"insertText",data:"// edited\n"}));
		source.setRangeText("// edited\n", source.selectionStart, source.selectionEnd, "end");
		source.dispatchEvent(new InputEvent("input", {bubbles:true,inputType:"insertText",data:"// edited\n"}));
		return {findReplaced,commented,indented,bracketMatched,undoDepth,undoRestored,redoRestored,lines:source.value.split("\n").length-1,pastedLines:(source.value.match(/^\/\/ paste-/gm)||[]).length,largeFileEdited:source.value.endsWith("// edited\n")};
	})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(editorChecklist, &checklist)); err != nil {
		t.Fatal(err)
	}
	if !checklist.FindReplaced || !checklist.Commented || !checklist.Indented || !checklist.BracketMatched || checklist.UndoDepth < 50 || !checklist.UndoRestored || !checklist.RedoRestored || checklist.Lines != 5001 || checklist.PastedLines != 500 || !checklist.LargeFileEdited {
		t.Fatalf("full editor checklist failed: %+v", checklist)
	}
	if errors := joinedErrors(&mutex, browserErrors); errors != "" {
		t.Fatalf("browser errors: %s", errors)
	}
}

func TestOrreryScaleAndPerformance(t *testing.T) {
	target := os.Getenv("MERCUTIO_E2E_URL")
	if target == "" {
		t.Skip("set MERCUTIO_E2E_URL to an authenticated fleet page")
	}
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(envOr("MERCUTIO_CHROME", "/usr/bin/google-chrome")),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
	)
	allocator, cancelAllocator := chromedp.NewExecAllocator(context.Background(), options...)
	defer cancelAllocator()
	browser, cancelBrowser := chromedp.NewContext(allocator)
	defer cancelBrowser()
	ctx, cancel := context.WithTimeout(browser, 45*time.Second)
	defer cancel()
	wantCells := envInt("MERCUTIO_E2E_CELL_COUNT", 50)
	if err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1600, 900),
		chromedp.Navigate("data:text/html,<p id=warmup>ready</p>"),
		chromedp.WaitVisible("#warmup", chromedp.ByQuery),
	); err != nil {
		t.Fatal(err)
	}
	paintStarted := time.Now()
	if err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.WaitVisible(".topbar", chromedp.ByQuery),
	); err != nil {
		t.Fatal(err)
	}
	paintReady := time.Since(paintStarted)
	var firstFrame []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&firstFrame)); err != nil {
		t.Fatal(err)
	}
	if len(firstFrame) < 1024 || paintReady >= 1500*time.Millisecond {
		t.Fatalf("first rendered frame = %s (%d bytes), budget 1.5s", paintReady, len(firstFrame))
	}
	if err := chromedp.Run(ctx,
		chromedp.WaitVisible("#orrery-panel", chromedp.ByQuery),
		chromedp.Poll(`document.querySelectorAll(".orrery-node").length === `+strconv.Itoa(wantCells), nil, chromedp.WithPollingTimeout(10*time.Second)),
		chromedp.Poll(`typeof window.gotreesitter === "object" && document.querySelectorAll("#editor-highlight-content [class^=syntax-]").length > 0`, nil, chromedp.WithPollingTimeout(15*time.Second)),
	); err != nil {
		var debug any
		_ = chromedp.Run(ctx, chromedp.Evaluate(`({cells:document.querySelectorAll(".orrery-node").length,runtime:typeof window.gotreesitter,diagnostic:document.querySelector("#editor-diagnostics")?.textContent})`, &debug))
		t.Fatalf("initial scale page: %v; debug=%+v", err, debug)
	}

	var measured struct {
		Cells           int       `json:"cells"`
		BulkActions     int       `json:"bulkActions"`
		FirstPaint      float64   `json:"firstPaint"`
		FCP             float64   `json:"fcp"`
		WASMResponseEnd float64   `json:"wasmResponseEnd"`
		ResponseStart   float64   `json:"responseStart"`
		ResponseEnd     float64   `json:"responseEnd"`
		DOMInteractive  float64   `json:"domInteractive"`
		LocalEchoP95    float64   `json:"localEchoP95"`
		WASMUpdateP95   float64   `json:"wasmUpdateP95"`
		FrameAverage    float64   `json:"frameAverage"`
		FrameP95        float64   `json:"frameP95"`
		FrameSamples    []float64 `json:"frameSamples"`
	}
	const measurement = `(async () => {
		const percentile = (values, p) => values.slice().sort((a,b) => a-b)[Math.ceil(values.length*p)-1];
		const source = document.querySelector("#editor-content");
		const local = [];
		for (let i=0; i<25; i++) { const start=performance.now(); source.setRangeText(" ", source.value.length, source.value.length, "end"); source.dispatchEvent(new Event("input", {bubbles:true})); local.push(performance.now()-start); }
		const runtime = window.gotreesitter;
		const documentID = "mercutio-performance-" + Date.now();
		let text = "package main\n\nfunc main() {}\n";
		const opened = runtime.open("go", documentID, text);
		if (!opened || opened.ok !== true) throw new Error(opened?.error || "performance document open failed");
		const wasm = [];
		for (let i=0; i<25; i++) { text += "\n"; const start=performance.now(); const result=runtime.update(documentID, text); wasm.push(performance.now()-start); if (!result || result.ok !== true) throw new Error(result?.error || "performance update failed"); }
		runtime.close(documentID);
		const frames = [];
		await new Promise(resolve => { let previous=0; let count=0; const step = now => { if (previous) frames.push(now-previous); previous=now; window.scrollTo(0, (count%2)*document.documentElement.scrollHeight); if (++count >= 121) resolve(); else requestAnimationFrame(step); }; requestAnimationFrame(step); });
		const paints = performance.getEntriesByType("paint");
		const firstPaint = paints.find(entry => entry.name === "first-paint")?.startTime || 0;
		const fcp = paints.find(entry => entry.name === "first-contentful-paint")?.startTime || 0;
		const wasmResource = performance.getEntriesByType("resource").find(entry => entry.name.includes("gotreesitter.wasm"));
		const navigation = performance.getEntriesByType("navigation")[0];
		return { cells:document.querySelectorAll(".orrery-node").length, bulkActions:document.querySelectorAll("#orrery-panel button,#orrery-panel form").length, firstPaint, fcp, wasmResponseEnd:wasmResource?.responseEnd||0, responseStart:navigation?.responseStart||0, responseEnd:navigation?.responseEnd||0, domInteractive:navigation?.domInteractive||0, localEchoP95:percentile(local,.95), wasmUpdateP95:percentile(wasm,.95), frameAverage:frames.reduce((a,b)=>a+b,0)/frames.length, frameP95:percentile(frames,.95), frameSamples:frames };
	})()`
	if err := chromedp.Run(ctx, chromedp.Evaluate(measurement, &measured, func(params *runtime.EvaluateParams) *runtime.EvaluateParams {
		return params.WithAwaitPromise(true)
	})); err != nil {
		t.Fatal(err)
	}
	if measured.Cells != wantCells || measured.BulkActions != 0 {
		t.Fatalf("Orrery scale/actions = %+v", measured)
	}
	if measured.FirstPaint <= 0 || measured.WASMResponseEnd <= 0 || measured.FirstPaint >= measured.WASMResponseEnd {
		t.Fatalf("first paint is not independent of WASM or exceeds 1.5s: %+v", measured)
	}
	if measured.LocalEchoP95 >= 16 || measured.WASMUpdateP95 >= 30 {
		t.Fatalf("editor performance budget exceeded: %+v", measured)
	}
	if len(measured.FrameSamples) != 120 || measured.FrameAverage > 18.2 || measured.FrameP95 > 20 {
		t.Fatalf("50-cell Orrery did not sustain the frame budget: %+v", measured)
	}
}

func TestPeerEditLatencyBudget(t *testing.T) {
	target := envOr("MERCUTIO_E2E_PEER_URL", os.Getenv("MERCUTIO_E2E_URL"))
	if target == "" {
		t.Skip("set MERCUTIO_E2E_URL to an authenticated collaborative editor page")
	}
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(envOr("MERCUTIO_CHROME", "/usr/bin/google-chrome")),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
	)
	allocator, cancelAllocator := chromedp.NewExecAllocator(context.Background(), options...)
	defer cancelAllocator()
	writer, cancelWriter := chromedp.NewContext(allocator)
	defer cancelWriter()
	peer, cancelPeer := chromedp.NewContext(allocator)
	defer cancelPeer()
	writer, cancelWriterTimeout := context.WithTimeout(writer, 30*time.Second)
	defer cancelWriterTimeout()
	peer, cancelPeerTimeout := context.WithTimeout(peer, 30*time.Second)
	defer cancelPeerTimeout()
	ready := func(ctx context.Context) error {
		return chromedp.Run(ctx,
			chromedp.Navigate(target),
			chromedp.WaitVisible("#editor-content", chromedp.ByQuery),
			chromedp.Poll(`document.querySelector(".editor-collaboration-status")?.textContent.includes("connected")`, nil, chromedp.WithPollingTimeout(10*time.Second)),
		)
	}
	if err := ready(writer); err != nil {
		t.Fatal(err)
	}
	if err := ready(peer); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(peer, chromedp.Evaluate(`(() => { window.__mercutioPeerAt = 0; document.querySelector("#editor-content").addEventListener("gosx:remote-input", () => { window.__mercutioPeerAt = Date.now(); }, {once:true}); return true; })()`, nil)); err != nil {
		t.Fatal(err)
	}
	var sent int64
	if err := chromedp.Run(writer, chromedp.Evaluate(`(() => { const source=document.querySelector("#editor-content"); const sent=Date.now(); source.setRangeText("\n// peer-latency-probe\n", source.value.length, source.value.length, "end"); source.dispatchEvent(new Event("input", {bubbles:true})); return sent; })()`, &sent)); err != nil {
		t.Fatal(err)
	}
	if err := chromedp.Run(peer, chromedp.Poll(`window.__mercutioPeerAt > 0`, nil, chromedp.WithPollingTimeout(5*time.Second))); err != nil {
		t.Fatal(err)
	}
	var received int64
	if err := chromedp.Run(peer, chromedp.Evaluate(`window.__mercutioPeerAt`, &received)); err != nil {
		t.Fatal(err)
	}
	if latency := time.Duration(received-sent) * time.Millisecond; latency < 0 || latency >= 120*time.Millisecond {
		t.Fatalf("peer edit latency = %s, budget 120ms", latency)
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
