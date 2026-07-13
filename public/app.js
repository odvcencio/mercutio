(() => {
  const initial = JSON.parse(document.getElementById("initial-state").textContent || "{}");
  let state = initial;
  let activeCellID = state.activeCellID || state.cells?.[0]?.id || "";
  let activeFilePath = "";
  let editorDirty = false;
  let socket;

  const $ = (id) => document.getElementById(id);
  const activeCell = () => state.cells?.find((cell) => cell.id === activeCellID) || state.cells?.[0];
  const escapeHTML = (value) => String(value ?? "").replace(/[&<>\"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[char]));
  const time = (value) => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  function render() {
    renderCells();
    renderEditor();
    renderFeeds();
    renderReview();
    renderOrrery();
    $("presence-count").textContent = `${state.connected || 0} online`;
  }

  function renderCells() {
    $("cell-count").textContent = String(state.cells?.length || 0);
    $("cell-list").innerHTML = (state.cells || []).map((cell) => `
      <button class="cell-card ${cell.id === activeCellID ? "active" : ""}" data-cell-id="${escapeHTML(cell.id)}">
        <div class="cell-name"><span class="cell-state ${escapeHTML(cell.status)}"></span>${escapeHTML(cell.id)}</div>
        <div class="cell-meta">${escapeHTML(cell.repoURL)} @ ${escapeHTML(cell.branch)}</div>
        <div class="cell-agent">◉ ${escapeHTML(cell.agent?.name || "agent detached")} · ${escapeHTML(cell.agent?.status || "offline")}</div>
      </button>`).join("") || `<div class="empty-feed">No cells yet. Create one from a repository.</div>`;
  }

  function renderEditor() {
    const cell = activeCell();
    if (!cell) {
      $("file-tabs").innerHTML = "";
      $("active-file").textContent = "No cell";
      $("code-editor").value = "";
      return;
    }
    if (!cell.files.some((file) => file.path === activeFilePath)) activeFilePath = cell.files[0]?.path || "";
    $("file-tabs").innerHTML = (cell.files || []).map((file) => `<button class="file-tab ${file.path === activeFilePath ? "active" : ""}" data-file-path="${escapeHTML(file.path)}">${escapeHTML(file.path)}</button>`).join("");
    const file = cell.files.find((item) => item.path === activeFilePath);
    $("active-file").textContent = file?.path || "—";
    $("active-language").textContent = file?.language || "text";
    $("revision").textContent = `rev ${cell.revision ?? "—"}${file?.modified ? " · modified" : ""}`;
    if (!editorDirty && document.activeElement !== $("code-editor")) $("code-editor").value = file?.content || "";
    updateLineNumbers();
    renderOutline(file?.content || "", file?.language || "text");
  }

  function updateLineNumbers() {
    const lines = Math.max(1, $("code-editor").value.split("\n").length);
    $("line-numbers").textContent = Array.from({ length: lines }, (_, index) => String(index + 1)).join("\n");
  }

  function renderOutline(content, language) {
    const matches = language === "go"
      ? [...content.matchAll(/\bfunc\s+([A-Za-z0-9_]+)/g)].map((match) => `func ${match[1]}`)
      : [...content.matchAll(/^(?:#{1,3}\s+|(?:[A-Za-z0-9_.-]+:)\s*|(?:function|class|def)\s+)([^\n{]+)/gm)].map((match) => match[1].trim());
    $("outline").innerHTML = matches.length ? matches.slice(0, 12).map((item) => `<span class="outline-item">${escapeHTML(item)}</span>`).join("") : `<span class="muted">No symbols in this buffer.</span>`;
  }

  function renderFeeds() {
    const cell = activeCell();
    const events = cell?.events || [];
    renderFeed($("intent-feed"), events.filter((event) => event.kind === "intent"));
    renderFeed($("kernel-feed"), events.filter((event) => event.kind === "kernel"));
    const latestIntent = events.filter((event) => event.kind === "intent").at(-1);
    const latestKernel = events.filter((event) => event.kind === "kernel").at(-1);
    const divergence = latestIntent && (!latestKernel || new Date(latestIntent.timestamp) > new Date(latestKernel.timestamp));
    $("divergence").classList.toggle("is-hidden", !divergence);
  }

  function renderFeed(target, events) {
    target.innerHTML = events.slice(-8).reverse().map((event) => `<article class="feed-item">
      <div class="event-head"><span class="event-action">${escapeHTML(event.action)}</span><span class="muted">${time(event.timestamp)}</span></div>
      <div>${escapeHTML(event.summary)}${event.danger ? ` <span class="event-danger">· ${escapeHTML(event.danger)}</span>` : ""}</div>
      ${event.detail ? `<div class="event-detail">${escapeHTML(event.detail)}</div>` : ""}
    </article>`).join("") || `<div class="empty-feed">No events in this pane.</div>`;
  }

  function renderReview() {
    const review = activeCell()?.reviews?.find((item) => item.status === "pending") || activeCell()?.reviews?.[0];
    if (!review) {
      $("review-content").textContent = "No pending entity diff.";
      $("review-status").textContent = "clear";
      $("approve-review").disabled = true;
      return;
    }
    $("review-status").textContent = review.status;
    $("review-content").innerHTML = `<div class="review-entity">${escapeHTML(review.title)} · ${escapeHTML(review.entity)}</div><div class="review-summary">${escapeHTML(review.summary)}</div>`;
    $("approve-review").disabled = review.status !== "pending";
  }

  function renderOrrery() {
    $("orrery-grid").innerHTML = (state.cells || []).map((cell) => `<article class="orrery-node">
      <div class="orrery-node-title"><span>${escapeHTML(cell.id)}</span><span class="cell-state ${escapeHTML(cell.status)}"></span></div>
      <div class="orrery-node-meta">${escapeHTML(cell.repoURL)}<br>agent: ${escapeHTML(cell.agent?.status || "offline")}<br>intent ${cell.intentCount || 0} / kernel ${cell.kernelEventCount || 0}</div>
      <div class="orrery-bar"><span style="width:${Math.min(100, 30 + (cell.revision || 0) * 8)}%"></span></div>
    </article>`).join("");
  }

  async function post(path, body) {
    const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "request failed");
    return payload;
  }

  function applyCell(snapshot) {
    const index = state.cells.findIndex((cell) => cell.id === snapshot.id);
    if (index < 0) state.cells.push(snapshot); else state.cells[index] = snapshot;
    activeCellID = snapshot.id;
    editorDirty = false;
    render();
  }

  function connect() {
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${protocol}://${location.host}/gosx/hub/cells`);
    socket.addEventListener("open", () => {
      $("connection-dot").className = "connection-dot connected";
      $("connection-label").textContent = "hub connected";
      socket.send(JSON.stringify({ event: "cell:select", data: { cellID: activeCellID } }));
    });
    socket.addEventListener("close", () => {
      $("connection-dot").className = "connection-dot error";
      $("connection-label").textContent = "hub disconnected";
      setTimeout(connect, 2000);
    });
    socket.addEventListener("message", (message) => {
      const envelope = JSON.parse(message.data);
      if (envelope.event === "state") { state = envelope.data; render(); return; }
      if (envelope.event === "cell:update") { applyCell(envelope.data); return; }
      if (envelope.event === "presence:count") { state.connected = envelope.data.count; $("presence-count").textContent = `${state.connected} online`; }
    });
  }

  document.addEventListener("click", (event) => {
    const cellButton = event.target.closest("[data-cell-id]");
    if (cellButton) { activeCellID = cellButton.dataset.cellId; activeFilePath = ""; editorDirty = false; render(); socket?.send(JSON.stringify({ event: "cell:select", data: { cellID: activeCellID } })); return; }
    const fileButton = event.target.closest("[data-file-path]");
    if (fileButton) { activeFilePath = fileButton.dataset.filePath; editorDirty = false; render(); return; }
    if (event.target.id === "fleet-toggle") $("orrery-panel").classList.toggle("is-hidden");
  });

  $("code-editor").addEventListener("input", () => { editorDirty = true; updateLineNumbers(); renderOutline($("code-editor").value, activeCell()?.files.find((file) => file.path === activeFilePath)?.language || "text"); });
  $("code-editor").addEventListener("scroll", () => { $("line-numbers").scrollTop = $("code-editor").scrollTop; });
  $("save-edit").addEventListener("click", async () => {
    try { applyCell(await post(`/api/cells/${encodeURIComponent(activeCellID)}/edit`, { path: activeFilePath, content: $("code-editor").value, actor: "operator" })); }
    catch (error) { alert(error.message); }
  });
  $("prompt-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = $("prompt-input");
    if (!input.value.trim()) return;
    try { applyCell(await post(`/api/cells/${encodeURIComponent(activeCellID)}/prompt`, { prompt: input.value })); input.value = ""; }
    catch (error) { alert(error.message); }
  });
  $("create-cell").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    try { applyCell(await post("/api/cells", { repoURL: form.get("repoURL"), branch: form.get("branch"), profile: form.get("profile") })); event.target.reset(); event.target.branch.value = "main"; }
    catch (error) { alert(error.message); }
  });
  $("approve-review").addEventListener("click", async () => {
    const review = activeCell()?.reviews?.find((item) => item.status === "pending");
    if (!review) return;
    try { applyCell(await post(`/api/cells/${encodeURIComponent(activeCellID)}/reviews/${encodeURIComponent(review.id)}/approve`, {})); }
    catch (error) { alert(error.message); }
  });

  render();
  connect();
})();
