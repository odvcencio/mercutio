package cell

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"m31labs.dev/gosx/crdt"
	"m31labs.dev/mercutio/internal/model"
)

type textDocument struct {
	doc  *crdt.Doc
	text crdt.ObjID
}

type record struct {
	cell   model.Cell
	events []model.Event
	docs   map[string]textDocument
}

// Store is the v1 control-plane state boundary. It is deliberately in-memory
// for the first trunk so the lifecycle and viewport can be tested without a
// Kubernetes cluster. Reconciliation and persistence attach here later.
type Store struct {
	mu       sync.RWMutex
	cells    map[string]*record
	nextID   uint64
	activeID string
}

func NewStore() *Store {
	s := &Store{cells: make(map[string]*record)}
	s.seedDemo()
	return s
}

func (s *Store) seedDemo() {
	files := []model.File{
		{Path: "agent/plan.md", Language: "markdown", Content: "# Cell plan\n\nObserve the agent, steer when needed, then approve the entity diff.\n"},
		{Path: "cmd/hello/main.go", Language: "go", Content: "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello from Mercutio\")\n}\n"},
		{Path: "policy/sandbox.yaml", Language: "yaml", Content: "profile: standard\nfilesystem:\n  workspace: read-write\negress:\n  - github.com\n"},
	}
	created := time.Now().UTC().Add(-7 * time.Minute)
	r := s.newRecordLocked("cell-demo", "https://github.com/odvcencio/mercutio", "main", "standard", files, created)
	r.cell.Agent = model.AgentPresence{ID: "agent-demo", Name: "mercutio-agent", Status: "watching", Connected: true, LastSeen: created}
	r.events = append(r.events,
		model.Event{ID: "evt-demo-1", Kind: model.EventLifecycle, Source: "control-plane", Action: "cell.ready", Summary: "Sandbox cell ready", Detail: "graft worktree materialized on branch main", Danger: "low", Timestamp: created},
		model.Event{ID: "evt-demo-2", Kind: model.EventIntent, Source: "agent", Action: "trace.tick", Summary: "Agent is waiting for direction", Detail: "No prompt has been sent for this cell yet.", Timestamp: created.Add(2 * time.Minute)},
		model.Event{ID: "evt-demo-3", Kind: model.EventKernel, Source: "horizon", Action: "sandbox.attach", Summary: "Horizon attached standard profile", Detail: "fs=workspace; exec=allowlist; egress=github.com", Danger: "low", Timestamp: created.Add(3 * time.Minute)},
	)
	r.cell.Revision = 1
	r.cell.UpdatedAt = created.Add(3 * time.Minute)
	r.cell.Reviews = []model.Review{{ID: "review-demo", Title: "Agent baseline", Entity: "main()", Summary: "Initial entity snapshot is ready for structural review.", Status: "pending", CommitReady: true}}
	s.cells[r.cell.ID] = r
	s.activeID = r.cell.ID
}

func (s *Store) newRecordLocked(id, repoURL, branch, profile string, files []model.File, created time.Time) *record {
	if branch == "" {
		branch = "main"
	}
	if profile == "" {
		profile = "standard"
	}
	r := &record{cell: model.Cell{ID: id, RepoURL: repoURL, Branch: branch, Status: model.CellReady, SandboxProfile: profile, CreatedAt: created, UpdatedAt: created}, docs: make(map[string]textDocument)}
	for i := range files {
		if files[i].Language == "" {
			files[i].Language = languageFor(files[i].Path)
		}
		r.cell.Files = append(r.cell.Files, files[i])
		doc := crdt.NewDoc()
		textID, err := docWithText(doc, files[i].Content)
		if err == nil {
			r.docs[files[i].Path] = textDocument{doc: doc, text: textID}
		}
	}
	return r
}

func docWithText(doc *crdt.Doc, content string) (crdt.ObjID, error) {
	textID, err := doc.MakeText(crdt.Root, "content")
	if err != nil {
		return "", err
	}
	for i, runeValue := range []rune(content) {
		if err := doc.InsertAt(textID, uint64(i), crdt.StringValue(string(runeValue))); err != nil {
			return "", err
		}
	}
	_, err = doc.Commit("initial content")
	return textID, err
}

func (s *Store) Create(repoURL, branch, profile string) (model.CellSnapshot, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return model.CellSnapshot{}, fmt.Errorf("repoURL is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := fmt.Sprintf("cell-%03d", s.nextID)
	now := time.Now().UTC()
	files := []model.File{{Path: "README.md", Language: "markdown", Content: fmt.Sprintf("# %s\n\nCreated from `%s` on branch `%s`.\n", filepath.Base(repoURL), repoURL, branch)}}
	r := s.newRecordLocked(id, repoURL, branch, profile, files, now)
	r.cell.Reviews = []model.Review{{ID: "review-" + id, Title: "Initial entity snapshot", Entity: "README.md", Summary: "The new cell is ready for structural review.", Status: "pending", CommitReady: true}}
	r.events = append(r.events, model.Event{ID: s.eventID(id), Kind: model.EventLifecycle, Source: "operator", Action: "cell.create", Summary: "Sandbox cell requested", Detail: "The cell is ready for an agent attach.", Danger: "medium", Timestamp: now})
	s.cells[id] = r
	s.activeID = id
	return snapshotLocked(r), nil
}

func (s *Store) Destroy(id string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	now := time.Now().UTC()
	r.cell.Status = model.CellStopped
	r.cell.Agent.Connected = false
	r.cell.Agent.Status = "stopped"
	r.cell.UpdatedAt = now
	r.cell.Revision++
	r.events = append(r.events, model.Event{ID: s.eventID(id), Kind: model.EventLifecycle, Source: "operator", Action: "cell.destroy", Summary: "Sandbox cell stopped", Detail: "The control plane released the cell; the worktree remains reviewable.", Danger: "high", Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) ApplyEdit(id, path, content, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return model.CellSnapshot{}, fmt.Errorf("file path is required")
	}
	idx := -1
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == path {
			idx = i
			break
		}
	}
	if idx < 0 {
		r.cell.Files = append(r.cell.Files, model.File{Path: path, Language: languageFor(path)})
		idx = len(r.cell.Files) - 1
		doc := crdt.NewDoc()
		textID, err := docWithText(doc, "")
		if err != nil {
			return model.CellSnapshot{}, fmt.Errorf("create document: %w", err)
		}
		r.docs[path] = textDocument{doc: doc, text: textID}
	}
	doc, ok := r.docs[path]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("document %q is unavailable", path)
	}
	if err := replaceText(doc, content); err != nil {
		return model.CellSnapshot{}, fmt.Errorf("apply edit: %w", err)
	}
	r.cell.Files[idx].Content = content
	r.cell.Files[idx].Modified = true
	r.cell.UpdatedAt = time.Now().UTC()
	r.cell.Revision++
	if actor == "" {
		actor = "operator"
	}
	r.events = append(r.events, model.Event{ID: s.eventID(id), Kind: model.EventEdit, Source: actor, Action: "buffer.update", Summary: fmt.Sprintf("%s edited %s", actor, path), Detail: "The shared document revision was committed through the cell document.", Danger: "medium", Timestamp: r.cell.UpdatedAt})
	return snapshotLocked(r), nil
}

func replaceText(doc textDocument, content string) error {
	length, err := doc.doc.ListLen(doc.text)
	if err != nil {
		return err
	}
	for i := length - 1; i >= 0; i-- {
		if err := doc.doc.DeleteAt(doc.text, uint64(i)); err != nil {
			return err
		}
	}
	for i, runeValue := range []rune(content) {
		if err := doc.doc.InsertAt(doc.text, uint64(i), crdt.StringValue(string(runeValue))); err != nil {
			return err
		}
	}
	_, err = doc.doc.Commit("buffer update")
	return err
}

func (s *Store) Prompt(id, prompt string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return model.CellSnapshot{}, fmt.Errorf("prompt is required")
	}
	now := time.Now().UTC()
	r.cell.Status = model.CellSteering
	r.cell.Agent.Status = "steering"
	r.cell.Agent.LastSeen = now
	r.cell.Agent.Connected = true
	r.cell.UpdatedAt = now
	r.cell.Revision++
	r.events = append(r.events,
		model.Event{ID: s.eventID(id), Kind: model.EventIntent, Source: "operator", Action: "agent.prompt", Summary: "Prompt sent to agent", Detail: prompt, Timestamp: now},
		model.Event{ID: s.eventID(id), Kind: model.EventPresence, Source: "agent", Action: "agent.steering", Summary: "Agent is processing the new direction", Detail: "Kernel truth will arrive independently from Horizon.", Timestamp: now.Add(time.Millisecond)},
	)
	return snapshotLocked(r), nil
}

func (s *Store) ApproveReview(id, reviewID string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	for i := range r.cell.Reviews {
		if r.cell.Reviews[i].ID == reviewID {
			r.cell.Reviews[i].Status = "approved"
			now := time.Now().UTC()
			r.cell.UpdatedAt = now
			r.cell.Revision++
			r.events = append(r.events, model.Event{ID: s.eventID(id), Kind: model.EventReview, Source: "operator", Action: "review.approve", Summary: "Entity diff approved", Detail: "Buckley commit handoff is ready inside the cell.", Danger: "high", Timestamp: now})
			return snapshotLocked(r), nil
		}
	}
	return model.CellSnapshot{}, fmt.Errorf("review %q not found", reviewID)
}

func (s *Store) Snapshot(id string) (model.CellSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	return snapshotLocked(r), nil
}

func (s *Store) State(connected int) model.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := model.State{ActiveCellID: s.activeID, Connected: connected}
	for _, r := range s.cells {
		state.Cells = append(state.Cells, snapshotLocked(r))
	}
	sort.Slice(state.Cells, func(i, j int) bool { return state.Cells[i].ID < state.Cells[j].ID })
	return state
}

func (s *Store) Documents(id string) map[string]*crdt.Doc {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cells[id]
	if !ok {
		return nil
	}
	result := make(map[string]*crdt.Doc, len(r.docs))
	for path, document := range r.docs {
		result[path] = document.doc
	}
	return result
}

func snapshotLocked(r *record) model.CellSnapshot {
	cell := r.cell
	cell.Files = append([]model.File(nil), r.cell.Files...)
	cell.Reviews = append([]model.Review(nil), r.cell.Reviews...)
	var intent, kernel int
	for _, evt := range r.events {
		if evt.Kind == model.EventIntent {
			intent++
		}
		if evt.Kind == model.EventKernel {
			kernel++
		}
	}
	cell.IntentCount = intent
	cell.KernelEventCount = kernel
	return model.CellSnapshot{Cell: cell, Events: append([]model.Event(nil), r.events...)}
}

func (s *Store) eventID(cellID string) string {
	s.nextID++
	return fmt.Sprintf("evt-%s-%d", cellID, s.nextID)
}

func languageFor(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return "go"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	case ".md", ".mdpp":
		return "markdown"
	case ".hcl":
		return "hcl"
	default:
		return "text"
	}
}
