package cell

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"m31labs.dev/gosx/crdt"
	"m31labs.dev/mercutio/internal/capability"
	"m31labs.dev/mercutio/internal/divergence"
	"m31labs.dev/mercutio/internal/evidence"
	"m31labs.dev/mercutio/internal/intelligence"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/policy"
	"m31labs.dev/mercutio/internal/review"
	"m31labs.dev/mercutio/internal/sandbox"
	"m31labs.dev/mercutio/internal/secrets"
	shadowmerge "m31labs.dev/mercutio/internal/shadow"
)

type textDocument struct {
	doc  *crdt.Doc
	text crdt.ObjID
}

// TextAnchor identifies a logical text position relative to a stable CRDT
// element so a cursor survives concurrent inserts and deletes.
type TextAnchor struct {
	ElemID   string `json:"elemID,omitempty"`
	Affinity string `json:"affinity,omitempty"`
	Boundary string `json:"boundary,omitempty"`
}

type writerState struct {
	actor         string
	activeUntil   time.Time
	before        string
	historyStart  int
	changeGroupID string
}

type editOperation struct {
	Actor         string      `json:"actor"`
	Path          string      `json:"path"`
	Inserted      []crdt.OpID `json:"inserted,omitempty"`
	Deleted       []crdt.OpID `json:"deleted,omitempty"`
	CreatedAt     time.Time   `json:"createdAt"`
	Reverted      bool        `json:"reverted,omitempty"`
	ChangeGroupID string      `json:"changeGroupId,omitempty"`
}

type record struct {
	cell        model.Cell
	events      []model.Event
	docs        map[string]textDocument
	baseline    []model.File
	attachToken string
	armToken    string
	workdir     string
	writers     map[string]writerState
	openWriters map[string]map[string]bool
	history     []editOperation
}

type Options struct {
	Runtime       sandbox.Runtime
	Intelligence  *intelligence.Service
	Reviews       *review.Service
	Committer     review.Committer
	WorktreeRoot  string
	HubURL        string
	Evidence      *evidence.Log
	CapabilityKey []byte
	StatePath     string
	SecretBroker  *secrets.Broker
}

// Store is the control-plane state boundary. Runtime-specific work happens
// behind sandbox.Runtime; local development uses the memory runtime while the
// Kubernetes deployment reconciles real pods from the installed Helm template.
type Store struct {
	mu            sync.RWMutex
	cells         map[string]*record
	nextID        uint64
	activeID      string
	runtime       sandbox.Runtime
	reviews       *review.Service
	intelligence  *intelligence.Service
	committer     review.Committer
	secretBroker  *secrets.Broker
	worktreeRoot  string
	hubURL        string
	evidence      *evidence.Log
	capabilities  *capability.Authority
	statePath     string
	kernelBatches map[string]uint64
}

func NewStore() *Store { return NewStoreWithOptions(Options{}) }

func NewStoreWithRuntime(runtime sandbox.Runtime) *Store {
	return NewStoreWithOptions(Options{Runtime: runtime})
}

func NewStoreWithOptions(options Options) *Store {
	if options.Runtime == nil {
		options.Runtime = sandbox.NewMemoryRuntime()
	}
	if options.Intelligence == nil {
		options.Intelligence = intelligence.New()
	}
	if options.Reviews == nil {
		options.Reviews = review.NewService(options.Intelligence)
	}
	if options.Committer == nil {
		options.Committer = review.LocalCommitter{}
	}
	if options.Evidence == nil {
		options.Evidence, _ = evidence.Open("")
	}
	if options.SecretBroker == nil {
		options.SecretBroker = secrets.NewBroker()
	}
	s := &Store{
		cells:         make(map[string]*record),
		runtime:       options.Runtime,
		reviews:       options.Reviews,
		intelligence:  options.Intelligence,
		committer:     options.Committer,
		secretBroker:  options.SecretBroker,
		worktreeRoot:  options.WorktreeRoot,
		hubURL:        options.HubURL,
		evidence:      options.Evidence,
		capabilities:  capability.New(options.CapabilityKey),
		statePath:     options.StatePath,
		kernelBatches: make(map[string]uint64),
	}
	loaded, err := s.loadState()
	if err != nil {
		panic(fmt.Errorf("load durable cell state: %w", err))
	}
	if !loaded {
		s.seedDemo()
		s.mu.Lock()
		_ = s.persistLocked()
		s.mu.Unlock()
	}
	return s
}

// SetCommitter installs the commit boundary after the collaboration hub is
// constructed. This lets an agent-side committer route approval into the
// active cell without making the store depend on the transport package.
func (s *Store) SetCommitter(committer review.Committer) {
	if committer == nil {
		return
	}
	s.mu.Lock()
	s.committer = committer
	s.mu.Unlock()
}

func (s *Store) seedDemo() {
	files := []model.File{
		{Path: "agent/plan.md", Language: "markdown", Content: "# Cell plan\n\nObserve the agent, steer when needed, then approve the entity diff.\n"},
		{Path: "cmd/hello/main.go", Language: "go", Content: "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello from Mercutio\")\n}\n"},
		{Path: "policy/sandbox.yaml", Language: "yaml", Content: "profile: standard\nfilesystem:\n  workspace: read-write\negress:\n  - github.com\n"},
	}
	created := time.Now().UTC().Add(-7 * time.Minute)
	r := s.newRecordLocked("cell-demo", "https://github.com/odvcencio/mercutio", "main", "standard", files, created)
	// The demo starts with one intentional entity change so the approval flow is
	// visible without inventing a review object unrelated to the buffer.
	r.baseline[1].Content = strings.Replace(files[1].Content, "hello from Mercutio", "hello", 1)
	r.cell.Agent = model.AgentPresence{ID: "agent-demo", Name: "mercutio-agent", Status: "watching", Connected: true, LastSeen: created}
	s.appendPolicyEventsLocked(r, created)
	if pod, err := s.runtime.Ensure(context.Background(), sandbox.Spec{CellID: r.cell.ID, RepoURL: r.cell.RepoURL, Branch: r.cell.Branch, Profile: r.cell.SandboxProfile, HubURL: s.hubURL, AttachToken: r.attachToken, ArmToken: r.armToken}); err == nil {
		s.applyPodLocked(r, pod, false)
	}
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "control-plane", Action: "cell.ready", Summary: "Sandbox cell ready", Detail: "graft worktree materialized and the agent attach surface is available", Danger: "low", Timestamp: created})
	s.appendEventLocked(r, model.Event{Kind: model.EventIntent, Source: "agent", Action: "trace.tick", Summary: "Agent is waiting for direction", Detail: "No prompt has been sent for this cell yet.", Timestamp: created.Add(2 * time.Minute)})
	s.appendEventLocked(r, model.Event{Kind: model.EventKernel, Source: "horizon", Action: "sandbox.attach", Summary: "Horizon attached standard profile", Detail: "fs=workspace; exec=allowlist; egress=github.com", Danger: "low", Timestamp: created.Add(3 * time.Minute)})
	r.cell.Revision = 1
	r.cell.UpdatedAt = created.Add(3 * time.Minute)
	r.cell.Reviews = s.generateReviews(r)
	s.cells[r.cell.ID] = r
	s.activeID = r.cell.ID
}

func (s *Store) newRecordLocked(id, repoURL, branch, profile string, files []model.File, created time.Time) *record {
	branch = defaultValue(branch, "main")
	profile = defaultValue(profile, "standard")
	manifest, _ := policy.Resolve(profile)
	token, _ := s.mintAgentCapability(id)
	armToken, _ := s.mintArmCapability(id)
	r := &record{
		cell: model.Cell{
			ID:             id,
			RepoURL:        repoURL,
			Branch:         branch,
			Status:         model.CellCreating,
			SandboxProfile: profile,
			Sandbox:        model.Sandbox{Phase: model.SandboxPending, LastTransition: created},
			Capabilities:   capabilityManifest(manifest),
			CreatedAt:      created,
			UpdatedAt:      created,
			EvidenceHealth: "healthy",
		},
		docs:        make(map[string]textDocument),
		attachToken: token,
		armToken:    armToken,
		workdir:     filepath.Join(s.worktreeRoot, id),
		writers:     make(map[string]writerState),
		openWriters: make(map[string]map[string]bool),
	}
	for i := range files {
		if files[i].Language == "" {
			files[i].Language = languageFor(files[i].Path)
		}
		r.cell.Files = append(r.cell.Files, files[i])
		r.baseline = append(r.baseline, files[i])
		doc := crdt.NewDoc()
		textID, err := docWithText(doc, files[i].Content)
		if err == nil {
			r.docs[files[i].Path] = textDocument{doc: doc, text: textID}
		}
		syncWorktreeFile(s.worktreeRoot, id, files[i].Path, files[i].Content)
	}
	return r
}

func docWithText(doc *crdt.Doc, content string) (crdt.ObjID, error) {
	textID, err := doc.MakeText(crdt.Root, "content")
	if err != nil {
		return "", err
	}
	if _, _, err := doc.SpliceText(textID, 0, 0, content); err != nil {
		return "", err
	}
	_, err = doc.Commit("initial content")
	return textID, err
}

func (s *Store) Create(repoURL, branch, profile string) (model.CellSnapshot, error) {
	repoURL = strings.TrimSpace(repoURL)
	if repoURL == "" {
		return model.CellSnapshot{}, fmt.Errorf("repoURL is required")
	}
	manifest, err := policy.Resolve(profile)
	if err != nil {
		return model.CellSnapshot{}, err
	}
	branch = defaultValue(branch, "main")
	profile = manifest.Profile
	s.mu.Lock()
	s.nextID++
	id := fmt.Sprintf("cell-%03d", s.nextID)
	now := time.Now().UTC()
	files := []model.File{{Path: "README.md", Language: "markdown", Content: fmt.Sprintf("# %s\n\nCreated from `%s` on branch `%s`.\n", filepath.Base(repoURL), repoURL, defaultValue(branch, "main"))}}
	r := s.newRecordLocked(id, repoURL, branch, profile, files, now)
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "operator", Action: "cell.create", Summary: "Sandbox cell requested", Detail: "The reconciler is materializing the graft worktree and agent pod.", Danger: "medium", Timestamp: now})
	s.appendPolicyEventsLocked(r, now)
	s.cells[id] = r
	s.activeID = id
	_ = s.persistLocked()
	attachToken := r.attachToken
	armToken := r.armToken
	s.mu.Unlock()

	pod, err := s.runtime.Ensure(context.Background(), sandbox.Spec{CellID: id, RepoURL: repoURL, Branch: branch, Profile: profile, HubURL: s.hubURL, AttachToken: attachToken, ArmToken: armToken})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		r.cell.Status = model.CellError
		r.cell.Sandbox = model.Sandbox{Phase: model.SandboxFailed, LastTransition: time.Now().UTC(), Failure: err.Error()}
		r.cell.UpdatedAt = time.Now().UTC()
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "sandbox-runtime", Action: "sandbox.failed", Summary: "Sandbox cell failed to start", Detail: err.Error(), Danger: "high"})
		return snapshotLocked(r), fmt.Errorf("start sandbox: %w", err)
	}
	s.applyPodLocked(r, pod, true)
	r.cell.Reviews = s.generateReviews(r)
	return snapshotLocked(r), nil
}

func (s *Store) Destroy(id string) (model.CellSnapshot, error) {
	s.mu.RLock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.RUnlock()
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Status == model.CellStopped {
		snapshot := snapshotLocked(r)
		s.mu.RUnlock()
		return snapshot, nil
	}
	s.mu.RUnlock()
	if err := s.runtime.Delete(context.Background(), id); err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		r.cell.Status = model.CellError
		r.cell.Sandbox.Phase = model.SandboxFailed
		r.cell.Sandbox.Failure = err.Error()
		r.cell.UpdatedAt = time.Now().UTC()
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "sandbox-runtime", Action: "sandbox.delete.failed", Summary: "Sandbox cell failed to stop", Detail: err.Error(), Danger: "high"})
		return snapshotLocked(r), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if err := s.secretBroker.DeleteCell(id); err != nil {
		r.cell.Status = model.CellError
		r.cell.Sandbox.Failure = "secret cleanup: " + secrets.RedactText(err.Error())
		return snapshotLocked(r), fmt.Errorf("delete brokered cell secrets: %w", err)
	}
	r.cell.Status = model.CellStopped
	r.cell.Sandbox.Phase = model.SandboxStopped
	r.cell.Sandbox.LastTransition = now
	r.cell.Agent.Connected = false
	r.cell.Agent.Status = "stopped"
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "operator", Action: "cell.destroy", Summary: "Sandbox cell stopped", Detail: "The control plane released the cell; the worktree remains reviewable.", Danger: "high", Timestamp: now})
	r.docs = nil
	r.history = nil
	r.writers = nil
	r.openWriters = nil
	r.attachToken = ""
	r.armToken = ""
	_ = s.persistLocked()
	return snapshotLocked(r), nil
}

func (s *Store) SetWriterActive(id, path, actor string, active bool) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	path = strings.TrimSpace(path)
	actor = defaultValue(actor, "operator")
	if path == "" {
		return model.CellSnapshot{}, fmt.Errorf("file path is required")
	}
	if !active {
		if actors := r.openWriters[path]; actors != nil {
			delete(actors, actor)
			if len(actors) == 0 {
				delete(r.openWriters, path)
			}
		}
		return snapshotLocked(r), nil
	}
	if !isAgentActor(actor) {
		if err := s.takeOverAgentWriteLocked(id, r, path, actor); err != nil {
			return model.CellSnapshot{}, err
		}
	}
	actors := r.openWriters[path]
	if actors == nil {
		actors = make(map[string]bool)
		r.openWriters[path] = actors
	}
	actors[actor] = true
	return snapshotLocked(r), nil
}

func (s *Store) AdoptShadow(id, shadowID, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	index := -1
	var shadow model.ShadowRevision
	for i, candidate := range r.cell.Shadows {
		if candidate.ID == shadowID {
			index = i
			shadow = candidate
			break
		}
	}
	if index < 0 {
		return model.CellSnapshot{}, fmt.Errorf("shadow %q not found", shadowID)
	}
	if shadow.Status != "open" {
		return model.CellSnapshot{}, fmt.Errorf("shadow %q is %s", shadowID, shadow.Status)
	}
	if shadow.Stale {
		return model.CellSnapshot{}, fmt.Errorf("shadow %q is stale and must be rebased before adoption", shadowID)
	}
	doc, ok := r.docs[shadow.Path]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("document %q unavailable", shadow.Path)
	}
	inserted, deleted, err := spliceTextMinimalOps(doc, shadow.After)
	if err != nil {
		return model.CellSnapshot{}, err
	}
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == shadow.Path {
			r.cell.Files[i].Content = shadow.After
			r.cell.Files[i].Modified = true
		}
	}
	if err := syncWorktreeFile(s.worktreeRoot, id, shadow.Path, shadow.After); err != nil {
		return model.CellSnapshot{}, err
	}
	now := time.Now().UTC()
	r.history = append(r.history, editOperation{Actor: defaultValue(actor, "operator"), Path: shadow.Path, Inserted: inserted, Deleted: deleted, CreatedAt: now})
	// Adoption never destroys the human's live work. Preserve it as a new,
	// independently reviewable shadow before replacing the live buffer.
	humanShadow := model.ShadowRevision{
		ID: s.nextShadowIDLocked(id), Path: shadow.Path, Author: defaultValue(actor, "operator"),
		Base: shadow.Base, Before: shadow.After, After: shadow.Before, BaseHash: shadow.BaseHash,
		Reason: "human live buffer preserved during adoption", Status: "open", CreatedAt: now,
	}
	r.cell.Shadows[index].Status = "adopted"
	r.cell.Shadows[index].ResolvedAt = now
	r.cell.Shadows = append(r.cell.Shadows, humanShadow)
	_ = s.appendEvidenceLocked(r, "shadow-resolution", map[string]string{"shadowID": shadow.ID, "status": "adopted", "preservedShadowID": humanShadow.ID})
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: defaultValue(actor, "operator"), Action: "shadow.adopt", Summary: "Shadow Revision adopted into live buffer", Detail: "shadow=" + shadow.ID + "; path=" + shadow.Path, Danger: "medium", Authenticated: true, Timestamp: now})
	r.cell.Reviews = s.generateReviews(r)
	return snapshotLocked(r), nil
}

func (s *Store) MergeShadow(id, shadowID, actor string) (model.CellSnapshot, shadowmerge.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, shadowmerge.Result{}, fmt.Errorf("cell %q not found", id)
	}
	index := -1
	var shadow model.ShadowRevision
	for i, candidate := range r.cell.Shadows {
		if candidate.ID == shadowID {
			index = i
			shadow = candidate
			break
		}
	}
	if index < 0 {
		return model.CellSnapshot{}, shadowmerge.Result{}, fmt.Errorf("shadow %q not found", shadowID)
	}
	if shadow.Status != "open" {
		return model.CellSnapshot{}, shadowmerge.Result{}, fmt.Errorf("shadow %q is %s", shadowID, shadow.Status)
	}
	var live model.File
	for _, file := range r.cell.Files {
		if file.Path == shadow.Path {
			live = file
			break
		}
	}
	base := shadow.Base
	if base == "" && shadow.BaseHash == contentHash(baselineContent(r.baseline, shadow.Path)) {
		// Backward compatibility for state written before exact shadow bases were
		// persisted. Never substitute a baseline whose hash does not match.
		base = baselineContent(r.baseline, shadow.Path)
	}
	if contentHash(base) != shadow.BaseHash {
		return model.CellSnapshot{}, shadowmerge.Result{}, fmt.Errorf("shadow %q base snapshot is unavailable", shadowID)
	}
	result := shadowmerge.Merge(s.intelligence, shadow.Path, live.Language, base, live.Content, shadow.After)
	now := time.Now().UTC()
	if !result.Clean {
		r.cell.Shadows[index].Conflicts = append([]string(nil), result.Conflicts...)
		r.cell.Shadows[index].Intelligence = result.Intelligence
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventReview, Source: defaultValue(actor, "operator"), Action: "shadow.merge.conflict", Summary: "Shadow merge requires entity review", Detail: "shadow=" + shadowID + "; conflicts=" + strings.Join(result.Conflicts, ","), Danger: "medium", Authenticated: true, Timestamp: now})
		r.cell.Reviews = s.generateReviews(r)
		return snapshotLocked(r), result, nil
	}
	doc := r.docs[shadow.Path]
	inserted, deleted, err := spliceTextMinimalOps(doc, result.Content)
	if err != nil {
		return model.CellSnapshot{}, result, err
	}
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == shadow.Path {
			r.cell.Files[i].Content = result.Content
			r.cell.Files[i].Modified = true
		}
	}
	if err := syncWorktreeFile(s.worktreeRoot, id, shadow.Path, result.Content); err != nil {
		return model.CellSnapshot{}, result, err
	}
	r.cell.Shadows[index].Status = "merged"
	r.cell.Shadows[index].ResolvedAt = now
	r.cell.Shadows[index].Intelligence = result.Intelligence
	r.history = append(r.history, editOperation{Actor: defaultValue(actor, "operator"), Path: shadow.Path, Inserted: inserted, Deleted: deleted, CreatedAt: now})
	_ = s.appendEvidenceLocked(r, "shadow-resolution", map[string]string{"shadowID": shadow.ID, "status": "merged", "intelligence": result.Intelligence})
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: defaultValue(actor, "operator"), Action: "shadow.merge", Summary: "Shadow Revision structurally merged", Detail: "shadow=" + shadow.ID + "; path=" + shadow.Path, Danger: "medium", Authenticated: true, Timestamp: now})
	r.cell.Reviews = s.generateReviews(r)
	return snapshotLocked(r), result, nil
}

func (s *Store) DiscardShadow(id, shadowID, actor, reason string) (model.CellSnapshot, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return model.CellSnapshot{}, fmt.Errorf("shadow discard reason is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	for i, shadow := range r.cell.Shadows {
		if shadow.ID != shadowID {
			continue
		}
		if shadow.Status != "open" {
			return model.CellSnapshot{}, fmt.Errorf("shadow %q is %s", shadowID, shadow.Status)
		}
		now := time.Now().UTC()
		r.cell.Shadows[i].Status = "discarded"
		r.cell.Shadows[i].DiscardReason = secrets.RedactText(reason)
		r.cell.Shadows[i].ResolvedAt = now
		_ = s.appendEvidenceLocked(r, "shadow-resolution", map[string]string{"shadowID": shadow.ID, "status": "discarded", "reason": secrets.RedactText(reason)})
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: defaultValue(actor, "operator"), Action: "shadow.discard", Summary: "Shadow Revision discarded with receipt", Detail: "shadow=" + shadow.ID + "; reason=" + secrets.RedactText(reason), Danger: "medium", Authenticated: true, Timestamp: now})
		r.cell.Reviews = s.generateReviews(r)
		return snapshotLocked(r), nil
	}
	return model.CellSnapshot{}, fmt.Errorf("shadow %q not found", shadowID)
}

// CollectShadowGarbage removes only revisions that have crossed a normative
// retention boundary. Resolution and garbage collection are deliberately
// separate so every shadow remains addressable after an operator decision.
func (s *Store) CollectShadowGarbage(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	removed := 0
	for _, r := range s.cells {
		kept := r.cell.Shadows[:0]
		for _, shadow := range r.cell.Shadows {
			agedOut := !shadow.CreatedAt.IsZero() && !shadow.CreatedAt.Add(14*24*time.Hour).After(now)
			reason := ""
			switch {
			case shadow.Status == "adopted":
				reason = "adopted"
			case shadow.Status == "merged":
				reason = "merged"
			case shadow.Status == "discarded" && shadow.Stale:
				reason = "discarded-past-base"
			case agedOut:
				reason = "ttl-expired"
			}
			if reason == "" {
				kept = append(kept, shadow)
				continue
			}
			if err := s.appendEvidenceLocked(r, "shadow-gc-receipt", map[string]string{"shadowID": shadow.ID, "author": shadow.Author, "baseHash": shadow.BaseHash, "status": shadow.Status, "reason": reason}); err != nil {
				kept = append(kept, shadow)
				continue
			}
			removed++
		}
		r.cell.Shadows = kept
	}
	if removed > 0 {
		_ = s.persistLocked()
	}
	return removed
}

func (s *Store) Reconcile(ctx context.Context, id string) (model.CellSnapshot, bool, error) {
	s.mu.RLock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.RUnlock()
		return model.CellSnapshot{}, false, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Status == model.CellStopped {
		snapshot := snapshotLocked(r)
		s.mu.RUnlock()
		return snapshot, false, nil
	}
	spec := sandbox.Spec{CellID: id, RepoURL: r.cell.RepoURL, Branch: r.cell.Branch, Profile: r.cell.SandboxProfile, HubURL: s.hubURL, AttachToken: r.attachToken, ArmToken: r.armToken}
	s.mu.RUnlock()

	pod, err := s.runtime.Observe(ctx, id)
	if err != nil {
		if errorsIsNotFound(err) {
			return s.restoreMissingSandbox(ctx, id)
		}
		return model.CellSnapshot{}, false, err
	}
	// Ensure is idempotent for a live pod and reconciles generated credentials,
	// Cell desired state, and status after a control-plane restart.
	pod, err = s.runtime.Ensure(ctx, spec)
	if err != nil {
		return model.CellSnapshot{}, false, fmt.Errorf("reconcile sandbox resources %q: %w", id, err)
	}
	s.mu.Lock()
	r, ok = s.cells[id]
	if !ok {
		s.mu.Unlock()
		return model.CellSnapshot{}, false, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Status == model.CellStopped {
		snapshot := snapshotLocked(r)
		s.mu.Unlock()
		_ = s.runtime.Delete(ctx, id)
		return snapshot, false, nil
	}
	if r.cell.RepoURL != spec.RepoURL || r.cell.Branch != spec.Branch || r.cell.SandboxProfile != spec.Profile {
		s.mu.Unlock()
		return model.CellSnapshot{}, false, fmt.Errorf("cell %q changed during sandbox reconciliation", id)
	}
	beforeSandbox := r.cell.Sandbox
	beforeStatus := r.cell.Status
	s.applyPodLocked(r, pod, false)
	changed := !reflect.DeepEqual(beforeSandbox, r.cell.Sandbox) || beforeStatus != r.cell.Status
	if changed {
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "sandbox-runtime", Action: "sandbox." + string(pod.Phase), Summary: "Sandbox pod transitioned to " + string(pod.Phase), Detail: pod.Name, Danger: map[bool]string{true: "high", false: "low"}[pod.Phase == sandbox.PhaseFailed], Timestamp: r.cell.UpdatedAt})
	}
	snapshot := snapshotLocked(r)
	s.mu.Unlock()
	return snapshot, changed, nil
}

func (s *Store) restoreMissingSandbox(ctx context.Context, id string) (model.CellSnapshot, bool, error) {
	s.mu.RLock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.RUnlock()
		return model.CellSnapshot{}, false, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Status == model.CellStopped {
		snapshot := snapshotLocked(r)
		s.mu.RUnlock()
		return snapshot, false, nil
	}
	spec := sandbox.Spec{CellID: id, RepoURL: r.cell.RepoURL, Branch: r.cell.Branch, Profile: r.cell.SandboxProfile, HubURL: s.hubURL, AttachToken: r.attachToken, ArmToken: r.armToken}
	s.mu.RUnlock()

	pod, err := s.runtime.Ensure(ctx, spec)
	if err != nil {
		return model.CellSnapshot{}, false, fmt.Errorf("restore missing sandbox %q: %w", id, err)
	}
	s.mu.Lock()
	r = s.cells[id]
	if r == nil || r.cell.Status == model.CellStopped {
		var snapshot model.CellSnapshot
		if r != nil {
			snapshot = snapshotLocked(r)
		}
		s.mu.Unlock()
		_ = s.runtime.Delete(ctx, id)
		if r == nil {
			return model.CellSnapshot{}, false, fmt.Errorf("cell %q disappeared during sandbox restore", id)
		}
		return snapshot, false, nil
	}
	if r.cell.RepoURL != spec.RepoURL || r.cell.Branch != spec.Branch || r.cell.SandboxProfile != spec.Profile {
		s.mu.Unlock()
		_ = s.runtime.Delete(ctx, id)
		return model.CellSnapshot{}, false, fmt.Errorf("cell %q changed during sandbox restore", id)
	}
	s.applyPodLocked(r, pod, false)
	r.cell.Revision++
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "sandbox-reconciler", Action: "sandbox.recreated", Summary: "Missing sandbox pod recreated from durable desired state", Detail: pod.Name, Danger: "medium", Authenticated: true, Timestamp: now})
	snapshot := snapshotLocked(r)
	s.mu.Unlock()
	return snapshot, true, nil
}

type ArmReceipt struct {
	NodeID         string
	Programs       []string
	ManifestDigest string
	ObjectDigest   string
	ProfileDigest  string
	CgroupID       uint64
	Enforcement    string
}

func (s *Store) MarkArmed(id string, receipt ArmReceipt) (model.CellSnapshot, error) {
	return s.MarkArmedContext(context.Background(), id, receipt)
}

func (s *Store) MarkArmedContext(ctx context.Context, id string, receipt ArmReceipt) (model.CellSnapshot, error) {
	if strings.TrimSpace(receipt.NodeID) == "" || strings.TrimSpace(receipt.ManifestDigest) == "" || strings.TrimSpace(receipt.ObjectDigest) == "" || strings.TrimSpace(receipt.ProfileDigest) == "" || receipt.CgroupID == 0 || len(receipt.Programs) == 0 {
		return model.CellSnapshot{}, fmt.Errorf("complete node, program, digest, and cgroup arm receipt is required")
	}
	s.mu.Lock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.Unlock()
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Status == model.CellStopped {
		s.mu.Unlock()
		return model.CellSnapshot{}, fmt.Errorf("cell %q is stopped", id)
	}
	expectedProfile, expectedDigest := r.cell.Capabilities.Profile, r.cell.Capabilities.ProfileDigest
	if receipt.ProfileDigest != expectedDigest {
		s.mu.Unlock()
		return model.CellSnapshot{}, fmt.Errorf("arm receipt profile digest does not match the desired policy")
	}
	s.mu.Unlock()
	if finalizer, ok := s.runtime.(sandbox.PolicyFinalizer); ok {
		if err := finalizer.FinalizePolicy(ctx, id, expectedProfile, expectedDigest); err != nil {
			return model.CellSnapshot{}, fmt.Errorf("finalize network policy: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r = s.cells[id]
	if r == nil || r.cell.Status == model.CellStopped || r.cell.Capabilities.ProfileDigest != expectedDigest {
		return model.CellSnapshot{}, fmt.Errorf("cell policy changed while arm receipt was finalized")
	}
	now := time.Now().UTC()
	r.cell.Sandbox.Armed = true
	r.cell.Sandbox.ArmedAt = now
	r.cell.Sandbox.Programs = append([]string(nil), receipt.Programs...)
	r.cell.Sandbox.ManifestDigest = receipt.ManifestDigest
	r.cell.Sandbox.ObjectDigest = receipt.ObjectDigest
	r.cell.Sandbox.CgroupID = receipt.CgroupID
	r.cell.Sandbox.Enforcement = defaultValue(receipt.Enforcement, "r1-kernel")
	if r.cell.Sandbox.Phase == model.SandboxRunning {
		r.cell.Status = model.CellReady
	}
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "horizon-node-agent", Action: "sandbox.armed", Summary: "Kernel enforcement armed before agent start", Detail: "node=" + receipt.NodeID + "; manifest=" + receipt.ManifestDigest + "; object=" + receipt.ObjectDigest, Danger: "low", Authenticated: true, Timestamp: now})
	_ = s.persistLocked()
	return snapshotLocked(r), nil
}

func (s *Store) ArmState(id string) (model.Sandbox, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cells[id]
	if !ok {
		return model.Sandbox{}, fmt.Errorf("cell %q not found", id)
	}
	sandboxState := r.cell.Sandbox
	sandboxState.Programs = append([]string(nil), sandboxState.Programs...)
	return sandboxState, nil
}

// GarbageCollect removes managed sandboxes that no longer have a live cell
// record. This closes the crash/restart gap where a pod can outlive control
// plane state, while retaining active pods and reviewable stopped cell data.
func (s *Store) GarbageCollect(ctx context.Context) ([]string, error) {
	pods, err := s.runtime.Managed(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	live := make(map[string]bool, len(s.cells))
	for id, record := range s.cells {
		live[id] = record.cell.Status != model.CellStopped
	}
	s.mu.RUnlock()

	removed := make([]string, 0)
	seen := make(map[string]struct{})
	for _, pod := range pods {
		if pod.CellID == "" || pod.Phase == sandbox.PhaseStopped || live[pod.CellID] {
			continue
		}
		if _, duplicate := seen[pod.CellID]; duplicate {
			continue
		}
		if err := s.runtime.Delete(ctx, pod.CellID); err != nil {
			return removed, fmt.Errorf("garbage collect sandbox %q: %w", pod.CellID, err)
		}
		seen[pod.CellID] = struct{}{}
		removed = append(removed, pod.CellID)
	}
	return removed, nil
}

func (s *Store) ApplyEdit(id, path, content, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	return s.applyEditLocked(id, r, path, content, actor, true)
}

// ApplyDiskEdit ingests a sidecar-observed worktree change against the exact
// bytes the sidecar last materialized. A stale or unknown base is preserved as
// a Shadow Revision; it is never guessed into the live CRDT.
func (s *Store) ApplyDiskEdit(id, path, base, content, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	current := ""
	for _, file := range r.cell.Files {
		if file.Path == path {
			current = file.Content
			break
		}
	}
	if base == "" || contentHash(base) != contentHash(current) {
		now := time.Now().UTC()
		shadow := model.ShadowRevision{ID: s.nextShadowIDLocked(id), Path: path, Author: defaultValue(actor, "agent-disk"), Base: base, Before: current, After: content, BaseHash: contentHash(base), Reason: "stale or unknown disk base", Status: "open", CreatedAt: now}
		r.cell.Shadows = append(r.cell.Shadows, shadow)
		r.cell.UpdatedAt, r.cell.Revision = now, r.cell.Revision+1
		_ = s.appendEvidenceLocked(r, "shadow-create", map[string]string{"shadowID": shadow.ID, "author": shadow.Author, "baseHash": shadow.BaseHash, "reason": shadow.Reason})
		s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: shadow.Author, Actor: shadow.Author, Action: "shadow.create", Summary: "Uncertain disk change preserved as a Shadow Revision", Detail: "path=" + path + "; shadow=" + shadow.ID, Danger: "medium", Timestamp: now})
		r.cell.Reviews = s.generateReviews(r)
		return snapshotLocked(r), nil
	}
	return s.applyEditLocked(id, r, path, content, actor, true)
}

// ApplyDiskDelete applies an observed unlink only when it is based on the
// exact live bytes. Uncertain deletes become Shadows so no concurrent human
// content can disappear silently.
func (s *Store) ApplyDiskDelete(id, path, base, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	current, found := "", false
	for _, file := range r.cell.Files {
		if file.Path == path {
			current, found = file.Content, true
			break
		}
	}
	if !found {
		return snapshotLocked(r), nil
	}
	if base == "" || contentHash(base) != contentHash(current) {
		now := time.Now().UTC()
		shadow := model.ShadowRevision{ID: s.nextShadowIDLocked(id), Path: path, Author: defaultValue(actor, "agent-disk"), Base: base, Before: current, After: "", BaseHash: contentHash(base), Reason: "stale or unknown disk delete base", Status: "open", CreatedAt: now}
		r.cell.Shadows = append(r.cell.Shadows, shadow)
		r.cell.UpdatedAt, r.cell.Revision = now, r.cell.Revision+1
		_ = s.appendEvidenceLocked(r, "shadow-create", map[string]string{"shadowID": shadow.ID, "author": shadow.Author, "baseHash": shadow.BaseHash, "reason": shadow.Reason})
		s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: shadow.Author, Actor: shadow.Author, Action: "shadow.create", Summary: "Uncertain disk deletion preserved as a Shadow Revision", Detail: "path=" + path + "; shadow=" + shadow.ID, Danger: "medium", Timestamp: now})
		r.cell.Reviews = s.generateReviews(r)
		return snapshotLocked(r), nil
	}
	return s.deleteFileLocked(id, r, path, defaultValue(actor, "agent-disk"), true)
}

// ApplySplice applies one authenticated, path-scoped browser operation against
// the exact buffer version the browser edited. Indexes count Unicode code
// points, matching the CRDT text model rather than UTF-16 browser offsets.
func (s *Store) ApplySplice(id, path string, baseHash uint32, index, deleteCount uint32, insert, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.Unlock()
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	current := ""
	for _, file := range r.cell.Files {
		if file.Path == strings.TrimSpace(path) {
			current = file.Content
			break
		}
	}
	if browserContentHash(current) != baseHash {
		snapshot := snapshotLocked(r)
		s.mu.Unlock()
		return snapshot, fmt.Errorf("browser splice base is stale")
	}
	runes := []rune(current)
	start := int(index)
	end := start + int(deleteCount)
	if start < 0 || start > len(runes) || end < start || end > len(runes) {
		snapshot := snapshotLocked(r)
		s.mu.Unlock()
		return snapshot, fmt.Errorf("browser splice range is invalid")
	}
	replacement := []rune(insert)
	content := string(append(append(append([]rune(nil), runes[:start]...), replacement...), runes[end:]...))
	snapshot, err := s.applyEditLocked(id, r, path, content, actor, false)
	s.mu.Unlock()
	return snapshot, err
}

// ResolveCursorAnchors converts browser UTF-16 selection offsets into stable
// CRDT element anchors before presence is relayed to other actors.
func (s *Store) ResolveCursorAnchors(id, path string, startUTF16, endUTF16 int) (TextAnchor, TextAnchor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cells[id]
	if !ok {
		return TextAnchor{}, TextAnchor{}, fmt.Errorf("cell %q not found", id)
	}
	document, ok := r.docs[strings.TrimSpace(path)]
	if !ok {
		return TextAnchor{}, TextAnchor{}, fmt.Errorf("file %q not found", path)
	}
	content, err := document.doc.TextToString(document.text)
	if err != nil {
		return TextAnchor{}, TextAnchor{}, err
	}
	startIndex, err := utf16OffsetToRuneIndex(content, startUTF16)
	if err != nil {
		return TextAnchor{}, TextAnchor{}, err
	}
	endIndex, err := utf16OffsetToRuneIndex(content, endUTF16)
	if err != nil {
		return TextAnchor{}, TextAnchor{}, err
	}
	start, err := textAnchorAt(document, len([]rune(content)), startIndex)
	if err != nil {
		return TextAnchor{}, TextAnchor{}, err
	}
	end, err := textAnchorAt(document, len([]rune(content)), endIndex)
	return start, end, err
}

func utf16OffsetToRuneIndex(content string, offset int) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("UTF-16 offset %d is negative", offset)
	}
	units, index := 0, 0
	for _, runeValue := range content {
		if units == offset {
			return index, nil
		}
		next := units + utf16.RuneLen(runeValue)
		if offset < next {
			return 0, fmt.Errorf("UTF-16 offset %d splits a surrogate pair", offset)
		}
		units, index = next, index+1
	}
	if units != offset {
		return 0, fmt.Errorf("UTF-16 offset %d exceeds document length %d", offset, units)
	}
	return index, nil
}

func textAnchorAt(document textDocument, length, index int) (TextAnchor, error) {
	if index < 0 || index > length {
		return TextAnchor{}, fmt.Errorf("cursor index %d outside document length %d", index, length)
	}
	if length == 0 {
		return TextAnchor{Boundary: "start"}, nil
	}
	if index == length {
		id, err := document.doc.ElementIDAt(document.text, uint64(length-1))
		return TextAnchor{ElemID: id.String(), Affinity: "after"}, err
	}
	id, err := document.doc.ElementIDAt(document.text, uint64(index))
	return TextAnchor{ElemID: id.String(), Affinity: "before"}, err
}

func (s *Store) applyEditLocked(id string, r *record, path, content, actor string, refreshReviews bool) (model.CellSnapshot, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return model.CellSnapshot{}, fmt.Errorf("file path is required")
	}
	if secrets.IsSensitivePath(path) {
		return model.CellSnapshot{}, fmt.Errorf("sensitive path %q must be edited through the secret broker", path)
	}
	actor = defaultValue(actor, "operator")
	secretScan := intelligence.SecretScan{}
	if secrets.ContainsSecretShape(content) {
		secretScan = s.intelligence.ScanSecrets(path, content)
	}
	if len(secretScan.Findings) > 0 {
		if !isAgentActor(actor) {
			return model.CellSnapshot{}, fmt.Errorf("secret-shaped content must be stored through the secret broker")
		}
		current := ""
		for i := range r.cell.Files {
			if r.cell.Files[i].Path == path {
				current = r.cell.Files[i].Content
				break
			}
		}
		base := baselineContent(r.baseline, path)
		now := time.Now().UTC()
		shadow := model.ShadowRevision{ID: s.nextShadowIDLocked(id), Path: path, Author: actor, Base: base, Before: secrets.RedactText(current), After: redactSecretFindings(content, secretScan.Findings), BaseHash: contentHash(base), Reason: "secret material rejected before CRDT ingestion", Status: "blocked", CreatedAt: now}
		r.cell.Shadows = append(r.cell.Shadows, shadow)
		r.cell.UpdatedAt = now
		r.cell.Revision++
		_ = s.appendEvidenceLocked(r, "secret-edit-rejection", map[string]any{"shadowID": shadow.ID, "author": actor, "path": path, "findings": len(secretScan.Findings), "scanStatus": secretScan.Status})
		s.appendEventLocked(r, model.Event{Kind: model.EventReview, Source: actor, Actor: actor, Action: "structural.secret.finding", Summary: "Agent edit was blocked before shared-document ingestion", Detail: "path=" + path + "; shadow=" + shadow.ID, Danger: "critical", Timestamp: now})
		r.cell.Reviews = s.generateReviews(r)
		return snapshotLocked(r), nil
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
	current := r.cell.Files[idx].Content
	writer := r.writers[path]
	now := time.Now().UTC()
	if isAgentActor(actor) && humanWriterActive(r, path, writer, now) {
		base := baselineContent(r.baseline, path)
		shadow := model.ShadowRevision{ID: s.nextShadowIDLocked(id), Path: path, Author: actor, Base: base, Before: current, After: content, BaseHash: contentHash(base), Reason: "active human writer", Status: "open", CreatedAt: now}
		r.cell.Shadows = append(r.cell.Shadows, shadow)
		r.cell.UpdatedAt = now
		r.cell.Revision++
		_ = s.appendEvidenceLocked(r, "shadow-create", map[string]string{"shadowID": shadow.ID, "author": actor, "baseHash": shadow.BaseHash, "reason": shadow.Reason})
		s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: actor, Actor: actor, Action: "shadow.create", Summary: "Agent write preserved as a Shadow Revision", Detail: "path=" + path + "; shadow=" + shadow.ID, Danger: "medium", Timestamp: now})
		r.cell.Reviews = s.generateReviews(r)
		return snapshotLocked(r), nil
	}
	// A human taking over an agent-active buffer preserves the in-flight agent
	// state before applying the human edit.
	if !isAgentActor(actor) && agentWriteActive(writer, now) && current != content {
		if err := s.takeOverAgentWriteLocked(id, r, path, actor); err != nil {
			return model.CellSnapshot{}, err
		}
		current = writer.before
	}
	changeGroupID := fmt.Sprintf("edit:%s:%d:%s", id, r.cell.Revision+1, actor)
	if isAgentActor(actor) && isAgentActor(writer.actor) && writer.actor == actor && agentWriteActive(writer, now) && writer.changeGroupID != "" {
		changeGroupID = writer.changeGroupID
	}
	inserted, deleted, err := spliceTextMinimalOpsGroup(doc, content, changeGroupID)
	if err != nil {
		return model.CellSnapshot{}, fmt.Errorf("apply edit: %w", err)
	}
	r.cell.Files[idx].Content = content
	r.cell.Files[idx].Modified = true
	if err := syncWorktreeFile(s.worktreeRoot, id, path, content); err != nil {
		return model.CellSnapshot{}, fmt.Errorf("sync worktree: %w", err)
	}
	r.cell.UpdatedAt = time.Now().UTC()
	r.cell.Revision++
	historyStart := len(r.history)
	if isAgentActor(actor) && isAgentActor(writer.actor) && writer.actor == actor && agentWriteActive(writer, now) {
		historyStart = writer.historyStart
	}
	if len(inserted) > 0 || len(deleted) > 0 {
		r.history = append(r.history, editOperation{Actor: actor, Path: path, Inserted: inserted, Deleted: deleted, CreatedAt: r.cell.UpdatedAt, ChangeGroupID: changeGroupID})
	}
	nextWriter := writerState{actor: actor, activeUntil: r.cell.UpdatedAt.Add(90 * time.Second), historyStart: historyStart, changeGroupID: changeGroupID}
	if isAgentActor(actor) {
		nextWriter.before = current
		if isAgentActor(writer.actor) && writer.actor == actor && agentWriteActive(writer, now) {
			nextWriter.before = writer.before
		}
	}
	r.writers[path] = nextWriter
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: actor, Actor: actor, Action: "buffer.update", Summary: fmt.Sprintf("%s edited %s", actor, path), Detail: "The shared document revision was committed through the cell document.", Danger: "medium", Authenticated: strings.HasPrefix(actor, "operator-") || actor == "operator", Timestamp: r.cell.UpdatedAt})
	if refreshReviews {
		r.cell.Reviews = s.generateReviews(r)
		_ = s.persistLocked()
	}
	return snapshotLocked(r), nil
}

// RefreshReviews recomputes structural review state after the collaboration
// hot path has durably published a CRDT edit. The expected revision prevents a
// slow analysis from overwriting review state for a newer edit.
func (s *Store) RefreshReviews(id string, expectedRevision uint64) (model.CellSnapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, false, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Revision != expectedRevision || r.cell.Status == model.CellStopped {
		return snapshotLocked(r), false, nil
	}
	reviews := s.generateReviews(r)
	if reflect.DeepEqual(r.cell.Reviews, reviews) {
		return snapshotLocked(r), false, nil
	}
	r.cell.Reviews = reviews
	r.cell.Revision++
	r.cell.UpdatedAt = time.Now().UTC()
	if err := s.persistLocked(); err != nil {
		return snapshotLocked(r), false, fmt.Errorf("persist refreshed structural reviews: %w", err)
	}
	return snapshotLocked(r), true, nil
}

func redactSecretFindings(content string, findings []model.SecretFinding) string {
	type span struct{ start, end int }
	spans := make([]span, 0, len(findings))
	for _, finding := range findings {
		start, end := int(finding.Range.StartByte), int(finding.Range.EndByte)
		if start < 0 || end <= start || end > len(content) {
			continue
		}
		spans = append(spans, span{start: start, end: end})
	}
	if len(spans) == 0 {
		return secrets.RedactText(content)
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start > spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	redacted := content
	lastStart := len(content) + 1
	for _, item := range spans {
		if item.end > lastStart {
			continue
		}
		redacted = redacted[:item.start] + "<redacted>" + redacted[item.end:]
		lastStart = item.start
	}
	return secrets.RedactText(redacted)
}

func humanWriterActive(r *record, path string, writer writerState, now time.Time) bool {
	return writer.actor != "" && !isAgentActor(writer.actor) && now.Before(writer.activeUntil) && r.openWriters[path][writer.actor]
}

func agentWriteActive(writer writerState, now time.Time) bool {
	return writer.actor != "" && isAgentActor(writer.actor) && now.Before(writer.activeUntil)
}

func (s *Store) takeOverAgentWriteLocked(id string, r *record, path, actor string) error {
	writer := r.writers[path]
	now := time.Now().UTC()
	if !agentWriteActive(writer, now) {
		return nil
	}
	index := -1
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == path {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("document %q is unavailable", path)
	}
	current := r.cell.Files[index].Content
	if current == writer.before {
		delete(r.writers, path)
		return nil
	}
	base := baselineContent(r.baseline, path)
	shadow := model.ShadowRevision{ID: s.nextShadowIDLocked(id), Path: path, Author: writer.actor, Base: base, Before: writer.before, After: current, BaseHash: contentHash(base), Reason: "human takeover of active agent writer", Status: "open", CreatedAt: now}
	r.cell.Shadows = append(r.cell.Shadows, shadow)
	doc, ok := r.docs[path]
	if !ok {
		return fmt.Errorf("document %q is unavailable", path)
	}
	if _, _, err := spliceTextMinimalOps(doc, writer.before); err != nil {
		return fmt.Errorf("restore pre-agent buffer: %w", err)
	}
	if err := syncWorktreeFile(s.worktreeRoot, id, path, writer.before); err != nil {
		return fmt.Errorf("restore pre-agent worktree: %w", err)
	}
	r.cell.Files[index].Content = writer.before
	r.cell.Files[index].Modified = true
	for i := writer.historyStart; i < len(r.history); i++ {
		if r.history[i].Path == path && r.history[i].Actor == writer.actor {
			r.history[i].Reverted = true
		}
	}
	delete(r.writers, path)
	r.cell.UpdatedAt = now
	r.cell.Revision++
	_ = s.appendEvidenceLocked(r, "shadow-create", map[string]string{"shadowID": shadow.ID, "author": shadow.Author, "baseHash": shadow.BaseHash, "reason": shadow.Reason})
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: defaultValue(actor, "operator"), Actor: defaultValue(actor, "operator"), Action: "shadow.takeover", Summary: "Human took the live buffer; the in-flight agent change became a Shadow Revision", Detail: "path=" + path + "; shadow=" + shadow.ID, Danger: "medium", Authenticated: true, Timestamp: now})
	r.cell.Reviews = s.generateReviews(r)
	return nil
}

func browserContentHash(content string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(content))
	return hash.Sum32()
}

// UndoEdit applies the inverse CRDT operations for the requesting actor's
// latest edit. Stable element identities keep neighboring edits from other
// writers intact.
func (s *Store) UndoEdit(id, path, actor string) (model.CellSnapshot, error) {
	return s.undoEdit(id, path, defaultValue(actor, "operator"), false)
}

// RevertAgentEdit is the explicit operator action for undoing the latest agent
// edit without rewinding human operations that followed it.
func (s *Store) RevertAgentEdit(id, path, actor string) (model.CellSnapshot, error) {
	return s.undoEdit(id, path, defaultValue(actor, "operator"), true)
}

func (s *Store) undoEdit(id, path, actor string, agentOnly bool) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	path = strings.TrimSpace(path)
	index := -1
	for i := len(r.history) - 1; i >= 0; i-- {
		operation := r.history[i]
		if operation.Reverted || (path != "" && operation.Path != path) {
			continue
		}
		if agentOnly {
			if !isAgentActor(operation.Actor) {
				continue
			}
		} else if operation.Actor != actor {
			continue
		}
		index = i
		break
	}
	if index < 0 {
		kind := "actor"
		if agentOnly {
			kind = "agent"
		}
		return model.CellSnapshot{}, fmt.Errorf("no reversible %s edit found for %q", kind, path)
	}
	operation := &r.history[index]
	targetPath, targetActor, targetGroupID := operation.Path, operation.Actor, operation.ChangeGroupID
	doc, ok := r.docs[targetPath]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("document %q unavailable", targetPath)
	}
	beforeContent, err := doc.doc.TextToString(doc.text)
	if err != nil {
		return model.CellSnapshot{}, err
	}
	groupIndexes := []int{index}
	if targetGroupID != "" {
		groupIndexes = groupIndexes[:0]
		for i := len(r.history) - 1; i >= 0; i-- {
			candidate := r.history[i]
			if !candidate.Reverted && candidate.Path == targetPath && candidate.Actor == targetActor && candidate.ChangeGroupID == targetGroupID {
				groupIndexes = append(groupIndexes, i)
			}
		}
	}
	applied := 0
	for _, operationIndex := range groupIndexes {
		groupOperation := &r.history[operationIndex]
		for i := len(groupOperation.Inserted) - 1; i >= 0; i-- {
			if err := doc.doc.DeleteByElemID(doc.text, groupOperation.Inserted[i]); err != nil {
				if strings.Contains(err.Error(), "not found") {
					continue
				}
				return model.CellSnapshot{}, fmt.Errorf("undo inserted element: %w", err)
			}
			applied++
		}
		for _, elem := range groupOperation.Deleted {
			if err := doc.doc.ReviveElem(doc.text, elem); err != nil {
				if strings.Contains(err.Error(), "not found") {
					continue
				}
				return model.CellSnapshot{}, fmt.Errorf("undo deleted element: %w", err)
			}
			applied++
		}
	}
	if applied > 0 {
		undoGroupID := "undo:" + targetGroupID
		if targetGroupID == "" {
			undoGroupID = ""
		}
		if _, err := doc.doc.CommitWithGroup("actor-scoped undo", undoGroupID); err != nil {
			return model.CellSnapshot{}, err
		}
	}
	content, err := doc.doc.TextToString(doc.text)
	if err != nil {
		return model.CellSnapshot{}, err
	}
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == targetPath {
			r.cell.Files[i].Content = content
			r.cell.Files[i].Modified = true
			break
		}
	}
	if err = syncWorktreeFile(s.worktreeRoot, id, targetPath, content); err != nil {
		return model.CellSnapshot{}, err
	}
	for _, operationIndex := range groupIndexes {
		r.history[operationIndex].Reverted = true
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	action := "buffer.undo"
	summary := actor + " undid their latest edit"
	if agentOnly {
		action = "buffer.revert-agent"
		summary = actor + " reverted the latest agent edit"
	}
	if content == beforeContent {
		action += ".noop"
		summary = "Undo had no visible effect because its target elements were already gone"
	}
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: actor, Actor: actor, Action: action, Summary: summary, Detail: "path=" + targetPath + "; originalActor=" + targetActor + "; changeGroup=" + targetGroupID, Danger: "medium", Authenticated: true, Timestamp: now})
	r.cell.Reviews = s.generateReviews(r)
	return snapshotLocked(r), nil
}

func (s *Store) DeleteFile(id, path, actor string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	return s.deleteFileLocked(id, r, path, actor, false)
}

func (s *Store) deleteFileLocked(id string, r *record, path, actor string, alreadyRemoved bool) (model.CellSnapshot, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return model.CellSnapshot{}, fmt.Errorf("file path is required")
	}
	if secrets.IsSensitivePath(path) {
		return model.CellSnapshot{}, fmt.Errorf("sensitive path %q is only available through the secret broker", path)
	}
	index := -1
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == path {
			index = i
			break
		}
	}
	if index < 0 {
		return model.CellSnapshot{}, fmt.Errorf("file %q not found", path)
	}
	if len(r.cell.Files) == 1 {
		return model.CellSnapshot{}, fmt.Errorf("a cell must retain at least one file")
	}
	if !alreadyRemoved {
		if err := removeWorktreeFile(s.worktreeRoot, id, path); err != nil {
			return model.CellSnapshot{}, fmt.Errorf("remove worktree file: %w", err)
		}
	}
	r.cell.Files = append(r.cell.Files[:index], r.cell.Files[index+1:]...)
	delete(r.docs, path)
	if actor == "" {
		actor = "operator"
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: actor, Action: "buffer.delete", Summary: fmt.Sprintf("%s deleted %s", actor, path), Detail: "The shared document was removed from the cell.", Danger: "medium", Timestamp: now})
	r.cell.Reviews = s.generateReviews(r)
	return snapshotLocked(r), nil
}

func spliceTextMinimal(doc textDocument, content string) (int, int, error) {
	inserted, deleted, err := spliceTextMinimalOps(doc, content)
	return len(inserted), len(deleted), err
}

func spliceTextMinimalOps(doc textDocument, content string) ([]crdt.OpID, []crdt.OpID, error) {
	return spliceTextMinimalOpsGroup(doc, content, "")
}

func spliceTextMinimalOpsGroup(doc textDocument, content, changeGroupID string) ([]crdt.OpID, []crdt.OpID, error) {
	current, err := doc.doc.TextToString(doc.text)
	if err != nil {
		return nil, nil, err
	}
	oldRunes, newRunes := []rune(current), []rune(content)
	prefix := 0
	for prefix < len(oldRunes) && prefix < len(newRunes) && oldRunes[prefix] == newRunes[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldRunes)-prefix && suffix < len(newRunes)-prefix && oldRunes[len(oldRunes)-1-suffix] == newRunes[len(newRunes)-1-suffix] {
		suffix++
	}
	deletes := len(oldRunes) - prefix - suffix
	inserts := len(newRunes) - prefix - suffix
	if deletes == 0 && inserts == 0 {
		return nil, nil, nil
	}
	insertedIDs, deletedIDs, err := doc.doc.SpliceText(doc.text, uint64(prefix), uint64(deletes), string(newRunes[prefix:len(newRunes)-suffix]))
	if err != nil {
		return nil, nil, err
	}
	_, err = doc.doc.CommitWithGroup("minimal buffer splice", changeGroupID)
	return insertedIDs, deletedIDs, err
}

func isAgentActor(actor string) bool { return strings.HasPrefix(strings.ToLower(actor), "agent") }
func contentHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func baselineContent(files []model.File, path string) string {
	for _, file := range files {
		if file.Path == path {
			return file.Content
		}
	}
	return ""
}

func (s *Store) nextShadowIDLocked(cellID string) string {
	s.nextID++
	return fmt.Sprintf("shadow-%s-%d", cellID, s.nextID)
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
	if r.cell.Status == model.CellStopped {
		return model.CellSnapshot{}, fmt.Errorf("cell %q is stopped", id)
	}
	now := time.Now().UTC()
	r.cell.Status = model.CellSteering
	r.cell.Agent.Status = "steering"
	r.cell.Agent.LastSeen = now
	r.cell.Agent.Connected = true
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventIntent, Source: "operator", Action: "agent.prompt", Summary: "Prompt sent to agent", Detail: secrets.RedactText(prompt), Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) PutSecret(id, name, value, actor, token string) (model.CellSnapshot, secrets.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, secrets.Receipt{}, fmt.Errorf("cell %q not found", id)
	}
	actor = defaultValue(actor, "operator")
	claims, err := s.capabilities.Verify(token, id, "secret:write")
	if err != nil || claims.Role != "operator" || claims.ActorID != actor {
		return model.CellSnapshot{}, secrets.Receipt{}, fmt.Errorf("fresh operator secret:write capability required")
	}
	receipt, err := s.secretBroker.Put(id, name, value, actor)
	if err != nil {
		return model.CellSnapshot{}, secrets.Receipt{}, err
	}
	if err := s.appendEvidenceLocked(r, "secret-receipt", receipt); err != nil {
		return snapshotLocked(r), secrets.Receipt{}, fmt.Errorf("persist secret write receipt: %w", err)
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: actor, Action: "secret.write", Summary: "Secret updated through broker", Detail: "name=" + name + "; receipt=" + receipt.ID, Danger: "high", Timestamp: now})
	return snapshotLocked(r), receipt, nil
}

func (s *Store) MintSecretCapability(id, actor, permission string) (string, error) {
	if permission != "secret:read" && permission != "secret:write" && permission != "secret:grant" {
		return "", fmt.Errorf("unsupported secret permission")
	}
	s.mu.RLock()
	_, ok := s.cells[id]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("cell %q not found", id)
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "operator"
	}
	return s.capabilities.Mint(capability.Claims{CellID: id, ActorID: actor, Role: "operator", Permissions: []string{permission}}, time.Minute)
}

func (s *Store) RequestSecretGrant(id, credential, purpose, actor, envName string, command []string, workingDir string, ttl time.Duration) (model.CellSnapshot, model.SecretGrantRequest, error) {
	if ttl <= 0 {
		ttl = 20 * time.Minute
	}
	if ttl > 20*time.Minute {
		return model.CellSnapshot{}, model.SecretGrantRequest{}, fmt.Errorf("Tier-2 TTL exceeds 20 minutes")
	}
	credential = strings.TrimSpace(credential)
	purpose = strings.TrimSpace(purpose)
	envName = strings.TrimSpace(envName)
	if envName == "" {
		envName = credential
	}
	if credential == "" || purpose == "" || len(command) == 0 || strings.TrimSpace(command[0]) == "" {
		return model.CellSnapshot{}, model.SecretGrantRequest{}, fmt.Errorf("credential, purpose, and command are required")
	}
	if !validEnvironmentName(envName) {
		return model.CellSnapshot{}, model.SecretGrantRequest{}, fmt.Errorf("invalid Tier-2 environment name")
	}
	for _, argument := range command {
		if strings.ContainsRune(argument, '\x00') {
			return model.CellSnapshot{}, model.SecretGrantRequest{}, fmt.Errorf("Tier-2 command contains an invalid null byte")
		}
	}
	workingDir = filepath.Clean(defaultValue(strings.TrimSpace(workingDir), "."))
	if filepath.IsAbs(workingDir) || workingDir == ".." || strings.HasPrefix(workingDir, ".."+string(filepath.Separator)) {
		return model.CellSnapshot{}, model.SecretGrantRequest{}, fmt.Errorf("Tier-2 working directory must stay inside the worktree")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, model.SecretGrantRequest{}, fmt.Errorf("cell %q not found", id)
	}
	actor = defaultValue(actor, r.cell.Agent.ID)
	now := time.Now().UTC()
	request := model.SecretGrantRequest{ID: fmt.Sprintf("secret-grant-%s-%d", id, s.nextID+1), Credential: credential, Purpose: secrets.RedactText(purpose), RequestedBy: actor, Status: "pending", RequestedTTLSeconds: int64(ttl / time.Second), CreatedAt: now, EnvName: envName, Command: append([]string(nil), command...), WorkingDir: workingDir}
	r.cell.SecretRequests = append(r.cell.SecretRequests, request)
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventIntent, Source: actor, Actor: actor, Action: "secret.ask-human", Summary: "Agent requested a Tier-2 credential grant", Detail: "credential=" + credential + "; purpose=" + request.Purpose, Danger: "high", Timestamp: now})
	return snapshotLocked(r), request, nil
}

func validEnvironmentName(value string) bool {
	if value == "" || !(value[0] == '_' || value[0] >= 'A' && value[0] <= 'Z' || value[0] >= 'a' && value[0] <= 'z') {
		return false
	}
	for i := 1; i < len(value); i++ {
		char := value[i]
		if char != '_' && !(char >= 'A' && char <= 'Z') && !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func (s *Store) ApproveSecretGrant(id, requestID, operator, capToken string) (model.CellSnapshot, string, error) {
	claims, err := s.capabilities.Verify(capToken, id, "secret:grant")
	if err != nil || claims.Role != "operator" || claims.ActorID != operator {
		return model.CellSnapshot{}, "", fmt.Errorf("fresh operator secret:grant capability required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, "", fmt.Errorf("cell %q not found", id)
	}
	for i := range r.cell.SecretRequests {
		request := &r.cell.SecretRequests[i]
		if request.ID != requestID {
			continue
		}
		if request.Status != "pending" {
			return snapshotLocked(r), "", fmt.Errorf("secret request is not pending")
		}
		ttl := time.Duration(request.RequestedTTLSeconds) * time.Second
		if ttl <= 0 || ttl > 20*time.Minute {
			ttl = 20 * time.Minute
		}
		token, err := s.capabilities.Mint(capability.Claims{CellID: id, ActorID: "attach-" + id, Role: "attach", Permissions: []string{"tier2:consume:" + requestID}}, ttl)
		if err != nil {
			return model.CellSnapshot{}, "", err
		}
		now := time.Now().UTC()
		request.Status = "approved"
		request.ApprovedBy = operator
		request.ExpiresAt = now.Add(ttl)
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: operator, Actor: operator, Action: "secret.grant.approve", Summary: "Operator approved a Tier-2 credential grant", Detail: "request=" + requestID + "; credential=" + request.Credential + "; ttl=" + ttl.String(), Danger: "critical", Authenticated: true, Timestamp: now})
		return snapshotLocked(r), token, nil
	}
	return model.CellSnapshot{}, "", fmt.Errorf("secret request %q not found", requestID)
}

// FailSecretGrantDelivery returns an unconsumed approval to pending after the
// attach-sidecar delivery boundary fails. The issued token becomes unusable
// because consumption also requires durable approved state.
func (s *Store) FailSecretGrantDelivery(id, requestID, _ string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	for index := range r.cell.SecretRequests {
		request := &r.cell.SecretRequests[index]
		if request.ID != requestID {
			continue
		}
		if request.Status != "approved" {
			return snapshotLocked(r), fmt.Errorf("secret request is not awaiting delivery")
		}
		now := time.Now().UTC()
		request.Status = "pending"
		request.ApprovedBy = ""
		request.ExpiresAt = time.Time{}
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "control-plane", Action: "secret.grant.delivery-failed", Summary: "Tier-2 credential grant delivery failed closed", Detail: "request=" + requestID + "; reason=attach-delivery-unavailable", Danger: "critical", Authenticated: true, Timestamp: now})
		return snapshotLocked(r), nil
	}
	return model.CellSnapshot{}, fmt.Errorf("secret request %q not found", requestID)
}

func (s *Store) ConsumeSecretGrant(id, requestID, token string) (string, secrets.Receipt, error) {
	claims, err := s.capabilities.Verify(token, id, "tier2:consume:"+requestID)
	if err != nil || claims.Role != "attach" || claims.ActorID != "attach-"+id {
		return "", secrets.Receipt{}, fmt.Errorf("valid attach-sidecar Tier-2 grant required")
	}
	s.mu.Lock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.Unlock()
		return "", secrets.Receipt{}, fmt.Errorf("cell %q not found", id)
	}
	var request *model.SecretGrantRequest
	for i := range r.cell.SecretRequests {
		if r.cell.SecretRequests[i].ID == requestID {
			request = &r.cell.SecretRequests[i]
			break
		}
	}
	if request == nil || request.Status != "approved" || time.Now().UTC().After(request.ExpiresAt) {
		s.mu.Unlock()
		return "", secrets.Receipt{}, fmt.Errorf("Tier-2 grant is unavailable or expired")
	}
	credential := request.Credential
	request.Status = "consuming"
	s.mu.Unlock()
	value, receipt, err := s.secretBroker.Get(id, credential, "attach-"+id)
	if err != nil {
		s.mu.Lock()
		for i := range s.cells[id].cell.SecretRequests {
			if s.cells[id].cell.SecretRequests[i].ID == requestID && s.cells[id].cell.SecretRequests[i].Status == "consuming" {
				s.cells[id].cell.SecretRequests[i].Status = "approved"
			}
		}
		s.mu.Unlock()
		return "", secrets.Receipt{}, err
	}
	receipt.Action = "secret:tier2-inject"
	s.mu.Lock()
	defer s.mu.Unlock()
	r = s.cells[id]
	for i := range r.cell.SecretRequests {
		if r.cell.SecretRequests[i].ID == requestID {
			if r.cell.SecretRequests[i].Status != "consuming" {
				return "", secrets.Receipt{}, fmt.Errorf("Tier-2 grant already consumed")
			}
		}
	}
	if err := s.appendEvidenceLocked(r, "secret-receipt", receipt); err != nil {
		for i := range r.cell.SecretRequests {
			if r.cell.SecretRequests[i].ID == requestID && r.cell.SecretRequests[i].Status == "consuming" {
				r.cell.SecretRequests[i].Status = "approved"
			}
		}
		return "", secrets.Receipt{}, fmt.Errorf("persist Tier-2 secret receipt: %w", err)
	}
	for i := range r.cell.SecretRequests {
		if r.cell.SecretRequests[i].ID == requestID {
			r.cell.SecretRequests[i].Status = "consumed"
			r.cell.SecretRequests[i].Receipt = receipt.ID
		}
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "attach-" + id, Action: "secret.tier2.inject", Summary: "Tier-2 credential injected for one process", Detail: "request=" + requestID + "; credential=" + credential + "; receipt=" + receipt.ID, Danger: "critical", Authenticated: true, Timestamp: now})
	return value, receipt, nil
}

func (s *Store) SecretValue(id, name, actor, token string) (string, secrets.Receipt, error) {
	claims, err := s.capabilities.Verify(token, id, "secret:read")
	if err != nil || claims.Role != "operator" || claims.ActorID != actor {
		return "", secrets.Receipt{}, fmt.Errorf("fresh operator secret:read capability required")
	}
	value, receipt, err := s.secretBroker.Get(id, name, actor)
	if err != nil {
		return "", secrets.Receipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return "", secrets.Receipt{}, fmt.Errorf("cell %q not found", id)
	}
	if err := s.appendEvidenceLocked(r, "secret-receipt", receipt); err != nil {
		return "", secrets.Receipt{}, fmt.Errorf("persist secret read receipt: %w", err)
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventEdit, Source: actor, Actor: actor, Action: "secret.reveal", Summary: "Secret explicitly revealed to operator", Detail: "name=" + name + "; receipt=" + receipt.ID, Danger: "high", Authenticated: true, Timestamp: now})
	return value, receipt, nil
}

func (s *Store) SecretDescriptors(id string) ([]secrets.Descriptor, error) {
	s.mu.RLock()
	_, ok := s.cells[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("cell %q not found", id)
	}
	return s.secretBroker.List(id)
}

func (s *Store) ConfigureSecretProxy(id, credential, destination, header, operator, capToken string) (model.CellSnapshot, model.SecretProxyRoute, string, error) {
	claims, err := s.capabilities.Verify(capToken, id, "secret:grant")
	if err != nil || claims.Role != "operator" || claims.ActorID != operator {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", fmt.Errorf("fresh operator secret:grant capability required")
	}
	target, err := url.Parse(destination)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Opaque != "" {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", fmt.Errorf("Tier-1 destination must be an exact HTTPS origin")
	}
	if (target.Path != "" && target.Path != "/") || target.RawPath != "" || target.RawQuery != "" || target.Fragment != "" {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", fmt.Errorf("Tier-1 destination must not contain a path, query, or fragment")
	}
	target.Path = ""
	if header == "" {
		header = "Authorization"
	}
	if !validProxyHeader(header) {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", fmt.Errorf("unsupported credential header")
	}
	found := false
	descriptors, err := s.secretBroker.List(id)
	if err != nil {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", err
	}
	for _, descriptor := range descriptors {
		if descriptor.Name == credential {
			found = true
			break
		}
	}
	if !found {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", fmt.Errorf("secret not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", fmt.Errorf("cell %q not found", id)
	}
	now := time.Now().UTC()
	route := model.SecretProxyRoute{ID: fmt.Sprintf("proxy-%s-%d", id, s.nextID+1), Credential: credential, Destination: strings.TrimRight(target.String(), "/"), Header: header, CreatedBy: operator, CreatedAt: now, ExpiresAt: now.Add(20 * time.Minute)}
	token, err := s.capabilities.Mint(capability.Claims{CellID: id, ActorID: "agent-" + id, Role: "agent", Permissions: []string{"proxy:use:" + route.ID}}, 20*time.Minute)
	if err != nil {
		return model.CellSnapshot{}, model.SecretProxyRoute{}, "", err
	}
	r.cell.SecretProxyRoutes = append(r.cell.SecretProxyRoutes, route)
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: operator, Actor: operator, Action: "secret.proxy.configure", Summary: "Tier-1 credential proxy configured", Detail: "route=" + route.ID + "; destination=" + target.Host + "; credential=" + credential, Danger: "high", Authenticated: true, Timestamp: now})
	return snapshotLocked(r), route, token, nil
}

func (s *Store) ResolveSecretProxy(id, routeID, token string) (model.SecretProxyRoute, string, secrets.Receipt, error) {
	claims, err := s.capabilities.Verify(token, id, "proxy:use:"+routeID)
	if err != nil || claims.Role != "agent" || claims.ActorID != "agent-"+id {
		return model.SecretProxyRoute{}, "", secrets.Receipt{}, fmt.Errorf("valid Tier-1 proxy capability required")
	}
	s.mu.RLock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.RUnlock()
		return model.SecretProxyRoute{}, "", secrets.Receipt{}, fmt.Errorf("cell %q not found", id)
	}
	var route model.SecretProxyRoute
	for _, candidate := range r.cell.SecretProxyRoutes {
		if candidate.ID == routeID {
			route = candidate
			break
		}
	}
	s.mu.RUnlock()
	if route.ID == "" || time.Now().UTC().After(route.ExpiresAt) {
		return model.SecretProxyRoute{}, "", secrets.Receipt{}, fmt.Errorf("Tier-1 route unavailable or expired")
	}
	value, receipt, err := s.secretBroker.Get(id, route.Credential, "egress-proxy")
	if err != nil {
		return model.SecretProxyRoute{}, "", secrets.Receipt{}, err
	}
	receipt.Action = "secret:proxy-inject"
	s.mu.Lock()
	r = s.cells[id]
	if err := s.appendEvidenceLocked(r, "secret-receipt", receipt); err != nil {
		s.mu.Unlock()
		return model.SecretProxyRoute{}, "", secrets.Receipt{}, fmt.Errorf("persist proxy secret receipt: %w", err)
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "egress-proxy", Action: "secret.proxy.inject", Summary: "Tier-1 proxy injected a network-scoped credential", Detail: "route=" + route.ID + "; destination=" + route.Destination + "; receipt=" + receipt.ID, Danger: "medium", Authenticated: true, Timestamp: now})
	s.mu.Unlock()
	return route, value, receipt, nil
}

func validProxyHeader(value string) bool {
	switch http.CanonicalHeaderKey(value) {
	case "Authorization", "X-Api-Key", "Private-Token":
		return true
	}
	return false
}

func (s *Store) ApproveReview(id, reviewID string) (model.CellSnapshot, error) {
	s.mu.Lock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.Unlock()
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	var request review.CommitRequest
	for _, candidate := range r.cell.Reviews {
		if candidate.ID == reviewID {
			if candidate.Status == "blocked" || !candidate.CommitReady {
				s.mu.Unlock()
				return model.CellSnapshot{}, fmt.Errorf("review %q is not commit-ready", reviewID)
			}
			if candidate.Status != "pending" {
				snapshot := snapshotLocked(r)
				s.mu.Unlock()
				return snapshot, nil
			}
			request = review.CommitRequest{CellID: id, Branch: r.cell.Branch, Review: candidate, Workdir: r.workdir}
			for i := range r.cell.Reviews {
				if r.cell.Reviews[i].ID == reviewID {
					r.cell.Reviews[i].Status = "committing"
					break
				}
			}
			break
		}
	}
	committer := s.committer
	s.mu.Unlock()
	if request.Review.ID == "" {
		return model.CellSnapshot{}, fmt.Errorf("review %q not found", reviewID)
	}
	commitContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	receipt, err := committer.Commit(commitContext, request)
	s.mu.Lock()
	defer s.mu.Unlock()
	r = s.cells[id]
	if err != nil {
		for i := range r.cell.Reviews {
			if r.cell.Reviews[i].ID == reviewID {
				r.cell.Reviews[i].Status = "pending"
				break
			}
		}
		s.appendEventLocked(r, model.Event{Kind: model.EventReview, Source: "buckley", Action: "review.commit.failed", Summary: "Entity diff commit failed", Detail: err.Error(), Danger: "high"})
		return snapshotLocked(r), err
	}
	receipt = secrets.RedactText(receipt)
	_ = s.appendEvidenceLocked(r, "review-receipt", map[string]string{"reviewID": reviewID, "receipt": receipt})
	for i := range r.cell.Reviews {
		if r.cell.Reviews[i].ID == reviewID {
			r.cell.Reviews[i].Status = "approved"
			r.cell.Reviews[i].Receipt = receipt
			break
		}
	}
	// A successful commit establishes one coherent BASE for the entire
	// worktree, not merely the entity paths displayed by the approved card.
	r.baseline = append(r.baseline[:0], r.cell.Files...)
	for i := range r.baseline {
		r.baseline[i].Modified = false
	}
	for i := range r.cell.Files {
		r.cell.Files[i].Modified = false
	}
	for i := range r.cell.Shadows {
		base := baselineContent(r.baseline, r.cell.Shadows[i].Path)
		if contentHash(base) != r.cell.Shadows[i].BaseHash {
			r.cell.Shadows[i].Stale = true
		}
	}
	now := time.Now().UTC()
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventReview, Source: "buckley", Action: "review.approve", Summary: "Entity diff approved", Detail: "Commit receipt: " + receipt, Danger: "high", Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) AcknowledgeReview(id, reviewID, actor, reason string, secretFinding, evidenceDegraded bool) (model.CellSnapshot, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return model.CellSnapshot{}, fmt.Errorf("acknowledgment reason is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	for i := range r.cell.Reviews {
		item := &r.cell.Reviews[i]
		if item.ID != reviewID {
			continue
		}
		if len(item.SecretFindings) > 0 && !secretFinding {
			return model.CellSnapshot{}, fmt.Errorf("secret finding acknowledgment is required")
		}
		if item.EvidenceHealth == "degraded" && !evidenceDegraded {
			return model.CellSnapshot{}, fmt.Errorf("degraded evidence acknowledgment is required")
		}
		item.SecretAcknowledged = secretFinding
		item.EvidenceAcknowledged = evidenceDegraded
		item.CommitReady = (len(item.SecretFindings) == 0 || item.SecretAcknowledged) && (item.EvidenceHealth != "degraded" || item.EvidenceAcknowledged)
		if item.CommitReady {
			item.Status = "pending"
		}
		now := time.Now().UTC()
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventReview, Source: defaultValue(actor, "operator"), Actor: defaultValue(actor, "operator"), Action: "review.risk.acknowledge", Summary: "Operator acknowledged review risk", Detail: "review=" + reviewID + "; reason=" + secrets.RedactText(reason), Danger: "critical", Authenticated: true, Timestamp: now})
		return snapshotLocked(r), nil
	}
	return model.CellSnapshot{}, fmt.Errorf("review %q not found", reviewID)
}

func (s *Store) RejectReview(id, reviewID, actor, reason string) (model.CellSnapshot, string, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return model.CellSnapshot{}, "", fmt.Errorf("rejection reason is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, "", fmt.Errorf("cell %q not found", id)
	}
	for i := range r.cell.Reviews {
		item := &r.cell.Reviews[i]
		if item.ID != reviewID {
			continue
		}
		item.Status = "rejected"
		item.CommitReady = false
		item.RejectionReason = secrets.RedactText(reason)
		prompt := "Review " + reviewID + " was rejected: " + item.RejectionReason
		now := time.Now().UTC()
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventReview, Source: defaultValue(actor, "operator"), Actor: defaultValue(actor, "operator"), Action: "review.reject", Summary: "Entity diff rejected with feedback", Detail: prompt, Danger: "medium", Authenticated: true, Timestamp: now})
		return snapshotLocked(r), prompt, nil
	}
	return model.CellSnapshot{}, "", fmt.Errorf("review %q not found", reviewID)
}

func (s *Store) Attach(id, token, agentID, name string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Status == model.CellStopped {
		return model.CellSnapshot{}, fmt.Errorf("cell %q is stopped", id)
	}
	if agentID == "" {
		agentID = "agent-" + id
	}
	claims, err := s.capabilities.Verify(token, id, "hub:attach")
	if err != nil || claims.Role != "agent" || claims.ActorID != agentID {
		return model.CellSnapshot{}, fmt.Errorf("invalid agent capability")
	}
	if name == "" {
		name = agentID
	}
	now := time.Now().UTC()
	r.cell.Agent = model.AgentPresence{ID: agentID, Name: name, Status: "attached", Connected: true, LastSeen: now}
	if r.cell.Status == model.CellCreating && r.cell.Sandbox.Phase == model.SandboxRunning {
		r.cell.Status = model.CellReady
	}
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventPresence, Source: agentID, Action: "agent.attach", Summary: name + " attached to the cell", Detail: "Prompt and edit messages are now bidirectional.", Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) Detach(id, agentID string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	if agentID != "" && r.cell.Agent.ID != agentID {
		return snapshotLocked(r), nil
	}
	now := time.Now().UTC()
	r.cell.Agent.Connected = false
	r.cell.Agent.Status = "detached"
	r.cell.Agent.LastSeen = now
	if r.cell.Status != model.CellStopped && r.cell.Status != model.CellError {
		r.cell.Status = model.CellReady
	}
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventPresence, Source: "control-plane", Action: "agent.detach", Summary: "Agent detached from the cell", Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) UpdateAgent(id, agentID, status string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	now := time.Now().UTC()
	r.cell.Agent.ID = defaultValue(agentID, r.cell.Agent.ID)
	r.cell.Agent.Status = defaultValue(status, "working")
	r.cell.Agent.Connected = true
	if r.cell.Agent.Status == "idle" && r.cell.Status != model.CellStopped && r.cell.Status != model.CellError {
		r.cell.Status = model.CellIdle
	}
	r.cell.Agent.LastSeen = now
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventPresence, Source: r.cell.Agent.ID, Action: "agent.status", Summary: "Agent status: " + r.cell.Agent.Status, Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) Heartbeat(id, agentID string) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	if r.cell.Agent.ID != "" && agentID != r.cell.Agent.ID {
		return model.CellSnapshot{}, fmt.Errorf("heartbeat actor does not own cell attachment")
	}
	now := time.Now().UTC()
	r.cell.Agent.Connected = true
	r.cell.Agent.LastSeen = now
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventPresence, Source: agentID, Actor: agentID, Action: "agent.heartbeat", Summary: "Agent attachment heartbeat", Timestamp: now})
	return snapshotLocked(r), nil
}

func (s *Store) RefreshAttachToken(id, token string) (string, error) {
	if !s.VerifyAttachToken(id, token) {
		return "", fmt.Errorf("invalid or expired agent capability")
	}
	return s.mintAgentCapability(id)
}

func (s *Store) RecordEvent(id string, event model.Event) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	if event.Kind == "" {
		return model.CellSnapshot{}, fmt.Errorf("event kind is required")
	}
	if event.Source == "" {
		event.Source = "external"
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.ID != "" {
		for _, existing := range r.events {
			if existing.ID == event.ID {
				return snapshotLocked(r), nil
			}
		}
	}
	s.appendEventLocked(r, event)
	r.cell.UpdatedAt = event.Timestamp
	r.cell.Revision++
	return snapshotLocked(r), nil
}

// KernelBatchCursor is the last durably accepted telemetry batch for a node.
// Node agents use it to resume monotonically after either side restarts.
func (s *Store) KernelBatchCursor(nodeID string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.kernelBatches[strings.TrimSpace(nodeID)]
}

// CommitKernelBatch advances a node cursor only after every event in the batch
// has entered durable cell state. Event IDs make a retry after a partial write
// idempotent, while this cursor makes replay rejection survive process restart.
func (s *Store) CommitKernelBatch(nodeID string, sequence uint64) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || sequence == 0 {
		return fmt.Errorf("node and non-zero kernel batch sequence are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.kernelBatches[nodeID]
	if sequence <= previous {
		return fmt.Errorf("kernel batch sequence %d is not newer than %d", sequence, previous)
	}
	s.kernelBatches[nodeID] = sequence
	if err := s.persistLocked(); err != nil {
		if previous == 0 {
			delete(s.kernelBatches, nodeID)
		} else {
			s.kernelBatches[nodeID] = previous
		}
		return err
	}
	return nil
}

func (s *Store) RequestActionApproval(id, requestID, nodeID string, cgroupID uint64, pid uint32, kind, resource string) (model.CellSnapshot, model.ActionApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, model.ActionApproval{}, fmt.Errorf("cell %q not found", id)
	}
	for _, existing := range r.cell.ActionApprovals {
		if existing.ID == requestID {
			return snapshotLocked(r), existing, nil
		}
	}
	now := time.Now().UTC()
	request := model.ActionApproval{
		ID: requestID, CellID: id, NodeID: strings.TrimSpace(nodeID), CgroupID: cgroupID,
		PID: pid, Kind: strings.TrimSpace(kind), Resource: secrets.RedactText(resource), Status: "pending",
		RequestedAt: now, ExpiresAt: now.Add(2 * time.Minute),
	}
	if request.ID == "" || request.NodeID == "" || request.CgroupID == 0 || request.PID == 0 || request.Kind == "" {
		return model.CellSnapshot{}, model.ActionApproval{}, fmt.Errorf("action approval requires request, node, cgroup, process, and kind")
	}
	r.cell.ActionApprovals = append(r.cell.ActionApprovals, request)
	r.cell.UpdatedAt = now
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "arbiter", Action: "action.ask-human", Summary: "Kernel-blocked action requires operator decision", Detail: "request=" + request.ID + "; kind=" + request.Kind + "; resource=" + request.Resource, Danger: "critical", Authenticated: true, Timestamp: now})
	return snapshotLocked(r), request, nil
}

func (s *Store) DecideActionApproval(id, requestID, actor string, approved bool) (model.CellSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cells[id]
	if !ok {
		return model.CellSnapshot{}, fmt.Errorf("cell %q not found", id)
	}
	now := time.Now().UTC()
	for index := range r.cell.ActionApprovals {
		request := &r.cell.ActionApprovals[index]
		if request.ID != requestID {
			continue
		}
		if request.Status != "pending" || !now.Before(request.ExpiresAt) {
			return snapshotLocked(r), fmt.Errorf("action approval is no longer pending")
		}
		request.Status = map[bool]string{true: "approved", false: "rejected"}[approved]
		request.DecidedAt = now
		request.DecidedBy = defaultValue(actor, "operator")
		r.cell.UpdatedAt = now
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: request.DecidedBy, Actor: request.DecidedBy, Action: "action." + request.Status, Summary: "Operator " + request.Status + " kernel-blocked action", Detail: "request=" + request.ID + "; kind=" + request.Kind + "; resource=" + request.Resource, Danger: "critical", Authenticated: true, Timestamp: now})
		return snapshotLocked(r), nil
	}
	return snapshotLocked(r), fmt.Errorf("action approval %q not found", requestID)
}

// TakeNodeActionDecisions returns each terminal decision exactly once. Pending
// requests become rejected at expiry so a stopped process is always resumed.
func (s *Store) TakeNodeActionDecisions(nodeID string) []model.ActionApproval {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var decisions []model.ActionApproval
	for _, r := range s.cells {
		changed := false
		for index := range r.cell.ActionApprovals {
			request := &r.cell.ActionApprovals[index]
			if request.NodeID != nodeID || request.Delivered {
				continue
			}
			if request.Status == "pending" && !now.Before(request.ExpiresAt) {
				request.Status = "rejected"
				request.DecidedBy = "timeout"
				request.DecidedAt = now
				changed = true
			}
			if request.Status != "approved" && request.Status != "rejected" {
				continue
			}
			request.Delivered = true
			decisions = append(decisions, *request)
			changed = true
		}
		if changed {
			r.cell.UpdatedAt = now
			r.cell.Revision++
			_ = s.persistLocked()
		}
	}
	return decisions
}

func (s *Store) VerifyAttachToken(id, token string) bool {
	s.mu.RLock()
	_, ok := s.cells[id]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	claims, err := s.capabilities.Verify(token, id, "hub:attach")
	return err == nil && claims.Role == "agent"
}

// VerifyCapability resolves a signed, cell-scoped capability for transport
// upgrade and API authorization. Callers must request the permission they
// actually consume; an empty permission is intentionally unsupported here.
func (s *Store) VerifyCapability(token, id, permission string) (capability.Claims, error) {
	if strings.TrimSpace(permission) == "" {
		return capability.Claims{}, fmt.Errorf("capability permission is required")
	}
	claims, err := s.capabilities.Verify(token, id, permission)
	if err != nil {
		return capability.Claims{}, err
	}
	s.mu.RLock()
	_, ok := s.cells[claims.CellID]
	s.mu.RUnlock()
	if !ok {
		return capability.Claims{}, fmt.Errorf("cell %q not found", claims.CellID)
	}
	return claims, nil
}

func (s *Store) MintOperatorCapability(id, actor string) (string, error) {
	s.mu.RLock()
	_, ok := s.cells[id]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("cell %q not found", id)
	}
	return s.capabilities.Mint(capability.Claims{
		CellID: id, ActorID: defaultValue(actor, "operator"), Role: "operator",
		Permissions: []string{"doc:read", "doc:write", "prompt:read", "prompt:write", "telemetry:read", "review:read", "review:approve", "cell:control", "policy:approve", "policy:apply"},
	}, 5*time.Minute)
}

func (s *Store) AttachToken(id string) (string, error) {
	s.mu.RLock()
	_, ok := s.cells[id]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("cell %q not found", id)
	}
	return s.mintAgentCapability(id)
}

func (s *Store) mintAgentCapability(id string) (string, error) {
	return s.capabilities.Mint(capability.Claims{
		CellID: id, ActorID: "agent-" + id, Role: "agent",
		Permissions: []string{"hub:attach", "doc:read", "doc:write", "prompt:read", "telemetry:write", "review:read", "secret:request", "agent:status", "agent:commit"},
	}, 15*time.Minute)
}

func (s *Store) mintArmCapability(id string) (string, error) {
	return s.capabilities.Mint(capability.Claims{
		CellID: id, ActorID: "armgate-" + id, Role: "armgate", Permissions: []string{"arm:read"},
	}, 5*time.Minute)
}

func (s *Store) VerifyArmToken(id, token string) bool {
	claims, err := s.capabilities.Verify(token, id, "arm:read")
	return err == nil && claims.Role == "armgate"
}

func (s *Store) File(id, path string) (model.File, error) {
	if secrets.IsSensitivePath(path) {
		return model.File{}, fmt.Errorf("sensitive path %q is only available through the secret broker", path)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cells[id]
	if !ok {
		return model.File{}, fmt.Errorf("cell %q not found", id)
	}
	for _, file := range r.cell.Files {
		if file.Path == path {
			return file, nil
		}
	}
	return model.File{}, fmt.Errorf("file %q not found", path)
}

func (s *Store) PolicyPreview(id, content string) (policy.PreviewResult, error) {
	s.mu.RLock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.RUnlock()
		return policy.PreviewResult{}, fmt.Errorf("cell %q not found", id)
	}
	before := policy.Manifest{
		Profile: r.cell.Capabilities.Profile, ProfileDigest: r.cell.Capabilities.ProfileDigest, Filesystem: r.cell.Capabilities.Filesystem,
		Exec: append([]string(nil), r.cell.Capabilities.Exec...), Egress: append([]string(nil), r.cell.Capabilities.Egress...), Programs: append([]string(nil), r.cell.Capabilities.Programs...), Danger: r.cell.Capabilities.Danger, RecordedOnly: r.cell.Capabilities.RecordedOnly,
	}
	replay := policy.ReplayCell{CellID: id, Profile: before.Profile, Worktree: r.workdir}
	for _, event := range r.events {
		if event.Kind != model.EventKernel {
			continue
		}
		replay.Events = append(replay.Events, policy.ReplayEvent{ID: event.ID, Action: event.Action, Path: event.Path, Argv: event.Argv, Destination: event.Destination})
	}
	s.mu.RUnlock()
	return policy.PreviewForCells(before, content, []policy.ReplayCell{replay})
}

// ApplyPolicy replays the governed decision and atomically re-arms enforcement
// on the live sandbox. The new manifest is published only after the runtime
// confirms the policy selector changed; the pod and agent are not restarted.
func (s *Store) ApplyPolicy(ctx context.Context, id, content, actor string) (model.CellSnapshot, policy.PreviewResult, error) {
	return s.applyPolicy(ctx, id, content, actor)
}

// ApplyPolicyAuthorized is the external mutation boundary. Authentication
// identifies the operator; this fresh cell-scoped capability proves that the
// caller is authorized for the distinct policy-apply operation.
func (s *Store) ApplyPolicyAuthorized(ctx context.Context, id, content, actor, token string) (model.CellSnapshot, policy.PreviewResult, error) {
	claims, err := s.VerifyCapability(token, id, "policy:apply")
	if err != nil || claims.Role != "operator" {
		return model.CellSnapshot{}, policy.PreviewResult{}, fmt.Errorf("fresh operator policy:apply capability required")
	}
	if strings.TrimSpace(actor) == "" {
		actor = claims.ActorID
	}
	return s.applyPolicy(ctx, id, content, actor)
}

func (s *Store) applyPolicy(ctx context.Context, id, content, actor string) (model.CellSnapshot, policy.PreviewResult, error) {
	preview, err := s.PolicyPreview(id, content)
	if err != nil {
		return model.CellSnapshot{}, policy.PreviewResult{}, err
	}
	s.mu.Lock()
	r, ok := s.cells[id]
	if !ok {
		s.mu.Unlock()
		return model.CellSnapshot{}, preview, fmt.Errorf("cell %q not found", id)
	}
	if len(preview.Changes) == 0 {
		snapshot := snapshotLocked(r)
		s.mu.Unlock()
		return snapshot, preview, nil
	}
	r.cell.Status = model.CellSteering
	r.cell.UpdatedAt = time.Now().UTC()
	r.cell.Revision++
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: defaultValue(actor, "operator"), Actor: defaultValue(actor, "operator"), Action: "policy.replay", Summary: "Policy replay approved; enforcement re-arm started", Detail: strings.Join(preview.Changes, "; "), Danger: preview.After.Danger, Authenticated: true, Timestamp: r.cell.UpdatedAt})
	token := r.attachToken
	armToken := r.armToken
	repoURL, branch := r.cell.RepoURL, r.cell.Branch
	s.mu.Unlock()
	pod, err := s.runtime.Rearm(ctx, sandbox.Spec{CellID: id, RepoURL: repoURL, Branch: branch, Profile: preview.After.Profile, HubURL: s.hubURL, AttachToken: token, ArmToken: armToken})
	s.mu.Lock()
	defer s.mu.Unlock()
	r = s.cells[id]
	if err != nil {
		r.cell.Status = model.CellReady
		r.cell.UpdatedAt = time.Now().UTC()
		r.cell.Revision++
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "sandbox-runtime", Action: "policy.rearm.failed", Summary: "Policy enforcement re-arm rejected; previous profile retained", Detail: secrets.RedactText(err.Error()), Danger: "critical", Timestamp: r.cell.UpdatedAt})
		return snapshotLocked(r), preview, fmt.Errorf("re-arm policy: %w", err)
	}
	r.cell.SandboxProfile = preview.After.Profile
	r.cell.Capabilities = capabilityManifest(preview.After)
	r.cell.Sandbox.Phase = model.SandboxRunning
	r.cell.Sandbox.LastTransition = time.Now().UTC()
	if pod.Armed {
		r.cell.Sandbox.Armed = true
		r.cell.Sandbox.ArmedAt = r.cell.Sandbox.LastTransition
		r.cell.Sandbox.Enforcement = "memory-runtime"
		r.cell.Status = model.CellReady
	} else {
		r.cell.Status = model.CellSteering
		r.cell.Sandbox.Armed = false
		r.cell.Sandbox.ArmedAt = time.Time{}
		r.cell.Sandbox.Programs = nil
		r.cell.Sandbox.ManifestDigest = ""
		r.cell.Sandbox.ObjectDigest = ""
		r.cell.Sandbox.CgroupID = 0
		r.cell.Sandbox.Enforcement = "rearming"
	}
	r.cell.UpdatedAt = r.cell.Sandbox.LastTransition
	r.cell.Revision++
	for i := range r.cell.Files {
		if r.cell.Files[i].Path == "policy/sandbox.yaml" {
			r.cell.Files[i].Content = content
			r.cell.Files[i].Modified = true
			syncWorktreeFile(s.worktreeRoot, id, r.cell.Files[i].Path, content)
		}
	}
	summary := "Live enforcement re-arm requested without sandbox restart"
	if pod.Armed {
		summary = "Live enforcement profile armed without sandbox restart"
	}
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "horizon", Action: "policy.rearm", Summary: summary, Detail: "profile=" + preview.After.Profile + "; digest=" + preview.After.ProfileDigest + "; affected=" + strings.Join(preview.Affects, ","), Danger: preview.After.Danger, Timestamp: r.cell.UpdatedAt})
	return snapshotLocked(r), preview, nil
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

func (s *Store) CellIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.cells))
	for id := range s.cells {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
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

func (s *Store) NodeCells(ctx context.Context, nodeID string) ([]sandbox.NodeCell, error) {
	source, ok := s.runtime.(sandbox.NodeCellSource)
	if !ok {
		return nil, fmt.Errorf("sandbox runtime does not expose node cell discovery")
	}
	return source.NodeCells(ctx, nodeID)
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
	for i := range cell.Files {
		if secrets.IsSensitivePath(cell.Files[i].Path) {
			cell.Files[i].Content = "<redacted>"
		}
	}
	cell.Reviews = append([]model.Review(nil), r.cell.Reviews...)
	cell.Shadows = append([]model.ShadowRevision(nil), r.cell.Shadows...)
	for i := range cell.Shadows {
		cell.Shadows[i].Before = secrets.RedactText(cell.Shadows[i].Before)
		cell.Shadows[i].After = secrets.RedactText(cell.Shadows[i].After)
		if cell.Shadows[i].URI == "" {
			cell.Shadows[i].URI = shadowURI(cell.ID, cell.Shadows[i].Path, cell.Shadows[i].ID)
		}
	}
	var intent, kernel int
	for _, event := range r.events {
		if event.Kind == model.EventIntent {
			intent++
		}
		if event.Kind == model.EventKernel {
			kernel++
		}
	}
	cell.IntentCount = intent
	cell.KernelEventCount = kernel
	cell.Divergences = divergence.Evaluate(r.events, divergence.Options{
		CellID: r.cell.ID, Worktree: r.workdir, NetAllow: r.cell.Capabilities.Egress,
		EvidenceHealthy: r.cell.EvidenceHealth == "healthy",
	})
	cell.Divergence = len(cell.Divergences) > 0
	cell.DivergenceDetail = ""
	if cell.Divergence {
		cell.DivergenceDetail = cell.Divergences[0].RuleID + " · " + cell.Divergences[0].Summary
	}
	return model.CellSnapshot{Cell: cell, Events: append([]model.Event(nil), r.events...)}
}

func (s *Store) applyPodLocked(r *record, pod sandbox.Pod, emit bool) {
	now := pod.LastTransition
	if now.IsZero() {
		now = time.Now().UTC()
	}
	armed := r.cell.Sandbox.Armed || pod.Armed
	previous := r.cell.Sandbox
	r.cell.Sandbox = model.Sandbox{Name: pod.Name, Phase: model.SandboxPhase(pod.Phase), LastTransition: now, Failure: pod.Failure, Armed: armed, ArmedAt: previous.ArmedAt, Programs: append([]string(nil), previous.Programs...), ManifestDigest: previous.ManifestDigest, ObjectDigest: previous.ObjectDigest, CgroupID: previous.CgroupID, Enforcement: previous.Enforcement}
	switch pod.Phase {
	case sandbox.PhaseRunning:
		if armed && r.cell.Status != model.CellSteering {
			r.cell.Status = model.CellReady
		} else if !armed {
			r.cell.Status = model.CellCreating
		}
	case sandbox.PhasePending:
		r.cell.Status = model.CellCreating
	case sandbox.PhaseStopped:
		r.cell.Status = model.CellStopped
	case sandbox.PhaseFailed:
		r.cell.Status = model.CellError
	}
	r.cell.UpdatedAt = now
	if emit {
		summary := "Sandbox pod is " + string(pod.Phase)
		danger := "low"
		if pod.Phase == sandbox.PhaseFailed {
			danger = "high"
		}
		s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "sandbox-runtime", Action: "sandbox." + string(pod.Phase), Summary: summary, Detail: pod.Name, Danger: danger, Timestamp: now})
	}
}

func (s *Store) appendEventLocked(r *record, event model.Event) {
	if event.ID == "" {
		event.ID = s.eventID(r.cell.ID)
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Summary = secrets.RedactText(event.Summary)
	event.Detail = secrets.RedactText(event.Detail)
	r.events = append(r.events, event)
	_ = s.appendEvidenceLocked(r, "event", event)
	if s.cells[r.cell.ID] == r {
		if err := s.persistLocked(); err != nil {
			r.cell.Status = model.CellError
			r.cell.EvidenceHealth = "degraded"
			r.cell.EvidenceError = "durable state checkpoint failed: " + secrets.RedactText(err.Error())
		}
	}
}

type persistedState struct {
	Version       int               `json:"version"`
	NextID        uint64            `json:"nextID"`
	ActiveID      string            `json:"activeID"`
	KernelBatches map[string]uint64 `json:"kernelBatches,omitempty"`
	Cells         []persistedRecord `json:"cells"`
}

type persistedRecord struct {
	Cell      model.Cell                   `json:"cell"`
	Events    []model.Event                `json:"events"`
	Baseline  []model.File                 `json:"baseline"`
	Documents map[string]persistedDocument `json:"documents,omitempty"`
	History   []editOperation              `json:"history,omitempty"`
}

type persistedDocument struct {
	TextID string `json:"textID"`
	Data   []byte `json:"data"`
}

func (s *Store) persistLocked() error {
	if strings.TrimSpace(s.statePath) == "" {
		return nil
	}
	state := persistedState{Version: 1, NextID: s.nextID, ActiveID: s.activeID, KernelBatches: make(map[string]uint64, len(s.kernelBatches))}
	for nodeID, sequence := range s.kernelBatches {
		state.KernelBatches[nodeID] = sequence
	}
	ids := make([]string, 0, len(s.cells))
	for id := range s.cells {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := s.cells[id]
		cell := r.cell
		cell.Divergences = nil
		cell.Divergence = false
		cell.DivergenceDetail = ""
		cell.Files = durableFiles(cell.Files)
		baseline := durableFiles(r.baseline)
		documents := make(map[string]persistedDocument, len(r.docs))
		for path, document := range r.docs {
			if secrets.IsSensitivePath(path) {
				continue
			}
			data, saveErr := document.doc.Save()
			if saveErr != nil {
				return fmt.Errorf("save CRDT document %q: %w", path, saveErr)
			}
			documents[path] = persistedDocument{TextID: string(document.text), Data: data}
		}
		state.Cells = append(state.Cells, persistedRecord{Cell: cell, Events: append([]model.Event(nil), r.events...), Baseline: baseline, Documents: documents, History: append([]editOperation(nil), r.history...)})
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".mercutio-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.statePath); err != nil {
		return err
	}
	ok = true
	if d, openErr := os.Open(dir); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func durableFiles(files []model.File) []model.File {
	out := make([]model.File, 0, len(files))
	for _, file := range files {
		if secrets.IsSensitivePath(file.Path) {
			continue
		}
		out = append(out, file)
	}
	return out
}

func (s *Store) loadState() (bool, error) {
	if strings.TrimSpace(s.statePath) == "" {
		return false, nil
	}
	data, err := os.ReadFile(s.statePath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var state persistedState
	if err = json.Unmarshal(data, &state); err != nil {
		return false, err
	}
	if state.Version != 1 {
		return false, fmt.Errorf("unsupported state version %d", state.Version)
	}
	s.nextID = state.NextID
	s.activeID = state.ActiveID
	for nodeID, sequence := range state.KernelBatches {
		if strings.TrimSpace(nodeID) == "" || sequence == 0 {
			return false, fmt.Errorf("invalid persisted kernel batch cursor")
		}
		s.kernelBatches[nodeID] = sequence
	}
	for _, saved := range state.Cells {
		if saved.Cell.ID == "" {
			return false, fmt.Errorf("persisted cell has no ID")
		}
		r := s.newRecordLocked(saved.Cell.ID, saved.Cell.RepoURL, saved.Cell.Branch, saved.Cell.SandboxProfile, saved.Cell.Files, saved.Cell.CreatedAt)
		r.cell = saved.Cell
		r.events = append([]model.Event(nil), saved.Events...)
		r.baseline = append([]model.File(nil), saved.Baseline...)
		if len(saved.Documents) > 0 {
			r.docs = make(map[string]textDocument, len(saved.Documents))
			for path, savedDocument := range saved.Documents {
				doc, loadErr := crdt.Load(savedDocument.Data)
				if loadErr != nil {
					return false, fmt.Errorf("load CRDT document %q: %w", path, loadErr)
				}
				textID := crdt.ObjID(savedDocument.TextID)
				if _, textErr := doc.TextToString(textID); textErr != nil {
					return false, fmt.Errorf("validate CRDT document %q: %w", path, textErr)
				}
				r.docs[path] = textDocument{doc: doc, text: textID}
			}
			r.history = append([]editOperation(nil), saved.History...)
		}
		token, tokenErr := s.mintAgentCapability(saved.Cell.ID)
		if tokenErr != nil {
			return false, tokenErr
		}
		r.attachToken = token
		armToken, armErr := s.mintArmCapability(saved.Cell.ID)
		if armErr != nil {
			return false, armErr
		}
		r.armToken = armToken
		s.cells[saved.Cell.ID] = r
	}
	return true, nil
}

func (s *Store) appendEvidenceLocked(r *record, kind string, value any) error {
	if _, err := s.evidence.Append(r.cell.ID, kind, value); err != nil {
		r.cell.EvidenceHealth = "degraded"
		r.cell.EvidenceError = secrets.RedactText(err.Error())
		return err
	}
	return nil
}

// Evidence returns durable hash-chained records even after a cell has stopped
// and its runtime resources and secret material have been removed.
func (s *Store) Evidence(cellID string) []evidence.Record {
	return s.evidence.Records(cellID)
}

func (s *Store) eventID(cellID string) string {
	s.nextID++
	return fmt.Sprintf("evt-%s-%d", cellID, s.nextID)
}

func errorsIsNotFound(err error) bool { return errors.Is(err, sandbox.ErrNotFound) }

func capabilityManifest(manifest policy.Manifest) model.CapabilityManifest {
	return model.CapabilityManifest{
		Profile: manifest.Profile, ProfileDigest: manifest.ProfileDigest, Filesystem: manifest.Filesystem,
		Exec: append([]string(nil), manifest.Exec...), Egress: append([]string(nil), manifest.Egress...), Programs: append([]string(nil), manifest.Programs...), Danger: manifest.Danger, RecordedOnly: manifest.RecordedOnly,
	}
}

func (s *Store) appendPolicyEventsLocked(r *record, timestamp time.Time) {
	manifest := r.cell.Capabilities
	decision, decisionErr := policy.Decide(manifest.Profile, r.cell.RepoURL)
	decisionDetail := "profile=" + manifest.Profile + "; danger=" + manifest.Danger + "; rule=" + decision.Rule + "; trace_steps=" + fmt.Sprint(decision.TraceSize)
	if decisionErr != nil {
		decisionDetail += "; error=" + decisionErr.Error()
	}
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "arbiter", Action: "policy.evaluate", Summary: "Sandbox policy evaluated", Detail: decisionDetail, Danger: manifest.Danger, Timestamp: timestamp})
	s.appendEventLocked(r, model.Event{Kind: model.EventLifecycle, Source: "continuum", Action: "manifest.compile", Summary: "Capability manifest compiled", Detail: "filesystem=" + manifest.Filesystem + "; exec=" + strings.Join(manifest.Exec, ",") + "; egress=" + strings.Join(manifest.Egress, ","), Danger: manifest.Danger, Timestamp: timestamp})
}

func (s *Store) generateReviews(r *record) []model.Review {
	reviews := s.reviews.GenerateWithWorktree(context.Background(), r.workdir, r.baseline, r.cell.Files)
	openByPath := map[string][]string{}
	for _, shadow := range r.cell.Shadows {
		if shadow.Status == "open" {
			openByPath[shadow.Path] = append(openByPath[shadow.Path], shadow.ID)
		}
	}
	for i := range reviews {
		for _, path := range reviews[i].Files {
			reviews[i].OutstandingShadowIDs = append(reviews[i].OutstandingShadowIDs, openByPath[path]...)
		}
		if len(reviews[i].OutstandingShadowIDs) > 0 {
			reviews[i].Status = "blocked"
			reviews[i].CommitReady = false
		}
	}
	for _, shadow := range r.cell.Shadows {
		if shadow.Status != "open" {
			continue
		}
		candidate := append([]model.File(nil), r.cell.Files...)
		for i := range candidate {
			if candidate[i].Path == shadow.Path {
				candidate[i].Content = shadow.After
			}
		}
		shadowReviews := s.reviews.Generate(r.cell.Files, candidate)
		for i := range shadowReviews {
			shadowReviews[i].ShadowID = shadow.ID
			shadowReviews[i].Status = "blocked"
			shadowReviews[i].CommitReady = false
			shadowReviews[i].Summary = "Shadow " + shadow.ID + ": " + shadowReviews[i].Summary
		}
		reviews = append(reviews, shadowReviews...)
	}
	findings := divergence.Evaluate(r.events, divergence.Options{CellID: r.cell.ID, Worktree: r.workdir, NetAllow: r.cell.Capabilities.Egress, EvidenceHealthy: r.cell.EvidenceHealth == "healthy"})
	ids := make([]string, len(findings))
	for i := range findings {
		ids[i] = findings[i].ID
	}
	for i := range reviews {
		reviews[i].EvidenceHealth = r.cell.EvidenceHealth
		reviews[i].DivergenceIDs = append([]string(nil), ids...)
		if r.cell.EvidenceHealth == "degraded" {
			reviews[i].Status = "blocked"
			reviews[i].CommitReady = false
		}
	}
	return reviews
}

func shadowURI(cellID, path, shadowID string) string {
	return "shadow://" + url.PathEscape(cellID) + "/" + url.PathEscape(path) + "/" + url.PathEscape(shadowID)
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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
	case ".arb":
		return "arbiter"
	case ".hzn":
		return "horizon"
	default:
		return "text"
	}
}

func syncWorktreeFile(root, cellID, path, content string) error {
	if strings.TrimSpace(root) == "" {
		return nil
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return fmt.Errorf("invalid worktree path %q", path)
	}
	destination := filepath.Join(root, cellID, clean)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	directory := filepath.Dir(destination)
	temp, err := os.CreateTemp(directory, ".mercutio-write-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err = temp.Chmod(0o644); err != nil {
		temp.Close()
		return err
	}
	if _, err = temp.Write([]byte(content)); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempName, destination); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeWorktreeFile(root, cellID, path string) error {
	if strings.TrimSpace(root) == "" {
		return nil
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return fmt.Errorf("invalid worktree path %q", path)
	}
	err := os.Remove(filepath.Join(root, cellID, clean))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
