package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"m31labs.dev/mercutio/internal/model"
)

type diskReconciler struct {
	root         string
	watcher      *fsnotify.Watcher
	outbound     func(path, base, content string, deleted bool)
	mu           sync.Mutex
	known        map[string]string
	suppressed   map[string]materialization
	generation   uint64
	ingestTimers map[string]*time.Timer
	writeTimers  map[string]*time.Timer
	pending      map[string]pendingMaterialization
	initialized  bool
	done         chan struct{}
}

type materialization struct {
	generation uint64
	hash       string
	deleted    bool
}

type pendingMaterialization struct {
	generation uint64
	content    string
	deleted    bool
}

func newDiskReconciler(root string, outbound func(path, base, content string, deleted bool)) (*diskReconciler, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		watcher.Close()
		return nil, err
	}
	r := &diskReconciler{root: root, watcher: watcher, outbound: outbound, known: map[string]string{}, suppressed: map[string]materialization{}, ingestTimers: map[string]*time.Timer{}, writeTimers: map[string]*time.Timer{}, pending: map[string]pendingMaterialization{}, done: make(chan struct{})}
	if err := r.addTree(root); err != nil {
		watcher.Close()
		return nil, err
	}
	go r.run()
	return r, nil
}

func (r *diskReconciler) Close() error {
	close(r.done)
	r.mu.Lock()
	for _, timer := range r.ingestTimers {
		timer.Stop()
	}
	for _, timer := range r.writeTimers {
		timer.Stop()
	}
	r.mu.Unlock()
	return r.watcher.Close()
}

func (r *diskReconciler) ApplySnapshot(files []model.File) {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := !r.initialized
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		seen[file.Path] = struct{}{}
		path, err := r.resolve(file.Path)
		if err != nil {
			continue
		}
		disk, readErr := os.ReadFile(path)
		if first && readErr == nil && string(disk) != file.Content && r.outbound != nil {
			go r.outbound(file.Path, "", string(disk), false)
		}
		if readErr != nil || string(disk) != file.Content {
			r.scheduleMaterializationLocked(file.Path, file.Content, false)
			continue
		}
		r.known[file.Path] = file.Content
	}
	if r.initialized {
		for path := range r.known {
			if _, exists := seen[path]; !exists {
				r.scheduleMaterializationLocked(path, "", true)
			}
		}
	}
	r.initialized = true
}

func (r *diskReconciler) scheduleMaterializationLocked(path, content string, deleted bool) {
	r.generation++
	r.pending[path] = pendingMaterialization{generation: r.generation, content: content, deleted: deleted}
	if timer := r.writeTimers[path]; timer != nil {
		timer.Stop()
	}
	r.writeTimers[path] = time.AfterFunc(75*time.Millisecond, func() { r.materialize(path) })
}

func (r *diskReconciler) materialize(rel string) {
	r.mu.Lock()
	pending, ok := r.pending[rel]
	if !ok {
		r.mu.Unlock()
		return
	}
	delete(r.pending, rel)
	delete(r.writeTimers, rel)
	r.suppressed[rel] = materialization{generation: pending.generation, hash: hashText(pending.content), deleted: pending.deleted}
	r.mu.Unlock()

	path, resolveErr := r.resolve(rel)
	var err error
	if resolveErr != nil {
		err = resolveErr
	} else if pending.deleted {
		err = os.Remove(path)
		if os.IsNotExist(err) {
			err = nil
		}
	} else {
		err = atomicWrite(path, []byte(pending.content))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		delete(r.suppressed, rel)
		return
	}
	if pending.deleted {
		delete(r.known, rel)
	} else {
		r.known[rel] = pending.content
	}
}

func (r *diskReconciler) run() {
	for {
		select {
		case <-r.done:
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}
			if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
				_ = r.addTree(event.Name)
				continue
			}
			r.schedule(event.Name)
		case <-r.watcher.Errors:
		}
	}
}

func (r *diskReconciler) schedule(path string) {
	rel, err := filepath.Rel(r.root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || ignoredDiskPath(rel) {
		return
	}
	r.mu.Lock()
	if timer := r.ingestTimers[rel]; timer != nil {
		timer.Stop()
	}
	r.ingestTimers[rel] = time.AfterFunc(75*time.Millisecond, func() { r.ingest(rel) })
	r.mu.Unlock()
}

func (r *diskReconciler) ingest(rel string) {
	path, err := r.resolve(rel)
	if err != nil {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
		content = nil
	}
	r.mu.Lock()
	delete(r.ingestTimers, rel)
	text := string(content)
	materialized, suppress := r.suppressed[rel]
	if suppress && materialized.generation > 0 && materialized.hash == hashText(text) {
		delete(r.suppressed, rel)
		if materialized.deleted {
			delete(r.known, rel)
		} else {
			r.known[rel] = text
		}
		r.mu.Unlock()
		return
	}
	base, tracked := r.known[rel]
	if tracked && base == text {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	if r.outbound != nil {
		r.outbound(rel, base, text, os.IsNotExist(err))
	}
}

func (r *diskReconciler) addTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(r.root, path)
		if entry.IsDir() && ignoredDiskPath(rel) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return r.watcher.Add(path)
		}
		return nil
	})
}

func (r *diskReconciler) resolve(rel string) (string, error) {
	clean := filepath.Clean(rel)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid worktree path")
	}
	resolved := filepath.Join(r.root, clean)
	current := r.root
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("worktree path crosses symlink")
		}
	}
	return resolved, nil
}

func ignoredDiskPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	return strings.HasPrefix(base, ".mercutio-write-") || rel == ".git" || strings.HasPrefix(rel, ".git/") || rel == ".graft" || strings.HasPrefix(rel, ".graft/")
}

func atomicWrite(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".mercutio-write-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func hashText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
