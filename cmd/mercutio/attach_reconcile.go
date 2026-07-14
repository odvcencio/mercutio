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
	root        string
	watcher     *fsnotify.Watcher
	outbound    func(path, base, content string, deleted bool)
	mu          sync.Mutex
	known       map[string]string
	suppressed  map[string]materialization
	generation  uint64
	timers      map[string]*time.Timer
	initialized bool
	done        chan struct{}
}

type materialization struct {
	generation uint64
	hash       string
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
	r := &diskReconciler{root: root, watcher: watcher, outbound: outbound, known: map[string]string{}, suppressed: map[string]materialization{}, timers: map[string]*time.Timer{}, done: make(chan struct{})}
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
	for _, timer := range r.timers {
		timer.Stop()
	}
	r.mu.Unlock()
	return r.watcher.Close()
}

func (r *diskReconciler) ApplySnapshot(files []model.File) {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := !r.initialized
	for _, file := range files {
		path, err := r.resolve(file.Path)
		if err != nil {
			continue
		}
		disk, readErr := os.ReadFile(path)
		if first && readErr == nil && string(disk) != file.Content && r.outbound != nil {
			go r.outbound(file.Path, "", string(disk), false)
		}
		if readErr != nil || string(disk) != file.Content {
			r.generation++
			r.suppressed[file.Path] = materialization{generation: r.generation, hash: hashText(file.Content)}
			if atomicWrite(path, []byte(file.Content)) != nil {
				delete(r.suppressed, file.Path)
				continue
			}
		}
		r.known[file.Path] = file.Content
	}
	r.initialized = true
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
	if timer := r.timers[rel]; timer != nil {
		timer.Stop()
	}
	r.timers[rel] = time.AfterFunc(75*time.Millisecond, func() { r.ingest(rel) })
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
	delete(r.timers, rel)
	text := string(content)
	materialized, suppress := r.suppressed[rel]
	if suppress && materialized.generation > 0 && materialized.hash == hashText(text) {
		delete(r.suppressed, rel)
		r.known[rel] = text
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
