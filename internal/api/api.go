package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/transport"
)

type Handler struct {
	store *cell.Store
	hub   *transport.CellHub
}

func New(store *cell.Store, hub *transport.CellHub) *Handler {
	return &Handler{store: store, hub: hub}
}

func (h *Handler) State(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.store.State(h.hub.ClientCount()))
}

func (h *Handler) CreateCell(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RepoURL string `json:"repoURL"`
		Branch  string `json:"branch"`
		Profile string `json:"profile"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Create(input.RepoURL, input.Branch, input.Profile)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.RegisterCell(snapshot.ID)
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusCreated, snapshot)
}

func (h *Handler) Cell(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Snapshot(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Events(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Snapshot(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	kind := model.EventKind(r.URL.Query().Get("kind"))
	if kind == "" {
		writeJSON(w, http.StatusOK, snapshot.Events)
		return
	}
	filtered := make([]model.Event, 0)
	for _, event := range snapshot.Events {
		if event.Kind == kind {
			filtered = append(filtered, event)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (h *Handler) Edit(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Path    string `json:"path"`
		Content string `json:"content"`
		Actor   string `json:"actor"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.ApplyEdit(id, input.Path, input.Content, input.Actor)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Prompt(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	var input struct {
		Prompt string `json:"prompt"`
	}
	if err := decodeJSON(r, &input); err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Prompt(id, input.Prompt)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Destroy(w http.ResponseWriter, r *http.Request) {
	id, err := pathParam(r.URL.Path, "cells", 2)
	if err != nil {
		errorJSON(w, http.StatusBadRequest, err)
		return
	}
	snapshot, err := h.store.Destroy(id)
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "cells" || parts[3] != "reviews" {
		errorJSON(w, http.StatusBadRequest, fmt.Errorf("invalid review path"))
		return
	}
	snapshot, err := h.store.ApproveReview(parts[2], parts[4])
	if err != nil {
		errorJSON(w, http.StatusNotFound, err)
		return
	}
	h.hub.BroadcastCell(snapshot)
	writeJSON(w, http.StatusOK, snapshot)
}

func pathParam(path, segment string, offset int) (string, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) <= offset || parts[0] != "api" || parts[1] != segment || parts[offset] == "" {
		return "", fmt.Errorf("invalid %s path", segment)
	}
	return parts[offset], nil
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func errorJSON(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
