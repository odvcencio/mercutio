package transport

import (
	"encoding/json"
	"net/http"

	"m31labs.dev/gosx/hub"
	"m31labs.dev/mercutio/internal/cell"
	"m31labs.dev/mercutio/internal/model"
)

// CellHub carries presence, steering, and buffer updates. The server also
// registers each cell's GoSX CRDT document so the binary sync protocol is
// available to the browser editor as it grows beyond the v1 snapshot path.
type CellHub struct {
	*hub.Hub
	store *cell.Store
}

func NewCellHub(store *cell.Store) *CellHub {
	h := &CellHub{Hub: hub.New("mercutio-cells"), store: store}
	h.Hub.Latch("state")
	for _, snapshot := range store.State(0).Cells {
		h.registerCell(snapshot.ID)
	}
	h.On("join", func(ctx *hub.Context) {
		h.Send(ctx.Client.ID, "state", store.State(h.ClientCount()))
		h.Broadcast("presence:count", map[string]int{"count": h.Presence().Count()})
	})
	h.On("leave", func(ctx *hub.Context) {
		h.Broadcast("presence:count", map[string]int{"count": h.Presence().Count()})
	})
	h.On("cell:select", func(ctx *hub.Context) {
		var payload struct {
			CellID string `json:"cellID"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.Snapshot(payload.CellID); err == nil {
			h.Send(ctx.Client.ID, "cell:update", snapshot)
		}
	})
	h.On("presence:cursor", func(ctx *hub.Context) {
		var payload map[string]any
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		payload["clientID"] = ctx.Client.ID
		h.Broadcast("presence:cursor", payload)
	})
	h.On("prompt", func(ctx *hub.Context) {
		var payload struct {
			CellID string `json:"cellID"`
			Prompt string `json:"prompt"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.Prompt(payload.CellID, payload.Prompt); err == nil {
			h.Broadcast("cell:update", snapshot)
		}
	})
	h.On("edit", func(ctx *hub.Context) {
		var payload struct {
			CellID  string `json:"cellID"`
			Path    string `json:"path"`
			Content string `json:"content"`
			Actor   string `json:"actor"`
		}
		if json.Unmarshal(ctx.Data, &payload) != nil {
			return
		}
		if snapshot, err := store.ApplyEdit(payload.CellID, payload.Path, payload.Content, payload.Actor); err == nil {
			h.Broadcast("cell:update", snapshot)
		}
	})
	return h
}

func (h *CellHub) RegisterCell(id string) {
	h.registerCell(id)
	if snapshot, err := h.store.Snapshot(id); err == nil {
		h.Broadcast("cell:update", snapshot)
	}
}

func (h *CellHub) registerCell(id string) {
	for path, doc := range h.store.Documents(id) {
		h.SyncDoc(id+":"+path, doc)
	}
}

func (h *CellHub) BroadcastCell(snapshot model.CellSnapshot) {
	h.Broadcast("cell:update", snapshot)
}

func (h *CellHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Hub.ServeHTTP(w, r)
}
