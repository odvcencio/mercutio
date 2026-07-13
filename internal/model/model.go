package model

import "time"

// CellStatus is intentionally small in v1. The control plane owns lifecycle;
// Kubernetes-backed sandbox reconciliation can add more states later.
type CellStatus string

const (
	CellCreating CellStatus = "creating"
	CellReady    CellStatus = "ready"
	CellSteering CellStatus = "steering"
	CellStopped  CellStatus = "stopped"
	CellError    CellStatus = "error"
)

type EventKind string

const (
	EventLifecycle EventKind = "lifecycle"
	EventIntent    EventKind = "intent"
	EventKernel    EventKind = "kernel"
	EventPresence  EventKind = "presence"
	EventEdit      EventKind = "edit"
	EventReview    EventKind = "review"
)

type File struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Content  string `json:"content"`
	Modified bool   `json:"modified"`
}

type AgentPresence struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"lastSeen"`
	Connected bool      `json:"connected"`
}

type Event struct {
	ID        string    `json:"id"`
	Kind      EventKind `json:"kind"`
	Source    string    `json:"source"`
	Action    string    `json:"action"`
	Summary   string    `json:"summary"`
	Detail    string    `json:"detail,omitempty"`
	Danger    string    `json:"danger,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Review struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Entity      string `json:"entity"`
	Summary     string `json:"summary"`
	Status      string `json:"status"`
	CommitReady bool   `json:"commitReady"`
}

type Cell struct {
	ID               string        `json:"id"`
	RepoURL          string        `json:"repoURL"`
	Branch           string        `json:"branch"`
	Status           CellStatus    `json:"status"`
	SandboxProfile   string        `json:"sandboxProfile"`
	CreatedAt        time.Time     `json:"createdAt"`
	UpdatedAt        time.Time     `json:"updatedAt"`
	Agent            AgentPresence `json:"agent"`
	Files            []File        `json:"files"`
	Reviews          []Review      `json:"reviews"`
	Revision         uint64        `json:"revision"`
	IntentCount      int           `json:"intentCount"`
	KernelEventCount int           `json:"kernelEventCount"`
}

type CellSnapshot struct {
	Cell
	Events []Event `json:"events"`
}

type State struct {
	Cells        []CellSnapshot `json:"cells"`
	ActiveCellID string         `json:"activeCellID"`
	Connected    int            `json:"connected"`
}
