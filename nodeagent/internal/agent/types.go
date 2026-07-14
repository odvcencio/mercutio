package agent

import (
	"context"
	"time"
)

type Cell struct {
	ID            string   `json:"id"`
	Namespace     string   `json:"namespace"`
	PodName       string   `json:"podName"`
	PodUID        string   `json:"podUID"`
	ContainerID   string   `json:"containerID,omitempty"`
	Profile       string   `json:"profile"`
	NodeID        string   `json:"nodeID"`
	CgroupPath    string   `json:"cgroupPath,omitempty"`
	CgroupID      uint64   `json:"cgroupID,omitempty"`
	CgroupIDs     []uint64 `json:"cgroupIDs,omitempty"`
	WorktreeDev   uint64   `json:"worktreeDev"`
	ScratchDev    uint64   `json:"scratchDev"`
	RuntimeDev    uint64   `json:"runtimeDev"`
	AllowedEgress []string `json:"allowedEgress"`
	Programs      []string `json:"programs"`
	ProfileDigest string   `json:"profileDigest"`
}

type ArmResult struct {
	Programs       []string
	ManifestDigest string
	ObjectDigest   string
	Enforcement    string
}

type KernelEvent struct {
	CellID          string            `json:"cellID"`
	NodeID          string            `json:"nodeID"`
	CgroupID        uint64            `json:"cgroupID"`
	CPU             uint32            `json:"cpu,omitempty"`
	Seq             uint64            `json:"seq"`
	TimestampNS     uint64            `json:"tsNs"`
	Kind            string            `json:"kind"`
	Verdict         string            `json:"verdict"`
	PID             uint32            `json:"pid"`
	PPID            uint32            `json:"ppid"`
	TGID            uint32            `json:"tgid"`
	UID             uint32            `json:"uid"`
	Comm            string            `json:"comm"`
	Path            string            `json:"path,omitempty"`
	PathTruncated   bool              `json:"pathTruncated,omitempty"`
	Argv            string            `json:"argv,omitempty"`
	ArgvTruncated   bool              `json:"argvTruncated,omitempty"`
	Destination     string            `json:"destination,omitempty"`
	Flags           uint32            `json:"flags,omitempty"`
	Mode            uint32            `json:"mode,omitempty"`
	Operation       uint32            `json:"operation,omitempty"`
	ActionDanger    map[string]string `json:"actionDanger"`
	ProgramDanger   map[string]string `json:"programDanger"`
	Program         string            `json:"program"`
	Evidence        string            `json:"evidence"`
	ClockSkewBoundM int64             `json:"clockSkewBoundMs"`
}

type ClockSync struct {
	MonotonicNS int64  `json:"monotonicNs"`
	RealtimeNS  int64  `json:"realtimeNs"`
	SkewBoundMS int64  `json:"skewBoundMs"`
	NodeID      string `json:"nodeID"`
}

type Batch struct {
	NodeID   string            `json:"nodeID"`
	BatchSeq uint64            `json:"batchSeq"`
	Clock    ClockSync         `json:"clockSync"`
	Events   []KernelEvent     `json:"events"`
	Drops    map[string]uint64 `json:"drops"`
	SentAt   time.Time         `json:"sentAt"`
}

type ActionDecision struct {
	ID        string    `json:"id"`
	CellID    string    `json:"cellID"`
	NodeID    string    `json:"nodeID"`
	CgroupID  uint64    `json:"cgroupID"`
	PID       uint32    `json:"pid"`
	Kind      string    `json:"kind"`
	Resource  string    `json:"resource"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Source interface {
	ListCells(context.Context) ([]Cell, error)
}

type Loader interface {
	Arm(context.Context, Cell) (ArmResult, error)
	Disarm(context.Context, string) error
	Close() error
}

type RuleRefresher interface {
	RefreshRules(context.Context, string) error
}

type Control interface {
	Armed(context.Context, Cell, ArmResult) error
}

type DrainReporter interface {
	FinalizeDisarm(context.Context, string) error
}
