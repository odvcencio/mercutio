package model

import "time"

// CellStatus is the durable control-plane lifecycle. Pod phase remains a
// separate observation because provisioning/arming and review/commit states
// cannot be inferred from Kubernetes phase alone.
type CellStatus string

const (
	CellRequested    CellStatus = "requested"
	CellAdmitting    CellStatus = "admitting"
	CellProvisioning CellStatus = "provisioning"
	CellArming       CellStatus = "arming"
	CellReady        CellStatus = "ready"
	CellActive       CellStatus = "active"
	CellPaused       CellStatus = "paused"
	CellReviewing    CellStatus = "reviewing"
	CellCommitting   CellStatus = "committing"
	CellDraining     CellStatus = "draining"
	CellTerminated   CellStatus = "terminated"
	CellFailed       CellStatus = "failed"

	// Compatibility names keep callers source-compatible while mapping every
	// transition onto the normative lifecycle.
	CellCreating = CellProvisioning
	CellIdle     = CellReady
	CellSteering = CellActive
	CellStopped  = CellTerminated
	CellError    = CellFailed
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

type SandboxPhase string

const (
	SandboxPending SandboxPhase = "pending"
	SandboxRunning SandboxPhase = "running"
	SandboxStopped SandboxPhase = "stopped"
	SandboxFailed  SandboxPhase = "failed"
)

type File struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Content  string `json:"content"`
	Modified bool   `json:"modified"`
}

type Range struct {
	StartByte   uint32 `json:"startByte"`
	EndByte     uint32 `json:"endByte"`
	StartLine   uint32 `json:"startLine"`
	StartColumn uint32 `json:"startColumn"`
	EndLine     uint32 `json:"endLine"`
	EndColumn   uint32 `json:"endColumn"`
}

type HighlightRange struct {
	Range
	Capture string `json:"capture"`
}

type Symbol struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Range     Range  `json:"range"`
	NameRange Range  `json:"nameRange"`
}

type Analysis struct {
	Path       string           `json:"path"`
	Language   string           `json:"language"`
	Highlights []HighlightRange `json:"highlights,omitempty"`
	Symbols    []Symbol         `json:"symbols,omitempty"`
	HasErrors  bool             `json:"hasErrors"`
	Error      string           `json:"error,omitempty"`
}

type AgentPresence struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"lastSeen"`
	Connected bool      `json:"connected"`
}

type Event struct {
	ID               string     `json:"id"`
	TraceID          string     `json:"traceID,omitempty"`
	Kind             EventKind  `json:"kind"`
	Source           string     `json:"source"`
	Action           string     `json:"action"`
	Summary          string     `json:"summary"`
	Detail           string     `json:"detail,omitempty"`
	Danger           string     `json:"danger,omitempty"`
	DangerAxes       DangerAxes `json:"dangerAxes,omitempty"`
	ProgramDanger    DangerAxes `json:"programDanger,omitempty"`
	Verdict          string     `json:"verdict,omitempty"`
	Path             string     `json:"path,omitempty"`
	PathTruncated    bool       `json:"pathTruncated,omitempty"`
	Argv             string     `json:"argv,omitempty"`
	ArgvTruncated    bool       `json:"argvTruncated,omitempty"`
	Destination      string     `json:"destination,omitempty"`
	Actor            string     `json:"actor,omitempty"`
	CPU              uint32     `json:"cpu,omitempty"`
	PID              uint32     `json:"pid,omitempty"`
	CgroupID         uint64     `json:"cgroupID,omitempty"`
	NodeID           string     `json:"nodeID,omitempty"`
	KernelSeq        uint64     `json:"kernelSeq,omitempty"`
	BatchSeq         uint64     `json:"batchSeq,omitempty"`
	Drops            uint64     `json:"drops,omitempty"`
	ClockSkewBoundMS int64      `json:"clockSkewBoundMs,omitempty"`
	Evidence         string     `json:"evidence,omitempty"`
	Authenticated    bool       `json:"authenticated,omitempty"`
	Timestamp        time.Time  `json:"timestamp"`
}

type ActionApproval struct {
	ID          string    `json:"id"`
	CellID      string    `json:"cellID"`
	NodeID      string    `json:"nodeID"`
	CgroupID    uint64    `json:"cgroupID"`
	PID         uint32    `json:"pid"`
	Kind        string    `json:"kind"`
	Resource    string    `json:"resource"`
	Status      string    `json:"status"`
	RequestedAt time.Time `json:"requestedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	DecidedAt   time.Time `json:"decidedAt,omitempty"`
	DecidedBy   string    `json:"decidedBy,omitempty"`
	Delivered   bool      `json:"delivered,omitempty"`
}

// DangerAxes preserves the Action Danger Triple used to rank a divergence.
// Values are ordered by the divergence engine, not lexically.
type DangerAxes struct {
	Mode          string `json:"mode,omitempty"`
	Scope         string `json:"scope,omitempty"`
	Reversibility string `json:"reversibility,omitempty"`
}

type DivergenceEvidence struct {
	Healthy  bool   `json:"healthy"`
	Drops    uint64 `json:"drops,omitempty"`
	BatchGap bool   `json:"batchGap,omitempty"`
}

type DivergenceRecord struct {
	ID           string             `json:"id"`
	RuleID       string             `json:"ruleID"`
	Rule         string             `json:"rule"`
	Severity     string             `json:"severity"`
	Summary      string             `json:"summary"`
	ActionDanger DangerAxes         `json:"actionDanger"`
	Intent       []Event            `json:"intent"`
	Kernel       []Event            `json:"kernel"`
	Evidence     DivergenceEvidence `json:"evidence"`
	FirstSeen    time.Time          `json:"firstSeen"`
	LastSeen     time.Time          `json:"lastSeen"`
}

type Sandbox struct {
	Name           string       `json:"name,omitempty"`
	NodeID         string       `json:"nodeID,omitempty"`
	Phase          SandboxPhase `json:"phase"`
	LastTransition time.Time    `json:"lastTransition,omitempty"`
	Failure        string       `json:"failure,omitempty"`
	Armed          bool         `json:"armed"`
	ArmedAt        time.Time    `json:"armedAt,omitempty"`
	Programs       []string     `json:"programs,omitempty"`
	ManifestDigest string       `json:"manifestDigest,omitempty"`
	ObjectDigest   string       `json:"objectDigest,omitempty"`
	CgroupID       uint64       `json:"cgroupID,omitempty"`
	Enforcement    string       `json:"enforcement,omitempty"`
}

type CapabilityManifest struct {
	Profile       string   `json:"profile"`
	ProfileDigest string   `json:"profileDigest"`
	Filesystem    string   `json:"filesystem"`
	Exec          []string `json:"exec"`
	Egress        []string `json:"egress"`
	Programs      []string `json:"programs"`
	Danger        string   `json:"danger"`
	RecordedOnly  bool     `json:"recordedOnly"`
}

type Review struct {
	ID                   string          `json:"id"`
	Title                string          `json:"title"`
	Entity               string          `json:"entity"`
	Summary              string          `json:"summary"`
	Status               string          `json:"status"`
	CommitReady          bool            `json:"commitReady"`
	Files                []string        `json:"files,omitempty"`
	Patch                string          `json:"patch,omitempty"`
	Receipt              string          `json:"receipt,omitempty"`
	SecretScanStatus     string          `json:"secretScanStatus"`
	SecretFindings       []SecretFinding `json:"secretFindings,omitempty"`
	SecretAcknowledged   bool            `json:"secretAcknowledged,omitempty"`
	EvidenceHealth       string          `json:"evidenceHealth"`
	EvidenceAcknowledged bool            `json:"evidenceAcknowledged,omitempty"`
	DivergenceIDs        []string        `json:"divergenceIDs,omitempty"`
	SignatureChanged     bool            `json:"signatureChanged,omitempty"`
	RejectionReason      string          `json:"rejectionReason,omitempty"`
	ShadowID             string          `json:"shadowID,omitempty"`
	OutstandingShadowIDs []string        `json:"outstandingShadowIDs,omitempty"`
}

type SecretFinding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Range    Range  `json:"range"`
	Redacted string `json:"redacted"`
}

type SecretGrantRequest struct {
	ID                  string    `json:"id"`
	Credential          string    `json:"credential"`
	Purpose             string    `json:"purpose"`
	RequestedBy         string    `json:"requestedBy"`
	Status              string    `json:"status"`
	RequestedTTLSeconds int64     `json:"requestedTTLSeconds"`
	CreatedAt           time.Time `json:"createdAt"`
	ExpiresAt           time.Time `json:"expiresAt,omitempty"`
	ApprovedBy          string    `json:"approvedBy,omitempty"`
	Receipt             string    `json:"receipt,omitempty"`
	EnvName             string    `json:"envName"`
	Command             []string  `json:"command"`
	WorkingDir          string    `json:"workingDir,omitempty"`
}

type SecretProxyRoute struct {
	ID          string    `json:"id"`
	Credential  string    `json:"credential"`
	Destination string    `json:"destination"`
	Header      string    `json:"header"`
	CreatedBy   string    `json:"createdBy"`
	CreatedAt   time.Time `json:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type ShadowRevision struct {
	ID            string    `json:"id"`
	URI           string    `json:"uri"`
	Path          string    `json:"path"`
	Author        string    `json:"author"`
	Base          string    `json:"base"`
	Before        string    `json:"before"`
	After         string    `json:"after"`
	BaseHash      string    `json:"baseHash"`
	Reason        string    `json:"reason"`
	Status        string    `json:"status"`
	DiscardReason string    `json:"discardReason,omitempty"`
	Stale         bool      `json:"stale,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	ResolvedAt    time.Time `json:"resolvedAt,omitempty"`
	Conflicts     []string  `json:"conflicts,omitempty"`
	Intelligence  string    `json:"intelligence,omitempty"`
}

type Cell struct {
	ID                string               `json:"id"`
	RepoURL           string               `json:"repoURL"`
	Branch            string               `json:"branch"`
	Status            CellStatus           `json:"status"`
	SandboxProfile    string               `json:"sandboxProfile"`
	Sandbox           Sandbox              `json:"sandbox"`
	Capabilities      CapabilityManifest   `json:"capabilities"`
	CreatedAt         time.Time            `json:"createdAt"`
	UpdatedAt         time.Time            `json:"updatedAt"`
	Agent             AgentPresence        `json:"agent"`
	Files             []File               `json:"files"`
	Reviews           []Review             `json:"reviews"`
	SecretRequests    []SecretGrantRequest `json:"secretRequests,omitempty"`
	SecretProxyRoutes []SecretProxyRoute   `json:"secretProxyRoutes,omitempty"`
	Shadows           []ShadowRevision     `json:"shadows,omitempty"`
	ActionApprovals   []ActionApproval     `json:"actionApprovals,omitempty"`
	Revision          uint64               `json:"revision"`
	IntentCount       int                  `json:"intentCount"`
	KernelEventCount  int                  `json:"kernelEventCount"`
	Divergence        bool                 `json:"divergence"`
	DivergenceDetail  string               `json:"divergenceDetail,omitempty"`
	Divergences       []DivergenceRecord   `json:"divergences,omitempty"`
	EvidenceHealth    string               `json:"evidenceHealth"`
	EvidenceError     string               `json:"evidenceError,omitempty"`
}

type CellSnapshot struct {
	Cell
	Events             []Event `json:"events"`
	OperatorCapability string  `json:"-"`
}

type State struct {
	Cells        []CellSnapshot `json:"cells"`
	ActiveCellID string         `json:"activeCellID"`
	Connected    int            `json:"connected"`
}
