package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	continuumhorizon "m31labs.dev/continuum/horizon"
	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

type EventQueue interface {
	Enqueue(KernelEvent) bool
	AddKernelDrops(string, uint64)
}

type ProgramOptions struct {
	ManifestPath string
	ObjectPath   string
	DigestPins   map[string]string
	PublicKeys   []continuumhorizon.TrustedPublicKey
	BaseAllow    []string
	Resolver     *net.Resolver
	Queue        EventQueue
	Signal       func(int, unix.Signal) error
	ProcRoot     string
}

type ProgramManager struct {
	mu           sync.Mutex
	options      ProgramOptions
	verification continuumhorizon.PreflightResult
	classes      map[uint32]*classPrograms
	cells        map[string]*loadedCell
	identities   map[[2]uint64]string
	seq          atomic.Uint64
}

type classPrograms struct {
	class       uint32
	objects     *bindings.Objects
	globalLinks []link.Link
	execLSM     bool
	fileLSM     bool
	readerCtx   context.Context
	cancelRead  context.CancelFunc
}

type loadedCell struct {
	cell     Cell
	programs *classPrograms
	links    []link.Link
	netKeys  []bindings.NetKey
	net6Keys []bindings.Net6Key
	fileKeys []bindings.FileKey
}

func NewProgramManager(options ProgramOptions) (*ProgramManager, error) {
	if options.Signal == nil {
		options.Signal = unix.Kill
	}
	verification, err := continuumhorizon.Preflight(continuumhorizon.PreflightOptions{
		ManifestPath: options.ManifestPath, ObjectPath: options.ObjectPath,
		DigestPins: options.DigestPins, PublicKeys: options.PublicKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("Horizon preflight: %w", err)
	}
	manager := &ProgramManager{options: options, verification: verification, classes: map[uint32]*classPrograms{}, cells: map[string]*loadedCell{}, identities: map[[2]uint64]string{}}
	for class := uint32(0); class < 3; class++ {
		programs, err := manager.loadClassPrograms(class)
		if err != nil {
			_ = manager.Close()
			return nil, err
		}
		manager.classes[class] = programs
	}
	return manager, nil
}

func (m *ProgramManager) loadClassPrograms(class uint32) (*classPrograms, error) {
	objects, err := bindings.LoadObjects(m.options.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load class %d BPF collection: %w", class, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	programs := &classPrograms{class: class, objects: objects, readerCtx: ctx, cancelRead: cancel}
	onExec, err := objects.AttachOnExec()
	if err != nil {
		cancel()
		_ = objects.Close()
		return nil, fmt.Errorf("attach class %d exec observation: %w", class, err)
	}
	programs.globalLinks = append(programs.globalLinks, onExec)
	m.startReaders(programs)
	return programs, nil
}

func (m *ProgramManager) ApplyDecision(decision ActionDecision) error {
	m.mu.Lock()
	loaded := m.cells[decision.CellID]
	m.mu.Unlock()
	if loaded == nil || !slices.Contains(cellCgroupIDs(loaded.cell), decision.CgroupID) || decision.PID == 0 {
		return fmt.Errorf("action decision is not scoped to a loaded cell process")
	}
	kind := map[string]uint32{"exec": 1, "file": 2, "connect": 3}[decision.Kind]
	if kind == 0 || decision.Status != "approved" && decision.Status != "rejected" {
		return fmt.Errorf("action decision kind or status is invalid")
	}
	key := bindings.ActionKey{CgroupId: decision.CgroupID, Pid: decision.PID, Kind: kind}
	if decision.Status == "approved" {
		if err := loaded.programs.objects.UpdateActionGrant(key, 1); err != nil {
			return fmt.Errorf("install one-shot action grant: %w", err)
		}
		time.AfterFunc(10*time.Second, func() { _ = loaded.programs.objects.DeleteActionGrant(key) })
	}
	if err := m.options.Signal(int(decision.PID), unix.SIGCONT); err != nil {
		if decision.Status == "approved" {
			_ = loaded.programs.objects.DeleteActionGrant(key)
		}
		return fmt.Errorf("resume action process: %w", err)
	}
	return nil
}

func (m *ProgramManager) Arm(ctx context.Context, cell Cell) (ArmResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	programs := append([]string(nil), cell.Programs...)
	if len(programs) == 0 {
		programs = []string{"OnExec", "GateExec", "GateFileOpen", "GateConnect4", "GateConnect6"}
	}
	if existing := m.cells[cell.ID]; existing != nil && slices.Equal(cellCgroupIDs(existing.cell), cellCgroupIDs(cell)) && existing.cell.WorktreeDev == cell.WorktreeDev && existing.cell.ScratchDev == cell.ScratchDev && existing.cell.RuntimeDev == cell.RuntimeDev && existing.cell.Profile == cell.Profile && existing.cell.ProfileDigest == cell.ProfileDigest && programSetEqual(existing.cell.Programs, programs) {
		return m.armResult(cell.Profile, programs), nil
	}
	existing := m.cells[cell.ID]
	cgroupIDs := cellCgroupIDs(cell)
	if len(cgroupIDs) == 0 || cell.CgroupPath == "" || cell.WorktreeDev == 0 || cell.ScratchDev == 0 || cell.RuntimeDev == 0 {
		return ArmResult{}, fmt.Errorf("cell %s has no resolved cgroup and writable mount devices", cell.ID)
	}
	lo, hi := cellIdentity(cell.ID)
	class, err := profileClass(cell.Profile)
	if err != nil {
		return ArmResult{}, err
	}
	programsForClass := m.classes[class]
	if programsForClass == nil {
		return ArmResult{}, fmt.Errorf("class %d program collection unavailable", class)
	}
	if err := m.installExecRules(cell, programsForClass, class); err != nil {
		return ArmResult{}, err
	}
	cell.Programs = append([]string(nil), programs...)
	for _, cgroupID := range cgroupIDs {
		if err := programsForClass.objects.UpdateCellScope(cgroupID, cellScopeValue(cell, lo, hi, class)); err != nil {
			m.rollbackArm(&loadedCell{cell: cell, programs: programsForClass}, existing)
			return ArmResult{}, fmt.Errorf("populate CellScope: %w", err)
		}
	}
	loaded := &loadedCell{cell: cell, programs: programsForClass}
	if hasProgram(programs, "GateFileOpen") {
		fileRules, err := m.collectFileRules(cell, class)
		if err != nil {
			m.rollbackArm(loaded, existing)
			return ArmResult{}, err
		}
		for key, verdict := range fileRules {
			if err := programsForClass.objects.UpdateFileRules(key, bindings.FileRule{Verdict: verdict}); err != nil {
				m.rollbackArm(loaded, existing)
				return ArmResult{}, fmt.Errorf("populate FileRules: %w", err)
			}
			loaded.fileKeys = append(loaded.fileKeys, key)
		}
	}
	if hasProgram(programs, "GateExec") && !programsForClass.execLSM {
		execLink, err := programsForClass.objects.AttachGateExec()
		if err != nil {
			m.rollbackArm(loaded, existing)
			return ArmResult{}, fmt.Errorf("attach exec LSM: %w", err)
		}
		programsForClass.globalLinks = append(programsForClass.globalLinks, execLink)
		programsForClass.execLSM = true
	}
	if hasProgram(programs, "GateFileOpen") && !programsForClass.fileLSM {
		fileLink, err := programsForClass.objects.AttachGateFileOpen()
		if err != nil {
			m.rollbackArm(loaded, existing)
			return ArmResult{}, fmt.Errorf("attach file LSM: %w", err)
		}
		programsForClass.globalLinks = append(programsForClass.globalLinks, fileLink)
		programsForClass.fileLSM = true
	}
	destinations := append([]string(nil), m.options.BaseAllow...)
	if class != 2 {
		destinations = append(destinations, cell.AllowedEgress...)
	}
	for _, destination := range destinations {
		var keys []bindings.NetKey
		var keys6 []bindings.Net6Key
		for _, cgroupID := range cgroupIDs {
			resolved4, resolved6, err := m.resolveNetKeys(ctx, cgroupID, destination)
			if err != nil {
				m.rollbackArm(loaded, existing)
				return ArmResult{}, err
			}
			keys = append(keys, resolved4...)
			keys6 = append(keys6, resolved6...)
		}
		for _, key := range keys {
			if err := programsForClass.objects.UpdateNetAllow(key, 1); err != nil {
				m.rollbackArm(loaded, existing)
				return ArmResult{}, fmt.Errorf("populate NetAllow: %w", err)
			}
			loaded.netKeys = append(loaded.netKeys, key)
		}
		for _, key := range keys6 {
			if err := programsForClass.objects.UpdateNet6Allow(key, 1); err != nil {
				m.rollbackArm(loaded, existing)
				return ArmResult{}, fmt.Errorf("populate Net6Allow: %w", err)
			}
			loaded.net6Keys = append(loaded.net6Keys, key)
		}
	}
	if hasProgram(programs, "GateConnect4") {
		connect4, err := programsForClass.objects.AttachGateConnect4(cell.CgroupPath)
		if err != nil {
			m.rollbackArm(loaded, existing)
			return ArmResult{}, fmt.Errorf("attach cgroup connect4: %w", err)
		}
		loaded.links = append(loaded.links, connect4)
	}
	if hasProgram(programs, "GateConnect6") {
		connect6, err := programsForClass.objects.AttachGateConnect6(cell.CgroupPath)
		if err != nil {
			m.rollbackArm(loaded, existing)
			return ArmResult{}, fmt.Errorf("attach cgroup connect6: %w", err)
		}
		loaded.links = append(loaded.links, connect6)
	}
	m.cells[cell.ID] = loaded
	m.identities[[2]uint64{lo, hi}] = cell.ID
	if existing != nil {
		m.retireLoaded(existing, loaded)
	}
	return m.armResult(cell.Profile, programs), nil
}

func (m *ProgramManager) Disarm(_ context.Context, cellID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disarmLocked(cellID)
}

func (m *ProgramManager) disarmLocked(cellID string) error {
	loaded := m.cells[cellID]
	if loaded == nil {
		return nil
	}
	m.disarmLoaded(loaded)
	lo, hi := cellIdentity(cellID)
	delete(m.identities, [2]uint64{lo, hi})
	delete(m.cells, cellID)
	deleteCellScopes(loaded.programs.objects, cellCgroupIDs(loaded.cell))
	return nil
}

func cellCgroupIDs(cell Cell) []uint64 {
	ids := append([]uint64(nil), cell.CgroupIDs...)
	if len(ids) == 0 && cell.CgroupID != 0 {
		ids = append(ids, cell.CgroupID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func deleteCellScopes(objects *bindings.Objects, ids []uint64) {
	for _, id := range ids {
		_ = objects.DeleteCellScope(id)
	}
}

func deleteInterpreterGrants(objects *bindings.Objects, ids []uint64) {
	wanted := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	var keys []bindings.InterpreterKey
	_ = objects.ForEachInterpreterGrant(func(key bindings.InterpreterKey, _ bindings.InterpreterGrantVal) error {
		if wanted[key.CgroupId] {
			keys = append(keys, key)
		}
		return nil
	})
	for _, key := range keys {
		_ = objects.DeleteInterpreterGrant(key)
	}
}

func deleteToolchainGrants(objects *bindings.Objects, ids []uint64) {
	wanted := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	var keys []bindings.InterpreterKey
	_ = objects.ForEachToolchainGrant(func(key bindings.InterpreterKey, _ bindings.InterpreterGrantVal) error {
		if wanted[key.CgroupId] {
			keys = append(keys, key)
		}
		return nil
	})
	for _, key := range keys {
		_ = objects.DeleteToolchainGrant(key)
	}
}

func (m *ProgramManager) disarmLoaded(loaded *loadedCell) {
	for _, item := range loaded.links {
		_ = item.Close()
	}
	for _, key := range loaded.netKeys {
		_ = loaded.programs.objects.DeleteNetAllow(key)
	}
	for _, key := range loaded.net6Keys {
		_ = loaded.programs.objects.DeleteNet6Allow(key)
	}
	for _, key := range loaded.fileKeys {
		_ = loaded.programs.objects.DeleteFileRules(key)
	}
	deleteInterpreterGrants(loaded.programs.objects, cellCgroupIDs(loaded.cell))
	deleteToolchainGrants(loaded.programs.objects, cellCgroupIDs(loaded.cell))
}

// rollbackArm removes only resources introduced by the attempted arm. When a
// same-class update overwrote a scope, the previous value is restored so a
// failed policy change cannot leave the cell unscoped.
func (m *ProgramManager) rollbackArm(attempt, previous *loadedCell) {
	for _, item := range attempt.links {
		_ = item.Close()
	}
	sameCollection := previous != nil && previous.programs == attempt.programs
	for _, key := range attempt.netKeys {
		if !sameCollection || !slices.Contains(previous.netKeys, key) {
			_ = attempt.programs.objects.DeleteNetAllow(key)
		}
	}
	for _, key := range attempt.net6Keys {
		if !sameCollection || !slices.Contains(previous.net6Keys, key) {
			_ = attempt.programs.objects.DeleteNet6Allow(key)
		}
	}
	for _, key := range attempt.fileKeys {
		if !sameCollection || !slices.Contains(previous.fileKeys, key) {
			_ = attempt.programs.objects.DeleteFileRules(key)
		}
	}
	deleteCellScopes(attempt.programs.objects, cellCgroupIDs(attempt.cell))
	deleteInterpreterGrants(attempt.programs.objects, cellCgroupIDs(attempt.cell))
	deleteToolchainGrants(attempt.programs.objects, cellCgroupIDs(attempt.cell))
	if sameCollection {
		m.restoreCellScopes(previous)
	}
}

func (m *ProgramManager) restoreCellScopes(loaded *loadedCell) {
	class, err := profileClass(loaded.cell.Profile)
	if err != nil {
		return
	}
	lo, hi := cellIdentity(loaded.cell.ID)
	for _, cgroupID := range cellCgroupIDs(loaded.cell) {
		_ = loaded.programs.objects.UpdateCellScope(cgroupID, cellScopeValue(loaded.cell, lo, hi, class))
	}
}

func cellScopeValue(cell Cell, lo, hi uint64, class uint32) bindings.CellScopeVal {
	return bindings.CellScopeVal{CellLo: lo, CellHi: hi, Class: class, FsDev: cell.WorktreeDev, ScratchDev: cell.ScratchDev, RuntimeDev: cell.RuntimeDev}
}

// retireLoaded runs only after the replacement is fully installed and visible
// to event routing. Shared same-class entries are retained for the replacement.
func (m *ProgramManager) retireLoaded(previous, replacement *loadedCell) {
	for _, item := range previous.links {
		_ = item.Close()
	}
	sameCollection := previous.programs == replacement.programs
	for _, key := range previous.netKeys {
		if !sameCollection || !slices.Contains(replacement.netKeys, key) {
			_ = previous.programs.objects.DeleteNetAllow(key)
		}
	}
	for _, key := range previous.net6Keys {
		if !sameCollection || !slices.Contains(replacement.net6Keys, key) {
			_ = previous.programs.objects.DeleteNet6Allow(key)
		}
	}
	for _, key := range previous.fileKeys {
		if !sameCollection || !slices.Contains(replacement.fileKeys, key) {
			_ = previous.programs.objects.DeleteFileRules(key)
		}
	}
	for _, cgroupID := range cellCgroupIDs(previous.cell) {
		if !sameCollection || !slices.Contains(cellCgroupIDs(replacement.cell), cgroupID) {
			_ = previous.programs.objects.DeleteCellScope(cgroupID)
		}
	}
}

func (m *ProgramManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.cells {
		_ = m.disarmLocked(id)
	}
	for _, programs := range m.classes {
		programs.cancelRead()
		for _, item := range programs.globalLinks {
			_ = item.Close()
		}
		_ = programs.objects.Close()
	}
	return nil
}

func (m *ProgramManager) armResult(profile string, programs []string) ArmResult {
	enforcement := "r1-network"
	if hasProgram(programs, "GateExec") || hasProgram(programs, "GateFileOpen") {
		enforcement = "r1-kernel"
	} else {
		enforcement = "recorded-not-contained"
	}
	return ArmResult{Programs: programs, ManifestDigest: "sha256:" + m.verification.Verification.Digest.Actual, ObjectDigest: "sha256:" + m.verification.ObjectDigest.Actual, Enforcement: enforcement}
}

func hasProgram(programs []string, want string) bool {
	for _, program := range programs {
		if program == want {
			return true
		}
	}
	return false
}

func programSetEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, item := range left {
		if !hasProgram(right, item) {
			return false
		}
	}
	return true
}

func (m *ProgramManager) resolveNetKeys(ctx context.Context, cgroupID uint64, destination string) ([]bindings.NetKey, []bindings.Net6Key, error) {
	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		portText = "443"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid egress destination %q", destination)
	}
	resolver := m.options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIP(ctx, "ip", strings.Trim(host, "[]"))
	if err != nil {
		return nil, nil, fmt.Errorf("resolve egress %s: %w", host, err)
	}
	keys := make([]bindings.NetKey, 0, len(addresses)*2)
	keys6 := make([]bindings.Net6Key, 0, len(addresses)*2)
	for _, address := range addresses {
		ipv4 := address.To4()
		if ipv4 != nil {
			ip := binary.BigEndian.Uint32(ipv4)
			keys = append(keys,
				bindings.NetKey{CgroupId: cgroupID, DstIp4: ip, DstPort: uint16(port), Protocol: 6},
				bindings.NetKey{CgroupId: cgroupID, DstIp4: ip, DstPort: uint16(port), Protocol: 17},
			)
			continue
		}
		ipv6 := address.To16()
		if ipv6 == nil {
			continue
		}
		key := bindings.Net6Key{CgroupId: cgroupID, DstIp60: binary.NativeEndian.Uint32(ipv6[0:4]), DstIp61: binary.NativeEndian.Uint32(ipv6[4:8]), DstIp62: binary.NativeEndian.Uint32(ipv6[8:12]), DstIp63: binary.NativeEndian.Uint32(ipv6[12:16]), DstPort: uint16(port)}
		key.Protocol = 6
		keys6 = append(keys6, key)
		key.Protocol = 17
		keys6 = append(keys6, key)
	}
	return keys, keys6, nil
}

func profileClass(profile string) (uint32, error) {
	switch profile {
	case "strict":
		return 0, nil
	case "", "standard":
		return 1, nil
	case "open":
		return 2, nil
	default:
		return 0, fmt.Errorf("unknown cell profile %q", profile)
	}
}

func cellIdentity(cellID string) (uint64, uint64) {
	sum := sha256.Sum256([]byte(cellID))
	return binary.LittleEndian.Uint64(sum[:8]), binary.LittleEndian.Uint64(sum[8:16])
}
