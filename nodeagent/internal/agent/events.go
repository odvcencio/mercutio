package agent

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	bindings "m31labs.dev/mercutio/nodeagent/generated"
)

func (m *ProgramManager) startReaders(programs *classPrograms) {
	if m.options.Queue == nil {
		return
	}
	go m.readExecEvents(programs)
	go m.readFileEvents(programs)
	go m.readConnectEvents(programs)
	go m.readDropCounters(programs)
}

func (m *ProgramManager) readExecEvents(programs *classPrograms) {
	err := programs.objects.ReadExecEvents(programs.readerCtx, func(raw bindings.ExecEvent) error {
		event, ok := m.baseEvent(programs, raw.Hdr)
		if !ok {
			return nil
		}
		event.Kind = "exec"
		event.Path = nulString(raw.Filename[:])
		event.Argv = argvString(raw.ArgvHead[:])
		event.ArgvTruncated = raw.ArgvTrunc != 0
		event.Program, event.ProgramDanger = execProgramMetadata(raw.Hdr.Kind)
		event.ActionDanger = danger("mutate", "process", "restart")
		m.options.Queue.Enqueue(event)
		return nil
	})
	if err != nil && programs.readerCtx.Err() == nil {
		m.options.Queue.AddKernelDrops(fmt.Sprintf("class-%d-exec-reader", programs.class), 1)
	}
}

func execProgramMetadata(kind uint32) (string, map[string]string) {
	if kind == 4 {
		return "GateExec", danger("control", "process", "restart")
	}
	return "OnExec", danger("observe", "event", "none")
}

func argvString(value []byte) string {
	value = bytes.TrimRight(value, "\x00")
	return strings.TrimSpace(string(bytes.ReplaceAll(value, []byte{0}, []byte{' '})))
}

func (m *ProgramManager) readFileEvents(programs *classPrograms) {
	err := programs.objects.ReadFileEvents(programs.readerCtx, func(raw bindings.FileEvent) error {
		event, ok := m.baseEvent(programs, raw.Hdr)
		if !ok {
			return nil
		}
		event.Kind = "file"
		event.Path = nulString(raw.Path[:])
		event.PathTruncated = raw.PathTrunc != 0
		event.Flags, event.Mode, event.Operation = raw.Flags, raw.Mode, raw.Op
		event.Program, event.ProgramDanger = fileProgramMetadata(programs.class)
		event.ActionDanger = danger(fileMode(raw.Flags), "filesystem", "restart")
		m.options.Queue.Enqueue(event)
		return nil
	})
	if err != nil && programs.readerCtx.Err() == nil {
		m.options.Queue.AddKernelDrops(fmt.Sprintf("class-%d-file-reader", programs.class), 1)
	}
}

func (m *ProgramManager) readConnectEvents(programs *classPrograms) {
	err := programs.objects.ReadConnectEvents(programs.readerCtx, func(raw bindings.ConnectEvent) error {
		event, ok := m.baseEvent(programs, raw.Hdr)
		if !ok {
			return nil
		}
		event.Kind = "connect"
		var ip net.IP
		if raw.Family == 10 {
			ip = append(net.IP(nil), raw.DstIp6[:]...)
		} else {
			ip = make(net.IP, net.IPv4len)
			binary.BigEndian.PutUint32(ip, raw.DstIp4)
		}
		event.Program, event.ProgramDanger = connectProgramMetadata(programs.class, raw.Family)
		event.Destination = net.JoinHostPort(ip.String(), fmt.Sprint(raw.DstPort))
		event.ActionDanger = danger("mutate", "network", "none")
		m.options.Queue.Enqueue(event)
		return nil
	})
	if err != nil && programs.readerCtx.Err() == nil {
		m.options.Queue.AddKernelDrops(fmt.Sprintf("class-%d-connect-reader", programs.class), 1)
	}
}

func fileProgramMetadata(class uint32) (string, map[string]string) {
	if class == 2 {
		return "ObserveFileOpen", danger("observe", "event", "none")
	}
	return "GateFileOpen", danger("control", "filesystem", "restart")
}

func connectProgramMetadata(class uint32, family uint16) (string, map[string]string) {
	name := "GateConnect4"
	if family == 10 {
		name = "GateConnect6"
	}
	if class == 2 {
		if family == 10 {
			name = "ObserveConnect6"
		} else {
			name = "ObserveConnect4"
		}
		return name, danger("observe", "event", "none")
	}
	return name, danger("control", "network", "restart")
}

func (m *ProgramManager) readDropCounters(programs *classPrograms) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	previous := map[uint32]uint64{}
	for {
		select {
		case <-programs.readerCtx.Done():
			return
		case <-ticker.C:
			for id := uint32(1); id <= 3; id++ {
				values, found, err := programs.objects.LookupDrops(id)
				if err != nil || !found {
					continue
				}
				var total uint64
				for _, value := range values {
					total += value.Count
				}
				if total > previous[id] {
					m.options.Queue.AddKernelDrops(fmt.Sprintf("class-%d-program-%d", programs.class, id), total-previous[id])
				}
				previous[id] = total
			}
		}
	}
}

func (m *ProgramManager) baseEvent(programs *classPrograms, header bindings.EventHeader) (KernelEvent, bool) {
	m.mu.Lock()
	cellID, ok := m.identities[[2]uint64{header.CellLo, header.CellHi}]
	loaded := m.cells[cellID]
	m.mu.Unlock()
	if !ok || loaded == nil || loaded.programs != programs {
		return KernelEvent{}, false
	}
	verdict := "allow"
	if header.Verdict == 1 {
		verdict = "deny"
	} else if header.Verdict == 2 {
		verdict = "ask"
	} else if header.Verdict == 3 {
		verdict = "approved"
		if programs.objects != nil {
			// A grant exists only to let the blocked syscall be retried once. The
			// first approved kernel event consumes it; the timer in ApplyDecision
			// remains a fail-safe if the process never retries.
			for kind := uint32(1); kind <= 3; kind++ {
				_ = programs.objects.DeleteActionGrant(bindings.ActionKey{CgroupId: header.CgroupId, Pid: header.Pid, Kind: kind})
			}
		}
	}
	seq := header.Seq
	if seq == 0 {
		seq = m.seq.Add(1)
	}
	event := KernelEvent{
		CellID: cellID, NodeID: m.cellNode(cellID), Seq: seq, TimestampNS: header.TsNs,
		CgroupID: header.CgroupId,
		Verdict:  verdict, PID: header.Pid, PPID: header.Ppid, TGID: header.Tgid, UID: header.Uid,
		Comm: nulString(header.Comm[:]), Evidence: "clean",
	}
	if verdict == "ask" {
		if err := m.options.Signal(int(event.PID), unix.SIGSTOP); err != nil {
			event.Evidence = "ask-stop-failed"
			if m.options.Queue != nil {
				m.options.Queue.AddKernelDrops("ask-stop", 1)
			}
		}
	}
	return event, true
}

func (m *ProgramManager) cellNode(cellID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if loaded := m.cells[cellID]; loaded != nil {
		return loaded.cell.NodeID
	}
	return ""
}

func nulString(data []byte) string {
	if index := strings.IndexByte(string(data), 0); index >= 0 {
		data = data[:index]
	}
	return string(data)
}

func danger(mode, scope, reversibility string) map[string]string {
	return map[string]string{"mode": mode, "scope": scope, "reversibility": reversibility}
}

func fileMode(flags uint32) string {
	if flags != 0 {
		return "mutate"
	}
	return "observe"
}
