package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Agent struct {
	Source   Source
	Loader   Loader
	Control  Control
	Interval time.Duration
	armed    map[string]string
}

func (a *Agent) Run(ctx context.Context) error {
	if a.Source == nil || a.Loader == nil || a.Control == nil {
		return fmt.Errorf("source, loader, and control client are required")
	}
	if a.Interval <= 0 {
		a.Interval = 2 * time.Second
	}
	if a.armed == nil {
		a.armed = map[string]string{}
	}
	defer a.Loader.Close()
	if err := a.Reconcile(ctx); err != nil && ctx.Err() == nil {
		// Discovery is eventually consistent while the pod and cgroup appear.
		// A failed pass must not prevent later fail-closed retries.
	}
	ticker := time.NewTicker(a.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = a.Reconcile(ctx)
		}
	}
}

func (a *Agent) Reconcile(ctx context.Context) error {
	if a.Source == nil || a.Loader == nil || a.Control == nil {
		return fmt.Errorf("source, loader, and control client are required")
	}
	if a.armed == nil {
		a.armed = map[string]string{}
	}
	cells, err := a.Source.ListCells(ctx)
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(cells))
	var failures []error
	for _, cell := range cells {
		seen[cell.ID] = struct{}{}
		fingerprint := cellFingerprint(cell)
		if a.armed[cell.ID] == fingerprint {
			if refresher, ok := a.Loader.(RuleRefresher); ok {
				if refreshErr := refresher.RefreshRules(ctx, cell.ID); refreshErr != nil {
					failures = append(failures, fmt.Errorf("refresh cell %s rules: %w", cell.ID, refreshErr))
				}
			}
			continue
		}
		result, armErr := a.Loader.Arm(ctx, cell)
		if armErr != nil {
			failures = append(failures, fmt.Errorf("arm cell %s: %w", cell.ID, armErr))
			continue
		}
		// The receipt is deliberately sent only after maps and links are live.
		if reportErr := a.Control.Armed(ctx, cell, result); reportErr != nil {
			failures = append(failures, fmt.Errorf("report armed cell %s: %w", cell.ID, reportErr))
			continue
		}
		a.armed[cell.ID] = fingerprint
	}
	for cellID := range a.armed {
		if _, ok := seen[cellID]; ok {
			continue
		}
		if disarmErr := a.Loader.Disarm(ctx, cellID); disarmErr != nil {
			failures = append(failures, fmt.Errorf("disarm cell %s: %w", cellID, disarmErr))
			continue
		}
		delete(a.armed, cellID)
	}
	return errors.Join(failures...)
}

func cellFingerprint(cell Cell) string {
	egress := append([]string(nil), cell.AllowedEgress...)
	slices.Sort(egress)
	programs := append([]string(nil), cell.Programs...)
	slices.Sort(programs)
	cgroups := append([]uint64(nil), cell.CgroupIDs...)
	slices.Sort(cgroups)
	return fmt.Sprintf("%v\x00%d\x00%d\x00%d\x00%s\x00%s\x00%s\x00%s", cgroups, cell.WorktreeDev, cell.ScratchDev, cell.RuntimeDev, strings.TrimSpace(cell.Profile), cell.ProfileDigest, strings.Join(programs, "\x00"), strings.Join(egress, "\x00"))
}
