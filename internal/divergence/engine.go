package divergence

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"m31labs.dev/mercutio/internal/model"
)

type Options struct {
	CellID           string
	Worktree         string
	NetAllow         []string
	EvidenceHealthy  bool
	SilenceThreshold time.Duration
}

type candidate struct {
	ruleID, rule, summary string
	intent, kernel        []model.Event
	axes                  model.DangerAxes
	evidence              model.DivergenceEvidence
}

// Evaluate applies the normative D1-D9 rules and returns deterministic records.
func Evaluate(events []model.Event, options Options) []model.DivergenceRecord {
	if options.SilenceThreshold <= 0 {
		options.SilenceThreshold = 45 * time.Second
	}
	intents, kernels := split(events)
	evidence := evidenceStatus(kernels, options.EvidenceHealthy)
	var found []candidate

	for _, k := range kernels {
		matches := correlatedIntents(intents, k)
		if dangerous(k) && !classMatch(matches, k) {
			found = append(found, makeCandidate("D1", "Unclaimed effect", "Dangerous kernel effect has no matching claimed action class.", matches, []model.Event{k}, k.DangerAxes, evidence))
		}
		if scopeEscape(k, options.Worktree) {
			found = append(found, makeCandidate("D3", "Scope escape", "Filesystem write escaped the cell worktree and temporary space.", matches, []model.Event{k}, k.DangerAxes, evidence))
		}
		if egressDenied(k, options.NetAllow) {
			found = append(found, makeCandidate("D4", "Egress attempt", "Network connection was denied or targeted a destination outside NetAllow.", matches, []model.Event{k}, k.DangerAxes, evidence))
		}
		if secretTouch(k) {
			found = append(found, makeCandidate("D5", "Secret-path touch", "Kernel activity touched a protected secret path.", matches, []model.Event{k}, k.DangerAxes, evidence))
		}
		if attributionMismatch(k, intents, events) {
			found = append(found, makeCandidate("D9", "Attribution mismatch", "Operator-attributed write has no authenticated operator document change.", matches, []model.Event{k}, k.DangerAxes, evidence))
		}
	}

	for _, in := range intents {
		observed := correlatedKernels(kernels, in, intents)
		if claimedEffect(in) && !hasKernelClass(observed, in) {
			found = append(found, makeCandidate("D2", "Claimed not observed", "Claimed test, build, or commit has no matching execution observation.", []model.Event{in}, observed, in.DangerAxes, evidence))
		}
	}

	if silentIntent, silentKernel, ok := silentWindow(events, options.SilenceThreshold); ok {
		found = append(found, makeCandidate("D6", "Silent window", "Kernel activity continued without intent or heartbeat for the allowed window.", silentIntent, silentKernel, axesOf(silentKernel), evidence))
	}
	if !evidence.Healthy {
		found = append(found, makeCandidate("D7", "Evidence degraded", "Evidence loss or a batch sequence gap prevents clean assertions.", intents, kernels, axesOf(kernels), evidence))
	}
	for _, event := range events {
		if structuralSecret(event) {
			found = append(found, makeCandidate("D8", "Structural secret", "Agent-authored structural diff contains secret material.", correlatedIntents(intents, event), correlatedKernels(kernels, event, intents), event.DangerAxes, evidence))
		}
	}

	return records(options.CellID, found)
}

func split(events []model.Event) (intent, kernel []model.Event) {
	for _, e := range events {
		if e.Kind == model.EventIntent {
			intent = append(intent, e)
		}
		if e.Kind == model.EventKernel {
			kernel = append(kernel, e)
		}
	}
	return
}

// correlatedIntents places a timestamped event into exactly one action window.
// A window starts at an intent tick and ends at the next tick of the same
// trace; the kernel-provided clock uncertainty widens both boundaries. When
// widened windows overlap, the latest eligible tick wins deterministically.
func correlatedIntents(intents []model.Event, target model.Event) []model.Event {
	if target.Timestamp.IsZero() {
		return nil
	}
	groups := make(map[string][]model.Event)
	for _, event := range intents {
		if event.TraceID == "" || target.TraceID != "" && event.TraceID != target.TraceID {
			continue
		}
		groups[event.TraceID] = append(groups[event.TraceID], event)
	}
	skew := time.Duration(target.ClockSkewBoundMS) * time.Millisecond
	var selected *model.Event
	for key := range groups {
		ticks := groups[key]
		sort.Slice(ticks, func(i, j int) bool { return ticks[i].Timestamp.Before(ticks[j].Timestamp) })
		for index := range ticks {
			lower := ticks[index].Timestamp.Add(-skew)
			if target.Timestamp.Before(lower) {
				continue
			}
			if index+1 < len(ticks) && target.Timestamp.After(ticks[index+1].Timestamp.Add(skew)) {
				continue
			}
			candidate := ticks[index]
			if selected == nil || candidate.Timestamp.After(selected.Timestamp) || candidate.Timestamp.Equal(selected.Timestamp) && eventIdentity(candidate) < eventIdentity(*selected) {
				selected = &candidate
			}
		}
	}
	if selected == nil {
		return nil
	}
	return []model.Event{*selected}
}

func correlatedKernels(kernels []model.Event, target model.Event, intents []model.Event) []model.Event {
	var result []model.Event
	want := eventIdentity(target)
	for _, kernel := range kernels {
		matched := correlatedIntents(intents, kernel)
		if len(matched) == 1 && eventIdentity(matched[0]) == want {
			result = append(result, kernel)
		}
	}
	return result
}

func eventIdentity(event model.Event) string {
	if event.ID != "" {
		return event.ID
	}
	return event.TraceID + "@" + event.Timestamp.UTC().Format(time.RFC3339Nano) + ":" + event.Action + ":" + event.Source
}

func actionClass(action string) string {
	a := strings.ToLower(action)
	for _, c := range []string{"commit", "build", "test", "exec", "write", "connect", "delete", "secret"} {
		if strings.Contains(a, c) {
			return c
		}
	}
	return a
}

func classMatch(events []model.Event, target model.Event) bool {
	for _, e := range events {
		if actionClass(e.Action) == actionClass(target.Action) {
			return true
		}
	}
	return false
}
func hasKernelClass(events []model.Event, target model.Event) bool {
	for _, e := range events {
		class := actionClass(e.Action)
		if class == actionClass(target.Action) || class == "exec" {
			return true
		}
	}
	return false
}
func claimedEffect(e model.Event) bool {
	c := actionClass(e.Action)
	return c == "test" || c == "build" || c == "commit"
}
func dangerous(e model.Event) bool {
	d := strings.ToLower(e.Danger)
	return d == "high" || d == "critical" || strings.EqualFold(e.DangerAxes.Reversibility, "persistent")
}
func scopeEscape(e model.Event, root string) bool {
	if actionClass(e.Action) != "write" || e.Path == "" {
		return false
	}
	return !(strings.HasPrefix(e.Path, root+"/") || strings.HasPrefix(e.Path, "/tmp/") || e.Path == root || e.Path == "/tmp")
}
func egressDenied(e model.Event, allow []string) bool {
	if actionClass(e.Action) != "connect" {
		return false
	}
	if strings.EqualFold(e.Verdict, "deny") {
		return true
	}
	if e.Destination == "" {
		return false
	}
	host := strings.Split(e.Destination, ":")[0]
	for _, a := range allow {
		if host == a || strings.HasSuffix(host, "."+a) {
			return false
		}
	}
	return true
}
func secretTouch(e model.Event) bool {
	s := strings.ToLower(e.Path + " " + e.Detail)
	for _, p := range []string{"/.ssh/", "/.aws/", "/.config/gcloud/", ".env", "secret", "credentials"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}
func structuralSecret(e model.Event) bool {
	a := strings.ToLower(e.Action)
	return (e.Kind == model.EventReview || e.Kind == model.EventEdit) && (strings.Contains(a, "structural.secret") || strings.Contains(a, "secret.finding")) && strings.HasPrefix(strings.ToLower(e.Source), "agent")
}
func attributionMismatch(k model.Event, intents []model.Event, all []model.Event) bool {
	if actionClass(k.Action) != "write" || !strings.HasPrefix(strings.ToLower(defaultActor(k)), "operator") {
		return false
	}
	for _, e := range all {
		if e.Kind == model.EventEdit && e.Authenticated && strings.HasPrefix(strings.ToLower(defaultActor(e)), "operator") && (k.TraceID == "" || e.TraceID == k.TraceID) {
			return false
		}
	}
	return true
}
func defaultActor(e model.Event) string {
	if e.Actor != "" {
		return e.Actor
	}
	return e.Source
}

func evidenceStatus(kernels []model.Event, healthy bool) model.DivergenceEvidence {
	status := model.DivergenceEvidence{Healthy: healthy}
	var seq uint64
	for _, e := range kernels {
		status.Drops += e.Drops
		if e.BatchSeq > 0 && seq > 0 && e.BatchSeq != seq+1 {
			status.BatchGap = true
		}
		if e.BatchSeq > seq {
			seq = e.BatchSeq
		}
	}
	if status.Drops > 0 || status.BatchGap {
		status.Healthy = false
	}
	return status
}

func silentWindow(events []model.Event, threshold time.Duration) ([]model.Event, []model.Event, bool) {
	var latestSignal time.Time
	var kernels []model.Event
	for _, e := range events {
		if e.Kind == model.EventIntent || strings.Contains(strings.ToLower(e.Action), "heartbeat") {
			if e.Timestamp.After(latestSignal) {
				latestSignal = e.Timestamp
			}
		}
		if e.Kind == model.EventKernel {
			kernels = append(kernels, e)
		}
	}
	if len(kernels) == 0 || latestSignal.IsZero() {
		return nil, nil, false
	}
	latest := kernels[len(kernels)-1].Timestamp
	if latest.Sub(latestSignal) <= threshold {
		return nil, nil, false
	}
	var window []model.Event
	for _, k := range kernels {
		if k.Timestamp.After(latestSignal) {
			window = append(window, k)
		}
	}
	return nil, window, len(window) > 0
}

func axesOf(events []model.Event) model.DangerAxes {
	var best model.DangerAxes
	for _, e := range events {
		if severity(e.DangerAxes) > severity(best) {
			best = e.DangerAxes
		}
	}
	return best
}
func severity(a model.DangerAxes) int {
	r := rank(a.Reversibility, []string{"ephemeral", "reversible", "persistent"})
	s := rank(a.Scope, []string{"local", "cell", "workspace", "external", "global"})
	m := rank(a.Mode, []string{"read", "observe", "write", "execute", "admin"})
	return r*100 + s*10 + m
}
func rank(v string, ordered []string) int {
	for i, x := range ordered {
		if strings.EqualFold(v, x) {
			return i + 1
		}
	}
	return 0
}
func label(a model.DangerAxes) string {
	n := severity(a)
	if n >= 300 {
		return "critical"
	}
	if n >= 240 {
		return "high"
	}
	if n >= 130 {
		return "medium"
	}
	return "low"
}
func makeCandidate(id, rule, summary string, in, kernel []model.Event, axes model.DangerAxes, evidence model.DivergenceEvidence) candidate {
	return candidate{id, rule, summary, in, kernel, axes, evidence}
}

func records(cellID string, found []candidate) []model.DivergenceRecord {
	seen := map[string]bool{}
	out := make([]model.DivergenceRecord, 0, len(found))
	for _, c := range found {
		ids := eventIDs(c.intent, c.kernel)
		key := c.ruleID + "|" + strings.Join(ids, ",")
		sum := sha256.Sum256([]byte(cellID + "|" + key))
		id := "div-" + hex.EncodeToString(sum[:8])
		if seen[id] {
			continue
		}
		seen[id] = true
		first, last := bounds(c.intent, c.kernel)
		out = append(out, model.DivergenceRecord{ID: id, RuleID: c.ruleID, Rule: c.rule, Severity: label(c.axes), Summary: c.summary, ActionDanger: c.axes, Intent: c.intent, Kernel: c.kernel, Evidence: c.evidence, FirstSeen: first, LastSeen: last})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID == out[j].RuleID {
			return out[i].ID < out[j].ID
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
func eventIDs(groups ...[]model.Event) []string {
	var ids []string
	for _, g := range groups {
		for _, e := range g {
			id := e.ID
			if id == "" {
				id = e.TraceID + "@" + e.Timestamp.UTC().Format(time.RFC3339Nano) + ":" + e.Action
			}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
func bounds(groups ...[]model.Event) (time.Time, time.Time) {
	var first, last time.Time
	for _, g := range groups {
		for _, e := range g {
			if first.IsZero() || e.Timestamp.Before(first) {
				first = e.Timestamp
			}
			if e.Timestamp.After(last) {
				last = e.Timestamp
			}
		}
	}
	return first, last
}
