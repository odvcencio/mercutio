package shadow

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"m31labs.dev/mercutio/internal/intelligence"
	"m31labs.dev/mercutio/internal/model"
)

type Result struct {
	Content      string   `json:"content"`
	Conflicts    []string `json:"conflicts,omitempty"`
	Clean        bool     `json:"clean"`
	Intelligence string   `json:"intelligence"`
}
type entity struct {
	text string
	span model.Range
}

func Merge(service *intelligence.Service, path, language, base, human, agent string) Result {
	if service == nil {
		service = intelligence.New()
	}
	baseEntities, baseOK := entities(service.Analyze(path, language, base), base)
	humanEntities, humanOK := entities(service.Analyze(path, language, human), human)
	agentEntities, agentOK := entities(service.Analyze(path, language, agent), agent)
	if !baseOK || !humanOK || !agentOK {
		return mergeLines(path, base, human, agent)
	}
	keys := map[string]bool{}
	for key := range baseEntities {
		keys[key] = true
	}
	for key := range humanEntities {
		keys[key] = true
	}
	for key := range agentEntities {
		keys[key] = true
	}
	type replacement struct {
		start, end int
		text       string
	}
	var edits []replacement
	var conflicts []string
	for key := range keys {
		b, bok := baseEntities[key]
		h, hok := humanEntities[key]
		a, aok := agentEntities[key]
		btext, htext, atext := "", "", ""
		if bok {
			btext = b.text
		}
		if hok {
			htext = h.text
		}
		if aok {
			atext = a.text
		}
		humanChanged := hok != bok || htext != btext
		agentChanged := aok != bok || atext != btext
		if !agentChanged {
			continue
		}
		if humanChanged && htext != atext {
			conflicts = append(conflicts, key)
			continue
		}
		if humanChanged {
			continue
		}
		if !aok && hok {
			edits = append(edits, replacement{int(h.span.StartByte), int(h.span.EndByte), ""})
		} else if aok && hok {
			edits = append(edits, replacement{int(h.span.StartByte), int(h.span.EndByte), a.text})
		} else if aok && !hok {
			edits = append(edits, replacement{len(human), len(human), "\n" + a.text + "\n"})
		}
	}
	sort.Strings(conflicts)
	if len(conflicts) > 0 {
		return Result{Content: human, Conflicts: conflicts, Intelligence: "structural"}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	merged := human
	for _, edit := range edits {
		if edit.start < 0 || edit.end < edit.start || edit.end > len(merged) {
			return Result{Content: human, Conflicts: []string{"file::" + path}, Intelligence: "unavailable"}
		}
		merged = merged[:edit.start] + edit.text + merged[edit.end:]
	}
	return Result{Content: merged, Clean: true, Intelligence: "structural"}
}

type lineHunk struct {
	start       int
	end         int
	replacement []string
	side        string
}

// mergeLines is the deterministic fallback when structural intelligence is
// unavailable. Conflicts never enter the live buffer: the caller receives the
// unchanged human text and can keep the agent version as a shadow revision.
func mergeLines(path, base, human, agent string) Result {
	baseLines := difflib.SplitLines(base)
	humanHunks := lineHunksFor(baseLines, difflib.SplitLines(human), "human")
	agentHunks := lineHunksFor(baseLines, difflib.SplitLines(agent), "agent")
	conflicts := make([]string, 0)
	for _, h := range humanHunks {
		for _, a := range agentHunks {
			if !lineHunksOverlap(h, a) || sameLineHunk(h, a) {
				continue
			}
			conflicts = append(conflicts, fmt.Sprintf("line::%s:%d-%d", path, min(h.start, a.start)+1, max(h.end, a.end)+1))
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return Result{Content: human, Conflicts: compactStrings(conflicts), Intelligence: "line-diff3"}
	}
	chosen := append(append([]lineHunk(nil), humanHunks...), agentHunks...)
	sort.SliceStable(chosen, func(i, j int) bool {
		if chosen[i].start != chosen[j].start {
			return chosen[i].start < chosen[j].start
		}
		return chosen[i].end < chosen[j].end
	})
	filtered := chosen[:0]
	for _, hunk := range chosen {
		if len(filtered) > 0 && sameLineHunk(filtered[len(filtered)-1], hunk) {
			continue
		}
		filtered = append(filtered, hunk)
	}
	var merged []string
	cursor := 0
	for _, hunk := range filtered {
		if hunk.start < cursor {
			return Result{Content: human, Conflicts: []string{"file::" + path}, Intelligence: "line-diff3"}
		}
		merged = append(merged, baseLines[cursor:hunk.start]...)
		merged = append(merged, hunk.replacement...)
		cursor = hunk.end
	}
	merged = append(merged, baseLines[cursor:]...)
	return Result{Content: strings.Join(merged, ""), Clean: true, Intelligence: "line-diff3"}
}

func lineHunksFor(base, target []string, side string) []lineHunk {
	matcher := difflib.NewMatcher(base, target)
	var hunks []lineHunk
	for _, opcode := range matcher.GetOpCodes() {
		if opcode.Tag == 'e' {
			continue
		}
		hunks = append(hunks, lineHunk{start: opcode.I1, end: opcode.I2, replacement: append([]string(nil), target[opcode.J1:opcode.J2]...), side: side})
	}
	return hunks
}

func lineHunksOverlap(a, b lineHunk) bool {
	if a.start == a.end && b.start == b.end {
		return a.start == b.start
	}
	if a.start == a.end {
		return a.start >= b.start && a.start <= b.end
	}
	if b.start == b.end {
		return b.start >= a.start && b.start <= a.end
	}
	return a.start < b.end && b.start < a.end
}

func sameLineHunk(a, b lineHunk) bool {
	return a.start == b.start && a.end == b.end && strings.Join(a.replacement, "") == strings.Join(b.replacement, "")
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func entities(analysis model.Analysis, content string) (map[string]entity, bool) {
	if analysis.Error != "" || analysis.HasErrors {
		return nil, false
	}
	out := map[string]entity{}
	for _, symbol := range analysis.Symbols {
		start, end := int(symbol.Range.StartByte), int(symbol.Range.EndByte)
		if start < 0 || end < start || end > len(content) {
			return nil, false
		}
		key := "decl:" + symbol.Kind + "::" + symbol.Name
		out[key] = entity{text: content[start:end], span: symbol.Range}
	}
	if len(out) == 0 && strings.TrimSpace(content) != "" {
		return nil, false
	}
	return out, true
}
func ConflictError(conflicts []string) error {
	if len(conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("structural merge conflict: %s", strings.Join(conflicts, ", "))
}
