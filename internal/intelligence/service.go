package intelligence

import (
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"m31labs.dev/mercutio/internal/model"
)

// Service is the code-intelligence boundary used by both the viewport and
// review generation. gotreesitter owns grammar loading; Mercutio only exposes
// stable editor-facing ranges and symbols.
type Service struct {
	mu                 sync.Mutex
	documents          map[string]*incrementalDocument
	parseTimeoutMicros uint64
}

const authoritativeParseTimeoutMicros = uint64(250_000)

type incrementalDocument struct {
	path          string
	language      string
	source        []byte
	highlighter   *gts.Highlighter
	tagger        *gts.Tagger
	highlightTree *gts.Tree
	tagTree       *gts.Tree
}

func New() *Service { return newWithParseTimeoutMicros(authoritativeParseTimeoutMicros) }

func newWithParseTimeoutMicros(timeoutMicros uint64) *Service {
	return &Service{documents: make(map[string]*incrementalDocument), parseTimeoutMicros: timeoutMicros}
}

func (s *Service) Analyze(path, language, content string) model.Analysis {
	result := model.Analysis{Path: path, Language: language}
	entry := grammars.DetectLanguage(parserPath(path))
	if entry == nil {
		return result
	}
	result.Language = entry.Name
	lang := entry.Language()
	if lang == nil {
		result.Error = fmt.Sprintf("grammar %q is unavailable", entry.Name)
		return result
	}
	source := []byte(content)
	if tree, err := parseStrict(entry, lang, source, s.parseTimeoutMicros); err == nil {
		result.HasErrors = tree.RootNode() != nil && tree.RootNode().HasError()
		tree.Release()
	} else {
		if tree != nil {
			tree.Release()
		}
		result.Error = "intelligence unavailable: " + err.Error()
		return result
	}

	highlighter, tagger, problem := newAnalyzers(entry, lang, s.parseTimeoutMicros)
	result.Error = appendError(result.Error, problem)
	if highlighter != nil {
		ranges, tree, err := highlighter.HighlightIncrementalStrict(source, nil)
		if tree != nil {
			tree.Release()
		}
		if err != nil {
			result.Error = appendError(result.Error, "highlight parse: "+err.Error())
			return result
		} else {
			for _, item := range ranges {
				result.Highlights = append(result.Highlights, model.HighlightRange{Range: rangeFromBytes(item.StartByte, item.EndByte, source), Capture: item.Capture})
			}
		}
	}

	if tagger != nil {
		tags, tree, err := tagger.TagIncrementalStrict(source, nil)
		if tree != nil {
			tree.Release()
		}
		if err != nil {
			result.Error = appendError(result.Error, "tags parse: "+err.Error())
			result.Highlights = nil
		} else {
			for _, item := range tags {
				result.Symbols = append(result.Symbols, model.Symbol{
					Kind:      item.Kind,
					Name:      item.Name,
					Range:     rangeFrom(item.Range.StartByte, item.Range.EndByte, item.Range.StartPoint, item.Range.EndPoint),
					NameRange: rangeFrom(item.NameRange.StartByte, item.NameRange.EndByte, item.NameRange.StartPoint, item.NameRange.EndPoint),
				})
			}
		}
	}
	return result
}

// AnalyzeIncremental keeps the parser trees for a document and applies the
// smallest source edit before re-running highlighting and tagging. The key is
// supplied by the caller so two cells can edit the same path independently.
func (s *Service) AnalyzeIncremental(key, path, language, content string) model.Analysis {
	result := model.Analysis{Path: path, Language: language}
	parsePath := parserPath(path)
	entry := grammars.DetectLanguage(parsePath)
	if entry == nil {
		return result
	}
	result.Language = entry.Name
	lang := entry.Language()
	if lang == nil {
		result.Error = fmt.Sprintf("grammar %q is unavailable", entry.Name)
		return result
	}
	if key == "" {
		key = path
	}
	source := []byte(content)

	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.documents[key]
	if state == nil || state.path != parsePath || state.language != result.Language {
		if state != nil {
			state.release()
		}
		state = &incrementalDocument{path: parsePath, language: result.Language}
		state.highlighter, state.tagger, result.Error = newAnalyzers(entry, lang, s.parseTimeoutMicros)
		if state.highlighter == nil && state.tagger == nil {
			// Preserve the full parser fallback for grammars without editor
			// queries, while keeping the same stable API shape.
			result = s.Analyze(path, language, content)
			return result
		}
		s.documents[key] = state
	}

	parseUnavailable := false
	if state.highlighter != nil {
		if state.highlightTree != nil {
			state.highlightTree.Edit(inputEdit(state.source, source))
		}
		ranges, tree, err := state.highlighter.HighlightIncrementalStrict(source, state.highlightTree)
		if state.highlightTree != nil && state.highlightTree != tree {
			state.highlightTree.Release()
		}
		if err != nil {
			if tree != nil {
				tree.Release()
			}
			state.highlightTree = nil
			result.Error = appendError(result.Error, "highlight parse: "+err.Error())
			parseUnavailable = true
		} else {
			state.highlightTree = tree
		}
		for _, item := range ranges {
			result.Highlights = append(result.Highlights, model.HighlightRange{
				Range: rangeFromBytes(item.StartByte, item.EndByte, source), Capture: item.Capture,
			})
		}
	}
	if parseUnavailable && state.tagTree != nil {
		state.tagTree.Release()
		state.tagTree = nil
	}
	if state.tagger != nil && !parseUnavailable {
		if state.tagTree != nil {
			state.tagTree.Edit(inputEdit(state.source, source))
		}
		tags, tree, err := state.tagger.TagIncrementalStrict(source, state.tagTree)
		if state.tagTree != nil && state.tagTree != tree {
			state.tagTree.Release()
		}
		if err != nil {
			if tree != nil {
				tree.Release()
			}
			state.tagTree = nil
			result.Error = appendError(result.Error, "tags parse: "+err.Error())
			parseUnavailable = true
		} else {
			state.tagTree = tree
		}
		for _, item := range tags {
			result.Symbols = append(result.Symbols, model.Symbol{
				Kind: item.Kind, Name: item.Name,
				Range:     rangeFrom(item.Range.StartByte, item.Range.EndByte, item.Range.StartPoint, item.Range.EndPoint),
				NameRange: rangeFrom(item.NameRange.StartByte, item.NameRange.EndByte, item.NameRange.StartPoint, item.NameRange.EndPoint),
			})
		}
	}
	if parseUnavailable {
		result.Highlights = nil
		result.Symbols = nil
	}
	if state.highlightTree != nil && state.highlightTree.RootNode() != nil {
		result.HasErrors = state.highlightTree.RootNode().HasError()
	} else if state.tagTree != nil && state.tagTree.RootNode() != nil {
		result.HasErrors = state.tagTree.RootNode().HasError()
	}
	state.source = append(state.source[:0], source...)
	return result
}

// parserPath projects Mercutio-owned DSLs onto compatible gotreesitter
// grammars until those languages ship dedicated grammar blobs. The original
// path and language remain in the public analysis result.
func parserPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".mdpp"):
		return path + ".md"
	case strings.HasSuffix(lower, ".arb"):
		return path + ".hcl"
	case strings.HasSuffix(lower, ".hzn"):
		return path + ".go"
	default:
		return path
	}
}

func newAnalyzers(entry *grammars.LangEntry, lang *gts.Language, timeoutMicros uint64) (*gts.Highlighter, *gts.Tagger, string) {
	var highlighter *gts.Highlighter
	var tagger *gts.Tagger
	var problem string
	if query := strings.TrimSpace(entry.HighlightQuery); query != "" {
		var err error
		options := []gts.HighlighterOption{gts.WithHighlighterTimeoutMicros(timeoutMicros)}
		if entry.TokenSourceFactory != nil {
			options = append(options, gts.WithTokenSourceFactory(func(src []byte) gts.TokenSource {
				return entry.TokenSourceFactory(src, lang)
			}))
		}
		highlighter, err = gts.NewHighlighter(lang, query, options...)
		if err != nil {
			problem = appendError(problem, "highlight query: "+err.Error())
			highlighter = nil
		}
	}
	if query := strings.TrimSpace(grammars.ResolveTagsQuery(*entry)); query != "" {
		var err error
		options := []gts.TaggerOption{gts.WithTaggerTimeoutMicros(timeoutMicros)}
		if entry.TokenSourceFactory != nil {
			options = append(options, gts.WithTaggerTokenSourceFactory(func(src []byte) gts.TokenSource {
				return entry.TokenSourceFactory(src, lang)
			}))
		}
		tagger, err = gts.NewTagger(lang, query, options...)
		if err != nil {
			problem = appendError(problem, "tags query: "+err.Error())
			tagger = nil
		}
	}
	return highlighter, tagger, problem
}

func parseStrict(entry *grammars.LangEntry, lang *gts.Language, source []byte, timeoutMicros uint64) (*gts.Tree, error) {
	parser := gts.NewParser(lang)
	parser.SetTimeoutMicros(timeoutMicros)
	if entry.TokenSourceFactory == nil {
		return parser.ParseStrict(source)
	}
	return parser.ParseWithTokenSourceStrict(source, entry.TokenSourceFactory(source, lang))
}

func (d *incrementalDocument) release() {
	if d.highlightTree != nil {
		d.highlightTree.Release()
	}
	if d.tagTree != nil {
		d.tagTree.Release()
	}
}

func inputEdit(oldSource, newSource []byte) gts.InputEdit {
	prefix := 0
	for prefix < len(oldSource) && prefix < len(newSource) && oldSource[prefix] == newSource[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(oldSource)-prefix && suffix < len(newSource)-prefix &&
		oldSource[len(oldSource)-1-suffix] == newSource[len(newSource)-1-suffix] {
		suffix++
	}
	for suffix > 0 && (!boundary(oldSource, len(oldSource)-suffix) || !boundary(newSource, len(newSource)-suffix)) {
		suffix--
	}
	for prefix > 0 && (!boundary(oldSource, prefix) || !boundary(newSource, prefix)) {
		prefix--
	}
	oldEnd := len(oldSource) - suffix
	newEnd := len(newSource) - suffix
	return gts.InputEdit{
		StartByte: uint32(prefix), OldEndByte: uint32(oldEnd), NewEndByte: uint32(newEnd),
		StartPoint: pointAt(oldSource, prefix), OldEndPoint: pointAt(oldSource, oldEnd), NewEndPoint: pointAt(newSource, newEnd),
	}
}

func boundary(source []byte, offset int) bool {
	return offset == len(source) || (offset >= 0 && offset < len(source) && utf8.RuneStart(source[offset]))
}

func pointAt(source []byte, offset int) gts.Point {
	if offset < 0 {
		offset = 0
	}
	if offset > len(source) {
		offset = len(source)
	}
	row, column := 0, 0
	for _, value := range source[:offset] {
		if value == '\n' {
			row++
			column = 0
			continue
		}
		column++
	}
	return gts.Point{Row: uint32(row), Column: uint32(column)}
}

func rangeFrom(startByte, endByte uint32, start, end gts.Point) model.Range {
	return model.Range{
		StartByte:   startByte,
		EndByte:     endByte,
		StartLine:   start.Row,
		StartColumn: start.Column,
		EndLine:     end.Row,
		EndColumn:   end.Column,
	}
}

func rangeFromBytes(startByte, endByte uint32, source []byte) model.Range {
	return model.Range{
		StartByte:   startByte,
		EndByte:     endByte,
		StartLine:   lineAt(source, startByte),
		StartColumn: columnAt(source, startByte),
		EndLine:     lineAt(source, endByte),
		EndColumn:   columnAt(source, endByte),
	}
}

func lineAt(source []byte, byteOffset uint32) uint32 {
	if byteOffset > uint32(len(source)) {
		byteOffset = uint32(len(source))
	}
	var line uint32
	for _, value := range source[:byteOffset] {
		if value == '\n' {
			line++
		}
	}
	return line
}

func columnAt(source []byte, byteOffset uint32) uint32 {
	if byteOffset > uint32(len(source)) {
		byteOffset = uint32(len(source))
	}
	last := strings.LastIndexByte(string(source[:byteOffset]), '\n')
	if last < 0 {
		return byteOffset
	}
	return byteOffset - uint32(last+1)
}

func appendError(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}
