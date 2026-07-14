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
	mu        sync.Mutex
	documents map[string]*incrementalDocument
}

type incrementalDocument struct {
	path          string
	language      string
	source        []byte
	highlighter   *gts.Highlighter
	tagger        *gts.Tagger
	highlightTree *gts.Tree
	tagTree       *gts.Tree
}

func New() *Service { return &Service{documents: make(map[string]*incrementalDocument)} }

func (s *Service) Analyze(path, language, content string) model.Analysis {
	result := model.Analysis{Path: path, Language: language}
	entry := grammars.DetectLanguage(path)
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
	if tree, err := grammars.ParseFilePooled(path, source); err == nil {
		result.HasErrors = tree.RootNode() != nil && tree.RootNode().HasError()
		tree.Release()
	} else if !strings.Contains(strings.ToLower(err.Error()), "unsupported file type") {
		result.Error = err.Error()
	}

	if query := strings.TrimSpace(entry.HighlightQuery); query != "" {
		var highlighter *gts.Highlighter
		var err error
		if entry.TokenSourceFactory == nil {
			highlighter, err = gts.NewHighlighter(lang, query)
		} else {
			highlighter, err = gts.NewHighlighter(lang, query, gts.WithTokenSourceFactory(func(src []byte) gts.TokenSource {
				return entry.TokenSourceFactory(src, lang)
			}))
		}
		if err != nil {
			result.Error = appendError(result.Error, "highlight query: "+err.Error())
		} else {
			for _, item := range highlighter.Highlight(source) {
				result.Highlights = append(result.Highlights, model.HighlightRange{Range: rangeFromBytes(item.StartByte, item.EndByte, source), Capture: item.Capture})
			}
		}
	}

	if query := strings.TrimSpace(grammars.ResolveTagsQuery(*entry)); query != "" {
		var tagger *gts.Tagger
		var err error
		if entry.TokenSourceFactory == nil {
			tagger, err = gts.NewTagger(lang, query)
		} else {
			tagger, err = gts.NewTagger(lang, query, gts.WithTaggerTokenSourceFactory(func(src []byte) gts.TokenSource {
				return entry.TokenSourceFactory(src, lang)
			}))
		}
		if err != nil {
			result.Error = appendError(result.Error, "tags query: "+err.Error())
		} else {
			for _, item := range tagger.Tag(source) {
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
	entry := grammars.DetectLanguage(path)
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
	if state == nil || state.path != path || state.language != result.Language {
		if state != nil {
			state.release()
		}
		state = &incrementalDocument{path: path, language: result.Language}
		state.highlighter, state.tagger, result.Error = newAnalyzers(entry, lang)
		if state.highlighter == nil && state.tagger == nil {
			// Preserve the full parser fallback for grammars without editor
			// queries, while keeping the same stable API shape.
			result = s.Analyze(path, language, content)
			return result
		}
		s.documents[key] = state
	}

	if state.highlighter != nil {
		if state.highlightTree != nil {
			state.highlightTree.Edit(inputEdit(state.source, source))
		}
		ranges, tree := state.highlighter.HighlightIncremental(source, state.highlightTree)
		if state.highlightTree != nil && state.highlightTree != tree {
			state.highlightTree.Release()
		}
		state.highlightTree = tree
		for _, item := range ranges {
			result.Highlights = append(result.Highlights, model.HighlightRange{
				Range: rangeFromBytes(item.StartByte, item.EndByte, source), Capture: item.Capture,
			})
		}
	}
	if state.tagger != nil {
		if state.tagTree != nil {
			state.tagTree.Edit(inputEdit(state.source, source))
		}
		tags, tree := state.tagger.TagIncremental(source, state.tagTree)
		if state.tagTree != nil && state.tagTree != tree {
			state.tagTree.Release()
		}
		state.tagTree = tree
		for _, item := range tags {
			result.Symbols = append(result.Symbols, model.Symbol{
				Kind: item.Kind, Name: item.Name,
				Range:     rangeFrom(item.Range.StartByte, item.Range.EndByte, item.Range.StartPoint, item.Range.EndPoint),
				NameRange: rangeFrom(item.NameRange.StartByte, item.NameRange.EndByte, item.NameRange.StartPoint, item.NameRange.EndPoint),
			})
		}
	}
	if state.highlightTree != nil && state.highlightTree.RootNode() != nil {
		result.HasErrors = state.highlightTree.RootNode().HasError()
	} else if state.tagTree != nil && state.tagTree.RootNode() != nil {
		result.HasErrors = state.tagTree.RootNode().HasError()
	}
	state.source = append(state.source[:0], source...)
	return result
}

func newAnalyzers(entry *grammars.LangEntry, lang *gts.Language) (*gts.Highlighter, *gts.Tagger, string) {
	var highlighter *gts.Highlighter
	var tagger *gts.Tagger
	var problem string
	if query := strings.TrimSpace(entry.HighlightQuery); query != "" {
		var err error
		if entry.TokenSourceFactory == nil {
			highlighter, err = gts.NewHighlighter(lang, query)
		} else {
			highlighter, err = gts.NewHighlighter(lang, query, gts.WithTokenSourceFactory(func(src []byte) gts.TokenSource {
				return entry.TokenSourceFactory(src, lang)
			}))
		}
		if err != nil {
			problem = appendError(problem, "highlight query: "+err.Error())
			highlighter = nil
		}
	}
	if query := strings.TrimSpace(grammars.ResolveTagsQuery(*entry)); query != "" {
		var err error
		if entry.TokenSourceFactory == nil {
			tagger, err = gts.NewTagger(lang, query)
		} else {
			tagger, err = gts.NewTagger(lang, query, gts.WithTaggerTokenSourceFactory(func(src []byte) gts.TokenSource {
				return entry.TokenSourceFactory(src, lang)
			}))
		}
		if err != nil {
			problem = appendError(problem, "tags query: "+err.Error())
			tagger = nil
		}
	}
	return highlighter, tagger, problem
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
