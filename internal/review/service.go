package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	graftentity "github.com/odvcencio/graft/pkg/entity"
	"m31labs.dev/mercutio/internal/intelligence"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/secrets"
)

type CommitRequest struct {
	CellID  string
	Branch  string
	Review  model.Review
	Workdir string
}

type Committer interface {
	Commit(context.Context, CommitRequest) (string, error)
}

type AgentCommitter struct {
	Request func(context.Context, CommitRequest) (string, error)
}

func NewAgentCommitter(request func(context.Context, CommitRequest) (string, error)) *AgentCommitter {
	return &AgentCommitter{Request: request}
}

func (c *AgentCommitter) Commit(ctx context.Context, request CommitRequest) (string, error) {
	if c == nil || c.Request == nil {
		return "", fmt.Errorf("agent commit transport is not configured")
	}
	return c.Request(ctx, request)
}

type LocalCommitter struct{}

func (LocalCommitter) Commit(_ context.Context, request CommitRequest) (string, error) {
	return "local-review-" + request.Review.ID, nil
}

type GraftDiffer struct {
	Binary string
}

func NewGraftDiffer(binary string) *GraftDiffer {
	if binary == "" {
		binary = "graft"
	}
	return &GraftDiffer{Binary: binary}
}

func (d *GraftDiffer) EntityDiff(ctx context.Context, workdir string) (string, error) {
	if d == nil || strings.TrimSpace(workdir) == "" {
		return "", fmt.Errorf("graft worktree is not configured")
	}
	if _, err := os.Stat(workdir); err != nil {
		return "", fmt.Errorf("graft worktree: %w", err)
	}
	cmd := exec.CommandContext(ctx, d.Binary, "diff", "--review")
	cmd.Dir = workdir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("graft diff: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

type Service struct {
	intelligence *intelligence.Service
}

const structuralParseTimeoutMicros = uint64(250_000)

func NewService(intelligenceService *intelligence.Service) *Service {
	if intelligenceService == nil {
		intelligenceService = intelligence.New()
	}
	return &Service{intelligence: intelligenceService}
}

func (s *Service) Generate(baseline, current []model.File) []model.Review {
	before := make(map[string]model.File, len(baseline))
	for _, file := range baseline {
		before[file.Path] = file
	}
	after := make(map[string]model.File, len(current))
	for _, file := range current {
		after[file.Path] = file
	}
	paths := make([]string, 0, len(before)+len(after))
	seen := make(map[string]struct{})
	for path := range before {
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	for path := range after {
		if _, ok := seen[path]; !ok {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)

	var reviews []model.Review
	for _, path := range paths {
		oldFile, oldOK := before[path]
		newFile, newOK := after[path]
		oldContent, newContent := "", ""
		language := "text"
		if oldOK {
			oldContent, language = oldFile.Content, oldFile.Language
		}
		if newOK {
			newContent, language = newFile.Content, newFile.Language
		}
		if oldContent == newContent && oldOK == newOK {
			continue
		}
		beforeAnalysis := s.intelligence.Analyze(path, language, oldContent)
		afterAnalysis := s.intelligence.Analyze(path, language, newContent)
		secretScan := combineSecretScans(s.intelligence.ScanSecrets(path, oldContent), s.intelligence.ScanSecrets(path, newContent))
		entities, labels, signatureChanges, structural := graftReviewEntities(path, oldContent, newContent, beforeAnalysis, afterAnalysis)
		if !structural {
			entities, labels, signatureChanges = symbolReviewEntities(oldContent, newContent, beforeAnalysis.Symbols, afterAnalysis.Symbols)
		}
		if len(entities) == 0 {
			entities = []string{path}
			labels = map[string]string{path: path}
		}
		sort.Strings(entities)
		for _, entity := range entities {
			secretShape := len(secretScan.Findings) > 0
			status := "pending"
			commitReady := true
			label := labels[entity]
			if label == "" {
				label = entity
			}
			summary := fmt.Sprintf("%s changed in %s.", label, path)
			if secretShape {
				status = "blocked"
				commitReady = false
				summary = fmt.Sprintf("%s changed in %s; secret-shaped content requires the secret broker.", label, path)
			}
			review := model.Review{
				ID:               reviewID(path, entity),
				Title:            "Entity diff",
				Entity:           entity,
				Summary:          summary,
				Status:           status,
				CommitReady:      commitReady,
				Files:            []string{path},
				Patch:            secrets.RedactText(lineSummary(oldContent, newContent)),
				SecretScanStatus: secretScan.Status,
				SecretFindings:   append([]model.SecretFinding(nil), secretScan.Findings...),
				SignatureChanged: signatureChanges[entity],
			}
			reviews = append(reviews, review)
		}
	}
	return reviews
}

type reviewEntity struct {
	body      string
	label     string
	signature string
}

func graftReviewEntities(path, before, after string, beforeAnalysis, afterAnalysis model.Analysis) ([]string, map[string]string, map[string]bool, bool) {
	if beforeAnalysis.Error != "" || beforeAnalysis.HasErrors || afterAnalysis.Error != "" || afterAnalysis.HasErrors {
		return nil, nil, nil, false
	}
	left, err := extractReviewEntities(path, before)
	if err != nil {
		return nil, nil, nil, false
	}
	right, err := extractReviewEntities(path, after)
	if err != nil {
		return nil, nil, nil, false
	}
	keys := make(map[string]bool, len(left)+len(right))
	for key := range left {
		keys[key] = true
	}
	for key := range right {
		keys[key] = true
	}
	labels := map[string]string{}
	signatures := map[string]bool{}
	var changed []string
	for key := range keys {
		oldEntity, oldOK := left[key]
		newEntity, newOK := right[key]
		if oldOK == newOK && oldEntity.body == newEntity.body {
			continue
		}
		changed = append(changed, key)
		chosen := oldEntity
		if newOK {
			chosen = newEntity
		}
		labels[key] = chosen.label
		signatures[key] = oldOK && newOK && oldEntity.signature != newEntity.signature
	}
	return changed, labels, signatures, true
}

func extractReviewEntities(path, content string) (map[string]reviewEntity, error) {
	list, err := graftentity.ExtractWithOptions(path, []byte(content), graftentity.ExtractOptions{ParseTimeoutMicros: structuralParseTimeoutMicros})
	if err != nil {
		return nil, err
	}
	result := make(map[string]reviewEntity, len(list.Entities))
	for i := range list.Entities {
		entity := &list.Entities[i]
		key := entity.IdentityKey()
		if key == "" {
			return nil, fmt.Errorf("entity has no identity")
		}
		label := entity.Name
		if entity.Receiver != "" {
			label = entity.Receiver + "." + entity.Name
		}
		if label == "" {
			label = key
		}
		result[key] = reviewEntity{body: string(entity.Body), label: label, signature: entity.Signature}
	}
	return result, nil
}

func symbolReviewEntities(before, after string, beforeSymbols, afterSymbols []model.Symbol) ([]string, map[string]string, map[string]bool) {
	oldSymbols := symbolsByKey(beforeSymbols)
	newSymbols := symbolsByKey(afterSymbols)
	keys := make(map[string]struct{}, len(oldSymbols)+len(newSymbols))
	for key := range oldSymbols {
		keys[key] = struct{}{}
	}
	for key := range newSymbols {
		keys[key] = struct{}{}
	}
	var entities []string
	labels := map[string]string{}
	signatureChanges := map[string]bool{}
	for key := range keys {
		oldSymbol, oldFound := oldSymbols[key]
		newSymbol, newFound := newSymbols[key]
		oldText := spanText(before, oldSymbol.Range)
		newText := spanText(after, newSymbol.Range)
		if oldFound && newFound && oldText == newText {
			continue
		}
		entities = append(entities, key)
		if newFound {
			labels[key] = newSymbol.Name
			signatureChanges[key] = oldFound && signatureText(before, oldSymbol) != signatureText(after, newSymbol)
		} else {
			labels[key] = oldSymbol.Name
		}
	}
	return entities, labels, signatureChanges
}

func combineSecretScans(scans ...intelligence.SecretScan) intelligence.SecretScan {
	combined := intelligence.SecretScan{Status: "structural"}
	for _, scan := range scans {
		combined.Findings = append(combined.Findings, scan.Findings...)
		if scan.Status == "unavailable" {
			combined.Status = "unavailable"
			if combined.Reason == "" {
				combined.Reason = scan.Reason
			}
		}
	}
	return combined
}

func signatureText(content string, symbol model.Symbol) string {
	start, end := int(symbol.Range.StartByte), int(symbol.Range.EndByte)
	if start < 0 || end < start || end > len(content) {
		return ""
	}
	value := content[start:end]
	if index := strings.IndexByte(value, '{'); index >= 0 {
		value = value[:index]
	}
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func (s *Service) GenerateWithWorktree(ctx context.Context, workdir string, baseline, current []model.File) []model.Review {
	reviews := s.Generate(baseline, current)
	if strings.TrimSpace(workdir) == "" || len(reviews) == 0 {
		return reviews
	}
	if diff, err := NewGraftDiffer("").EntityDiff(ctx, workdir); err == nil && diff != "" {
		diff = secrets.RedactText(diff)
		if len(diff) > 256<<10 {
			diff = diff[:256<<10] + "\n…"
		}
		for i := range reviews {
			reviews[i].Title = "Graft entity diff"
			reviews[i].Patch = diff
		}
	}
	return reviews
}

func symbolsByKey(symbols []model.Symbol) map[string]model.Symbol {
	result := make(map[string]model.Symbol, len(symbols))
	for _, symbol := range symbols {
		key := symbol.Kind + ":" + symbol.Name
		result[key] = symbol
	}
	return result
}

func spanText(content string, span model.Range) string {
	start, end := int(span.StartByte), int(span.EndByte)
	if start < 0 || end < start || end > len(content) {
		return ""
	}
	return content[start:end]
}

func lineSummary(before, after string) string {
	if before == "" {
		return "+ " + firstLine(after)
	}
	if after == "" {
		return "- " + firstLine(before)
	}
	return "- " + firstLine(before) + "\n+ " + firstLine(after)
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		value = value[:index]
	}
	if len(value) > 180 {
		value = value[:180] + "…"
	}
	return value
}

func reviewID(path, entity string) string {
	sum := sha256.Sum256([]byte(path + "\x00" + entity))
	return "review-" + hex.EncodeToString(sum[:8])
}
