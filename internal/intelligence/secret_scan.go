package intelligence

import (
	"strings"

	gts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
	"m31labs.dev/mercutio/internal/model"
	"m31labs.dev/mercutio/internal/secrets"
)

type SecretScan struct {
	Status   string                `json:"status"`
	Findings []model.SecretFinding `json:"findings,omitempty"`
	Reason   string                `json:"reason,omitempty"`
}

// ScanSecrets treats parsing as authoritative only when it succeeds cleanly.
// Unavailable/hostile inputs fall back to byte-level detection and say so.
func (s *Service) ScanSecrets(path, content string) SecretScan {
	return scanSecretsWithTimeout(path, content, authoritativeParseTimeoutMicros)
}

func scanSecretsWithTimeout(path, content string, timeoutMicros uint64) SecretScan {
	if knownUnreliable(path, content) {
		return fallbackSecretScan(content, "known-unreliable minified JavaScript")
	}
	entry := grammars.DetectLanguage(path)
	if entry == nil {
		return fallbackSecretScan(content, "grammar unavailable")
	}
	lang := entry.Language()
	if lang == nil {
		return fallbackSecretScan(content, "grammar unavailable")
	}
	pool := gts.NewParserPool(lang, gts.WithParserPoolTimeoutMicros(timeoutMicros))
	source := []byte(content)
	var tree *gts.Tree
	var err error
	if entry.TokenSourceFactory != nil {
		tree, err = pool.ParseWithTokenSourceStrict(source, entry.TokenSourceFactory(source, lang))
	} else {
		tree, err = pool.ParseStrict(source)
	}
	if err != nil || tree == nil {
		if tree != nil {
			tree.Release()
		}
		return fallbackSecretScan(content, "parse failed or timed out")
	}
	defer tree.Release()
	if tree.RootNode() == nil || tree.RootNode().HasError() {
		return fallbackSecretScan(content, "parse contains errors")
	}
	result := SecretScan{Status: "structural"}
	walkSecretNodes(tree.RootNode(), lang, source, &result)
	return result
}

func walkSecretNodes(node *gts.Node, lang *gts.Language, source []byte, result *SecretScan) {
	if node == nil {
		return
	}
	kind := strings.ToLower(node.Type(lang))
	if secretNodeType(kind) {
		text := node.Text(source)
		context := text
		if parent := node.Parent(); parent != nil {
			context = parent.Text(source)
		}
		if secrets.ContainsSecretShape(text) || secrets.ContainsSecretShape(context) {
			result.Findings = append(result.Findings, model.SecretFinding{Kind: kind, Severity: "critical", Range: rangeFromBytes(node.StartByte(), node.EndByte(), source), Redacted: secrets.RedactText(text)})
		}
	}
	for i := 0; i < node.NamedChildCount(); i++ {
		walkSecretNodes(node.NamedChild(i), lang, source, result)
	}
}
func secretNodeType(kind string) bool {
	return strings.Contains(kind, "string") || strings.Contains(kind, "scalar") || strings.Contains(kind, "value") || strings.Contains(kind, "literal")
}
func fallbackSecretScan(content, reason string) SecretScan {
	result := SecretScan{Status: "unavailable", Reason: reason}
	if secrets.ContainsSecretShape(content) {
		result.Findings = []model.SecretFinding{{Kind: "byte-pattern", Severity: "critical", Range: model.Range{EndByte: uint32(len(content))}, Redacted: "<redacted secret-shaped content>"}}
	}
	return result
}
func knownUnreliable(path, content string) bool {
	lower := strings.ToLower(path)
	if !(strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".cjs")) {
		return false
	}
	lines := strings.Count(content, "\n") + 1
	return len(content) > 4096 && lines < 4
}
