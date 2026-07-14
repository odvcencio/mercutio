package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errCapability = errors.New("secret broker capability is required")

var secretNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type Receipt struct {
	ID        string    `json:"id"`
	CellID    string    `json:"cellID"`
	Name      string    `json:"name"`
	Version   uint64    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
}

type Descriptor struct {
	Name     string `json:"name"`
	Version  uint64 `json:"version"`
	Redacted string `json:"redacted"`
}

type Broker struct {
	mu      sync.RWMutex
	values  map[string]map[string]string
	version map[string]map[string]uint64
	store   Persistence
}

type Persistence interface {
	Put(cellID, name, value string) (uint64, error)
	Get(cellID, name string) (string, uint64, error)
	List(cellID string) ([]Descriptor, error)
	DeleteCell(cellID string) error
}

func NewBroker() *Broker {
	return &Broker{values: make(map[string]map[string]string), version: make(map[string]map[string]uint64)}
}

func NewBrokerWithPersistence(store Persistence) *Broker { b := NewBroker(); b.store = store; return b }

func (b *Broker) Put(cellID, name, value, actor string) (Receipt, error) {
	if strings.TrimSpace(actor) == "" {
		return Receipt{}, errCapability
	}
	cellID = strings.TrimSpace(cellID)
	name = strings.TrimSpace(name)
	if cellID == "" || name == "" {
		return Receipt{}, errors.New("secret cell and name are required")
	}
	if !secretNamePattern.MatchString(name) {
		return Receipt{}, errors.New("secret name contains unsupported characters")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.store != nil {
		version, err := b.store.Put(cellID, name, value)
		if err != nil {
			return Receipt{}, err
		}
		now := time.Now().UTC()
		return Receipt{ID: receiptID(cellID, name, version, now), CellID: cellID, Name: name, Version: version, Timestamp: now, Action: "secret:write", Actor: actor}, nil
	}
	if b.values[cellID] == nil {
		b.values[cellID] = make(map[string]string)
		b.version[cellID] = make(map[string]uint64)
	}
	b.values[cellID][name] = value
	b.version[cellID][name]++
	now := time.Now().UTC()
	return Receipt{ID: receiptID(cellID, name, b.version[cellID][name], now), CellID: cellID, Name: name, Version: b.version[cellID][name], Timestamp: now, Action: "secret:write", Actor: actor}, nil
}

func (b *Broker) DeleteCell(cellID string) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.store != nil {
		return b.store.DeleteCell(cellID)
	}
	delete(b.values, cellID)
	delete(b.version, cellID)
	return nil
}

func (b *Broker) Get(cellID, name, actor string) (string, Receipt, error) {
	if strings.TrimSpace(actor) == "" {
		return "", Receipt{}, errCapability
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.store != nil {
		value, version, err := b.store.Get(cellID, name)
		if err != nil {
			return "", Receipt{}, err
		}
		now := time.Now().UTC()
		return value, Receipt{ID: receiptID(cellID, name, version, now), CellID: cellID, Name: name, Version: version, Timestamp: now, Action: "secret:reveal", Actor: actor}, nil
	}
	value, ok := b.values[cellID][name]
	if !ok {
		return "", Receipt{}, errors.New("secret not found")
	}
	version := b.version[cellID][name]
	now := time.Now().UTC()
	return value, Receipt{ID: receiptID(cellID, name, version, now), CellID: cellID, Name: name, Version: version, Timestamp: now, Action: "secret:reveal", Actor: actor}, nil
}

func (b *Broker) List(cellID string) ([]Descriptor, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.store != nil {
		out, err := b.store.List(cellID)
		if err != nil {
			return nil, err
		}
		return out, nil
	}
	out := make([]Descriptor, 0, len(b.values[cellID]))
	for name, value := range b.values[cellID] {
		out = append(out, Descriptor{Name: name, Version: b.version[cellID][name], Redacted: RedactedValue(value)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func RedactedValue(value string) string {
	n := len([]rune(value))
	tail := ""
	runes := []rune(value)
	if len(runes) > 4 {
		tail = string(runes[len(runes)-4:])
	} else if len(runes) > 0 {
		tail = string(runes)
	}
	return "•••• (len=" + strconv.Itoa(n) + ", last=" + tail + ")"
}

func IsSensitivePath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	base := path
	if index := strings.LastIndexByte(base, '/'); index >= 0 {
		base = base[index+1:]
	}
	return base == ".env" || strings.Contains(base, "secret") || strings.Contains(base, "credential") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key")
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(["']?)[^\s"']{8,}`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`),
}

func ContainsSecretShape(value string) bool {
	for _, pattern := range secretPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func RedactText(value string) string {
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllStringFunc(value, func(match string) string {
			if index := strings.IndexAny(match, ":="); index >= 0 {
				return match[:index+1] + " <redacted>"
			}
			return "<redacted>"
		})
	}
	return value
}

func receiptID(cellID, name string, version uint64, timestamp time.Time) string {
	if timestamp.IsZero() {
		timestamp = time.Unix(0, 0)
	}
	sum := sha256.Sum256([]byte(cellID + "\x00" + name + "\x00" + strconv.FormatUint(version, 10) + "\x00" + timestamp.String()))
	return "secret-receipt-" + hex.EncodeToString(sum[:8])
}
