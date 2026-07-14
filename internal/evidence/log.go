// Package evidence provides Mercutio's append-only durable evidence boundary.
package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one hash-chained evidence envelope. Payload is already redacted by
// the producer and remains opaque to the log.
type Record struct {
	Sequence  uint64          `json:"sequence"`
	CellID    string          `json:"cellID"`
	Kind      string          `json:"kind"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
	Previous  string          `json:"previous,omitempty"`
	Hash      string          `json:"hash"`
}

// Log is an append-only JSONL ledger. An empty path keeps the same verified
// hash-chain semantics in memory for tests and ephemeral development.
type Log struct {
	mu      sync.RWMutex
	path    string
	records []Record
	last    string
}

func Open(path string) (*Log, error) {
	log := &Log{path: path}
	if path == "" {
		return log, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create evidence directory: %w", err)
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return log, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open evidence log: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 8*1024*1024)
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode evidence record: %w", err)
		}
		if err := verifyRecord(record, log.last, uint64(len(log.records)+1)); err != nil {
			return nil, err
		}
		log.records = append(log.records, record)
		log.last = record.Hash
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read evidence log: %w", err)
	}
	return log, nil
}

func (l *Log) Append(cellID, kind string, value any) (Record, error) {
	if l == nil {
		return Record{}, fmt.Errorf("evidence log is unavailable")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return Record{}, fmt.Errorf("encode evidence payload: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := Record{
		Sequence: uint64(len(l.records) + 1), CellID: cellID, Kind: kind,
		Timestamp: time.Now().UTC(), Payload: payload, Previous: l.last,
	}
	record.Hash = recordHash(record)
	if l.path != "" {
		if err := appendDurable(l.path, record); err != nil {
			return Record{}, err
		}
	}
	l.records = append(l.records, record)
	l.last = record.Hash
	return record, nil
}

func (l *Log) Records(cellID string) []Record {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Record, 0)
	for _, record := range l.records {
		if cellID == "" || record.CellID == cellID {
			result = append(result, record)
		}
	}
	return result
}

func (l *Log) Verify() error {
	if l == nil {
		return fmt.Errorf("evidence log is unavailable")
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	previous := ""
	for i, record := range l.records {
		if err := verifyRecord(record, previous, uint64(i+1)); err != nil {
			return err
		}
		previous = record.Hash
	}
	return nil
}

func appendDurable(path string, record Record) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open evidence append: %w", err)
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(record); err != nil {
		file.Close()
		return fmt.Errorf("append evidence record: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync evidence record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close evidence record: %w", err)
	}
	return nil
}

func verifyRecord(record Record, previous string, sequence uint64) error {
	if record.Sequence != sequence || record.Previous != previous {
		return fmt.Errorf("evidence chain discontinuity at sequence %d", sequence)
	}
	if record.Hash != recordHash(record) {
		return fmt.Errorf("evidence hash mismatch at sequence %d", sequence)
	}
	return nil
}

func recordHash(record Record) string {
	copy := record
	copy.Hash = ""
	encoded, _ := json.Marshal(copy)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
