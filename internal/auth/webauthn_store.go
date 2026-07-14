package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	gosxauth "m31labs.dev/gosx/auth"
)

type fileWebAuthnStore struct {
	mu          sync.Mutex
	path        string
	credentials map[string]gosxauth.WebAuthnCredential
}

func newFileWebAuthnStore(path string) (*fileWebAuthnStore, error) {
	store := &fileWebAuthnStore{path: filepath.Clean(path), credentials: make(map[string]gosxauth.WebAuthnCredential)}
	data, err := os.ReadFile(store.path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	var credentials []gosxauth.WebAuthnCredential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, err
	}
	for _, credential := range credentials {
		credential.ID = strings.TrimSpace(credential.ID)
		if credential.ID == "" || credential.User.ID == "" {
			return nil, fmt.Errorf("invalid passkey credential state")
		}
		if _, duplicate := store.credentials[credential.ID]; duplicate {
			return nil, fmt.Errorf("duplicate passkey credential %q", credential.ID)
		}
		store.credentials[credential.ID] = cloneCredential(credential)
	}
	return store, nil
}

func (s *fileWebAuthnStore) SaveCredential(credential gosxauth.WebAuthnCredential) error {
	if s == nil || strings.TrimSpace(credential.ID) == "" || strings.TrimSpace(credential.User.ID) == "" {
		return gosxauth.ErrWebAuthnCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential.ID = strings.TrimSpace(credential.ID)
	previous, existed := s.credentials[credential.ID]
	s.credentials[credential.ID] = cloneCredential(credential)
	if err := s.persistLocked(); err != nil {
		if existed {
			s.credentials[credential.ID] = previous
		} else {
			delete(s.credentials, credential.ID)
		}
		return err
	}
	return nil
}

func (s *fileWebAuthnStore) Credential(id string) (gosxauth.WebAuthnCredential, error) {
	if s == nil {
		return gosxauth.WebAuthnCredential{}, gosxauth.ErrWebAuthnCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[strings.TrimSpace(id)]
	if !ok {
		return gosxauth.WebAuthnCredential{}, gosxauth.ErrWebAuthnCredentialNotFound
	}
	return cloneCredential(credential), nil
}

func (s *fileWebAuthnStore) Credentials(userID string) ([]gosxauth.WebAuthnCredential, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]gosxauth.WebAuthnCredential, 0)
	for _, credential := range s.credentials {
		if credential.User.ID == userID {
			result = append(result, cloneCredential(credential))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (s *fileWebAuthnStore) UpdateCounter(id string, count uint32, usedAt time.Time) error {
	if s == nil {
		return gosxauth.ErrWebAuthnCredentialNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.credentials[strings.TrimSpace(id)]
	if !ok {
		return gosxauth.ErrWebAuthnCredentialNotFound
	}
	previous := credential
	credential.SignCount = count
	credential.LastUsedAt = usedAt
	s.credentials[credential.ID] = credential
	if err := s.persistLocked(); err != nil {
		s.credentials[credential.ID] = previous
		return err
	}
	return nil
}

func (s *fileWebAuthnStore) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	values := make([]gosxauth.WebAuthnCredential, 0, len(s.credentials))
	for _, credential := range s.credentials {
		values = append(values, cloneCredential(credential))
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	data, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".mercutio-passkeys-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	ok = true
	if directory, openErr := os.Open(filepath.Dir(s.path)); openErr == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func cloneCredential(credential gosxauth.WebAuthnCredential) gosxauth.WebAuthnCredential {
	credential.PublicKey = append([]byte(nil), credential.PublicKey...)
	credential.Transports = append([]string(nil), credential.Transports...)
	return credential
}
