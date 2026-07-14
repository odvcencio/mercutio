package capability

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Claims struct {
	CellID      string   `json:"cellID"`
	ActorID     string   `json:"actorID"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	IssuedAt    int64    `json:"issuedAt"`
	ExpiresAt   int64    `json:"expiresAt"`
	Nonce       string   `json:"nonce"`
}

type Authority struct {
	key []byte
	now func() time.Time
}

func New(key []byte) *Authority {
	if len(key) < 32 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
	}
	return &Authority{key: append([]byte(nil), key...), now: time.Now}
}

func (a *Authority) Mint(claims Claims, ttl time.Duration) (string, error) {
	if a == nil || claims.CellID == "" || claims.ActorID == "" || ttl <= 0 {
		return "", fmt.Errorf("cell, actor, and positive capability TTL are required")
	}
	now := a.now().UTC()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(ttl).Unix()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	claims.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + a.signature(encoded), nil
}

func (a *Authority) Verify(token, cellID, permission string) (Claims, error) {
	var claims Claims
	if a == nil {
		return claims, fmt.Errorf("capability authority is unavailable")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(a.signature(parts[0]))) {
		return claims, fmt.Errorf("invalid capability signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &claims) != nil {
		return Claims{}, fmt.Errorf("invalid capability payload")
	}
	now := a.now().UTC().Unix()
	if claims.ExpiresAt <= now || claims.IssuedAt > now+30 {
		return Claims{}, fmt.Errorf("capability expired or not yet valid")
	}
	if cellID != "" && claims.CellID != cellID {
		return Claims{}, fmt.Errorf("capability is scoped to another cell")
	}
	if permission != "" && !hasPermission(claims.Permissions, permission) {
		return Claims{}, fmt.Errorf("capability lacks %s", permission)
	}
	return claims, nil
}

func (a *Authority) signature(payload string) string {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hasPermission(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
