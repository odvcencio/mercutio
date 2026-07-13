package auth

import (
	"encoding/json"
	"net/http"
	"os"
)

// Auth is the deliberately narrow single-operator boundary for v1. Local
// development is open by default; deployments must set
// MERCUTIO_OPERATOR_TOKEN and MERCUTIO_DEV_MODE=0. The gosx magic-link and
// passkey handlers can replace this adapter without changing the control
// plane routes.
type Auth struct {
	devMode bool
	token   string
}

func FromEnv() *Auth {
	return &Auth{devMode: os.Getenv("MERCUTIO_DEV_MODE") != "0", token: os.Getenv("MERCUTIO_OPERATOR_TOKEN")}
}

func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.authorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "operator authentication required"})
	})
}

func (a *Auth) Session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": a.authorized(r), "mode": map[bool]string{true: "development", false: "operator-token"}[a.devMode]})
}

func (a *Auth) authorized(r *http.Request) bool {
	if a.devMode {
		return true
	}
	return a.token != "" && r.Header.Get("Authorization") == "Bearer "+a.token
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
