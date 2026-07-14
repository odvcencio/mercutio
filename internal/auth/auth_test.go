package auth

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBrowserProtectionRequiresSessionCSRFToken(t *testing.T) {
	t.Setenv("MERCUTIO_DEV_MODE", "1")
	authn := FromEnv()
	protected := authn.SessionMiddleware(authn.ProtectBrowser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	bootstrap := authn.SessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, authn.CSRFToken(r))
	}))
	getResponse := httptest.NewRecorder()
	bootstrap.ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	cookies := getResponse.Result().Cookies()
	if len(cookies) == 0 || strings.TrimSpace(getResponse.Body.String()) == "" {
		t.Fatal("session bootstrap did not issue CSRF state")
	}

	deniedRequest := httptest.NewRequest(http.MethodPost, "/gosx/action/edit", nil)
	deniedRequest.AddCookie(cookies[0])
	denied := httptest.NewRecorder()
	protected.ServeHTTP(denied, deniedRequest)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", denied.Code)
	}

	form := url.Values{"csrf_token": {getResponse.Body.String()}}
	allowedRequest := httptest.NewRequest(http.MethodPost, "/gosx/action/edit", strings.NewReader(form.Encode()))
	allowedRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	allowedRequest.AddCookie(cookies[0])
	allowed := httptest.NewRecorder()
	protected.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("valid CSRF status = %d, body=%s", allowed.Code, allowed.Body.String())
	}
}

func TestInternalBoundaryRequiresVerifiedMTLSWhenConfigured(t *testing.T) {
	authn := &Auth{eventToken: "event", requireInternalMTLS: true}
	handler := authn.RequireInternal(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := httptest.NewRequest(http.MethodPost, "/api/internal/events", nil)
	request.Header.Set("X-Mercutio-Event-Token", "event")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("plaintext status=%d", denied.Code)
	}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, request)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("mTLS status=%d", allowed.Code)
	}
}

func TestTokenBoundary(t *testing.T) {
	auth := &Auth{token: "test-token"}
	next := auth.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	unauthorized := httptest.NewRecorder()
	next.ServeHTTP(unauthorized, httptest.NewRequest("GET", "/", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	next.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d", authorized.Code)
	}
}
