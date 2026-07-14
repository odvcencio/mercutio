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

func TestBrowserProtectionPreservesOperatorBearerClients(t *testing.T) {
	t.Setenv("MERCUTIO_DEV_MODE", "1")
	t.Setenv("MERCUTIO_OPERATOR_TOKEN", "cli-operator-token")
	authn := FromEnv()
	protected := authn.ProtectBrowser(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/cells", nil)
	request.Header.Set("Authorization", "Bearer cli-operator-token")
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("bearer client status=%d body=%s", response.Code, response.Body.String())
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

func TestProductionConfigurationRequiresStableSessionAndOperatorIdentity(t *testing.T) {
	t.Setenv("MERCUTIO_DEV_MODE", "0")
	t.Setenv("MERCUTIO_SESSION_SECRET", "")
	t.Setenv("MERCUTIO_OPERATOR_EMAIL", "")
	if err := FromEnv().Validate(); err == nil {
		t.Fatal("production auth accepted ephemeral configuration")
	}
	t.Setenv("MERCUTIO_SESSION_SECRET", "a-stable-production-session-secret-with-enough-entropy")
	t.Setenv("MERCUTIO_OPERATOR_EMAIL", "operator@example.test")
	t.Setenv("MERCUTIO_AUTH_STATE_PATH", t.TempDir()+"/passkeys.json")
	if err := FromEnv().Validate(); err != nil {
		t.Fatalf("valid production auth: %v", err)
	}
}

func TestMagicLinkAndPasskeyRegistrationAreOperatorBound(t *testing.T) {
	t.Setenv("MERCUTIO_DEV_MODE", "1")
	t.Setenv("MERCUTIO_OPERATOR_EMAIL", "operator@example.test")
	authn := FromEnv()
	wrong := httptest.NewRequest(http.MethodPost, "/auth/magic-link", strings.NewReader("email=attacker%40example.test"))
	wrong.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	authn.SessionMiddleware(authn.MagicLinkRequest()).ServeHTTP(response, wrong)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "token=") {
		t.Fatalf("wrong identity response=%d %s", response.Code, response.Body.String())
	}

	register := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/options", strings.NewReader(`{"email":"operator@example.test"}`))
	register.Header.Set("Content-Type", "application/json")
	registerResponse := httptest.NewRecorder()
	authn.SessionMiddleware(authn.WebAuthnRegisterOptions()).ServeHTTP(registerResponse, register)
	if registerResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated passkey registration=%d %s", registerResponse.Code, registerResponse.Body.String())
	}
}

func TestProductionSessionCookieHasSecurityAttributes(t *testing.T) {
	t.Setenv("MERCUTIO_DEV_MODE", "0")
	t.Setenv("MERCUTIO_SESSION_SECRET", "a-stable-production-session-secret-with-enough-entropy")
	t.Setenv("MERCUTIO_OPERATOR_EMAIL", "operator@example.test")
	t.Setenv("MERCUTIO_AUTH_STATE_PATH", t.TempDir()+"/passkeys.json")
	authn := FromEnv()
	handler := authn.SessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = authn.CSRFToken(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://mercutio.example.test/", nil))
	cookies := response.Result().Cookies()
	if len(cookies) == 0 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite == http.SameSiteDefaultMode {
		t.Fatalf("insecure production cookie: %+v", cookies)
	}
}
