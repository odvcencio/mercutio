package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"strings"

	gosxauth "m31labs.dev/gosx/auth"
	"m31labs.dev/gosx/session"
)

// Auth combines the local development switch, bearer-token boundary, and the
// GoSX session-backed magic-link/passkey flows used by the production shell.
// Agent cell tokens are deliberately handled by a separate verifier and are
// accepted only by the WebSocket hub boundary.
type Auth struct {
	devMode             bool
	token               string
	eventToken          string
	sessions            *session.Manager
	manager             *gosxauth.Manager
	magicLinks          *gosxauth.MagicLinks
	webAuthn            *gosxauth.WebAuthn
	operatorEmail       string
	requireInternalMTLS bool
	configurationError  error
}

func FromEnv() *Auth {
	authn := &Auth{devMode: os.Getenv("MERCUTIO_DEV_MODE") != "0", token: os.Getenv("MERCUTIO_OPERATOR_TOKEN"), eventToken: os.Getenv("MERCUTIO_EVENT_TOKEN"), requireInternalMTLS: strings.TrimSpace(os.Getenv("MERCUTIO_INTERNAL_TLS_CLIENT_CA")) != ""}
	if authn.eventToken == "" {
		authn.eventToken = authn.token
	}
	secret := strings.TrimSpace(os.Getenv("MERCUTIO_SESSION_SECRET"))
	if secret == "" && !authn.devMode {
		authn.configurationError = fmt.Errorf("MERCUTIO_SESSION_SECRET is required outside development mode")
	}
	if secret == "" && authn.devMode {
		secret = "mercutio-development-session-secret"
	}
	if secret == "" {
		secret = randomSessionSecret()
	}
	authn.operatorEmail = strings.ToLower(strings.TrimSpace(os.Getenv("MERCUTIO_OPERATOR_EMAIL")))
	if authn.operatorEmail == "" && !authn.devMode {
		authn.configurationError = fmt.Errorf("MERCUTIO_OPERATOR_EMAIL is required outside development mode")
	}
	authn.sessions, _ = session.New(secret, session.Options{
		CookieName: "mercutio_session",
		HTTPOnly:   true,
		Secure:     !authn.devMode || os.Getenv("MERCUTIO_SESSION_SECURE") == "1",
		SameSite:   http.SameSiteLaxMode,
		Encrypt:    true,
	})
	if authn.sessions == nil {
		return authn
	}
	authn.manager = gosxauth.New(authn.sessions, gosxauth.Options{LoginPath: "/login"})
	sender, senderConfigured, senderErr := smtpMagicLinkSenderFromEnv()
	if senderErr != nil {
		authn.configurationError = senderErr
	}
	if authn.devMode || senderConfigured {
		authn.magicLinks = authn.manager.MagicLinks(gosxauth.MagicLinkOptions{
			Path: "/auth/magic-link", SuccessPath: "/", FailurePath: "/login", Sender: sender,
			Resolver: gosxauth.MagicLinkResolverFunc(authn.resolveOperator),
		})
	}
	authn.webAuthn = authn.manager.WebAuthn(gosxauth.WebAuthnOptions{
		RPID:             envOr("MERCUTIO_AUTH_RP_ID", "127.0.0.1"),
		RPName:           "Mercutio",
		Origin:           os.Getenv("MERCUTIO_AUTH_ORIGIN"),
		SuccessPath:      "/",
		FailurePath:      "/login",
		UserVerification: "preferred",
		Resolver:         gosxauth.WebAuthnResolverFunc(authn.resolveOperator),
	})
	return authn
}

func (a *Auth) Validate() error {
	if a == nil {
		return fmt.Errorf("authentication is unavailable")
	}
	return a.configurationError
}

func (a *Auth) resolveOperator(_ context.Context, value string) (gosxauth.User, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if a.operatorEmail != "" && value != a.operatorEmail {
		return gosxauth.User{}, fmt.Errorf("operator identity is not permitted")
	}
	if value == "" {
		value = a.operatorEmail
	}
	return gosxauth.User{ID: value, Email: value, Name: "Mercutio operator"}, nil
}

// CSRFToken returns the request-bound token used by GoSX browser actions.
func (a *Auth) CSRFToken(r *http.Request) string {
	if a == nil || a.sessions == nil {
		return ""
	}
	return a.sessions.Token(r)
}

// ProtectBrowser applies GoSX CSRF validation to cookie-authenticated unsafe
// requests. Explicit operator bearer tokens remain suitable for API clients.
func (a *Auth) ProtectBrowser(next http.Handler) http.Handler {
	if a == nil || a.sessions == nil {
		return next
	}
	protected := a.sessions.Protect(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.operatorAuthorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})
}

func (a *Auth) SessionMiddleware(next http.Handler) http.Handler {
	if a == nil || a.sessions == nil {
		return next
	}
	return a.sessions.Middleware(a.manager.Middleware(next))
}

func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.authorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "operator authentication required"})
	})
}

// RequireHub allows either the operator or a caller presenting a valid cell
// token in the WebSocket URL. The hub still requires an explicit agent:attach
// message before it grants agent capabilities.
func (a *Auth) RequireHub(agentVerifier func(*http.Request) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.authorized(r) || (agentVerifier != nil && agentVerifier(r)) {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "hub authentication required"})
	})
}

func (a *Auth) RequireInternal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a != nil && a.requireInternalMTLS && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified internal mTLS client required"})
			return
		}
		if a != nil && (a.devMode || a.operatorAuthorized(r) || (a.eventToken != "" && (r.Header.Get("X-Mercutio-Event-Token") == a.eventToken || r.Header.Get("Authorization") == "Bearer "+a.eventToken))) {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "internal event authentication required"})
	})
}

// RequireSecret keeps broker reads separate from operator APIs. Agents prove
// possession of their cell attach token; the store performs the constant-time
// cell-specific check before returning a value.
func (a *Auth) RequireSecret(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a != nil && (a.authorized(r) || strings.TrimSpace(r.Header.Get("X-Mercutio-Attach-Token")) != "") {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "secret broker authentication required"})
	})
}

func (a *Auth) Session(w http.ResponseWriter, r *http.Request) {
	mode := "operator-token"
	if a != nil && a.devMode {
		mode = "development"
	} else if a != nil && a.manager != nil {
		if _, ok := a.manager.Current(r); ok {
			mode = "session"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": a.authorized(r), "mode": mode})
}

func (a *Auth) MagicLinkRequest() http.Handler {
	if a == nil || a.magicLinks == nil {
		return unavailableHandler("magic-link authentication is not configured")
	}
	return a.magicLinks.RequestHandler()
}

func (a *Auth) MagicLinkCallback() http.Handler {
	if a == nil || a.magicLinks == nil {
		return unavailableHandler("magic-link authentication is not configured")
	}
	return a.magicLinks.CallbackHandler()
}

func (a *Auth) WebAuthnRegisterOptions() http.Handler {
	if a == nil || a.webAuthn == nil {
		return unavailableHandler("passkey authentication is not configured")
	}
	return a.requireOperatorSession(a.webAuthn.RegisterOptionsHandler())
}

func (a *Auth) WebAuthnRegister() http.Handler {
	if a == nil || a.webAuthn == nil {
		return unavailableHandler("passkey authentication is not configured")
	}
	return a.requireOperatorSession(a.webAuthn.RegisterHandler())
}

func (a *Auth) WebAuthnLoginOptions() http.Handler {
	if a == nil || a.webAuthn == nil {
		return unavailableHandler("passkey authentication is not configured")
	}
	return a.webAuthn.LoginOptionsHandler()
}

func (a *Auth) WebAuthnLogin() http.Handler {
	if a == nil || a.webAuthn == nil {
		return unavailableHandler("passkey authentication is not configured")
	}
	return a.webAuthn.LoginHandler()
}

func (a *Auth) authorized(r *http.Request) bool {
	if a == nil {
		return false
	}
	if a.devMode || a.operatorAuthorized(r) {
		return true
	}
	if a.manager == nil {
		return false
	}
	user, ok := a.manager.Current(r)
	if !ok {
		return false
	}
	if a.operatorEmail == "" {
		return true
	}
	return strings.EqualFold(user.Email, a.operatorEmail) || strings.EqualFold(user.ID, a.operatorEmail)
}

func (a *Auth) operatorAuthorized(r *http.Request) bool {
	return a != nil && a.token != "" && r.Header.Get("Authorization") == "Bearer "+a.token
}

func unavailableHandler(message string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": message})
	})
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomSessionSecret() string {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "mercutio-ephemeral-session-secret"
	}
	return hex.EncodeToString(buffer)
}

func (a *Auth) requireOperatorSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := a.manager.Current(r)
		if !ok || (a.operatorEmail != "" && !strings.EqualFold(user.Email, a.operatorEmail) && !strings.EqualFold(user.ID, a.operatorEmail)) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authenticated operator session required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func smtpMagicLinkSenderFromEnv() (gosxauth.MagicLinkSender, bool, error) {
	address := strings.TrimSpace(os.Getenv("MERCUTIO_SMTP_ADDR"))
	fromValue := strings.TrimSpace(os.Getenv("MERCUTIO_SMTP_FROM"))
	username := strings.TrimSpace(os.Getenv("MERCUTIO_SMTP_USERNAME"))
	password := os.Getenv("MERCUTIO_SMTP_PASSWORD")
	if address == "" && fromValue == "" && username == "" && password == "" {
		return nil, false, nil
	}
	if address == "" || fromValue == "" {
		return nil, false, fmt.Errorf("MERCUTIO_SMTP_ADDR and MERCUTIO_SMTP_FROM must be configured together")
	}
	from, err := mail.ParseAddress(fromValue)
	if err != nil {
		return nil, false, fmt.Errorf("invalid MERCUTIO_SMTP_FROM: %w", err)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, false, fmt.Errorf("MERCUTIO_SMTP_ADDR must include host and port: %w", err)
	}
	if (username == "") != (password == "") {
		return nil, false, fmt.Errorf("MERCUTIO_SMTP_USERNAME and MERCUTIO_SMTP_PASSWORD must be configured together")
	}
	return gosxauth.MagicLinkSenderFunc(func(_ context.Context, delivery gosxauth.MagicLinkDelivery) error {
		to, err := mail.ParseAddress(delivery.Email)
		if err != nil {
			return err
		}
		var auth smtp.Auth
		if username != "" {
			auth = smtp.PlainAuth("", username, password, host)
		}
		message := []byte("From: " + from.String() + "\r\nTo: " + to.String() + "\r\nSubject: Mercutio sign-in\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nOpen this single-use link to sign in to Mercutio:\r\n" + delivery.URL + "\r\n")
		return smtp.SendMail(address, auth, from.Address, []string{to.Address}, message)
	}), true, nil
}
