package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
