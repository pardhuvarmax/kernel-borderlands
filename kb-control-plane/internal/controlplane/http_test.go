package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- BUG-001: /api/isolate and /api/restore must refuse all requests when
// no API token is configured (fail closed), and accept only a matching
// bearer token when one is. ---

func TestRequireAPIToken_NoTokenConfiguredRefusesAll(t *testing.T) {
	s := &HTTPServer{apiToken: ""}
	handler := s.requireAPIToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached when no token is configured")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/isolate", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestRequireAPIToken_WrongTokenRejected(t *testing.T) {
	s := &HTTPServer{apiToken: "correct-token"}
	handler := s.requireAPIToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached with a wrong token")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/isolate", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAPIToken_MissingAuthHeaderRejected(t *testing.T) {
	s := &HTTPServer{apiToken: "correct-token"}
	handler := s.requireAPIToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached with no Authorization header")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/isolate", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAPIToken_CorrectTokenReachesHandler(t *testing.T) {
	s := &HTTPServer{apiToken: "correct-token"}
	called := false
	handler := s.requireAPIToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/isolate", nil)
	req.Header.Set("Authorization", "Bearer correct-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Error("handler was not reached with a correct token")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}

// --- BUG-001: CORS must reflect only an explicitly allowed origin, never
// the previous unconditional wildcard "*". ---

func TestCorsHandler_AllowedOriginReflected(t *testing.T) {
	s := &HTTPServer{allowedOrigins: []string{"http://localhost:5173"}}
	handler := s.corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/processes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("got Access-Control-Allow-Origin=%q, want the exact allowed origin reflected", got)
	}
}

func TestCorsHandler_UnknownOriginNotReflected(t *testing.T) {
	s := &HTTPServer{allowedOrigins: []string{"http://localhost:5173"}}
	handler := s.corsHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/processes", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("got Access-Control-Allow-Origin=%q for an unlisted origin, want empty (no wildcard fallback)", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Error("got wildcard Access-Control-Allow-Origin — this is exactly BUG-001's regression")
	}
}
