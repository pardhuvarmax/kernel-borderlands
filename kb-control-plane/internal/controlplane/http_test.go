package controlplane

import (
	"encoding/json"
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

// --- /api/policy, /api/policy/reload, /api/agents — added to back
// kb-dashboard's Settings and Rogue Management pages. ---

func TestHandlePolicy_ReturnsParsedDefaults(t *testing.T) {
	cp := newTestControlPlane(t)
	s := &HTTPServer{cp: cp}

	req := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	rec := httptest.NewRecorder()
	s.handlePolicy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON body: %v", err)
	}
	// newTestControlPlane passes an empty policy path, so policy.New falls
	// back to its own hardcoded defaults (40/75) — see policy.go's New().
	if got := resp["suspicious_threshold"]; got != 40.0 {
		t.Errorf("suspicious_threshold = %v, want 40", got)
	}
	if got := resp["borderlands_threshold"]; got != 75.0 {
		t.Errorf("borderlands_threshold = %v, want 75", got)
	}
}

func TestHandlePolicy_RejectsNonGet(t *testing.T) {
	cp := newTestControlPlane(t)
	s := &HTTPServer{cp: cp}

	req := httptest.NewRequest(http.MethodPost, "/api/policy", nil)
	rec := httptest.NewRecorder()
	s.handlePolicy(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want 405", rec.Code)
	}
}

func TestHandlePolicyReload_GatedBehindAPIToken(t *testing.T) {
	cp := newTestControlPlane(t)
	s := &HTTPServer{cp: cp, apiToken: ""}
	handler := s.requireAPIToken(s.handlePolicyReload)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/reload", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want 503 (no token configured should fail closed, same as isolate/restore)", rec.Code)
	}
}

func TestHandlePolicyReload_SucceedsWithValidToken(t *testing.T) {
	cp := newTestControlPlane(t)
	s := &HTTPServer{cp: cp, apiToken: "test-token"}
	handler := s.requireAPIToken(s.handlePolicyReload)

	req := httptest.NewRequest(http.MethodPost, "/api/policy/reload", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON body: %v", err)
	}
	if resp["success"] != true {
		t.Errorf("success = %v, want true — cp.policyPath is empty so reload should be a no-op success, not an error", resp["success"])
	}
}

func TestHandleAgents_ReturnsServiceUnavailableWhenAADSUnreachable(t *testing.T) {
	// No kb-aads status server is running in this test — handleAgents
	// must fail fast with a clear message, not hang or 500. Uses the
	// real default address (127.0.0.1:8601) since nothing overrides
	// KB_AADS_API_ADDR in the test environment.
	s := &HTTPServer{}

	req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	rec := httptest.NewRecorder()
	s.handleAgents(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want 503 when kb-aads's status server isn't running", rec.Code)
	}
}
