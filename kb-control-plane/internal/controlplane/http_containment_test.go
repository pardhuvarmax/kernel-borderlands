package controlplane

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/enforcement"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// Isolate and Kill are separate dashboard actions: Isolate must reach the
// sensor as NAMESPACE (level 3, reversible) and never as TERMINATE, which is
// what makes the enforcer SIGKILL the process.

func TestHandleIsolate_SendsNamespaceNotTerminate(t *testing.T) {
	cp := newTestControlPlane(t)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	l, err := ipc.NewTestListener(serverConn)
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}
	cp.enforcer = enforcement.NewEnforcer(l, cp.store)
	s := &HTTPServer{cp: cp}

	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleIsolate(rec, httptest.NewRequest(http.MethodPost, "/api/isolate", strings.NewReader(`{"pid":4321}`)))
	}()

	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	frame := make([]byte, length)
	for n := 0; n < len(frame); {
		m, err := clientConn.Read(frame[n:])
		if err != nil {
			t.Fatalf("reading frame: %v", err)
		}
		n += m
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleIsolate did not return in time")
	}

	// Payload follows the 4-byte header: pid(4) + level(4) + reason(64).
	if pid := binary.LittleEndian.Uint32(frame[4:8]); pid != 4321 {
		t.Errorf("pid = %d, want 4321", pid)
	}
	if level := binary.LittleEndian.Uint32(frame[8:12]); level != ipc.ContainmentNamespace {
		t.Errorf("level = %d, want %d (NAMESPACE); isolate must not terminate", level, ipc.ContainmentNamespace)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// With no sensor connected, Contain fails before any kill can happen, so
// these tests never signal a real PID.
func TestHandleKill_ReportsFailureWhenNoSensor(t *testing.T) {
	cp := newTestControlPlane(t)
	s := &HTTPServer{cp: cp}

	rec := httptest.NewRecorder()
	s.handleKill(rec, httptest.NewRequest(http.MethodPost, "/api/kill", strings.NewReader(`{"pid":4321}`)))

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (a failed kill must not be reported as success)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"success":false`) {
		t.Errorf("body = %s, want success:false", rec.Body.String())
	}
}

func TestHandleKill_RefusesProtectedPid1(t *testing.T) {
	cp := newTestControlPlane(t)
	s := &HTTPServer{cp: cp}

	rec := httptest.NewRecorder()
	s.handleKill(rec, httptest.NewRequest(http.MethodPost, "/api/kill", strings.NewReader(`{"pid":1}`)))

	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "pid 1") {
		t.Errorf("status = %d body = %s, want 502 mentioning pid 1", rec.Code, rec.Body.String())
	}
}

func TestHandleKill_RejectsNonPost(t *testing.T) {
	s := &HTTPServer{cp: newTestControlPlane(t)}
	rec := httptest.NewRecorder()
	s.handleKill(rec, httptest.NewRequest(http.MethodGet, "/api/kill", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}
