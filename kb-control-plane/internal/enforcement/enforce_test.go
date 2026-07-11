package enforcement

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// newListenerWithConn builds an *ipc.Listener wired to a net.Pipe() server
// end, so tests can both trigger a real SendContainmentCmd call and read
// the resulting frame from the client end — mirroring the pattern used in
// internal/ipc/listener_test.go. NOTE: Listener's fields are unexported, so
// this helper only works if enforce_test.go lives in a position that can
// reach ipc.Listener's zero-value + exported way of registering a conn. If
// ipc.Listener has no exported constructor/registration method, add one
// (e.g. ipc.NewListenerForTest or an exported AddConn) — see comment below.
func newListenerWithConn(t *testing.T) (*ipc.Listener, net.Conn, func()) {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	l, err := ipc.NewTestListener(serverConn)
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}

	cleanup := func() {
		serverConn.Close()
		clientConn.Close()
	}
	return l, clientConn, cleanup
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// --- Valid containment levels route through to SendContainmentCmd ---

func TestContain_ValidLevelsSendCmd(t *testing.T) {
	levels := []uint32{
		ipc.ContainmentCgroup,
		ipc.ContainmentSeccomp,
		ipc.ContainmentNamespace,
		ipc.ContainmentTerminate,
	}

	for _, level := range levels {
		level := level
		t.Run(levelName(level), func(t *testing.T) {
			l, clientConn, cleanup := newListenerWithConn(t)
			defer cleanup()

			e := NewEnforcer(l)

			errCh := make(chan error, 1)
			go func() {
				errCh <- e.Contain(1234, level, "test reason")
			}()

			// Drain the length prefix + header + payload so the goroutine
			// doesn't block on net.Pipe()'s synchronous write.
			var length uint32
			if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
				t.Fatalf("reading length prefix: %v", err)
			}
			frame := make([]byte, length)
			if _, err := readFull(clientConn, frame); err != nil {
				t.Fatalf("reading frame: %v", err)
			}

			// Payload starts after the 4-byte header: pid(4) + level(4) + reason(64)
			gotPID := binary.LittleEndian.Uint32(frame[4:8])
			gotLevel := binary.LittleEndian.Uint32(frame[8:12])
			if gotPID != 1234 {
				t.Errorf("pid = %d, want 1234", gotPID)
			}
			if gotLevel != level {
				t.Errorf("level = %d, want %d", gotLevel, level)
			}

			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("Contain returned error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Contain did not return in time")
			}
		})
	}
}

func levelName(level uint32) string {
	switch level {
	case ipc.ContainmentCgroup:
		return "Cgroup"
	case ipc.ContainmentSeccomp:
		return "Seccomp"
	case ipc.ContainmentNamespace:
		return "Namespace"
	case ipc.ContainmentTerminate:
		return "Terminate"
	default:
		return "Unknown"
	}
}

// --- ContainmentNone sends a level-0 wire message so the sensor clears its
// contained_pids_map entry. A bare no-op return would leave the PID
// kernel-contained even after an operator restore. ---

func TestContain_NoneNotifiesSensor(t *testing.T) {
	l, clientConn, cleanup := newListenerWithConn(t)
	defer cleanup()

	e := NewEnforcer(l)

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.Contain(1, ipc.ContainmentNone, "restore")
	}()

	// Drain the length prefix + frame so the goroutine doesn't block.
	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	frame := make([]byte, length)
	if _, err := readFull(clientConn, frame); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	// Payload: header(4) + pid(4) + level(4) + reason(64).
	// Level must be ContainmentNone (0) so the sensor deletes the map entry.
	gotLevel := binary.LittleEndian.Uint32(frame[8:12])
	if gotLevel != ipc.ContainmentNone {
		t.Errorf("level on wire = %d, want ContainmentNone (%d)", gotLevel, ipc.ContainmentNone)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Contain(None) returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Contain(None) did not return in time")
	}
}

// --- Unknown level returns an error, doesn't panic or send ---

func TestContain_UnknownLevel(t *testing.T) {
	l, clientConn, cleanup := newListenerWithConn(t)
	defer cleanup()

	e := NewEnforcer(l)

	err := e.Contain(1, 999, "bogus level")
	if err == nil {
		t.Fatal("expected error for unknown containment level, got nil")
	}

	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = clientConn.Read(buf)
	if err == nil {
		t.Fatal("expected no data written for unknown level, but got data")
	}
}

// --- Downstream SendContainmentCmd failure (no connected clients) is
// wrapped and propagated, not swallowed — for all levels including None. ---

func TestContain_NoClientsErrorPropagates(t *testing.T) {
	l, err := ipc.NewTestListener() // no conns registered
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}

	e := NewEnforcer(l)

	err = e.Contain(1, ipc.ContainmentSeccomp, "no clients connected")
	if err == nil {
		t.Fatal("expected error when no clients connected, got nil")
	}

	// ContainmentNone also hits the wire now, so it too must propagate the error.
	err = e.Contain(1, ipc.ContainmentNone, "no clients connected")
	if err == nil {
		t.Fatal("expected error for ContainmentNone when no clients connected, got nil")
	}
}