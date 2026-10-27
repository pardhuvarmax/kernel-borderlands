package enforcement

import (
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
)

// fakeTarget stands in for a pinned process so tests never signal a real PID.
type fakeTarget struct {
	pid    uint32
	result error
	killed *[]int
}

func (f fakeTarget) Kill() error { *f.killed = append(*f.killed, int(f.pid)); return f.result }
func (f fakeTarget) Close()      {}

// TestMain replaces prepareTerminate for the whole package so no test can
// ever SIGKILL a real PID (several tests contain made-up PIDs at level 4).
func TestMain(m *testing.M) {
	ackTimeout = 300 * time.Millisecond // tests that expect no ack must not wait 3 s
	var sink []int
	prepareTerminate = func(_ *Enforcer, pid uint32) (terminateTarget, error) {
		return fakeTarget{pid: pid, killed: &sink}, nil
	}
	os.Exit(m.Run())
}

// stubKill swaps prepareTerminate for one test: the gate passes, Kill
// records the PID and returns result. It returns the recorded PIDs.
func stubKill(t *testing.T, result error) *[]int {
	t.Helper()
	killed := new([]int)
	prev := prepareTerminate
	prepareTerminate = func(_ *Enforcer, pid uint32) (terminateTarget, error) {
		return fakeTarget{pid: pid, result: result, killed: killed}, nil
	}
	t.Cleanup(func() { prepareTerminate = prev })
	return killed
}

// stubGateRefuses makes the Go-side CPM/CWP gate refuse every TERMINATE.
func stubGateRefuses(t *testing.T) {
	t.Helper()
	prev := prepareTerminate
	prepareTerminate = func(_ *Enforcer, pid uint32) (terminateTarget, error) {
		return nil, refuse("CPM", pid, "Protected Executable /usr/lib/systemd/systemd-logind")
	}
	t.Cleanup(func() { prepareTerminate = prev })
}

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

			e := NewEnforcer(l, nil)

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

			// The sensor would now answer a level-4 command; TERMINATE waits for it.
			e.OnContainmentAck(&ipc.ContainmentAckMsg{PID: 1234, Level: level, Decision: ipc.ContainmentAckApplied})

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

	e := NewEnforcer(l, nil)

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

	e := NewEnforcer(l, nil)

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

	e := NewEnforcer(l, nil)

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

// --- BUG-011 regression: the Go control plane had zero exemption logic of
// its own, forwarding any PID it was given (including PID 1 or itself)
// straight to kb-core's downstream CPM gate with no independent backstop. ---

func TestContain_RefusesPid1(t *testing.T) {
	l, err := ipc.NewTestListener() // no conns — if the gate didn't fire, we'd see the "no clients" error instead
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}
	e := NewEnforcer(l, nil)

	err = e.Contain(1, ipc.ContainmentTerminate, "test")
	if err == nil {
		t.Fatal("expected error containing pid 1, got nil")
	}
	if !strings.Contains(err.Error(), "pid 1") {
		t.Errorf("got error %q, want it to mention pid 1 (not just a downstream wire failure)", err)
	}
}

func TestContain_RefusesSelfPid(t *testing.T) {
	l, err := ipc.NewTestListener()
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}
	e := NewEnforcer(l, nil)

	err = e.Contain(uint32(os.Getpid()), ipc.ContainmentTerminate, "test")
	if err == nil {
		t.Fatal("expected error containing self pid, got nil")
	}
	if !strings.Contains(err.Error(), "self") {
		t.Errorf("got error %q, want it to mention self", err)
	}
}

func TestContain_RefusesProtectedComm(t *testing.T) {
	t.Setenv("KB_PROTECTED_COMM", "systemd,kbd")
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(s.Close)
	s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 555, Comm: "kbd"})

	l, err := ipc.NewTestListener()
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}
	e := NewEnforcer(l, s)

	err = e.Contain(555, ipc.ContainmentTerminate, "test")
	if err == nil {
		t.Fatal("expected error containing protected comm, got nil")
	}
	if !strings.Contains(err.Error(), "protected") {
		t.Errorf("got error %q, want it to mention protected", err)
	}
}

func TestContain_UnprotectedCommNotBlockedByGate(t *testing.T) {
	s, err := store.New(":memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(s.Close)
	s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 777, Comm: "curl"})

	l, err := ipc.NewTestListener() // no conns
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}
	e := NewEnforcer(l, s)

	err = e.Contain(777, ipc.ContainmentTerminate, "test")
	if err == nil || strings.Contains(err.Error(), "protected") || strings.Contains(err.Error(), "pid 1") || strings.Contains(err.Error(), "self") {
		t.Fatalf("got error %v, want the downstream 'no clients' wire error (gate should not have fired for an unprotected comm)", err)
	}
}

func TestContain_RestoreExemptFromProtectedPidGate(t *testing.T) {
	l, clientConn, cleanup := newListenerWithConn(t)
	defer cleanup()
	e := NewEnforcer(l, nil)

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.Contain(1, ipc.ContainmentNone, "restore pid 1 after a bad containment call")
	}()

	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	frame := make([]byte, length)
	if _, err := readFull(clientConn, frame); err != nil {
		t.Fatalf("reading frame: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Contain(pid=1, None) should be exempt from the gate, got error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Contain did not return in time")
	}
}

// --- Level 4 also SIGKILLs the process ---

// containAndDrain runs Contain on a connected listener and consumes the frame
// the sensor would receive, so the send completes.
func containAndDrain(t *testing.T, pid, level uint32) error {
	t.Helper()
	applied := ipc.ContainmentAckApplied
	return containAndDrainAck(t, pid, level, &applied)
}

// containAndDrainAck is containAndDrain with the fake sensor's reply chosen:
// nil means it never answers.
func containAndDrainAck(t *testing.T, pid, level uint32, ack *uint32) error {
	t.Helper()
	l, clientConn, cleanup := newListenerWithConn(t)
	defer cleanup()
	e := NewEnforcer(l, nil)

	errCh := make(chan error, 1)
	go func() { errCh <- e.Contain(pid, level, "test") }()

	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	if _, err := readFull(clientConn, make([]byte, length)); err != nil {
		t.Fatalf("reading frame: %v", err)
	}
	if ack != nil {
		e.OnContainmentAck(&ipc.ContainmentAckMsg{PID: pid, Level: level, Decision: *ack})
	}
	select {
	case err := <-errCh:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Contain did not return in time")
		return nil
	}
}

func TestContain_TerminateSendsSIGKILL(t *testing.T) {
	killed := stubKill(t, nil)
	if err := containAndDrain(t, 4321, ipc.ContainmentTerminate); err != nil {
		t.Fatalf("Contain(Terminate): %v", err)
	}
	if len(*killed) != 1 || (*killed)[0] != 4321 {
		t.Fatalf("killed = %v, want [4321]", *killed)
	}
}

func TestContain_NonTerminateLevelsDoNotKill(t *testing.T) {
	for _, level := range []uint32{ipc.ContainmentNone, ipc.ContainmentCgroup, ipc.ContainmentSeccomp, ipc.ContainmentNamespace} {
		killed := stubKill(t, nil)
		if err := containAndDrain(t, 4321, level); err != nil {
			t.Fatalf("Contain(level %d): %v", level, err)
		}
		if len(*killed) != 0 {
			t.Errorf("level %d killed %v, want no kill", level, *killed)
		}
	}
}

func TestContain_TerminateDoesNotKillWhenSendFails(t *testing.T) {
	killed := stubKill(t, nil)
	l, err := ipc.NewTestListener() // no sensor connected
	if err != nil {
		t.Fatalf("ipc.NewTestListener: %v", err)
	}
	if err := NewEnforcer(l, nil).Contain(4321, ipc.ContainmentTerminate, "test"); err == nil {
		t.Fatal("want the no-sensor error, got nil")
	}
	if len(*killed) != 0 {
		t.Fatalf("killed %v after a failed send, want none", *killed)
	}
}

func TestContain_TerminateAlreadyExitedIsNotAnError(t *testing.T) {
	stubKill(t, syscall.ESRCH)
	if err := containAndDrain(t, 4321, ipc.ContainmentTerminate); err != nil {
		t.Fatalf("ESRCH should count as success, got %v", err)
	}
}

func TestContain_TerminateKillFailureIsReported(t *testing.T) {
	stubKill(t, syscall.EPERM)
	err := containAndDrain(t, 4321, ipc.ContainmentTerminate)
	if err == nil || !strings.Contains(err.Error(), "SIGKILL") {
		t.Fatalf("got %v, want an error mentioning SIGKILL", err)
	}
}

// --- The Go-side gate stops the kill and the level-4 command ---

func TestContain_TerminateRefusedByGateSendsNothingAndKillsNothing(t *testing.T) {
	stubGateRefuses(t)
	l, clientConn, cleanup := newListenerWithConn(t)
	defer cleanup()
	e := NewEnforcer(l, nil)

	err := e.Contain(4321, ipc.ContainmentTerminate, "test")
	if err == nil || !strings.Contains(err.Error(), "CPM") {
		t.Fatalf("got %v, want a CPM refusal", err)
	}
	// Nothing may have been written to the sensor.
	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _ := clientConn.Read(make([]byte, 1)); n != 0 {
		t.Fatal("a refused TERMINATE still sent a containment frame to the sensor")
	}
}

func TestContain_GateDoesNotApplyToOtherLevels(t *testing.T) {
	stubGateRefuses(t) // would refuse any TERMINATE; other levels never call it
	if err := containAndDrain(t, 4321, ipc.ContainmentNamespace); err != nil {
		t.Fatalf("Contain(Namespace): %v", err)
	}
}

// --- The sensor's verdict decides whether the kill happens ---

func TestContain_SensorRefusalMeansNoKill(t *testing.T) {
	for _, d := range []uint32{
		ipc.ContainmentAckCPMProtectedExec,
		ipc.ContainmentAckCPMProtectedPID,
		ipc.ContainmentAckCWPPath,
		ipc.ContainmentAckCWPHash,
		ipc.ContainmentAckMapUpdateFailed,
		99, // unknown decisions are never read as "applied"
	} {
		killed := stubKill(t, nil)
		d := d
		err := containAndDrainAck(t, 4321, ipc.ContainmentTerminate, &d)
		if err == nil || !strings.Contains(err.Error(), "sensor refused") {
			t.Fatalf("decision %d: got %v, want a sensor refusal", d, err)
		}
		if len(*killed) != 0 {
			t.Fatalf("decision %d: killed %v although the sensor did not apply level 4", d, *killed)
		}
	}
}

func TestContain_NoAckMeansNoKillAndLocksOutThePid(t *testing.T) {
	killed := stubKill(t, nil)
	err := containAndDrainAck(t, 4321, ipc.ContainmentTerminate, nil)
	if err == nil || !strings.Contains(err.Error(), "did not acknowledge") {
		t.Fatalf("got %v, want a missing-ack error", err)
	}
	if len(*killed) != 0 {
		t.Fatalf("killed %v without an ack", *killed)
	}

	// A new request for the same pid is refused while the old one is unresolved,
	// so a late ack for the first cannot be taken as the answer to the second.
	l, _, cleanup := newListenerWithConn(t)
	defer cleanup()
	e := NewEnforcer(l, nil)
	e.acks.markUnresolved(4321)
	err = e.Contain(4321, ipc.ContainmentTerminate, "again")
	if err == nil || !strings.Contains(err.Error(), "never acknowledged") {
		t.Fatalf("got %v, want the unresolved-pid lockout", err)
	}
}

func TestContain_AckForAnotherPidIsIgnored(t *testing.T) {
	killed := stubKill(t, nil)
	l, clientConn, cleanup := newListenerWithConn(t)
	defer cleanup()
	e := NewEnforcer(l, nil)

	errCh := make(chan error, 1)
	go func() { errCh <- e.Contain(4321, ipc.ContainmentTerminate, "test") }()

	var length uint32
	if err := binary.Read(clientConn, binary.LittleEndian, &length); err != nil {
		t.Fatalf("reading length prefix: %v", err)
	}
	if _, err := readFull(clientConn, make([]byte, length)); err != nil {
		t.Fatalf("reading frame: %v", err)
	}
	e.OnContainmentAck(&ipc.ContainmentAckMsg{PID: 9999, Level: ipc.ContainmentTerminate, Decision: ipc.ContainmentAckApplied})
	e.OnContainmentAck(&ipc.ContainmentAckMsg{PID: 4321, Level: ipc.ContainmentNamespace, Decision: ipc.ContainmentAckApplied})

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("an ack for another pid/level was taken as the answer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Contain did not return in time")
	}
	if len(*killed) != 0 {
		t.Fatalf("killed %v on an unrelated ack", *killed)
	}
}

func TestContain_NonTerminateLevelsDoNotWaitForAcks(t *testing.T) {
	// No ack is ever sent; Namespace must still return promptly.
	start := time.Now()
	if err := containAndDrainAck(t, 4321, ipc.ContainmentNamespace, nil); err != nil {
		t.Fatalf("Contain(Namespace): %v", err)
	}
	if time.Since(start) >= ackTimeout {
		t.Fatal("non-terminate containment waited for an ack")
	}
}
