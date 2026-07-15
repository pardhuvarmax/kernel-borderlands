package controlplane

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// ═══════════════════════════════════════════════════════════════════
// Shared test fixtures
// ═══════════════════════════════════════════════════════════════════

// newTestControlPlane wires a real ControlPlane against an in-memory
// SQLite DB and no policy file (defaults only). This exercises the same
// New() path production uses — store.New, store.Restore, policy.New,
// audit.New, enforcement.New — just pointed at ":memory:" instead of a
// real file, and Start() is never called so no gRPC server or Unix
// socket listener spins up.
func newTestControlPlane(t *testing.T) *ControlPlane {
	t.Helper()
	cp, err := New(":memory:", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(cp.store.Close)
	return cp
}

// waitForCount polls until get() returns want, or fails after a timeout.
// Needed because Store's L2 writes (audit_log, zone_transitions) go
// through an async channel + background worker — asserting on them
// immediately after the triggering call would be racy.
func waitForCount(t *testing.T, get func() (int, error), want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last int
	var lastErr error
	for time.Now().Before(deadline) {
		n, err := get()
		if err == nil && n == want {
			return
		}
		last, lastErr = n, err
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for count=%d, last saw count=%d err=%v", want, last, lastErr)
}

func auditCount(t *testing.T, cp *ControlPlane) int {
	t.Helper()
	n, err := auditCountErr(cp)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	return n
}

func auditCountErr(cp *ControlPlane) (int, error) {
	var n int
	err := cp.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

// ═══════════════════════════════════════════════════════════════════
// OnProcessState / OnZoneTransition — scoring & PID-reuse guard
// ═══════════════════════════════════════════════════════════════════

func TestOnProcessStateUpdatesL1(t *testing.T) {
	cp := newTestControlPlane(t)

	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 100, PPID: 1, Comm: "nginx", StartTimeNs: 1000,
		EMAScore: 55.5, Zone: ipc.ZoneSuspicious,
	})

	cs, ok := cp.store.GetProcessState(100)
	if !ok {
		t.Fatal("expected L1 hit immediately after OnProcessState")
	}
	if cs.Zone != ipc.ZoneSuspicious || cs.EMAScore != 55.5 {
		t.Errorf("got zone=%v score=%.1f, want SUSPICIOUS/55.5", cs.Zone, cs.EMAScore)
	}

	// Comm cache (used to attach comm to later ZoneTransition messages,
	// which don't carry comm on the wire) should also be populated.
	if v, ok := cp.commCache.Load(uint32(100)); !ok || v.(string) != "nginx" {
		t.Errorf("commCache[100] = %v, %v; want \"nginx\", true", v, ok)
	}
}

func TestOnProcessExitFlushesCache(t *testing.T) {
	cp := newTestControlPlane(t)

	// Seed the process state
	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 100, PPID: 1, Comm: "nginx", StartTimeNs: 1000,
		EMAScore: 55.5, Zone: ipc.ZoneSuspicious,
	})

	// Verify L1 cache is populated
	_, ok := cp.store.GetProcessState(100)
	if !ok {
		t.Fatal("expected process to be tracked in L1")
	}
	if _, ok := cp.commCache.Load(uint32(100)); !ok {
		t.Fatal("expected process comm to be in commCache")
	}

	// Wait for the async L2 SQLite insert to complete
	waitForCount(t, func() (int, error) {
		var count int
		err := cp.store.DB().QueryRow("SELECT COUNT(*) FROM process_state WHERE pid = ?", 100).Scan(&count)
		return count, err
	}, 1)

	// Trigger process exit
	cp.OnProcessExit(&ipc.ProcessExitMsg{
		PID:        100,
		ExitTimeNs: 2000,
		ExitCode:   0,
	})

	// Verify it is flushed from L1 and commCache
	if _, ok := cp.store.GetProcessState(100); ok {
		t.Error("expected process to be evicted from L1 after exit")
	}
	if _, ok := cp.commCache.Load(uint32(100)); ok {
		t.Error("expected process comm to be removed from commCache after exit")
	}

	// Verify SQLite row is deleted synchronously
	var count int
	err := cp.store.DB().QueryRow("SELECT COUNT(*) FROM process_state WHERE pid = ?", 100).Scan(&count)
	if err != nil {
		t.Fatalf("querying SQLite: %v", err)
	}
	if count != 0 {
		t.Errorf("expected process row to be deleted from SQLite process_state table, got count %d", count)
	}
}

func TestOnZoneTransitionWithValidStartTimeRecordsAudit(t *testing.T) {
	cp := newTestControlPlane(t)

	// Seed L1 with a known start_time_ns, as a real ProcessState message
	// from kbd_sensor would before any ZoneTransition arrives for that pid.
	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 200, Comm: "bash", StartTimeNs: 5000, Zone: ipc.ZoneSafe,
	})

	beforeAudit := auditCount(t, cp)

	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{
		PID: 200, StartTimeNs: 5000, // matches — guard should pass
		FromZone: ipc.ZoneSafe, ToZone: ipc.ZoneSuspicious,
		Score: 47.3, TsNs: 6000,
	})

	waitForCount(t, func() (int, error) { return auditCountErr(cp) }, beforeAudit+1)

	waitForCount(t, func() (int, error) {
		var n int
		err := cp.store.DB().QueryRow(`SELECT COUNT(*) FROM zone_transitions WHERE pid=200`).Scan(&n)
		return n, err
	}, 1)
}

func TestOnZoneTransitionWithStalePIDSkipsEnforcementAndAudit(t *testing.T) {
	cp := newTestControlPlane(t)

	// Seed L1 with start_time_ns=5000 (the "real" process).
	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 300, Comm: "curl", StartTimeNs: 5000, Zone: ipc.ZoneSafe,
	})

	beforeAudit := auditCount(t, cp)

	// A ZoneTransition arrives claiming a *different* start_time_ns —
	// this is the PID-reuse case: pid 300 was reaped and reassigned to a
	// new process, but a stale event for the old process is still in
	// flight. Enforcement must NOT act on it.
	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{
		PID: 300, StartTimeNs: 9999, // mismatch
		FromZone: ipc.ZoneSuspicious, ToZone: ipc.ZoneBorderlands,
		Score: 90.0, TsNs: 6000,
	})

	// Give the (non-existent, since we return early) async write a moment
	// to have landed if the guard had incorrectly let it through.
	time.Sleep(100 * time.Millisecond)

	afterAudit := auditCount(t, cp)
	if afterAudit != beforeAudit {
		t.Errorf("audit_log grew from %d to %d on a stale-PID transition — guard did not block it",
			beforeAudit, afterAudit)
	}

	var ztCount int
	if err := cp.store.DB().QueryRow(`SELECT COUNT(*) FROM zone_transitions WHERE pid=300`).Scan(&ztCount); err != nil {
		t.Fatalf("query zone_transitions: %v", err)
	}
	if ztCount != 0 {
		t.Errorf("zone_transitions row inserted for pid=300 despite stale start_time_ns guard")
	}
}

func TestOnZoneTransitionUnknownPIDAllowsThrough(t *testing.T) {
	// A ZoneTransition for a pid we've never seen a ProcessState for (L1
	// miss, and nothing in L2 either) — VerifyStartTime returns an error
	// (sql.ErrNoRows), and the current design chooses to "fail open"
	// (allow) rather than block on an unverifiable guard. This test pins
	// that documented behavior so a future change to fail-closed is a
	// deliberate decision, not an accidental regression either way.
	cp := newTestControlPlane(t)
	before := auditCount(t, cp)

	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{
		PID: 400, StartTimeNs: 123,
		FromZone: ipc.ZoneSafe, ToZone: ipc.ZoneSuspicious,
		Score: 45.0, TsNs: 111,
	})

	waitForCount(t, func() (int, error) { return auditCountErr(cp) }, before+1)
}

// ═══════════════════════════════════════════════════════════════════
// Task 2 — gRPC health service, Group 1: protocol logic over bufconn
// (in-memory transport, no real socket/file involved).
// ═══════════════════════════════════════════════════════════════════

const bufSize = 1024 * 1024

// newBufconnHealthClient spins up a real *grpc.Server with only the
// health service registered via registerHealthService — the same helper
// Start() calls — served over bufconn instead of a real UDS path.
func newBufconnHealthClient(t *testing.T) (healthpb.HealthClient, *health.Server, func()) {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	hs := health.NewServer()
	registerHealthService(grpcServer, hs)

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	//nolint:staticcheck // DialContext is fine for bufconn test dialing
	conn, err := grpc.DialContext(ctx, "passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("failed to dial bufconn: %v", err)
	}

	cleanup := func() {
		conn.Close()
		grpcServer.GracefulStop()
		lis.Close()
	}

	return healthpb.NewHealthClient(conn), hs, cleanup
}

func TestHealthService_ReportsServingAfterRegister(t *testing.T) {
	client, _, cleanup := newBufconnHealthClient(t)
	defer cleanup()

	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: ServiceName,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("status = %v, want SERVING", resp.Status)
	}
}

func TestHealthService_FlipsToNotServingBeforeShutdown(t *testing.T) {
	client, hs, cleanup := newBufconnHealthClient(t)
	defer cleanup()

	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{Service: ServiceName})
	if err != nil {
		t.Fatalf("Check (pre): %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("precondition failed: status = %v, want SERVING", resp.Status)
	}

	// Mirrors the exact line Stop() runs before grpc.GracefulStop().
	hs.SetServingStatus(ServiceName, healthpb.HealthCheckResponse_NOT_SERVING)

	resp, err = client.Check(context.Background(), &healthpb.HealthCheckRequest{Service: ServiceName})
	if err != nil {
		t.Fatalf("Check (post): %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("status = %v, want NOT_SERVING", resp.Status)
	}
}

func TestHealthService_UnknownServiceNameErrors(t *testing.T) {
	client, _, cleanup := newBufconnHealthClient(t)
	defer cleanup()

	_, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "kb.SomeServiceThatWasNeverRegistered",
	})
	if err == nil {
		t.Fatal("expected an error for an unregistered service name, got nil")
	}
}

func TestHealthService_EmptyServiceNameChecksOverallServer(t *testing.T) {
	client, hs, cleanup := newBufconnHealthClient(t)
	defer cleanup()

	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("status = %v, want SERVING", resp.Status)
	}
}

// Regression guard: New() must construct healthServer exactly once, and
// Start() must reuse that same instance (not silently allocate a second
// health.Server, which was the original bug in this file).
func TestNewControlPlane_HealthServerIsSingleInstance(t *testing.T) {
	cp := newTestControlPlane(t)

	if cp.healthServer == nil {
		t.Fatal("expected New() to construct a non-nil healthServer")
	}

	before := cp.healthServer
	registerHealthService(grpc.NewServer(), cp.healthServer)

	if cp.healthServer != before {
		t.Error("healthServer instance changed after registration — New()/Start() likely re-created it")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Task 2 — gRPC health service, Group 2: real Unix domain socket
// behavior. Covers listenUnix() specifically — stale-file recovery and
// the 0660 permission requirement from the ownership table — which
// bufconn structurally cannot exercise.
// ═══════════════════════════════════════════════════════════════════

func TestGRPCHealthService_OverRealUnixSocket(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "kba-test.sock")

	lis, err := listenUnix(sockPath)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}

	grpcServer := grpc.NewServer()
	hs := health.NewServer()
	registerHealthService(grpcServer, hs)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.GracefulStop)

	// Confirm listenUnix actually set permissions per the ownership
	// table (root:root, 0660), not just that it bound successfully.
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Errorf("socket file mode = %o, want 0660", perm)
	}

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	//nolint:staticcheck // DialContext is fine for a test dial
	conn, err := grpc.DialContext(ctx, "passthrough:///unix-test",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial real unix socket: %v", err)
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: ServiceName,
	})
	if err != nil {
		t.Fatalf("Check over real UDS: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("status = %v, want SERVING", resp.Status)
	}
}

// Reproduces the exact failure mode that only exists for UDS, never TCP:
// a socket file left on disk by a previous (e.g. crashed) run. Without
// the os.Remove guard inside listenUnix, this fails with
// "address already in use" instead of recovering.
//
// We simulate the leftover file directly rather than binding a real
// listener and closing it — Go's net.UnixListener automatically unlinks
// its socket file on a graceful Close() (that's the default
// unlink-on-close behavior), which would just delete the very file we're
// trying to leave behind. A real crash never calls Close(), so the file
// survives; bind() fails with EADDRINUSE against any existing path
// regardless of whether it's a real socket, so a plain empty file
// reproduces the scenario without depending on listener internals.
func TestListenUnix_RemovesStaleSocketFile(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "stale.sock")

	if err := os.WriteFile(sockPath, nil, 0o660); err != nil {
		t.Fatalf("failed to create stale file fixture: %v", err)
	}

	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("precondition failed, stale file not present: %v", err)
	}

	lis, err := listenUnix(sockPath)
	if err != nil {
		t.Fatalf("listenUnix did not recover from stale socket file: %v", err)
	}
	lis.Close()
}

// Exercises listenUnix + registerHealthService together in the exact
// sequence Start() uses, over a real (temp) UDS path — catches the class
// of bug where the helpers exist but Start() doesn't actually call them
// in the right order.
func TestStartSequence_ListenThenRegisterOverUnixSocket(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "kba-sequence-test.sock")

	lis, err := listenUnix(sockPath)
	if err != nil {
		t.Fatalf("listenUnix: %v", err)
	}
	grpcServer := grpc.NewServer()
	hs := health.NewServer()
	registerHealthService(grpcServer, hs)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.GracefulStop)

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	//nolint:staticcheck
	conn, err := grpc.DialContext(ctx, "passthrough:///seq-test",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := healthpb.NewHealthClient(conn)
	resp, err := client.Check(context.Background(), &healthpb.HealthCheckRequest{Service: ServiceName})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("status = %v, want SERVING", resp.Status)
	}
}

// ═══════════════════════════════════════════════════════════════════
// recordStoreResult — consecutive-failure health safety net
// ═══════════════════════════════════════════════════════════════════

// TestRecordStoreResult_StaysHealthyBelowThreshold confirms isolated
// failures (fewer than storeFailureThreshold in a row) do NOT flip
// health status — this is the whole point of counting consecutive
// failures instead of reacting to every single error.
func TestRecordStoreResult_StaysHealthyBelowThreshold(t *testing.T) {
	cp := newTestControlPlane(t)
	dummyErr := fmt.Errorf("simulated transient write failure")

	for i := 0; i < storeFailureThreshold-1; i++ {
		cp.recordStoreResult(dummyErr)
	}

	if cp.storeUnhealthy {
		t.Fatalf("flipped unhealthy after %d failures, threshold is %d",
			storeFailureThreshold-1, storeFailureThreshold)
	}
}

// TestRecordStoreResult_FlipsAtThreshold confirms health status flips to
// NOT_SERVING (via onCriticalDependencyLost -> cp.healthServer) exactly
// when the Nth consecutive failure lands, not before.
func TestRecordStoreResult_FlipsAtThreshold(t *testing.T) {
	cp := newTestControlPlane(t)
	dummyErr := fmt.Errorf("simulated persistent write failure")

	for i := 0; i < storeFailureThreshold; i++ {
		cp.recordStoreResult(dummyErr)
	}

	if !cp.storeUnhealthy {
		t.Fatalf("did not flip unhealthy after %d consecutive failures", storeFailureThreshold)
	}

	resp, err := cp.healthServer.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: ServiceName,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Errorf("gRPC health status = %v, want NOT_SERVING after threshold breach", resp.Status)
	}
}

// TestRecordStoreResult_RecoversOnNextSuccess confirms a single success
// after crossing the failure threshold clears the unhealthy state and
// flips gRPC health back to SERVING — the documented asymmetric
// recovery behavior (fail-fast, recover-fast).
func TestRecordStoreResult_RecoversOnNextSuccess(t *testing.T) {
	cp := newTestControlPlane(t)
	dummyErr := fmt.Errorf("simulated persistent write failure")

	for i := 0; i < storeFailureThreshold; i++ {
		cp.recordStoreResult(dummyErr)
	}
	if !cp.storeUnhealthy {
		t.Fatal("precondition failed: expected unhealthy state before testing recovery")
	}

	cp.recordStoreResult(nil) // one success

	if cp.storeUnhealthy {
		t.Fatal("did not recover after a single success post-threshold")
	}
	if cp.storeFailureCount != 0 {
		t.Errorf("storeFailureCount = %d, want 0 after a success", cp.storeFailureCount)
	}

	resp, err := cp.healthServer.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: ServiceName,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("gRPC health status = %v, want SERVING after recovery", resp.Status)
	}
}

// TestRecordStoreResult_SuccessResetsCounterBelowThreshold confirms an
// intermittent success in the middle of a failure streak resets the
// consecutive counter, matching the documented "consecutive, not
// cumulative" semantics — fail, fail, succeed, fail, fail should never
// trip the threshold even though 4 total failures occurred.
func TestRecordStoreResult_SuccessResetsCounterBelowThreshold(t *testing.T) {
	cp := newTestControlPlane(t)
	dummyErr := fmt.Errorf("simulated intermittent failure")

	cp.recordStoreResult(dummyErr)
	cp.recordStoreResult(dummyErr)
	cp.recordStoreResult(nil) // resets streak
	cp.recordStoreResult(dummyErr)
	cp.recordStoreResult(dummyErr)

	if cp.storeUnhealthy {
		t.Fatal("flipped unhealthy despite the failure streak being broken by a success partway through")
	}
	if cp.storeFailureCount != 2 {
		t.Errorf("storeFailureCount = %d, want 2 (only counts since the last success)", cp.storeFailureCount)
	}
}

// TestRecordStoreResult_ConcurrentCallsDontRace exercises
// recordStoreResult from many goroutines simultaneously, mixing success
// and failure outcomes. This test's job is to fail under `go test -race`
// if the storeFailureMu guard is ever removed or bypassed — it
// intentionally does not assert a specific final state, since the
// interleaving of concurrent mixed outcomes is nondeterministic by
// design.
func TestRecordStoreResult_ConcurrentCallsDontRace(t *testing.T) {
	cp := newTestControlPlane(t)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if n%2 == 0 {
				cp.recordStoreResult(fmt.Errorf("simulated failure %d", n))
			} else {
				cp.recordStoreResult(nil)
			}
		}(i)
	}
	wg.Wait()
}