package controlplane

import (
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

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