package controlplane

import (
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

// subscribeAlerts/waitForAlert give tests direct access to fanOutAlert's
// output without going through a real gRPC stream — same pattern as
// StreamAlerts (grpc.go) minus the network plumbing.
func subscribeAlerts(cp *ControlPlane) chan *pb.Alert {
	ch := make(chan *pb.Alert, 4)
	cp.alertMu.Lock()
	cp.alertSubs = append(cp.alertSubs, ch)
	cp.alertMu.Unlock()
	return ch
}

func waitForAlert(t *testing.T, ch chan *pb.Alert) *pb.Alert {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert")
		return nil
	}
}

func TestClassifySeverity(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{10, "LOW"}, {49.9, "LOW"},
		{50, "MEDIUM"}, {74.9, "MEDIUM"},
		{75, "HIGH"}, {89.9, "HIGH"},
		{90, "CRITICAL"}, {100, "CRITICAL"},
	}
	for _, c := range cases {
		if got := classifySeverity(c.score); got != c.want {
			t.Errorf("classifySeverity(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestEscalateSeverity(t *testing.T) {
	cases := map[string]string{
		"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL",
		"CRITICAL": "CRITICAL", // capped — nothing above it
	}
	for in, want := range cases {
		if got := escalateSeverity(in); got != want {
			t.Errorf("escalateSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindCWPMatch(t *testing.T) {
	registry := []ipc.CWPWorkloadEntry{
		{Path: "/usr/bin/postgres", PolicyID: 17, OwnerTeam: "data-platform", Justification: "OLTP database"},
	}

	m, ok := findCWPMatch(registry, "postgres")
	if !ok {
		t.Fatal("expected a match for comm=postgres")
	}
	if m.PolicyID != 17 || m.OwnerTeam != "data-platform" {
		t.Errorf("unexpected match: %+v", m)
	}

	if _, ok := findCWPMatch(registry, "nginx"); ok {
		t.Error("expected no match for an unregistered comm")
	}
	if _, ok := findCWPMatch(registry, ""); ok {
		t.Error("expected no match for empty comm")
	}
	if _, ok := findCWPMatch(nil, "postgres"); ok {
		t.Error("expected no match against an empty registry")
	}
}

// --- Integration: OnZoneTransition escalates severity for a CWP-protected workload ---

func TestOnZoneTransition_CWPProtectedWorkloadEscalatesSeverity(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.cwpRegistry = []ipc.CWPWorkloadEntry{
		{Path: "/usr/bin/postgres", PolicyID: 17, OwnerTeam: "data-platform", Justification: "OLTP database"},
	}

	sub := subscribeAlerts(cp)

	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 700, Comm: "postgres", StartTimeNs: 1000, Zone: ipc.ZoneSafe,
	})
	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{
		PID: 700, StartTimeNs: 1000,
		FromZone: ipc.ZoneSuspicious, ToZone: ipc.ZoneBorderlands,
		Score: 80.0, // HIGH before escalation
		TsNs:  2000,
	})

	alert := waitForAlert(t, sub)
	if !alert.ProtectedWorkload {
		t.Fatal("expected ProtectedWorkload=true")
	}
	if alert.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL (HIGH escalated one tier)", alert.Severity)
	}
	if alert.PolicyId != 17 || alert.OwnerTeam != "data-platform" {
		t.Errorf("unexpected metadata: policy_id=%d owner_team=%q", alert.PolicyId, alert.OwnerTeam)
	}
}

func TestOnZoneTransition_UnprotectedWorkloadNoEscalation(t *testing.T) {
	cp := newTestControlPlane(t)
	// cwpRegistry left empty — nothing protected.

	sub := subscribeAlerts(cp)

	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 701, Comm: "curl", StartTimeNs: 1000, Zone: ipc.ZoneSafe,
	})
	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{
		PID: 701, StartTimeNs: 1000,
		FromZone: ipc.ZoneSuspicious, ToZone: ipc.ZoneBorderlands,
		Score: 80.0,
		TsNs:  2000,
	})

	alert := waitForAlert(t, sub)
	if alert.ProtectedWorkload {
		t.Fatal("expected ProtectedWorkload=false for an unregistered comm")
	}
	if alert.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH (unescalated)", alert.Severity)
	}
}

// --- Integration: OnNetFlow raises an EXFIL_BEACON_SUSPECTED alert ---

func TestOnNetFlow_SustainedRigidBeaconRaisesAlert(t *testing.T) {
	cp := newTestControlPlane(t)
	sub := subscribeAlerts(cp)

	cp.OnProcessState(&ipc.ProcessStateMsg{
		PID: 900, Comm: "curl", StartTimeNs: 1000, Zone: ipc.ZoneSafe,
	})

	var ts uint64 = 1000
	const nsPerSec = 1e9
	// Baseline: low, rigid rate.
	for i := 0; i < 20; i++ {
		ts += 30 * nsPerSec
		cp.OnNetFlow(&ipc.NetFlowMsg{PID: 900, Daddr: 1, Dport: 443, TsNs: ts})
	}
	// Shift: same rigidity, much higher sustained frequency.
	for i := 0; i < 10; i++ {
		for j := 0; j < 40; j++ {
			ts += 1 * nsPerSec
			cp.OnNetFlow(&ipc.NetFlowMsg{PID: 900, Daddr: 1, Dport: 443, TsNs: ts})
		}
	}

	alert := waitForAlert(t, sub)
	if alert.AlertType != "EXFIL_BEACON_SUSPECTED" {
		t.Errorf("alert_type = %q, want EXFIL_BEACON_SUSPECTED", alert.AlertType)
	}
	if alert.Pid != 900 || alert.Comm != "curl" {
		t.Errorf("unexpected alert subject: pid=%d comm=%s", alert.Pid, alert.Comm)
	}
}

func TestOnNetFlow_NormalTrafficNeverAlerts(t *testing.T) {
	cp := newTestControlPlane(t)
	sub := subscribeAlerts(cp)

	var ts uint64 = 1000
	const nsPerSec = 1e9
	for i := 0; i < 50; i++ {
		ts += uint64((5 + i%37) * nsPerSec) // irregular intervals, never a rigid cadence
		cp.OnNetFlow(&ipc.NetFlowMsg{PID: 901, Daddr: 2, Dport: 443, TsNs: ts})
	}

	select {
	case a := <-sub:
		t.Fatalf("expected no alert for irregular traffic, got %+v", a)
	case <-time.After(100 * time.Millisecond):
		// expected: no alert
	}
}

func TestOnNetFlow_RepeatedBeaconDebounced(t *testing.T) {
	cp := newTestControlPlane(t)
	sub := subscribeAlerts(cp)

	var ts uint64 = 1000
	const nsPerSec = 1e9
	for i := 0; i < 20; i++ {
		ts += 30 * nsPerSec
		cp.OnNetFlow(&ipc.NetFlowMsg{PID: 902, Daddr: 3, Dport: 443, TsNs: ts})
	}
	// Push far more shift-phase events than the earlier alerting test —
	// every one of these, after the first, is still "still a beacon"
	// on the SAME flow and must not each re-alert.
	for i := 0; i < 20; i++ {
		for j := 0; j < 40; j++ {
			ts += 1 * nsPerSec
			cp.OnNetFlow(&ipc.NetFlowMsg{PID: 902, Daddr: 3, Dport: 443, TsNs: ts})
		}
	}

	waitForAlert(t, sub) // exactly one alert expected
	select {
	case a := <-sub:
		t.Fatalf("expected debouncing to suppress repeat alerts on the same flow within the window, got a second alert: %+v", a)
	case <-time.After(100 * time.Millisecond):
		// expected: no second alert
	}
}
