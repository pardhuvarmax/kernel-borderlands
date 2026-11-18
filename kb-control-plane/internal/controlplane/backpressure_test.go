package controlplane

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

// A subscriber that never reads loses events once its buffer is full; every loss is counted. Before this the discard
// had no counter and no log line (internal latency report, section 7.2).
func TestFanOutDropsAreCounted(t *testing.T) {
	cp := newTestControlPlane(t)
	evCh := make(chan *pb.KBEvent, 1)
	alCh := make(chan *pb.Alert, 1)
	cp.subMu.Lock()
	cp.eventSubs = append(cp.eventSubs, evCh)
	cp.subMu.Unlock()
	cp.alertMu.Lock()
	cp.alertSubs = append(cp.alertSubs, alCh)
	cp.alertMu.Unlock()

	for i := 0; i < 4; i++ {
		cp.fanOutEvent(&pb.KBEvent{Pid: uint32(i)})
	}
	for i := 0; i < 3; i++ {
		cp.fanOutAlert(&pb.Alert{Pid: uint32(i)})
	}
	ev, al := cp.FanoutDrops()
	if ev != 3 || al != 2 {
		t.Fatalf("drops = (events %d, alerts %d), want (3, 2): capacity 1 holds one of each", ev, al)
	}
}

// The warning is rate limited: a sustained overload logs once per interval, not once per dropped event.
func TestFanOutDropWarningIsRateLimited(t *testing.T) {
	cp := newTestControlPlane(t)
	ch := make(chan *pb.KBEvent) // unbuffered and unread: every send drops
	cp.subMu.Lock()
	cp.eventSubs = append(cp.eventSubs, ch)
	cp.subMu.Unlock()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(log.Writer()) })
	for i := 0; i < 500; i++ {
		cp.fanOutEvent(&pb.KBEvent{Pid: 1})
	}
	if n := strings.Count(buf.String(), "event feed subscriber buffer full"); n != 1 {
		t.Fatalf("warning logged %d times for 500 drops, want exactly 1 within the interval", n)
	}
	if ev, _ := cp.FanoutDrops(); ev != 500 {
		t.Fatalf("counted %d drops, want 500", ev)
	}
}

func zoneAuditCount(t *testing.T, cp *ControlPlane, action string) func() (int, error) {
	return func() (int, error) {
		var n int
		err := cp.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n)
		return n, err
	}
}

// A process whose first state is already above SAFE has no transition message to drive the audit, alert and
// containment path; kbd now runs it through the same handler.
func TestFirstSightFlaggedStateGoesThroughTheTransitionPath(t *testing.T) {
	cp := newTestControlPlane(t)
	ch := make(chan *pb.KBEvent, 16)
	cp.subMu.Lock()
	cp.eventSubs = append(cp.eventSubs, ch)
	cp.subMu.Unlock()

	cp.OnProcessState(&ipc.ProcessStateMsg{PID: 500, Comm: "injector", StartTimeNs: 1000, EMAScore: 60, Zone: ipc.ZoneBorderlands})

	waitForCount(t, zoneAuditCount(t, cp, "ZONE_SAFE_TO_BORDERLANDS"), 1)
	// containment is deferred for a synthesised transition: recorded, not applied
	waitForCount(t, zoneAuditCount(t, cp, "FIRST_SIGHT_CONTAINMENT_DEFERRED"), 1)
	if n, _ := zoneAuditCount(t, cp, "CGROUP_THROTTLE")(); n != 0 {
		t.Fatalf("containment was applied (%d CGROUP_THROTTLE audit rows) for a first-sight transition", n)
	}
	if _, first := cp.TransitionCounters(); first != 1 {
		t.Fatalf("first-sight transitions = %d, want 1", first)
	}
	var sawTransition bool
	for len(ch) > 0 {
		if e := <-ch; e.EventType == "zone_transition" && e.Metadata["to_zone"] == "BORDERLANDS" {
			sawTransition = true
		}
	}
	if !sawTransition {
		t.Fatal("no zone_transition event reached the feed for a first-sight BORDERLANDS process")
	}
}

// The common case: the sensor sends the transition and then the state. The state must not synthesise a duplicate.
func TestNoDuplicateTransitionWhenTheRealOneArrivesFirst(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{PID: 501, StartTimeNs: 2000, FromZone: ipc.ZoneSafe, ToZone: ipc.ZoneSuspicious, Score: 40, TsNs: 2100})
	cp.OnProcessState(&ipc.ProcessStateMsg{PID: 501, Comm: "tar", StartTimeNs: 2000, EMAScore: 40, Zone: ipc.ZoneSuspicious})

	waitForCount(t, zoneAuditCount(t, cp, "ZONE_SAFE_TO_SUSPICIOUS"), 1)
	time.Sleep(100 * time.Millisecond)
	n, _ := zoneAuditCount(t, cp, "ZONE_SAFE_TO_SUSPICIOUS")()
	if n != 1 {
		t.Fatalf("audit rows for the transition = %d, want exactly 1 (no duplicate)", n)
	}
	if _, first := cp.TransitionCounters(); first != 0 {
		t.Fatalf("first-sight transitions = %d, want 0 when the real transition was handled", first)
	}
}

// A known process that later changes zone gets its transition from the sensor, not from this fallback.
func TestKnownProcessIsNotGivenASyntheticTransition(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.OnProcessState(&ipc.ProcessStateMsg{PID: 502, Comm: "sh", StartTimeNs: 3000, Zone: ipc.ZoneSafe})
	cp.OnProcessState(&ipc.ProcessStateMsg{PID: 502, Comm: "sh", StartTimeNs: 3000, EMAScore: 30, Zone: ipc.ZoneSuspicious})
	time.Sleep(100 * time.Millisecond)
	if _, first := cp.TransitionCounters(); first != 0 {
		t.Fatalf("first-sight transitions = %d, want 0 for an already-known process", first)
	}
}

// The PID-reuse guard's drops are counted, not only logged through a rate-limited printer.
func TestStaleTransitionIsCounted(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.OnProcessState(&ipc.ProcessStateMsg{PID: 503, Comm: "curl", StartTimeNs: 5000, Zone: ipc.ZoneSafe})
	cp.OnZoneTransition(&ipc.ZoneTransitionMsg{PID: 503, StartTimeNs: 9999, FromZone: ipc.ZoneSafe, ToZone: ipc.ZoneSuspicious, Score: 50, TsNs: 6000})
	if stale, _ := cp.TransitionCounters(); stale != 1 {
		t.Fatalf("stale transitions skipped = %d, want 1", stale)
	}
}
