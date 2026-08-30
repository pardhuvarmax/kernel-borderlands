package store

import (
	"testing"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

func newTestStore(t *testing.T) *Store {
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestUpsertAndGetProcessState(t *testing.T) {
	s := newTestStore(t)
	msg := &ipc.ProcessStateMsg{PID: 42, Comm: "bash", StartTimeNs: 100, EMAScore: 81.2, Zone: ipc.ZoneBorderlands}
	if err := s.UpsertProcessState(msg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	cs, ok := s.GetProcessState(42)
	if !ok {
		t.Fatal("expected L1 hit immediately after upsert")
	}
	if cs.Zone != ipc.ZoneBorderlands || cs.EMAScore != 81.2 {
		t.Errorf("got zone=%v score=%.1f, want BORDERLANDS/81.2", cs.Zone, cs.EMAScore)
	}
}

func TestVerifyStartTimeGuardsAgainstPIDReuse(t *testing.T) {
	s := newTestStore(t)
	s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 7, StartTimeNs: 1000})

	ok, err := s.VerifyStartTime(7, 1000)
	if err != nil || !ok {
		t.Errorf("VerifyStartTime(matching) = %v, %v; want true, nil", ok, err)
	}

	ok, err = s.VerifyStartTime(7, 9999) // different start_time_ns = reused PID
	if err != nil || ok {
		t.Errorf("VerifyStartTime(mismatched) = %v, %v; want false, nil", ok, err)
	}
}

func TestRemoveProcessEvictsFromL1(t *testing.T) {
	s := newTestStore(t)
	s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 5, Comm: "x"})
	s.RemoveProcess(5)
	if _, ok := s.GetProcessState(5); ok {
		t.Error("expected L1 miss after RemoveProcess")
	}
}

func TestSetZoneUpdatesTrackedProcess(t *testing.T) {
	s := newTestStore(t)
	s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 9, Comm: "y", Zone: ipc.ZoneSafe})

	if ok := s.SetZone(9, int32(ipc.ZoneBorderlands)); !ok {
		t.Fatal("SetZone on tracked pid should return true")
	}
	cs, ok := s.GetProcessState(9)
	if !ok {
		t.Fatal("expected L1 hit after SetZone")
	}
	if cs.Zone != ipc.ZoneBorderlands {
		t.Errorf("got zone=%v, want BORDERLANDS", cs.Zone)
	}
}

func TestSetZoneUntrackedPidReturnsFalse(t *testing.T) {
	s := newTestStore(t)
	if ok := s.SetZone(404, int32(ipc.ZoneSuspicious)); ok {
		t.Error("SetZone on untracked pid should return false")
	}
}

// BUG-002 regression: a routine telemetry-driven UpsertProcessState used to
// build a brand-new CachedState literal with no Containment field, silently
// resetting an actively-contained process back to NONE on the very next
// ProcessState message from kb-core.
func TestUpsertProcessStatePreservesContainment(t *testing.T) {
	s := newTestStore(t)
	s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 11, Comm: "evil", Zone: ipc.ZoneBorderlands})
	s.SetContainment(11, int32(3))

	cs, ok := s.GetProcessState(11)
	if !ok || cs.Containment != 3 {
		t.Fatalf("setup: got containment=%v ok=%v, want 3/true", cs, ok)
	}

	// A routine telemetry update for the same pid must not clobber it.
	if err := s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 11, Comm: "evil", Zone: ipc.ZoneBorderlands, EventCount: 42}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	cs, ok = s.GetProcessState(11)
	if !ok {
		t.Fatal("expected L1 hit after second upsert")
	}
	if cs.Containment != 3 {
		t.Errorf("got containment=%d after routine telemetry update, want 3 (preserved)", cs.Containment)
	}
	if cs.EventCount != 42 {
		t.Errorf("got event_count=%d, want 42 (other fields must still update normally)", cs.EventCount)
	}
}

// A never-before-seen PID has no prior Containment to preserve — should
// default to NONE (0), not error or panic.
func TestUpsertProcessStateNewPidDefaultsToNoContainment(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertProcessState(&ipc.ProcessStateMsg{PID: 99, Comm: "fresh"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	cs, ok := s.GetProcessState(99)
	if !ok {
		t.Fatal("expected L1 hit after upsert")
	}
	if cs.Containment != 0 {
		t.Errorf("got containment=%d for never-before-seen pid, want 0", cs.Containment)
	}
}