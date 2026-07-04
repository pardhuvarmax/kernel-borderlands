package store

import (
	"testing"

	"github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/internal/ipc"
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