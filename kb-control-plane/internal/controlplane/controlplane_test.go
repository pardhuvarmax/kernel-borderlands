package controlplane

import "testing"

func TestClassifyZone(t *testing.T) {
	cp := &ControlPlane{cfg: DefaultConfig()}

	cases := []struct {
		score float64
		want  Zone
	}{
		{0, ZoneSafe},
		{39.9, ZoneSafe},
		{40, ZoneSuspicious},
		{74.9, ZoneSuspicious},
		{75, ZoneBorderlands},
		{100, ZoneBorderlands},
	}

	for _, c := range cases {
		if got := cp.classifyZone(c.score); got != c.want {
			t.Errorf("classifyZone(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestUpdateScoreEMA(t *testing.T) {
	cp := &ControlPlane{
		cfg:       DefaultConfig(),
		processes: make(map[uint32]*ProcessState),
	}

	// First sample seeds the state directly (no prior score to smooth against).
	first := cp.UpdateScore(1234, 50)
	if first != 50 {
		t.Fatalf("first UpdateScore = %.2f, want 50", first)
	}

	// Second sample should apply EMA with alpha = 0.3:
	// S_t = 0.3*90 + 0.7*50 = 62.0
	got := cp.UpdateScore(1234, 90)
	want := 0.3*90 + 0.7*50
	if got < want-0.0001 || got > want+0.0001 {
		t.Errorf("UpdateScore EMA = %.4f, want %.4f", got, want)
	}
}

func TestUpdateScoreTriggersZoneTransition(t *testing.T) {
	cp := &ControlPlane{
		cfg:       DefaultConfig(),
		processes: make(map[uint32]*ProcessState),
	}

	cp.UpdateScore(42, 10) // seeds at Safe
	cp.processes[42].Comm = "test-proc"

	// Push the score well past the Borderlands threshold (75) across a few
	// samples; with alpha=0.3 a single jump to 100 won't clear it, so we
	// iterate like a real event stream would.
	for i := 0; i < 10; i++ {
		cp.UpdateScore(42, 100)
	}

	cp.mu.RLock()
	zone := cp.processes[42].Zone
	cp.mu.RUnlock()

	if zone != ZoneBorderlands {
		t.Errorf("after sustained high scores, zone = %s, want %s", zone, ZoneBorderlands)
	}
}