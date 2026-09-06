package detection

import (
	"math"
	"testing"
)

const nsPerSec = 1e9

func TestCalculateTimingEntropy_TooFewSamplesReturnsSentinel(t *testing.T) {
	w := &NetFlowWindow{}
	w.Push(1 * nsPerSec)
	w.Push(2 * nsPerSec)
	if got := w.CalculateTimingEntropy(); got != 3.0 {
		t.Errorf("got %v, want sentinel 3.0 with < minIntervalSamples deltas", got)
	}
}

func TestCalculateTimingEntropy_RigidBeaconIsLowEntropy(t *testing.T) {
	w := &NetFlowWindow{}
	var ts uint64
	for i := 0; i < 20; i++ {
		ts += 10 * nsPerSec // exact 10s intervals every time -> all in one bin -> entropy 0
		w.Push(ts)
	}
	got := w.CalculateTimingEntropy()
	if got > 0.01 {
		t.Errorf("rigid 10s-interval beacon: entropy = %v, want ~0", got)
	}
}

func TestCalculateTimingEntropy_VariedTrafficIsHighEntropy(t *testing.T) {
	w := &NetFlowWindow{}
	// Deltas spread across all 5 bins roughly evenly.
	deltas := []float64{0.5, 3, 7, 20, 45}
	var ts uint64
	for i := 0; i < 25; i++ {
		ts += uint64(deltas[i%len(deltas)] * nsPerSec)
		w.Push(ts)
	}
	got := w.CalculateTimingEntropy()
	if got < 2.0 {
		t.Errorf("evenly spread deltas across 5 bins: entropy = %v, want close to log2(5)=%.3f", got, math.Log2(5))
	}
}

func TestCUSUM_StablyLowVolumeNeverExceeds(t *testing.T) {
	w := &NetFlowWindow{}
	var ts uint64
	// One connection per 90s bucket (bucket width is 60s), steady rate.
	for i := 0; i < 30; i++ {
		ts += 90 * nsPerSec
		w.Push(ts)
	}
	if w.CUSUMExceeded() {
		t.Error("steady low-rate traffic should never cross the CUSUM threshold")
	}
}

func TestCUSUM_SustainedVolumeShiftExceeds(t *testing.T) {
	w := &NetFlowWindow{}
	var ts uint64
	// Baseline: ~1 connection per bucket for a while.
	for i := 0; i < 15; i++ {
		ts += DefaultBucketSeconds * nsPerSec
		w.Push(ts)
	}
	// Sustained shift: many connections per bucket, repeated over several buckets.
	for i := 0; i < 10; i++ {
		bucketStart := ts
		for j := 0; j < 50; j++ {
			ts += 1 * nsPerSec // 50 conns crammed into one bucket
			w.Push(ts)
		}
		// Ensure the bucket actually rolls over before the next round.
		if ts-bucketStart < uint64(DefaultBucketSeconds*nsPerSec) {
			ts = bucketStart + uint64(DefaultBucketSeconds*nsPerSec) + 1
			w.Push(ts)
		}
	}
	if !w.CUSUMExceeded() {
		t.Error("a sustained large volume shift should cross the CUSUM threshold")
	}
}

func TestDetector_ObserveGroupsByFlowKey(t *testing.T) {
	d := NewDetector(0)
	var ts uint64 = 1000
	r1 := d.Observe(1, 100, 443, ts)
	ts += 5 * nsPerSec
	r2 := d.Observe(1, 200, 443, ts) // different daddr -> different window, no shared history
	if r1.SampleCount != 0 || r2.SampleCount != 0 {
		t.Errorf("first observation of a new flow should have 0 prior samples: r1=%d r2=%d", r1.SampleCount, r2.SampleCount)
	}
}

func TestDetector_BeaconRequiresBothSignals(t *testing.T) {
	d := NewDetector(1.2)
	var ts uint64
	var last Result

	// Baseline: a rigid but low-frequency cadence (one connection per
	// 30s bucket) for long enough to establish CUSUM's baseline mean.
	for i := 0; i < 20; i++ {
		ts += 30 * nsPerSec
		last = d.Observe(42, 999, 53, ts)
	}
	if last.CUSUMExceeded {
		t.Fatalf("baseline-only traffic should not exceed CUSUM yet")
	}

	// Shift: same rigid regularity, but much higher frequency, sustained
	// across many buckets — a persistent volume shift CUSUM should catch,
	// while entropy stays low throughout (intervals are still constant).
	for i := 0; i < 10; i++ {
		for j := 0; j < 40; j++ {
			ts += 1 * nsPerSec
			last = d.Observe(42, 999, 53, ts)
		}
	}
	if !last.Beacon {
		t.Errorf("expected a rigid-cadence stream with a sustained frequency shift to be flagged as a beacon: entropy=%.3f cusum=%v", last.Entropy, last.CUSUMExceeded)
	}
}
