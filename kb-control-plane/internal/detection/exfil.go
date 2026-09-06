// Package detection implements the slow-data-exfiltration / beaconing
// detector from docs/development/control-aads/dev-exfiltration-detection.md
// — Shannon-entropy timing analysis (§3.A) and CUSUM volume-shift
// detection (§3.B), run out-of-band on the Go control plane per the
// doc's own recommendation ("to prevent adding CPU overhead to the Ring
// 0 sensor").
//
// FIDELITY LIMITATION, stated plainly: the doc's CUSUM example uses byte
// volume ("average output bytes per second") as x_i. kbd only receives a
// per-connection timestamp today (ipc.NetFlowMsg, from
// KB_WIRE_MSG_NET_FLOW — connect() events carry no payload-size field;
// real per-byte accounting would need new write()/sendto() syscall
// telemetry on the wire, which doesn't exist and is out of scope here).
// This implementation therefore runs CUSUM over CONNECTION FREQUENCY per
// fixed time bucket as the volume proxy instead of byte volume — it
// still catches the pattern §3.B describes (a persistent shift in a
// process's connection rate that stays under any single-sample spike
// threshold), just at connection-count granularity, not byte granularity.
package detection

import (
	"math"
	"sync"
)

// Tunable via NewDetector; defaults match dev-exfiltration-detection.md's
// worked example (§4: "entropy dips below 1.2").
const (
	DefaultEntropyThreshold  = 1.2
	DefaultBucketSeconds     = 60.0 // CUSUM sample bucket width
	DefaultCUSUMSigmaK       = 0.5  // K = sigma/2 (§3.B)
	DefaultCUSUMThresholdMul = 5.0  // flag at S_i > 5*sigma (§3.B: "4*sigma or 5*sigma")
	minIntervalSamples       = 10   // §3.A/blueprint: below this, entropy is unprofiled
	minBucketSamples         = 5    // don't judge CUSUM off a near-empty baseline
	maxIntervalWindow        = 100  // matches the doc's Go example's sliding window cap
)

// NetFlowWindow is the per-(pid,daddr,dport) sliding-window state — a
// direct port of dev-exfiltration-detection.md §4's Go example
// (LastTimestamp/Intervals/Push/CalculateTimingEntropy), extended with
// the bucketed-count CUSUM state needed for §3.B.
type NetFlowWindow struct {
	LastTimestamp uint64
	Intervals     []float64 // sliding window of delta seconds, matches the doc's example exactly

	bucketStartNs   uint64
	bucketCount     int
	baselineMean    float64
	baselineM2      float64 // Welford running variance accumulator
	baselineSamples int
	cusum           float64
}

// Push records one connect-event timestamp, matching the doc's
// Push(tsNs, size) signature in spirit — size is omitted because connect
// events carry no payload-size field (see package doc comment); frequency
// (one connection per Push call) is CUSUM's input instead.
func (w *NetFlowWindow) Push(tsNs uint64) {
	if w.LastTimestamp > 0 {
		deltaSec := float64(tsNs-w.LastTimestamp) / 1e9
		w.Intervals = append(w.Intervals, deltaSec)
		if len(w.Intervals) > maxIntervalWindow {
			w.Intervals = w.Intervals[1:]
		}
	}
	w.LastTimestamp = tsNs
	w.pushBucket(tsNs, DefaultBucketSeconds)
}

// CalculateTimingEntropy is dev-exfiltration-detection.md §3.A/§4's
// algorithm verbatim: bin transmission-interval deltas into
// [0-1s, 1-5s, 5-10s, 10-30s, >30s] and compute Shannon entropy over the
// bin distribution. Low entropy (-> 0) means high timing regularity — a
// rigid timer loop, i.e. a beacon. Returns 3.0 (high/"unprofiled") with
// fewer than minIntervalSamples deltas, same sentinel the doc's example
// uses.
func (w *NetFlowWindow) CalculateTimingEntropy() float64 {
	if len(w.Intervals) < minIntervalSamples {
		return 3.0
	}
	bins := make([]int, 5)
	for _, dt := range w.Intervals {
		switch {
		case dt <= 1.0:
			bins[0]++
		case dt <= 5.0:
			bins[1]++
		case dt <= 10.0:
			bins[2]++
		case dt <= 30.0:
			bins[3]++
		default:
			bins[4]++
		}
	}
	entropy := 0.0
	total := float64(len(w.Intervals))
	for _, count := range bins {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// pushBucket implements §3.B's CUSUM over fixed-width time buckets of
// connection count: S_i = max(0, S_{i-1} + (x_i - mu - K)). Baseline
// mean/variance are updated with Welford's online algorithm (numerically
// stable, no need to retain raw history) each time a bucket closes.
func (w *NetFlowWindow) pushBucket(tsNs uint64, bucketSeconds float64) {
	bucketNs := uint64(bucketSeconds * 1e9)
	if w.bucketStartNs == 0 {
		w.bucketStartNs = tsNs
	}
	if tsNs-w.bucketStartNs < bucketNs {
		w.bucketCount++
		return
	}
	// Bucket closed — fold its count into the baseline and CUSUM, then
	// start the next bucket counting this event.
	x := float64(w.bucketCount)
	w.baselineSamples++
	delta := x - w.baselineMean
	w.baselineMean += delta / float64(w.baselineSamples)
	w.baselineM2 += delta * (x - w.baselineMean)

	sigma := w.stddev()
	k := sigma * DefaultCUSUMSigmaK
	w.cusum = math.Max(0, w.cusum+(x-w.baselineMean-k))

	w.bucketStartNs = tsNs
	w.bucketCount = 1
}

func (w *NetFlowWindow) stddev() float64 {
	if w.baselineSamples < 2 {
		return 0
	}
	return math.Sqrt(w.baselineM2 / float64(w.baselineSamples-1))
}

// CUSUMExceeded reports whether the current cumulative deviation has
// crossed the §3.B threshold (H = k_sigma * sigma), and is only
// meaningful once a real baseline exists (minBucketSamples buckets
// closed) — before that, a persistent-shift verdict off near-zero
// history would be noise, not signal.
func (w *NetFlowWindow) CUSUMExceeded() bool {
	if w.baselineSamples < minBucketSamples {
		return false
	}
	sigma := w.stddev()
	if sigma == 0 {
		return false
	}
	return w.cusum > DefaultCUSUMThresholdMul*sigma
}

// flowKey groups connect events into a (pid, daddr, dport) stream, per
// dev-exfiltration-detection.md §3.A step 1.
type flowKey struct {
	pid   uint32
	daddr uint32
	dport uint16
}

// Detector holds one NetFlowWindow per (pid, daddr, dport) tuple observed
// — the "L1 Sliding Window Memory Cache" in the doc's §4 architecture
// diagram. Safe for concurrent use.
type Detector struct {
	mu               sync.Mutex
	windows          map[flowKey]*NetFlowWindow
	entropyThreshold float64
}

// NewDetector builds a Detector using dev-exfiltration-detection.md's
// documented default entropy threshold (1.2). entropyThreshold <= 0 uses
// the default.
func NewDetector(entropyThreshold float64) *Detector {
	if entropyThreshold <= 0 {
		entropyThreshold = DefaultEntropyThreshold
	}
	return &Detector{
		windows:          make(map[flowKey]*NetFlowWindow),
		entropyThreshold: entropyThreshold,
	}
}

// Result is what Observe reports back for a single connect event —
// enough for the caller (controlplane.go's OnNetFlow) to decide whether
// to raise an alert and/or act, without the detection package knowing
// anything about alerting/enforcement itself.
type Result struct {
	Entropy       float64
	CUSUMExceeded bool
	Beacon        bool // both signals agree: low-entropy timing AND a persistent frequency shift (§3.A + §3.B combined, see package doc comment)
	SampleCount   int
}

// Observe records one connect event and evaluates both detectors.
// Beacon is only true once BOTH signals independently indicate anomalous
// behavior — combining Shannon-entropy timing regularity with a CUSUM
// frequency-shift crossing cuts false positives either algorithm alone
// would produce (a single quiet cron job has low entropy but no volume
// shift; a single traffic spike has a CUSUM cross but normal-entropy
// timing).
func (d *Detector) Observe(pid, daddr uint32, dport uint16, tsNs uint64) Result {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := flowKey{pid: pid, daddr: daddr, dport: dport}
	w, ok := d.windows[key]
	if !ok {
		w = &NetFlowWindow{}
		d.windows[key] = w
	}
	w.Push(tsNs)

	entropy := w.CalculateTimingEntropy()
	cusumExceeded := w.CUSUMExceeded()
	return Result{
		Entropy:       entropy,
		CUSUMExceeded: cusumExceeded,
		Beacon:        entropy < d.entropyThreshold && cusumExceeded,
		SampleCount:   len(w.Intervals),
	}
}
