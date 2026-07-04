package ipc

import (
	"encoding/binary"
	"math"
	"testing"
)

func f64(v float64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, math.Float64bits(v))
	return b
}
func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// buildProcessStateFrame constructs a byte buffer matching the real
// kb_bridge.c v3 ProcessState layout (128 bytes total, header included).
// This mirrors sizeof(kb_wire_process_state) — if that C struct's layout
// ever changes, this test (and parseProcessState) both need updating
// together, which is the point: a silent drift between the two is exactly
// the 128-vs-130 class of bug this test exists to catch automatically.
func buildProcessStateFrame(pid, ppid, uid uint32, comm string, startNs, lastNs uint64,
	dims [DimCount]float64, composite, ema, entropy float64, zone KBZone, eventCount uint32) []byte {

	var b []byte
	b = append(b, 0x42, 0x4B)             // magic, LE: 0x4B42
	b = append(b, WireVersion, WireMsgProcessState)
	b = append(b, u32(pid)...)
	b = append(b, u32(ppid)...)
	b = append(b, u32(uid)...)

	commBuf := make([]byte, 16)
	copy(commBuf, comm) // zero-padded; parseProcessState trims at first NUL
	b = append(b, commBuf...)

	b = append(b, u64(startNs)...)
	b = append(b, u64(lastNs)...)
	for _, d := range dims {
		b = append(b, f64(d)...)
	}
	b = append(b, f64(composite)...)
	b = append(b, f64(ema)...)
	b = append(b, f64(entropy)...)
	b = append(b, u32(uint32(zone))...)
	b = append(b, u32(eventCount)...)
	return b
}

func buildZoneTransitionFrame(pid uint32, startNs uint64, from, to KBZone, score float64, tsNs uint64) []byte {
	var b []byte
	b = append(b, 0x42, 0x4B)
	b = append(b, WireVersion, WireMsgZoneTransition)
	b = append(b, u32(pid)...)
	b = append(b, u64(startNs)...)
	b = append(b, u32(uint32(from))...)
	b = append(b, u32(uint32(to))...)
	b = append(b, f64(score)...)
	b = append(b, u64(tsNs)...)
	return b
}

func TestProcessStateFrameIsExactly128Bytes(t *testing.T) {
	frame := buildProcessStateFrame(1, 1, 0, "x", 0, 0,
		[DimCount]float64{}, 0, 0, 0, ZoneSafe, 0)
	if len(frame) != 128 {
		t.Fatalf("constructed frame is %d bytes, want 128 — the wire layout assumption has drifted", len(frame))
	}
}

func TestZoneTransitionFrameIsExactly40Bytes(t *testing.T) {
	frame := buildZoneTransitionFrame(1, 0, ZoneSafe, ZoneSuspicious, 0, 0)
	if len(frame) != 40 {
		t.Fatalf("constructed frame is %d bytes, want 40 — the wire layout assumption has drifted", len(frame))
	}
}

func TestParseProcessStateRoundTrip(t *testing.T) {
	dims := [DimCount]float64{5.0, 12.5, 80.0, 5.0, 15.0, 90.0}
	frame := buildProcessStateFrame(
		5678, 1234, 1000, "bash", 111_000_000_000, 222_000_000_000,
		dims, 61.75, 58.3, 2.1, ZoneBorderlands, 42,
	)

	msg, err := parseProcessState(frame)
	if err != nil {
		t.Fatalf("parseProcessState: %v", err)
	}

	if msg.PID != 5678 || msg.PPID != 1234 || msg.UID != 1000 {
		t.Errorf("pid/ppid/uid = %d/%d/%d, want 5678/1234/1000", msg.PID, msg.PPID, msg.UID)
	}
	if msg.Comm != "bash" {
		t.Errorf("comm = %q, want \"bash\" (null-termination trimming failed)", msg.Comm)
	}
	if msg.StartTimeNs != 111_000_000_000 || msg.LastUpdatedNs != 222_000_000_000 {
		t.Errorf("start/last = %d/%d, want 111e9/222e9", msg.StartTimeNs, msg.LastUpdatedNs)
	}
	for i := range dims {
		if msg.DimScore[i] != dims[i] {
			t.Errorf("DimScore[%d] (%s) = %v, want %v", i, DimNames[i], msg.DimScore[i], dims[i])
		}
	}
	if msg.CompositeScore != 61.75 || msg.EMAScore != 58.3 || msg.SyscallEntropyLifetime != 2.1 {
		t.Errorf("composite/ema/entropy = %v/%v/%v, want 61.75/58.3/2.1",
			msg.CompositeScore, msg.EMAScore, msg.SyscallEntropyLifetime)
	}
	if msg.Zone != ZoneBorderlands {
		t.Errorf("zone = %v, want BORDERLANDS", msg.Zone)
	}
	if msg.EventCount != 42 {
		t.Errorf("event_count = %d, want 42", msg.EventCount)
	}
}

func TestParseProcessStateRejectsShortBuffer(t *testing.T) {
	frame := buildProcessStateFrame(1, 1, 0, "x", 0, 0, [DimCount]float64{}, 0, 0, 0, ZoneSafe, 0)
	short := frame[:len(frame)-1] // one byte short of 128
	if _, err := parseProcessState(short); err == nil {
		t.Error("expected error for truncated ProcessState frame, got nil")
	}
}

func TestParseZoneTransitionRoundTrip(t *testing.T) {
	frame := buildZoneTransitionFrame(5678, 111_000_000_000, ZoneSuspicious, ZoneBorderlands, 81.2, 333_000_000_000)

	msg, err := parseZoneTransition(frame)
	if err != nil {
		t.Fatalf("parseZoneTransition: %v", err)
	}

	if msg.PID != 5678 {
		t.Errorf("pid = %d, want 5678", msg.PID)
	}
	if msg.StartTimeNs != 111_000_000_000 {
		t.Errorf("start_time_ns = %d, want 111e9", msg.StartTimeNs)
	}
	if msg.FromZone != ZoneSuspicious || msg.ToZone != ZoneBorderlands {
		t.Errorf("from/to = %v/%v, want SUSPICIOUS/BORDERLANDS", msg.FromZone, msg.ToZone)
	}
	if msg.Score != 81.2 {
		t.Errorf("score = %v, want 81.2", msg.Score)
	}
	if msg.TsNs != 333_000_000_000 {
		t.Errorf("ts_ns = %d, want 333e9", msg.TsNs)
	}
}

func TestParseZoneTransitionRejectsShortBuffer(t *testing.T) {
	frame := buildZoneTransitionFrame(1, 0, ZoneSafe, ZoneSuspicious, 0, 0)
	short := frame[:len(frame)-1] // one byte short of 40
	if _, err := parseZoneTransition(short); err == nil {
		t.Error("expected error for truncated ZoneTransition frame, got nil")
	}
}

func TestKBZoneStringNames(t *testing.T) {
	cases := map[KBZone]string{
		ZoneSafe: "SAFE", ZoneSuspicious: "SUSPICIOUS", ZoneBorderlands: "BORDERLANDS",
		KBZone(99): "UNKNOWN",
	}
	for zone, want := range cases {
		if got := zone.String(); got != want {
			t.Errorf("KBZone(%d).String() = %q, want %q", zone, got, want)
		}
	}
}