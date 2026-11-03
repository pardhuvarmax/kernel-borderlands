package ipc

import (
	"encoding/binary"
	"testing"
)

// 48 bytes, matching sizeof(struct kb_wire_process_counters) in kb_bridge.h.
func counterFrame() []byte {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint16(b[0:], WireMagic)
	b[2], b[3] = WireVersion, MsgTypeProcessCounters
	binary.LittleEndian.PutUint32(b[4:], 4242)
	binary.LittleEndian.PutUint64(b[8:], 111)
	binary.LittleEndian.PutUint64(b[16:], 222)
	binary.LittleEndian.PutUint32(b[24:], 3)   // sensitive_file_count
	binary.LittleEndian.PutUint32(b[28:], 2)   // cred_change_count
	binary.LittleEndian.PutUint32(b[32:], 0)   // bytes_sent_kib (reserved)
	binary.LittleEndian.PutUint32(b[36:], 9)   // dropped_events
	binary.LittleEndian.PutUint32(b[40:], 0x5) // seq_signature
	return b
}

func TestParseProcessCounters_RoundTrip(t *testing.T) {
	m, err := parseProcessCounters(counterFrame())
	if err != nil {
		t.Fatal(err)
	}
	want := ProcessCountersMsg{PID: 4242, StartTimeNs: 111, WindowEndNs: 222, SensitiveFileCount: 3,
		CredChangeCount: 2, BytesSentKiB: 0, DroppedEvents: 9, SeqSignature: 0x5}
	if *m != want {
		t.Fatalf("got %+v want %+v", *m, want)
	}
	if m.SeqSignature&SeqSigCredThenConnect == 0 || m.SeqSignature&SeqSigShellThenConnect != 0 ||
		m.SeqSignature&SeqSigConnectThenMemExec == 0 {
		t.Errorf("signature bits decoded wrongly: %#x", m.SeqSignature)
	}
}

// The parseNetFlow 22-vs-24 bug is why every short length is rejected here.
func TestParseProcessCounters_RejectsShortFrames(t *testing.T) {
	full := counterFrame()
	for n := 0; n < 48; n++ {
		if _, err := parseProcessCounters(full[:n]); err == nil {
			t.Fatalf("%d-byte frame must be rejected", n)
		}
	}
}
