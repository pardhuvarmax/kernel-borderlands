package ipc

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// ackFrame builds the bytes kb_bridge.c sends: length prefix + packed
// kb_wire_containment_ack (hdr, pid, level, decision), little-endian.
func ackFrame(pid, level, decision uint32) []byte {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint16(payload[0:2], WireMagic)
	payload[2] = WireVersion
	payload[3] = MsgTypeContainmentAck
	binary.LittleEndian.PutUint32(payload[4:8], pid)
	binary.LittleEndian.PutUint32(payload[8:12], level)
	binary.LittleEndian.PutUint32(payload[12:16], decision)
	frame := make([]byte, 4, 20)
	binary.LittleEndian.PutUint32(frame, uint32(len(payload)))
	return append(frame, payload...)
}

func TestParseContainmentAck(t *testing.T) {
	msg, err := parseContainmentAck(ackFrame(4321, 4, ContainmentAckCPMProtectedExec)[4:])
	if err != nil {
		t.Fatal(err)
	}
	if msg.PID != 4321 || msg.Level != 4 || msg.Decision != ContainmentAckCPMProtectedExec {
		t.Fatalf("got %+v", msg)
	}
	if _, err := parseContainmentAck(make([]byte, 15)); err == nil {
		t.Fatal("a short frame must be rejected")
	}
}

type ackRecorder struct {
	noopHandler
	got chan *ContainmentAckMsg
}

func (a *ackRecorder) OnContainmentAck(m *ContainmentAckMsg) { a.got <- m }

type noopHandler struct{}

func (noopHandler) OnProcessState(*ProcessStateMsg)     {}
func (noopHandler) OnZoneTransition(*ZoneTransitionMsg) {}
func (noopHandler) OnProcessExit(*ProcessExitMsg)       {}
func (noopHandler) OnNetFlow(*NetFlowMsg)               {}

func TestReader_DispatchesContainmentAck(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	rec := &ackRecorder{got: make(chan *ContainmentAckMsg, 1)}
	go NewReader(server, rec).ReadLoop()

	if _, err := client.Write(ackFrame(77, 4, ContainmentAckApplied)); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-rec.got:
		if m.PID != 77 || m.Level != 4 || m.Decision != ContainmentAckApplied {
			t.Fatalf("got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ack was not dispatched")
	}
	client.Close()
}

// A handler without OnContainmentAck (every existing one) must keep working:
// the frame is skipped and the loop keeps reading.
func TestReader_HandlerWithoutAckSupportIgnoresAck(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	go NewReader(server, noopHandler{}).ReadLoop()
	if _, err := client.Write(ackFrame(77, 4, ContainmentAckApplied)); err != nil {
		t.Fatal(err)
	}
	client.Close()
}

func TestAckDecisionString_UnknownIsNotApplied(t *testing.T) {
	if AckDecisionString(99) == AckDecisionString(ContainmentAckApplied) {
		t.Fatal("unknown decision rendered as applied")
	}
}
