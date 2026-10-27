package enforcement

import (
	"fmt"
	"sync"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// The sensor answers every containment command with a CONTAINMENT_ACK
// (wire-protocol.md, msg_type 10) saying what its CPM/CWP gates and the
// contained_pids_map write did. Contain waits for it before a TERMINATE may
// SIGKILL: "the frame was written" says nothing about whether the sensor
// accepted the command.
//
// Acks are matched on (pid, level) because the command frame carries no
// sequence number. A timed-out request could therefore be answered late and
// mistaken for the answer to a newer one, so a pid whose request went
// unanswered is locked out for ackStaleWindow; by then the sensor, which
// handles commands in order, has either answered or is not answering.

var (
	// ackTimeout is how long Contain waits for the sensor's reply. A
	// variable so tests can shorten it.
	ackTimeout = 3 * time.Second
	// ackStaleWindow is how long a pid stays locked out after an unanswered
	// TERMINATE.
	ackStaleWindow = 30 * time.Second
)

type ackKey struct{ pid, level uint32 }

type ackTracker struct {
	mu         sync.Mutex
	waiters    map[ackKey][]chan uint32
	unresolved map[uint32]time.Time // pid -> locked out until
}

func newAckTracker() *ackTracker {
	return &ackTracker{
		waiters:    map[ackKey][]chan uint32{},
		unresolved: map[uint32]time.Time{},
	}
}

// expect registers a waiter for the ack to (pid, level). It must be called
// before the command is sent, or a fast ack could be missed. The returned
// cancel removes the waiter and is safe to call after an ack arrived.
func (t *ackTracker) expect(pid, level uint32) (<-chan uint32, func(), error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if until, ok := t.unresolved[pid]; ok {
		if time.Now().Before(until) {
			return nil, nil, fmt.Errorf("enforcement: refusing to terminate pid %d: an earlier request for it was never acknowledged by the sensor (retry after %s)", pid, until.Sub(time.Now()).Round(time.Second))
		}
		delete(t.unresolved, pid)
	}
	key := ackKey{pid, level}
	ch := make(chan uint32, 1)
	t.waiters[key] = append(t.waiters[key], ch)
	cancel := func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		ws := t.waiters[key]
		for i, w := range ws {
			if w == ch {
				t.waiters[key] = append(ws[:i], ws[i+1:]...)
				break
			}
		}
		if len(t.waiters[key]) == 0 {
			delete(t.waiters, key)
		}
	}
	return ch, cancel, nil
}

// deliver hands an ack to every waiter for (pid, level) and reports whether
// there was one.
func (t *ackTracker) deliver(msg *ipc.ContainmentAckMsg) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := ackKey{msg.PID, msg.Level}
	ws := t.waiters[key]
	for _, w := range ws {
		w <- msg.Decision // buffered, one send per waiter
	}
	delete(t.waiters, key)
	return len(ws) > 0
}

func (t *ackTracker) markUnresolved(pid uint32) {
	t.mu.Lock()
	t.unresolved[pid] = time.Now().Add(ackStaleWindow)
	t.mu.Unlock()
}

// OnContainmentAck receives the sensor's reply to a containment command. It
// reports whether a Contain call was waiting for it.
func (e *Enforcer) OnContainmentAck(msg *ipc.ContainmentAckMsg) bool {
	return e.acks.deliver(msg)
}
