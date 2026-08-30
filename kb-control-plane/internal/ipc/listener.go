package ipc

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

type Listener struct {
	path  string
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]bool
	Done  chan struct{}

	handler MessageHandler // set by NewListener; dispatched per-conn by ReadLoop

	sensitivePathsMu sync.Mutex
	sensitivePaths   []string // set via SetSensitivePaths, pushed to each newly-connected sensor

	rulesPathMu sync.Mutex
	rulesPath   string // set via SetRulesPath, pushed to each newly-connected sensor

	cwpWorkloadsMu sync.Mutex
	cwpWorkloads   []CWPWorkloadEntry // set via SetCWPWorkloads, pushed to each newly-connected sensor
}

// SetSensitivePaths updates the operator-supplied sensitive-path
// additions pushed to every sensor that connects from now on. It does
// not retroactively push to already-connected sensors — this feature is
// restart/reconnect-only by design, not a live reload.
func (l *Listener) SetSensitivePaths(paths []string) {
	l.sensitivePathsMu.Lock()
	defer l.sensitivePathsMu.Unlock()
	l.sensitivePaths = paths
}

func (l *Listener) getSensitivePaths() []string {
	l.sensitivePathsMu.Lock()
	defer l.sensitivePathsMu.Unlock()
	return l.sensitivePaths
}

// SetRulesPath configures the rules.yaml path pushed (as a compiled
// KB_WIRE_MSG_RULES payload, see SendRulesPayload) to every sensor that
// connects from now on. Empty means "don't push" — the sensor falls back
// to its compiled-in default rules, same as it does on any send failure.
// Same restart/reconnect-only scope as SetSensitivePaths, not a live reload.
func (l *Listener) SetRulesPath(path string) {
	l.rulesPathMu.Lock()
	defer l.rulesPathMu.Unlock()
	l.rulesPath = path
}

func (l *Listener) getRulesPath() string {
	l.rulesPathMu.Lock()
	defer l.rulesPathMu.Unlock()
	return l.rulesPath
}

// SetCWPWorkloads updates the operator-configured protected-workload
// registry (docs/features/CWP.md) pushed to every sensor that connects
// from now on. Unlike SetSensitivePaths/SetRulesPath, this is NOT
// restart/reconnect-only — the sensor polls for this continuously at
// runtime (non-blocking, see kbd_sensor.c's read_cwp_workloads_from_bridge),
// so BroadcastCWPWorkloads below can push a change to every
// already-connected sensor immediately, not just future connections.
func (l *Listener) SetCWPWorkloads(entries []CWPWorkloadEntry) {
	l.cwpWorkloadsMu.Lock()
	defer l.cwpWorkloadsMu.Unlock()
	l.cwpWorkloads = entries
}

func (l *Listener) getCWPWorkloads() []CWPWorkloadEntry {
	l.cwpWorkloadsMu.Lock()
	defer l.cwpWorkloadsMu.Unlock()
	return l.cwpWorkloads
}

// BroadcastCWPWorkloads pushes the current SetCWPWorkloads registry to
// every currently-connected sensor immediately — the live-reload path
// (e.g. the ReloadWorkloads RPC), as opposed to pushConnectTimeFrames
// which only covers new connections.
func (l *Listener) BroadcastCWPWorkloads() error {
	entries := l.getCWPWorkloads()
	if len(entries) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) == 0 {
		return fmt.Errorf("ipc: no connected sensors to receive CWP workloads")
	}
	var firstErr error
	for conn := range l.conns {
		if err := SendCWPWorkloads(conn, entries); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NewListener creates a Listener that will bind to path when Listen() is
// called. The handler is stored now so it can be passed to NewReader per
// connection without a separate setter call. The socket is NOT bound yet —
// that happens inside Listen() — so NewListener is safe to call in tests
// and during initialisation even when the socket directory does not yet
// exist. Callers pass GetSocketPath() or GetControlSocketPath() (or an
// explicit override) — see ControlPlane.New() for the two production
// instances (telemetry vs. control) this is used to build.
func NewListener(path string, h MessageHandler) (*Listener, error) {
	return &Listener{
		path:    path,
		conns:   make(map[net.Conn]bool),
		Done:    make(chan struct{}),
		handler: h,
	}, nil
}

// Listen binds the UDS socket (removing any stale file first) and runs the
// accept loop. For each new connection from the C sensor it:
//  1. Registers the conn under l.mu.
//  2. Spawns a goroutine that runs NewReader(conn, l.handler).ReadLoop().
//  3. When ReadLoop returns (conn closed or protocol error), removes the conn
//     from l.conns and closes it.
//
// Listen blocks until l.ln is closed (e.g. close(l.Done) triggers the
// goroutine below to close the listener) or until a non-temporary accept
// error occurs. It returns the first non-temporary error, or nil on clean
// shutdown.
func (l *Listener) Listen() error {
	// Remove a stale socket file if one exists from a previous run; net.Listen
	// will return "address already in use" otherwise even if nothing is bound.
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("ipc: removing stale socket %s: %w", l.path, err)
	}

	ln, err := net.Listen("unix", l.path)
	if err != nil {
		return fmt.Errorf("ipc: listen on %s: %w", l.path, err)
	}
	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()

	log.Printf("[IPC] Listening on %s", l.path)

	// Optionally honour l.Done: closing it signals Listen to stop accepting.
	go func() {
		if l.Done == nil {
			return
		}
		<-l.Done
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// If Done was closed (graceful shutdown), treat as clean exit.
			select {
			case <-l.Done:
				return nil
			default:
			}
			// net.Error with Temporary() == true: transient; keep looping.
			if ne, ok := err.(net.Error); ok && ne.Temporary() { //nolint:staticcheck
				log.Printf("[IPC] transient accept error: %v — retrying", err)
				continue
			}
			// Permanent error (listener closed, etc.): stop.
			return fmt.Errorf("ipc: accept: %w", err)
		}

		l.mu.Lock()
		l.conns[conn] = true
		l.mu.Unlock()

		log.Printf("[IPC] sensor connected: %v", conn.RemoteAddr())
		l.pushConnectTimeFrames(conn)

		go func(c net.Conn) {
			defer func() {
				l.mu.Lock()
				delete(l.conns, c)
				l.mu.Unlock()
				c.Close()
				log.Printf("[IPC] sensor disconnected: %v", c.RemoteAddr())
			}()
			if err := NewReader(c, l.handler).ReadLoop(); err != nil {
				log.Printf("[IPC] ReadLoop error: %v", err)
			}
		}(conn)
	}
}

// pushConnectTimeFrames sends the operator-configured sensitive-paths and
// dynamic-rules payloads to a newly-connected sensor, if configured.
// Extracted from Listen()'s accept loop so it's unit-testable against a
// net.Pipe() without binding a real socket. Both pushes are best-effort —
// a failure here is logged, not fatal, since the sensor already tolerates
// a missing/malformed push by falling back to its compiled-in defaults.
func (l *Listener) pushConnectTimeFrames(conn net.Conn) {
	// Order matters and is NOT interchangeable: kbd_sensor.c's connect-time
	// handshake calls read_rules_from_bridge() first, then
	// read_sensitive_paths_from_bridge() second. Only the second call has a
	// stash-based fallback for "the other frame arrived instead" — the
	// first is a blind length-prefixed read with no such recovery. Since a
	// single writer's sequential Write() calls on one stream socket are
	// delivered in that same order, rules MUST be sent before sensitive
	// paths, or the rules frame is left unconsumed in the socket and
	// corrupts the connection's later framing (containment commands are
	// read off the same fd afterward). See kbd_sensor.c's main() for the
	// call order this depends on.
	//
	// Dynamic rules push (docs/development/core-control/dynamic-rules.md)
	// — previously compiled by SendRulesPayload but never called from
	// production code; the sensor already reads for this at connect time
	// and falls back to its compiled-in default rules on any failure
	// here, so a missing/unreadable rules.yaml is logged, not fatal.
	if rp := l.getRulesPath(); rp != "" {
		if err := SendRulesPayload(conn, rp); err != nil {
			log.Printf("[IPC] failed to send dynamic rules to sensor: %v", err)
		}
	}

	if sp := l.getSensitivePaths(); len(sp) > 0 {
		if err := SendSensitivePaths(conn, sp); err != nil {
			log.Printf("[IPC] failed to send sensitive paths to sensor: %v", err)
		}
	}

	// CWP workload registry (docs/features/CWP.md) — no ordering constraint
	// with the two pushes above: the sensor reads this via a separate,
	// non-blocking poll loop (read_cwp_workloads_from_bridge), not the
	// blocking connect-time handshake read_rules_from_bridge/
	// read_sensitive_paths_from_bridge share. Pushed at connect time too
	// (in addition to BroadcastCWPWorkloads' live path) so a
	// newly-(re)connected sensor doesn't have to wait for the next live
	// reload to pick up the current registry.
	if wl := l.getCWPWorkloads(); len(wl) > 0 {
		if err := SendCWPWorkloads(conn, wl); err != nil {
			log.Printf("[IPC] failed to send CWP workloads to sensor: %v", err)
		}
	}
}

// SendContainmentCmd frames and writes a containment command to every
// currently-connected C sensor client.
func (l *Listener) SendContainmentCmd(pid uint32, level uint32, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.conns) == 0 {
		return fmt.Errorf("ipc: no connected sensors to receive containment cmd")
	}

	// Truncate defensively — copy() would silently truncate anyway, but an
	// explicit check makes the behavior obvious in logs.
	if len(reason) > 64 {
		reason = reason[:64]
	}
	var reasonBytes [64]byte
	copy(reasonBytes[:], []byte(reason))

	payload := ContainmentCmdMsg{PID: pid, Level: level, Reason: reasonBytes}

	var header [headerSize]byte
	binary.LittleEndian.PutUint16(header[0:2], MsgMagic)
	header[2] = WireVersion
	header[3] = MsgTypeContainmentCmd

	length := uint32(headerSize + cmdPayloadSize)

	var deadConns []net.Conn
	for conn := range l.conns {
		if err := binary.Write(conn, binary.LittleEndian, length); err != nil {
			log.Printf("[IPC] length-prefix write failed, dropping conn: %v", err)
			deadConns = append(deadConns, conn)
			continue
		}
		if _, err := conn.Write(header[:]); err != nil {
			log.Printf("[IPC] header write failed, dropping conn: %v", err)
			deadConns = append(deadConns, conn)
			continue
		}
		if err := binary.Write(conn, binary.LittleEndian, payload); err != nil {
			log.Printf("[IPC] payload write failed, dropping conn: %v", err)
			deadConns = append(deadConns, conn)
			continue
		}
	}

	// Prune connections that failed mid-loop so future sends don't retry them.
	for _, c := range deadConns {
		delete(l.conns, c)
		c.Close()
	}

	return nil
}
