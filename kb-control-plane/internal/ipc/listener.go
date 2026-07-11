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
}

// NewListener creates a Listener that will bind to the UDS path from
// GetSocketPath() when Listen() is called. The handler is stored now so it
// can be passed to NewReader per connection without a separate setter call.
// The socket is NOT bound yet — that happens inside Listen() — so NewListener
// is safe to call in tests and during initialisation even when the socket
// directory does not yet exist.
func NewListener(h MessageHandler) (*Listener, error) {
	return &Listener{
		path:    GetSocketPath(),
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