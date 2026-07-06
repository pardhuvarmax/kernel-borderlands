package ipc

import (
    "log"
    "net"
    "os"
)

type Listener struct{ handler MessageHandler }

func NewListener(h MessageHandler) *Listener { return &Listener{h} }

func (l *Listener) Listen() error {
    sock := GetSocketPath()
    os.Remove(sock)
    ln, err := net.Listen("unix", sock)
    if err != nil { return err }
    defer ln.Close()
    os.Chmod(sock, 0600)
    log.Printf("[IPC] Listening on %s (wire v%d)", sock, WireVersion)

    for {
        conn, err := ln.Accept()
        if err != nil { log.Printf("[IPC] accept: %v", err); continue }
        log.Printf("[IPC] kbd_sensor connected")
        go l.handle(conn)
    }
}

func (l *Listener) handle(conn net.Conn) {
	defer func() { conn.Close(); log.Printf("[IPC] kbd_sensor disconnected") }()

	if err := SendRulesPayload(conn, "config/rules.yaml"); err != nil {
		log.Printf("[IPC] failed to send rules payload: %v", err)
	}

	if err := NewReader(conn, l.handler).ReadLoop(); err != nil {
		log.Printf("[IPC] read: %v", err)
	}
}