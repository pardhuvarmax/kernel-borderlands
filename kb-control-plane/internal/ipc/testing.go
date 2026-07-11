// internal/ipc/testing.go
package ipc

import "net"

// NewTestListener builds a Listener wired to the given connections, for use
// in tests outside the ipc package. Not for production use.
func NewTestListener(conns ...net.Conn) (*Listener, error) {
	m := make(map[net.Conn]bool, len(conns))
	for _, c := range conns {
		m[c] = true
	}
	return &Listener{conns: m}, nil
}