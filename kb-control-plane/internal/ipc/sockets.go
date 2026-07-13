// internal/ipc/sockets.go — canonical registry of every UDS path in kb.
// Do not hardcode these paths elsewhere; import from here.
package ipc
	
const (
	// SocketIPC — bound by kbd (Go). Binary telemetry pipe carrying raw
	// framed eBPF events from kbd_sensor (C) to the Go control plane.
	// NOT gRPC. See Task 1.
	SocketIPC = "/run/kb/kbd.sock"

	// SocketGRPC — bound by kbd (Go). General-purpose gRPC socket:
	// client registrations, enforcer/containment directives (the main
	// KernelBorderlandsServer API), AND the standard grpc_health_v1
	// service registered on the same server. See Task 2.
	SocketGRPC = "/run/kb/kba.sock"

	// SocketCheckerDiag — bound by kb-checker (Rust), NOT kbd. Serves
	// aggregated health/diagnostic reporting to TUIs/CLIs. Go code only
	// ever DIALS this as a client (e.g. from kb-tui, if diagnostics are
	// surfaced there) — never binds it.
	SocketCheckerDiag = "/run/kb/kbc.sock"

	// CheckerPIDFile — owned/written by kb-checker (Rust) to prevent
	// duplicate instances. Go does not read or write this file under
	// the current design.
	CheckerPIDFile = "/run/kb/kb-checker.pid"
)