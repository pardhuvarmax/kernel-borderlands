// internal/ipc/sockets.go — canonical registry of every UDS path in kb.
// Do not hardcode these paths elsewhere; import from here.
package ipc
	
const (
	// SocketIPC — bound by kbd (Go). Binary telemetry pipe carrying raw
	// framed eBPF events from kbd_sensor (C) to the Go control plane.
	// NOT gRPC. Telemetry-only, one direction (sensor -> Go) — Go never
	// writes back on this connection. See Task 1.
	//
	// Containment/sensitive-path/rules pushes used to also go out over
	// this same connection (Go -> sensor) until they were split onto
	// SocketControl below: a burst of telemetry could fill this
	// connection's send buffer, get misread as a dead connection, and
	// take the containment-command path down as collateral damage even
	// though nothing was wrong with delivering containment commands.
	// See docs/development/core-control/control-plane-catalog.md §5.3.
	SocketIPC = "/run/kb/kbd.sock"

	// SocketControl — bound by kbd (Go). Every Go -> sensor control push:
	// containment commands (SendContainmentCmd), sensitive-path pushes,
	// and (if ever revived) the rules push. Split out from SocketIPC so a
	// telemetry-volume burst on the sensor -> Go direction can never
	// stall or kill delivery of containment commands — see SocketIPC's
	// comment above for why this split exists.
	SocketControl = "/run/kb/kbct.sock"

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