package controlplane

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/audit"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/enforcement"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/policy"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// ServiceName is the gRPC health-checking service name kbd registers
// itself under. kb-checker (Rust) must query this exact string when
// dialing /run/kb/kba.sock.
const ServiceName = "kernel-borderlands"

// storeFailureThreshold is the number of CONSECUTIVE store-write failures
// required before health status flips to NOT_SERVING. Isolated failures
// (lock contention, brief disk pressure) are expected occasionally under
// load and should not page anyone — only a real trend should.
const storeFailureThreshold = 5

type ControlPlane struct {
	pb.UnimplementedKernelBorderlandsServer
	store        *store.Store
	healthServer *health.Server
	audit        *audit.Logger
	enforcer     *enforcement.Enforcer
	policyMu      sync.RWMutex
	policy        *policy.Engine
	policyPath    string
	workloadsPath string // docs/features/CWP.md — config/workloads.yaml by convention
	grpc          *grpc.Server
	// grpcSocketPath is set once in Start() (from --grpc-socket/KB_GRPC_SOCKET)
	// and read by the HTTP API's /api/services health probe — a single
	// source of truth so that flag and the dashboard's connectivity check
	// can't drift apart (§2.7).
	grpcSocketPath string
	// telemetryListener (SocketIPC, kbd.sock) and controlListener
	// (SocketControl, kbct.sock) are both created once in New() and
	// started in Start(). Split so a telemetry-volume burst on the
	// sensor -> Go direction can never stall or kill delivery of
	// containment commands (Go -> sensor) — see SocketIPC's comment in
	// internal/ipc/sockets.go for the failure mode this avoids.
	telemetryListener *ipc.Listener
	controlListener   *ipc.Listener

	// comm cache — pid → comm (populated by ProcessState messages)
	commCache sync.Map

	// event fan-out
	subMu     sync.Mutex
	eventSubs []chan *pb.KBEvent

	alertMu   sync.Mutex
	alertSubs []chan *pb.Alert

	// Live metrics tracking
	metricMu        sync.Mutex
	eventTimestamps []time.Time

	// Store-write health tracking — see recordStoreResult. Guards
	// storeFailureCount/storeUnhealthy since OnProcessState can be
	// called concurrently across multiple sensor connections.
	storeFailureMu    sync.Mutex
	storeFailureCount int
	storeUnhealthy    bool

	// Per-agent-ID minimum-interval throttle for SubmitAgentDecision/
	// SetContainment (BUG-012) — a buggy or compromised client looping on
	// these RPCs previously had no backpressure at all.
	rateLimitMu   sync.Mutex
	lastDecision  map[string]time.Time
}

// rulesPath points at rules.yaml (docs/development/core-control/
// dynamic-rules.md) — pass "" to disable the dynamic-rules push entirely
// (sensor uses its compiled-in default rules, same as any push failure).
// workloadsPath points at workloads.yaml (docs/features/CWP.md) — pass ""
// to disable CWP entirely. Unlike policyPath, a missing or invalid
// workloads file is never fatal to daemon startup (same posture as
// policy.New's own missing-file handling) — it's logged and CWP simply
// has nothing registered until a valid file exists and ReloadWorkloads
// (or a restart) picks it up.
func New(dbPath, policyPath, rulesPath, workloadsPath string) (*ControlPlane, error) {
	s, err := store.New(dbPath)
	if err != nil {
		return nil, err
	}

	// ADR-1 cold-start recovery: L1 is volatile (in-process memory), so on
	// every fresh start we rebuild it from the last durable L2 (SQLite)
	// state *before* the eBPF ingestion hook goes live. Without this, a
	// restart would make VerifyStartTime miss on every already-tracked PID
	// until a fresh ProcessState message arrived for it.
	if err := s.Restore(); err != nil {
		log.Printf("[KB] L1 restore failed: %v — starting with empty cache", err)
	}

	p, err := policy.New(policyPath)
	if err != nil {
		return nil, err
	}

	// Build cp first (handler must exist before NewListener so it can be
	// passed as the MessageHandler), then wire the enforcer to the listener.
	cp := &ControlPlane{
		store:         s,
		audit:         audit.New(s.DB()),
		policy:        p,
		policyPath:    policyPath,
		workloadsPath: workloadsPath,
		healthServer:  health.NewServer(),
		lastDecision:  make(map[string]time.Time),
	}

	// NewListener records the socket path and stores cp as the MessageHandler.
	// The UDS socket is NOT bound here — binding happens inside Listen(), which
	// is called by Start(). This keeps New() safe to call in test environments
	// where /run/kb/ may not exist.
	//
	// Two listeners: telemetryListener (kbd.sock) only ever receives from
	// the sensor via cp's MessageHandler methods below; controlListener
	// (kbct.sock) is the one actually used to push containment commands
	// and sensitive-path additions out to the sensor. cp is registered as
	// the MessageHandler on both, but controlListener's ReadLoop will just
	// block on reads since the sensor never writes anything back on that
	// connection — same idle-until-close behavior telemetryListener
	// already tolerates today, just on the other side.
	telemetryListener, err := ipc.NewListener(ipc.GetSocketPath(), cp)
	if err != nil {
		return nil, fmt.Errorf("ipc telemetry listener: %w", err)
	}
	cp.telemetryListener = telemetryListener

	controlListener, err := ipc.NewListener(ipc.GetControlSocketPath(), cp)
	if err != nil {
		return nil, fmt.Errorf("ipc control listener: %w", err)
	}
	cp.controlListener = controlListener
	controlListener.SetSensitivePaths(p.SensitivePaths())
	controlListener.SetRulesPath(rulesPath)
	controlListener.SetCWPWorkloads(loadWorkloadsOrEmpty(workloadsPath))

	// Enforcer routes containment commands to the C sensor via the control listener.
	cp.enforcer = enforcement.NewEnforcer(controlListener, s)

	return cp, nil
}

// Start begins serving. httpAddr and grpcSocketPath come from cmd/kbd's
// --http-addr/--grpc-socket cobra flags (§2.7) — callers that want the old
// env-var-only behavior can still compute these from KB_HTTP_BIND/
// KB_GRPC_SOCKET before calling Start, same as cmd/kbd's flag defaults do.
func (cp *ControlPlane) Start(httpAddr, grpcSocketPath string) error {
	// SSH is no longer served in-process (see docs/development/core-control/
	// control-plane-catalog.md §2.11) — remote operator access to kb-tui now
	// goes through a real, OS-managed sshd instance with ForceCommand
	// exec'ing /usr/local/bin/kb-tui directly, entirely outside kbd's
	// process tree. See deploy/systemd/sshd@kb-operator.service and
	// deploy/ssh/sshd_config.d/kb-operator.conf.

	// Use the listeners constructed in New() — do NOT call NewListener again.
	go func() {
		if err := cp.telemetryListener.Listen(); err != nil {
			log.Fatalf("[KB] IPC telemetry: %v", err)
		}
	}()
	go func() {
		if err := cp.controlListener.Listen(); err != nil {
			log.Fatalf("[KB] IPC control: %v", err)
		}
	}()

	if grpcSocketPath == "" {
		grpcSocketPath = ipc.SocketGRPC
	}
	cp.grpcSocketPath = grpcSocketPath
	lis, err := listenUnix(grpcSocketPath)
	if err != nil {
		return fmt.Errorf("grpc uds listen: %w", err)
	}

	cp.grpc = grpc.NewServer()
	registerHealthService(cp.grpc, cp.healthServer)
	pb.RegisterKernelBorderlandsServer(cp.grpc, cp)

	go func() {
		log.Println("[KB] gRPC on unix://" + grpcSocketPath)
		if err := cp.grpc.Serve(lis); err != nil {
			log.Printf("[KB] grpc Serve exited: %v", err)
		}
	}()

	// Start HTTP API & SSE server for web dashboard. Loopback-only by
	// default (BUG-001) — remote dashboard access requires explicitly
	// opting in via --http-addr/KB_HTTP_BIND, e.g. "0.0.0.0:8080".
	if httpAddr == "" {
		httpAddr = "127.0.0.1:8080"
	}
	go func() {
		if err := cp.StartHTTPServer(httpAddr); err != nil {
			log.Printf("[KB] HTTP server failed: %v", err)
		}
	}()

	// One-shot startup tamper check: if the audit chain was already broken
	// before kbd came up (e.g. rows edited/deleted directly in SQLite),
	// operators need to know immediately — but a possibly-already-broken
	// audit trail shouldn't stop the daemon from doing its job, so this
	// is a loud warning, not log.Fatal.
	if ok, count, err := cp.audit.VerifyChain(); ok {
		log.Printf("[KB] audit log hash chain verified intact (%d entries)", count)
	} else {
		log.Printf("[KB] WARNING: audit log hash chain is BROKEN (verified %d entries before break: %v) — audit_log may have been tampered with", count, err)
	}

	log.Println("[KB] Control plane ready")
	return nil
}

// reloadPolicyFromDisk re-reads policy.yaml from the path kbd was started
// with, builds a fresh policy.Engine, and atomically swaps it in under
// policyMu. Also re-pushes the (possibly changed) sensitive_paths list to
// the sensor over kbct.sock, mirroring what New() does on first load.
// Called from the ReloadPolicy gRPC handler (grpc.go).
func (cp *ControlPlane) reloadPolicyFromDisk() (bool, string, error) {
	p, err := policy.New(cp.policyPath)
	if err != nil {
		return false, "", fmt.Errorf("reload policy: %w", err)
	}

	cp.policyMu.Lock()
	cp.policy = p
	cp.policyMu.Unlock()

	if cp.controlListener != nil {
		cp.controlListener.SetSensitivePaths(p.SensitivePaths())
	}

	msg := fmt.Sprintf("reloaded policy from %s", cp.policyPath)
	log.Printf("[KB] %s", msg)
	return true, msg, nil
}

// loadWorkloadsOrEmpty reads workloadsPath (docs/features/CWP.md) and
// returns its entries, or nil if the path is empty, the file doesn't
// exist, or it fails to parse — CWP is opt-in and a missing/bad config
// file is never fatal to daemon startup, same posture as policy.New's own
// missing-file handling.
func loadWorkloadsOrEmpty(workloadsPath string) []ipc.CWPWorkloadEntry {
	if workloadsPath == "" {
		return nil
	}
	entries, err := ipc.LoadWorkloadsYAML(workloadsPath)
	if err != nil {
		log.Printf("[KB] CWP: no workloads loaded from %s: %v", workloadsPath, err)
		return nil
	}
	log.Printf("[KB] CWP: loaded %d protected workload(s) from %s", len(entries), workloadsPath)
	return entries
}

// reloadWorkloadsFromDisk re-reads workloads.yaml and broadcasts the
// result to every currently-connected sensor — see ipc.Listener's
// BroadcastCWPWorkloads for why this is a genuinely live push, unlike
// reloadPolicyFromDisk above. Called from the ReloadWorkloads gRPC
// handler (grpc.go).
func (cp *ControlPlane) reloadWorkloadsFromDisk() (int, string, error) {
	if cp.workloadsPath == "" {
		return 0, "", fmt.Errorf("no --workloads path configured")
	}
	entries, err := ipc.LoadWorkloadsYAML(cp.workloadsPath)
	if err != nil {
		return 0, "", fmt.Errorf("reload workloads: %w", err)
	}
	if cp.controlListener != nil {
		cp.controlListener.SetCWPWorkloads(entries)
		if err := cp.controlListener.BroadcastCWPWorkloads(); err != nil {
			// Not fatal to the reload itself — the registry is updated
			// for future connections either way (pushConnectTimeFrames);
			// this only means no sensor is connected right now to push to
			// live, or the push to at least one failed.
			log.Printf("[KB] CWP: broadcast to connected sensors failed: %v", err)
		}
	}
	msg := fmt.Sprintf("reloaded %d workload(s) from %s", len(entries), cp.workloadsPath)
	log.Printf("[KB] %s", msg)
	return len(entries), msg, nil
}

// Stop shuts down the daemon. grpcSocketPath must match whatever was passed
// to Start (same §2.7 flag-threading as Start) so the stale-socket cleanup
// below removes the right file.
func (cp *ControlPlane) Stop(grpcSocketPath string) {
	// Flip to NOT_SERVING *before* tearing anything else down, so any
	// in-flight health probe from kb-checker gets an honest answer
	// instead of a connection-refused/hang.
	if cp.healthServer != nil {
		cp.healthServer.SetServingStatus(ServiceName, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	cp.grpc.GracefulStop()
	if grpcSocketPath == "" {
		grpcSocketPath = ipc.SocketGRPC
	}
	os.Remove(grpcSocketPath) // best-effort cleanup so next start doesn't hit a stale file
	cp.store.Close()
	// Signal both IPC accept loops to stop.
	if cp.telemetryListener != nil {
		close(cp.telemetryListener.Done)
	}
	if cp.controlListener != nil {
		close(cp.controlListener.Done)
	}
}

// listenUnix binds a UDS listener at path, clearing any stale socket file
// left behind by a previous run, and sets 0660 permissions per the
// ownership table (root:root, group-readable/writable for kb-checker).
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket %s: %w", path, err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		lis.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return lis, nil
}

// registerHealthService wires the standard gRPC health-checking protocol
// onto an existing server pair and marks it SERVING. Extracted so it can
// be exercised in tests without binding a real socket.
func registerHealthService(grpcServer *grpc.Server, hs *health.Server) {
	healthpb.RegisterHealthServer(grpcServer, hs)
	hs.SetServingStatus(ServiceName, healthpb.HealthCheckResponse_SERVING)
	log.Printf("[KB] gRPC health service registered, status=SERVING for %q", ServiceName)
}

// onCriticalDependencyLost flips health status to NOT_SERVING immediately
// when something the control plane depends on to function correctly goes
// down — e.g. the last connected sensor drops off the IPC socket, or a
// store write starts failing. This gives kb-checker an honest signal
// right away instead of waiting until Stop() is called, which only
// covers deliberate shutdown, not degraded-but-still-running states.
func (cp *ControlPlane) onCriticalDependencyLost(reason string) {
	log.Printf("[KB] critical dependency lost, marking NOT_SERVING: %s", reason)
	cp.healthServer.SetServingStatus(ServiceName, healthpb.HealthCheckResponse_NOT_SERVING)
}

// onDependencyRecovered flips health status back to SERVING once a
// previously-lost dependency (see onCriticalDependencyLost) is confirmed
// healthy again.
func (cp *ControlPlane) onDependencyRecovered() {
	cp.healthServer.SetServingStatus(ServiceName, healthpb.HealthCheckResponse_SERVING)
}

// recordStoreResult tracks CONSECUTIVE store-write outcomes and flips
// gRPC health status only when a real trend emerges, not on isolated
// failures. Call this after every store write on the hot path (currently
// just OnProcessState's UpsertProcessState call).
//
// Recovery is intentionally simple for now: a single success after
// crossing the failure threshold clears the unhealthy state immediately
// (asymmetric — fail-fast at storeFailureThreshold, recover-fast at 1).
// This errs on the safe side (staying NOT_SERVING slightly longer than
// strictly necessary) rather than requiring a separate, more complex
// consecutive-success counter. Revisit if this proves too twitchy in
// practice — start simple, tune from real failure data.
func (cp *ControlPlane) recordStoreResult(err error) {
	cp.storeFailureMu.Lock()
	defer cp.storeFailureMu.Unlock()

	if err != nil {
		cp.storeFailureCount++
		if cp.storeFailureCount == storeFailureThreshold && !cp.storeUnhealthy {
			cp.storeUnhealthy = true
			cp.onCriticalDependencyLost(fmt.Sprintf(
				"store: %d consecutive write failures, last error: %v",
				cp.storeFailureCount, err))
		}
		return
	}

	cp.storeFailureCount = 0
	if cp.storeUnhealthy {
		cp.storeUnhealthy = false
		cp.onDependencyRecovered()
	}
}

// ── MessageHandler (called by IPC listener) ──

func (cp *ControlPlane) OnProcessState(msg *ipc.ProcessStateMsg) {
	cp.recordEventTime()
	cp.commCache.Store(msg.PID, msg.Comm)

	err := cp.store.UpsertProcessState(msg)
	if err != nil {
		log.Printf("[KB] store: %v", err)
	}
	cp.recordStoreResult(err)

	cp.fanOutEvent(&pb.KBEvent{
		Pid:        msg.PID,
		Ppid:       msg.PPID,
		Comm:       msg.Comm,
		EventType:  "process_state",
		ScoreDelta: float32(msg.EMAScore),
		Timestamp:  int64(msg.LastUpdatedNs),
		Metadata: map[string]string{
			"zone":          ipc.KBZone(msg.Zone).String(),
			"composite":     fmt.Sprintf("%.2f", msg.CompositeScore),
			"dim_syscall":   fmt.Sprintf("%.2f", msg.DimScore[ipc.DimCount-5]),
			"dim_privilege": fmt.Sprintf("%.2f", msg.DimScore[2]),
			"uid":           fmt.Sprintf("%d", msg.UID),
		},
	})
}

func (cp *ControlPlane) OnProcessExit(msg *ipc.ProcessExitMsg) {
	// Delete volatile cache entries to prevent PID reuse vulnerabilities
	cp.commCache.Delete(msg.PID)

	// Push exit details to L2 DB
	if err := cp.store.TerminateProcessState(msg.PID, msg.ExitTimeNs, msg.ExitCode); err != nil {
		log.Printf("[KB] store term: %v", err)
	}
	log.Printf("[KB] Process PID=%d terminated (Code: %d)", msg.PID, msg.ExitCode)
}

func (cp *ControlPlane) OnZoneTransition(msg *ipc.ZoneTransitionMsg) {
	cp.recordEventTime()
	comm := ""
	if v, ok := cp.commCache.Load(msg.PID); ok {
		comm = v.(string)
	}

	log.Printf("[KB] Zone PID=%d COMM=%s %s→%s score=%.1f",
		msg.PID, comm, msg.FromZone, msg.ToZone, msg.Score)

	// PID-reuse guard — L1-backed, ~30-50ns per ADR-1.
	ok, err := cp.store.VerifyStartTime(msg.PID, msg.StartTimeNs)
	if err != nil {
		log.Printf("[KB] start_time verify: %v — allowing", err)
	} else if !ok {
		log.Printf("[KB] PID=%d start_time mismatch — stale transition, skipping enforcement", msg.PID)
		return
	}

	cp.store.InsertZoneTransition(msg, comm)
	cp.audit.LogZoneTransition(msg, comm)

	if msg.ToZone == ipc.ZoneBorderlands {
		alert := &pb.Alert{
			AlertId:    fmt.Sprintf("alert-%d-%d", msg.PID, msg.TsNs),
			AlertType:  "BORDERLANDS_ENTRY",
			Pid:        msg.PID,
			Comm:       comm,
			Confidence: float32(msg.Score / 100.0),
			Severity:   "CRITICAL",
			Timestamp:  int64(msg.TsNs),
			Evidence: []string{
				fmt.Sprintf("ema_score=%.1f", msg.Score),
				fmt.Sprintf("from=%s", msg.FromZone),
			},
		}
		cp.fanOutAlert(alert)

		cp.policyMu.RLock()
		autoTerminate := cp.policy.AutoTerminate(comm)
		cp.policyMu.RUnlock()
		if autoTerminate {
			cp.enforcer.Contain(msg.PID, uint32(pb.ContainmentLevel_TERMINATE), "policy:auto_terminate=true")
			cp.audit.Log("AUTO_TERMINATE",
				fmt.Sprintf("pid=%d comm=%s", msg.PID, comm),
				"SYSTEM_AUTO", "policy:auto_terminate=true")
		} else {
			cp.enforcer.Contain(msg.PID, uint32(pb.ContainmentLevel_CGROUP), "zone=BORDERLANDS")
			cp.audit.Log("CGROUP_THROTTLE",
				fmt.Sprintf("pid=%d comm=%s", msg.PID, comm),
				"SYSTEM_AUTO", "zone=BORDERLANDS")
		}
	}

	cp.fanOutEvent(&pb.KBEvent{
		Pid:        msg.PID,
		Comm:       comm,
		EventType:  "zone_transition",
		ScoreDelta: float32(msg.Score),
		Timestamp:  int64(msg.TsNs),
		Metadata: map[string]string{
			"from_zone": msg.FromZone.String(),
			"to_zone":   msg.ToZone.String(),
		},
	})
}

func (cp *ControlPlane) fanOutEvent(e *pb.KBEvent) {
	cp.subMu.Lock()
	defer cp.subMu.Unlock()
	for _, ch := range cp.eventSubs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (cp *ControlPlane) fanOutAlert(a *pb.Alert) {
	cp.alertMu.Lock()
	defer cp.alertMu.Unlock()
	for _, ch := range cp.alertSubs {
		select {
		case ch <- a:
		default:
		}
	}
}

func (cp *ControlPlane) recordEventTime() {
	cp.metricMu.Lock()
	defer cp.metricMu.Unlock()
	cp.eventTimestamps = append(cp.eventTimestamps, time.Now())

	// Keep last 10 seconds
	cutoff := time.Now().Add(-10 * time.Second)
	idx := 0
	for i, t := range cp.eventTimestamps {
		if t.After(cutoff) {
			idx = i
			break
		}
	}
	if idx > 0 {
		cp.eventTimestamps = cp.eventTimestamps[idx:]
	}
}

func (cp *ControlPlane) GetEventsPerSecond() float64 {
	cp.metricMu.Lock()
	defer cp.metricMu.Unlock()

	cutoff := time.Now().Add(-10 * time.Second)
	count := 0
	for _, t := range cp.eventTimestamps {
		if t.After(cutoff) {
			count++
		}
	}
	return float64(count) / 10.0
}
