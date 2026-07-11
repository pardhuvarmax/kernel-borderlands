package controlplane

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/audit"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/enforcement"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/policy"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
)

type ControlPlane struct {
	pb.UnimplementedKernelBorderlandsServer
	store    *store.Store
	audit    *audit.Logger
	enforcer *enforcement.Enforcer
	policy   *policy.Engine
	grpc     *grpc.Server
	listener *ipc.Listener // created once in New(), used in Start()

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
}

func New(dbPath, policyPath string) (*ControlPlane, error) {
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
		store:  s,
		audit:  audit.New(s.DB()),
		policy: p,
	}

	// NewListener records the socket path and stores cp as the MessageHandler.
	// The UDS socket is NOT bound here — binding happens inside Listen(), which
	// is called by Start(). This keeps New() safe to call in test environments
	// where /run/kb/ may not exist.
	listener, err := ipc.NewListener(cp)
	if err != nil {
		return nil, fmt.Errorf("ipc listener: %w", err)
	}
	cp.listener = listener

	// Enforcer routes containment commands to the C sensor via the listener.
	cp.enforcer = enforcement.NewEnforcer(listener)

	return cp, nil
}

func (cp *ControlPlane) Start() error {
	// Use the listener constructed in New() — do NOT call NewListener again.
	go func() {
		if err := cp.listener.Listen(); err != nil {
			log.Fatalf("[KB] IPC: %v", err)
		}
	}()

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}
	cp.grpc = grpc.NewServer()
	pb.RegisterKernelBorderlandsServer(cp.grpc, cp)
	go func() {
		log.Println("[KB] gRPC on :50051")
		cp.grpc.Serve(lis)
	}()

	// Start HTTP API & SSE server on :8080 for web dashboard
	go func() {
		if err := cp.StartHTTPServer(":8080"); err != nil {
			log.Printf("[KB] HTTP server failed: %v", err)
		}
	}()

	log.Println("[KB] Control plane ready")
	return nil
}

func (cp *ControlPlane) Stop() {
	cp.grpc.GracefulStop()
	cp.store.Close()
	// Signal the IPC accept loop to stop.
	if cp.listener != nil {
		close(cp.listener.Done)
	}
}

// ── MessageHandler (called by IPC listener) ──

func (cp *ControlPlane) OnProcessState(msg *ipc.ProcessStateMsg) {
	cp.recordEventTime()
	cp.commCache.Store(msg.PID, msg.Comm)

	if err := cp.store.UpsertProcessState(msg); err != nil {
		log.Printf("[KB] store: %v", err)
	}

	// Remove on process exit — event_count won't increment after exit,
	// so use the zone: if a process_exit event came through the C side
	// it already called kb_scoring_remove(), but the last state message
	// may not reflect that. Use EventCount==0 as proxy? No — just leave
	// the store row; it'll get overwritten when/if the PID is reused.
	// TODO: C side should send a dedicated process_exit wire message type.

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

		if cp.policy.AutoTerminate(comm) {
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