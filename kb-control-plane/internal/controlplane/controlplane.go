package controlplane

import (
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	pb "github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/proto"
	"github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/internal/audit"
	"github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/internal/enforcement"
	"github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/internal/policy"
	"github.com/PardhuSreeRushiVarma20060119/kernel-borderlands/kb-control-plane/internal/store"
)

type ControlPlane struct {
	pb.UnimplementedKernelBorderlandsServer
	store    *store.Store
	audit    *audit.Logger
	enforcer *enforcement.Enforcer
	policy   *policy.Engine
	grpc     *grpc.Server

	// comm cache — pid → comm (populated by ProcessState messages)
	commCache sync.Map

	// event fan-out
	subMu     sync.Mutex
	eventSubs []chan *pb.KBEvent

	alertMu   sync.Mutex
	alertSubs []chan *pb.Alert
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
	return &ControlPlane{
		store:    s,
		audit:    audit.New(s.DB()),
		enforcer: enforcement.New(),
		policy:   p,
	}, nil
}

func (cp *ControlPlane) Start() error {
	go func() {
		if err := ipc.NewListener(cp).Listen(); err != nil {
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

	log.Println("[KB] Control plane ready")
	return nil
}

func (cp *ControlPlane) Stop() {
	cp.grpc.GracefulStop()
	cp.store.Close()
}

// ── MessageHandler (called by IPC listener) ──

func (cp *ControlPlane) OnProcessState(msg *ipc.ProcessStateMsg) {
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
		},
	})
}

func (cp *ControlPlane) OnZoneTransition(msg *ipc.ZoneTransitionMsg) {
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
			cp.enforcer.Apply(msg.PID, pb.ContainmentLevel_TERMINATE)
			cp.audit.Log("AUTO_TERMINATE",
				fmt.Sprintf("pid=%d comm=%s", msg.PID, comm),
				"SYSTEM_AUTO", "policy:auto_terminate=true")
		} else {
			cp.enforcer.Apply(msg.PID, pb.ContainmentLevel_CGROUP)
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