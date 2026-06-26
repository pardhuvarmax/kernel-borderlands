package controlplane

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/kb-research/kb-control-plane/proto"
)

// Zone mirrors pb.Zone but lives independently in this package so the
// scoring/classification logic below has no compile-time dependency on the
// wire format beyond the final pb.Zone(...) conversion at the API boundary.
type Zone int

const (
	ZoneSafe Zone = iota
	ZoneSuspicious
	ZoneBorderlands
)

func (z Zone) String() string {
	switch z {
	case ZoneSafe:
		return "SAFE"
	case ZoneSuspicious:
		return "SUSPICIOUS"
	case ZoneBorderlands:
		return "BORDERLANDS"
	default:
		return "UNKNOWN"
	}
}

// ProcessState tracks behavioral state per process. Access is always
// mediated through ControlPlane.mu — this struct holds no lock of its own
// to avoid lock-ordering bugs when a caller holds cp.mu and touches a state
// pointer it pulled out of the map.
type ProcessState struct {
	PID         uint32
	PPID        uint32
	Comm        string
	UID         uint32
	Score       float64
	Zone        Zone
	Containment pb.ContainmentLevel
	FirstSeen   int64
	LastSeen    int64
}

// ControlPlane is the main KB daemon. It implements pb.KernelBorderlandsServer
// directly.
type ControlPlane struct {
	pb.UnimplementedKernelBorderlandsServer

	cfg *Config

	mu        sync.RWMutex
	processes map[uint32]*ProcessState

	grpcServer *grpc.Server
	eventChan  chan *pb.KBEvent
	alertChan  chan *pb.Alert

	subMu            sync.Mutex
	eventSubscribers map[chan *pb.KBEvent]struct{}
	alertSubscribers map[chan *pb.Alert]struct{}
}

// New creates a new ControlPlane instance, loading configuration from
// configPath (falling back to defaults if the file doesn't exist yet).
func New(configPath string) (*ControlPlane, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config %q: %w", configPath, err)
	}

	return &ControlPlane{
		cfg:              cfg,
		processes:        make(map[uint32]*ProcessState),
		eventChan:        make(chan *pb.KBEvent, 10000),
		alertChan:        make(chan *pb.Alert, 1000),
		eventSubscribers: make(map[chan *pb.KBEvent]struct{}),
		alertSubscribers: make(map[chan *pb.Alert]struct{}),
	}, nil
}

// Start initializes and starts the control plane.
func (cp *ControlPlane) Start() error {
	log.Println("[KB] Initializing state store...")
	// TODO(internal/scoring + SQLite): the process map below is in-memory
	// only and resets on restart. Swap for the SQLite-backed store
	// (mattn/go-sqlite3 is already in go.mod) so behavioral history
	// survives daemon restarts.

	log.Printf("[KB] Starting gRPC server on :%d...", cp.cfg.GRPCPort)
	if err := cp.startGRPC(); err != nil {
		return err
	}

	log.Println("[KB] Starting event processor...")
	go cp.processEvents()

	log.Printf("[KB] Control plane ready. (enforcement mode: %s)", cp.cfg.Enforcement.Mode)
	return nil
}

// Stop gracefully shuts down the control plane.
func (cp *ControlPlane) Stop() {
	if cp.grpcServer != nil {
		cp.grpcServer.GracefulStop()
	}
}

func (cp *ControlPlane) startGRPC() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cp.cfg.GRPCPort))
	if err != nil {
		return err
	}

	cp.grpcServer = grpc.NewServer()
	pb.RegisterKernelBorderlandsServer(cp.grpcServer, cp)

	go func() {
		if err := cp.grpcServer.Serve(lis); err != nil {
			log.Printf("[KB] gRPC server stopped: %v", err)
		}
	}()

	return nil
}

// UpdateScore applies EMA smoothing and updates a process's score, returning
// the new smoothed score. This is the entry point the eBPF event pipeline
// (internal/scoring, once it exists) will call after computing a raw
// per-dimension composite score for an event.
//
//	S_t = alpha * s_t + (1 - alpha) * S_{t-1}
func (cp *ControlPlane) UpdateScore(pid uint32, rawScore float64) float64 {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	state, exists := cp.processes[pid]
	if !exists {
		state = &ProcessState{PID: pid, Score: rawScore, Zone: cp.classifyZone(rawScore)}
		cp.processes[pid] = state
		return state.Score
	}

	alpha := cp.cfg.Scoring.Alpha
	state.Score = alpha*rawScore + (1-alpha)*state.Score

	if newZone := cp.classifyZone(state.Score); newZone != state.Zone {
		cp.onZoneTransition(state, newZone)
		state.Zone = newZone
	}

	return state.Score
}

// classifyZone maps a smoothed score to a zone using the configured
// thresholds (defaults: Safe < 40 <= Suspicious < 75 <= Borderlands).
func (cp *ControlPlane) classifyZone(score float64) Zone {
	if score < cp.cfg.Scoring.Thresholds.Suspicious {
		return ZoneSafe
	}
	if score < cp.cfg.Scoring.Thresholds.Borderlands {
		return ZoneSuspicious
	}
	return ZoneBorderlands
}

// onZoneTransition handles a zone change: logs it and kicks off the
// (currently stubbed) graduated response for the new zone.
func (cp *ControlPlane) onZoneTransition(state *ProcessState, newZone Zone) {
	log.Printf("[KB] Zone transition: PID=%d COMM=%s %s -> %s score=%.2f",
		state.PID, state.Comm, state.Zone, newZone, state.Score)

	switch newZone {
	case ZoneSuspicious:
		go cp.applyMonitoring(state.PID)
	case ZoneBorderlands:
		go cp.applyContainment(state.PID)
	case ZoneSafe:
		go cp.relaxContainment(state.PID)
	}
}

// applyContainment, applyMonitoring, and relaxContainment are placeholders
// for the graduated containment ladder (Observe -> Restrict -> Isolate ->
// Terminate). The real namespace/seccomp/cgroup primitives belong in
// internal/enforcement — wiring them in is the next milestone, not today's.
func (cp *ControlPlane) applyContainment(pid uint32) {
	log.Printf("[KB] Applying containment to PID=%d", pid)
	// TODO(internal/enforcement): namespace isolation + cgroup throttle.
}

func (cp *ControlPlane) applyMonitoring(pid uint32) {
	log.Printf("[KB] Increasing monitoring for PID=%d", pid)
	// TODO(internal/enforcement): seccomp network-syscall block.
}

func (cp *ControlPlane) relaxContainment(pid uint32) {
	log.Printf("[KB] Relaxing containment for PID=%d", pid)
	// TODO(internal/enforcement): reverse the containment ladder.
}

func (cp *ControlPlane) processEvents() {
	for event := range cp.eventChan {
		cp.handleEvent(event)
	}
}

func (cp *ControlPlane) handleEvent(event *pb.KBEvent) {
	log.Printf("[KB] Event: type=%s pid=%d comm=%s", event.EventType, event.Pid, event.Comm)
	// TODO(internal/scoring): route this event into the six weighted
	// behavioral dimensions and call cp.UpdateScore(event.Pid, rawScore).
	cp.broadcastEvent(event)
}

// broadcastEvent fans an event out to every active StreamEvents subscriber.
// Sends are non-blocking: a slow consumer drops events rather than stalling
// the whole event processor.
func (cp *ControlPlane) broadcastEvent(event *pb.KBEvent) {
	cp.subMu.Lock()
	defer cp.subMu.Unlock()
	for ch := range cp.eventSubscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (cp *ControlPlane) broadcastAlert(alert *pb.Alert) {
	cp.subMu.Lock()
	defer cp.subMu.Unlock()
	for ch := range cp.alertSubscribers {
		select {
		case ch <- alert:
		default:
		}
	}
}

func stateToProto(s *ProcessState) *pb.ProcessState {
	return &pb.ProcessState{
		Pid:         s.PID,
		Ppid:        s.PPID,
		Comm:        s.Comm,
		Score:       float32(s.Score),
		Zone:        pb.Zone(s.Zone),
		Uid:         s.UID,
		Containment: s.Containment,
		FirstSeen:   s.FirstSeen,
		LastSeen:    s.LastSeen,
	}
}

// ---------------------------------------------------------------------------
// gRPC service implementation (pb.KernelBorderlandsServer)
// ---------------------------------------------------------------------------

func (cp *ControlPlane) GetProcessState(ctx context.Context, req *pb.PidRequest) (*pb.ProcessState, error) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	state, exists := cp.processes[req.Pid]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "no state tracked for pid %d", req.Pid)
	}
	return stateToProto(state), nil
}

func (cp *ControlPlane) ListZone(req *pb.ZoneRequest, stream pb.KernelBorderlands_ListZoneServer) error {
	cp.mu.RLock()
	matches := make([]*pb.ProcessState, 0)
	for _, state := range cp.processes {
		if pb.Zone(state.Zone) == req.Zone {
			matches = append(matches, stateToProto(state))
		}
	}
	cp.mu.RUnlock()

	for _, m := range matches {
		if err := stream.Send(m); err != nil {
			return err
		}
	}
	return nil
}

func (cp *ControlPlane) SetContainment(ctx context.Context, req *pb.ContainmentRequest) (*pb.ContainmentResponse, error) {
	cp.mu.Lock()
	state, exists := cp.processes[req.Pid]
	if !exists {
		cp.mu.Unlock()
		return &pb.ContainmentResponse{Success: false}, status.Errorf(codes.NotFound, "no state tracked for pid %d", req.Pid)
	}
	state.Containment = req.Level
	cp.mu.Unlock()

	log.Printf("[KB] Operator override: containment for PID=%d set to %s (reason: %q)",
		req.Pid, req.Level, req.Reason)
	// TODO(internal/enforcement): actually apply/relax the requested
	// primitive instead of just recording the requested level.
	// TODO(internal/audit): this is exactly the kind of action that needs
	// a tamper-evident audit entry (who/what/when/why).

	return &pb.ContainmentResponse{Success: true}, nil
}

func (cp *ControlPlane) StreamEvents(filter *pb.EventFilter, stream pb.KernelBorderlands_StreamEventsServer) error {
	ch := make(chan *pb.KBEvent, 100)

	cp.subMu.Lock()
	cp.eventSubscribers[ch] = struct{}{}
	cp.subMu.Unlock()

	defer func() {
		cp.subMu.Lock()
		delete(cp.eventSubscribers, ch)
		cp.subMu.Unlock()
	}()

	wanted := toSet(filter.GetEventTypes())

	for {
		select {
		case event := <-ch:
			if len(wanted) > 0 && !wanted[event.EventType] {
				continue
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (cp *ControlPlane) StreamAlerts(filter *pb.EventFilter, stream pb.KernelBorderlands_StreamAlertsServer) error {
	ch := make(chan *pb.Alert, 100)

	cp.subMu.Lock()
	cp.alertSubscribers[ch] = struct{}{}
	cp.subMu.Unlock()

	defer func() {
		cp.subMu.Lock()
		delete(cp.alertSubscribers, ch)
		cp.subMu.Unlock()
	}()

	for {
		select {
		case alert := <-ch:
			if err := stream.Send(alert); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (cp *ControlPlane) SubmitAgentDecision(ctx context.Context, decision *pb.AgentDecision) (*pb.DecisionAck, error) {
	log.Printf("[KB] Agent decision: id=%s agent=%s action=%s pid=%d confidence=%.2f authorized_by=%v",
		decision.DecisionId, decision.AgentId, decision.Action, decision.Pid,
		decision.Confidence, decision.AuthorizedBy)

	// AI Dependency Constraint (design doc Sec 7.1): no enforcement action
	// may be taken solely on an agent recommendation without a corresponding
	// policy authorization. This is a minimal placeholder for that check —
	// the real policy engine (YAML rules -> authorization) isn't built yet.
	if len(decision.AuthorizedBy) == 0 {
		return &pb.DecisionAck{
			Success: false,
			Message: "rejected: no policy authorization attached to decision",
		}, nil
	}

	// TODO(internal/audit): record full decision provenance to the
	// tamper-evident chain before/while acting on it.
	return &pb.DecisionAck{Success: true, Message: "decision recorded"}, nil
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}