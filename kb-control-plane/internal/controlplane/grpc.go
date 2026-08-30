package controlplane

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// minDecisionInterval is the minimum spacing enforced per agent ID between
// SubmitAgentDecision/SetContainment calls (BUG-012). Override via
// KB_AGENT_MIN_INTERVAL_MS for tests/tuning.
func minDecisionInterval() time.Duration {
	if v := os.Getenv("KB_AGENT_MIN_INTERVAL_MS"); v != "" {
		if ms, err := time.ParseDuration(v + "ms"); err == nil {
			return ms
		}
	}
	return 200 * time.Millisecond
}

// rateLimited reports whether callerID has issued a decision within
// minDecisionInterval(), recording this call's timestamp either way so the
// window advances on every attempt (not just accepted ones).
func (cp *ControlPlane) rateLimited(callerID string) bool {
	cp.rateLimitMu.Lock()
	defer cp.rateLimitMu.Unlock()
	now := time.Now()
	if last, ok := cp.lastDecision[callerID]; ok && now.Sub(last) < minDecisionInterval() {
		return true
	}
	cp.lastDecision[callerID] = now
	return false
}

// agentAllowlist is the set of AuthorizedBy identities SubmitAgentDecision
// trusts for destructive actions (BUG-010). AuthorizedBy is otherwise just
// a caller-supplied string with no real authority behind it — this doesn't
// make it cryptographically verified, but it stops an arbitrary/typo'd
// identity from being logged and acted on as if it were meaningful
// provenance. Configurable via KB_AGENT_ALLOWLIST (comma-separated);
// defaults to this system's known agent roles (see kb-aads/agents/base_agent.py).
func agentAllowlist() map[string]bool {
	names := os.Getenv("KB_AGENT_ALLOWLIST")
	if names == "" {
		names = "patroller,hunter,healer,containment,judge,jury,executor"
	}
	allow := map[string]bool{}
	for _, n := range strings.Split(names, ",") {
		if n = strings.TrimSpace(n); n != "" {
			allow[n] = true
		}
	}
	return allow
}

func isDestructiveAction(action string) bool {
	switch action {
	case "TERMINATE", "NAMESPACE", "SECCOMP", "CGROUP":
		return true
	default:
		return false
	}
}

// cachedToProto converts the store's L1 CachedState into the gRPC wire
// type. This is the only place that translation happens — GetProcessState
// and ListZone both read L1 directly (ADR-1: ~30-50ns), never SQLite.
func cachedToProto(cs *store.CachedState) *pb.ProcessState {
	return &pb.ProcessState{
		Pid:         cs.PID,
		Ppid:        cs.PPID,
		Comm:        cs.Comm,
		Uid:         cs.UID,
		Score:       float32(cs.EMAScore),
		Zone:        pb.Zone(cs.Zone),
		Containment: pb.ContainmentLevel(cs.Containment),
	}
}

func (cp *ControlPlane) GetProcessState(
	ctx context.Context, req *pb.PidRequest,
) (*pb.ProcessState, error) {
	cs, ok := cp.store.GetProcessState(req.Pid)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no tracked process with pid=%d", req.Pid)
	}
	return cachedToProto(cs), nil
}

func (cp *ControlPlane) ListZone(
	req *pb.ZoneRequest,
	stream pb.KernelBorderlands_ListZoneServer,
) error {
	for _, cs := range cp.store.ListZone(ipc.KBZone(req.Zone)) {
		if err := stream.Send(cachedToProto(cs)); err != nil {
			return err
		}
	}
	return nil
}

func (cp *ControlPlane) SetContainment(
	ctx context.Context, req *pb.ContainmentRequest,
) (*pb.ContainmentResponse, error) {
	if cp.rateLimited("OPERATOR") {
		return nil, status.Errorf(codes.ResourceExhausted, "containment requests throttled, retry after %s", minDecisionInterval())
	}
	if _, ok := cp.store.GetProcessState(req.Pid); !ok {
		return nil, status.Errorf(codes.NotFound, "no tracked process with pid=%d", req.Pid)
	}
	if err := cp.enforcer.Contain(req.Pid, uint32(req.Level), req.Reason); err != nil {
		return &pb.ContainmentResponse{Success: false}, status.Errorf(codes.PermissionDenied, "%s", err)
	}
	cp.audit.Log(
		fmt.Sprintf("SET_CONTAINMENT_%s", req.Level),
		fmt.Sprintf("pid=%d", req.Pid),
		"OPERATOR", req.Reason,
	)
	cp.store.SetContainment(req.Pid, int32(req.Level))
	return &pb.ContainmentResponse{Success: true}, nil
}

func (cp *ControlPlane) StreamEvents(
	filter *pb.EventFilter,
	stream pb.KernelBorderlands_StreamEventsServer,
) error {
	ch := make(chan *pb.KBEvent, 256)
	cp.subMu.Lock()
	cp.eventSubs = append(cp.eventSubs, ch)
	cp.subMu.Unlock()
	defer func() {
		cp.subMu.Lock()
		for i, s := range cp.eventSubs {
			if s == ch {
				cp.eventSubs = append(cp.eventSubs[:i], cp.eventSubs[i+1:]...)
				break
			}
		}
		cp.subMu.Unlock()
	}()
	for {
		select {
		case e := <-ch:
			if err := stream.Send(e); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (cp *ControlPlane) StreamAlerts(
	filter *pb.EventFilter,
	stream pb.KernelBorderlands_StreamAlertsServer,
) error {
	ch := make(chan *pb.Alert, 64)
	cp.alertMu.Lock()
	cp.alertSubs = append(cp.alertSubs, ch)
	cp.alertMu.Unlock()
	defer func() {
		cp.alertMu.Lock()
		for i, s := range cp.alertSubs {
			if s == ch {
				cp.alertSubs = append(cp.alertSubs[:i], cp.alertSubs[i+1:]...)
				break
			}
		}
		cp.alertMu.Unlock()
	}()
	for {
		select {
		case a := <-ch:
			if err := stream.Send(a); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (cp *ControlPlane) SubmitAgentDecision(
	ctx context.Context, d *pb.AgentDecision,
) (*pb.DecisionAck, error) {
	if d.Confidence < 0.85 && d.Action == "TERMINATE" {
		return &pb.DecisionAck{
			Success: false,
			Message: fmt.Sprintf("confidence %.2f below 0.85 threshold", d.Confidence),
		}, nil
	}

	if cp.rateLimited(d.AgentId) {
		return &pb.DecisionAck{
			Success: false,
			Message: fmt.Sprintf("agent %s throttled, retry after %s", d.AgentId, minDecisionInterval()),
		}, nil
	}

	// BUG-010: AuthorizedBy is caller-supplied and was previously only
	// logged, never checked against anything — a fabricated identity
	// would be recorded as if it were real provenance. Destructive
	// actions now require at least one recognized identity in the list.
	if isDestructiveAction(d.Action) {
		allowed := agentAllowlist()
		authorized := false
		for _, id := range d.AuthorizedBy {
			if allowed[id] {
				authorized = true
				break
			}
		}
		if !authorized {
			return &pb.DecisionAck{
				Success: false,
				Message: fmt.Sprintf("authorized_by %v contains no recognized agent identity for action %s", d.AuthorizedBy, d.Action),
			}, nil
		}
	}

	// BUG-012: act only on PIDs this system has actually observed.
	if _, ok := cp.store.GetProcessState(d.Pid); !ok {
		return &pb.DecisionAck{
			Success: false,
			Message: fmt.Sprintf("no tracked process with pid=%d", d.Pid),
		}, nil
	}

	agentReason := fmt.Sprintf("agent=%s action=%s confidence=%.2f", d.AgentId, d.Action, d.Confidence)
	var containErr error
	switch d.Action {
	case "TERMINATE":
		containErr = cp.enforcer.Contain(d.Pid, uint32(pb.ContainmentLevel_TERMINATE), agentReason)
	case "NAMESPACE":
		containErr = cp.enforcer.Contain(d.Pid, uint32(pb.ContainmentLevel_NAMESPACE), agentReason)
	case "SECCOMP":
		containErr = cp.enforcer.Contain(d.Pid, uint32(pb.ContainmentLevel_SECCOMP), agentReason)
	case "CGROUP":
		containErr = cp.enforcer.Contain(d.Pid, uint32(pb.ContainmentLevel_CGROUP), agentReason)
	}
	if containErr != nil {
		return &pb.DecisionAck{Success: false, Message: containErr.Error()}, nil
	}

	cp.audit.Log(
		fmt.Sprintf("AGENT_%s", d.Action),
		fmt.Sprintf("pid=%d agent=%s conf=%.2f auth=%v",
			d.Pid, d.AgentId, d.Confidence, d.AuthorizedBy),
		d.AgentId, "",
	)
	return &pb.DecisionAck{Success: true, Message: "executed"}, nil
}

func (cp *ControlPlane) GetSystemStats(
	ctx context.Context, req *pb.Empty,
) (*pb.SystemStats, error) {
	eps := cp.GetEventsPerSecond()
	active := uint32(len(cp.store.ListAll()))
	return &pb.SystemStats{
		EventsPerSecond: eps,
		ActiveProcesses: active,
	}, nil
}

// VerifyAuditChain wires up Logger.VerifyChain() (internal/audit/audit.go)
// to gRPC — see docs/development/core-control/control-plane-catalog.md
// §2.1. Chain-broken is a normal, successful response (chain_intact=false),
// not a gRPC error — the caller needs the count/positional info either way.
func (cp *ControlPlane) VerifyAuditChain(
	ctx context.Context, req *pb.Empty,
) (*pb.AuditVerifyResponse, error) {
	ok, count, err := cp.audit.VerifyChain()
	resp := &pb.AuditVerifyResponse{
		ChainIntact:     ok,
		EntriesVerified: uint32(count),
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

// ExportAuditLog returns the full audit_log table in chain order.
func (cp *ControlPlane) ExportAuditLog(
	ctx context.Context, req *pb.Empty,
) (*pb.AuditExportResponse, error) {
	rows, err := cp.store.DB().Query(`
        SELECT ts_ns,action,subject,actor,reason,prev_hash,entry_hash
        FROM audit_log ORDER BY id ASC
    `)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit export query: %v", err)
	}
	defer rows.Close()

	var entries []*pb.AuditEntry
	for rows.Next() {
		var e pb.AuditEntry
		if err := rows.Scan(&e.TsNs, &e.Action, &e.Subject, &e.Actor, &e.Reason, &e.PrevHash, &e.EntryHash); err != nil {
			return nil, status.Errorf(codes.Internal, "audit export scan: %v", err)
		}
		entries = append(entries, &e)
	}
	return &pb.AuditExportResponse{Entries: entries}, nil
}

// OverrideZone relabels an operator-tracked process's zone classification
// in L1 (store.SetZone) without touching kernel/enforcement state, and
// audit-logs the override. A subsequent real ZoneTransition event from
// the sensor will overwrite this the next time the process's score
// crosses a threshold.
func (cp *ControlPlane) OverrideZone(
	ctx context.Context, req *pb.ZoneOverrideRequest,
) (*pb.ZoneOverrideResponse, error) {
	if !cp.store.SetZone(req.Pid, int32(req.Zone)) {
		return nil, status.Errorf(codes.NotFound, "no tracked process with pid=%d", req.Pid)
	}
	cp.audit.Log(
		fmt.Sprintf("ZONE_OVERRIDE_%s", req.Zone),
		fmt.Sprintf("pid=%d", req.Pid),
		"OPERATOR", req.Reason,
	)
	return &pb.ZoneOverrideResponse{Success: true}, nil
}

// ReloadPolicy re-reads policy.yaml from the path kbd was started with —
// see ControlPlane.ReloadPolicy (controlplane.go).
func (cp *ControlPlane) ReloadPolicy(
	ctx context.Context, req *pb.Empty,
) (*pb.ReloadPolicyResponse, error) {
	ok, msg, err := cp.reloadPolicyFromDisk()
	if err != nil {
		return &pb.ReloadPolicyResponse{Success: false, Message: err.Error()}, nil
	}
	cp.audit.Log("POLICY_RELOAD", cp.policyPath, "OPERATOR", "")
	return &pb.ReloadPolicyResponse{Success: ok, Message: msg}, nil
}

// ReloadWorkloads re-reads workloads.yaml and broadcasts the protected
// workload registry to every connected sensor — see
// ControlPlane.reloadWorkloadsFromDisk (controlplane.go), docs/features/CWP.md.
func (cp *ControlPlane) ReloadWorkloads(
	ctx context.Context, req *pb.Empty,
) (*pb.ReloadWorkloadsResponse, error) {
	count, msg, err := cp.reloadWorkloadsFromDisk()
	if err != nil {
		return &pb.ReloadWorkloadsResponse{Success: false, Message: err.Error()}, nil
	}
	cp.audit.Log("CWP_WORKLOADS_RELOAD", cp.workloadsPath, "OPERATOR", fmt.Sprintf("count=%d", count))
	return &pb.ReloadWorkloadsResponse{Success: true, Message: msg, WorkloadCount: uint32(count)}, nil
}

// RecordSSHSession is the audit-tie-in callback described in
// docs/development/core-control/control-plane-catalog.md §2.12 step 5 —
// called by the ForceCommand wrapper script (docs/architecture/
// boot_sequence_spec.md §3), not by kb-tui itself, since internal/ssh/'s
// Go code (the only place that previously even attempted this, via a bare
// log.Printf) is gone as of the §2.11 migration. Deliberately narrow: only
// ever writes one of two fixed audit actions, not an arbitrary-action
// write endpoint.
func (cp *ControlPlane) RecordSSHSession(
	ctx context.Context, req *pb.SSHSessionEvent,
) (*pb.Empty, error) {
	var action string
	switch req.Event {
	case "session_start":
		action = "SSH_SESSION_START"
	case "session_end":
		action = "SSH_SESSION_END"
	default:
		return nil, status.Errorf(codes.InvalidArgument, "event must be \"session_start\" or \"session_end\", got %q", req.Event)
	}
	cp.audit.Log(
		action,
		fmt.Sprintf("principal=%s remote=%s", req.Principal, req.RemoteAddr),
		req.Principal,
		fmt.Sprintf("identity=%s", req.Identity),
	)
	return &pb.Empty{}, nil
}