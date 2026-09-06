package controlplane

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These call the ControlPlane's RPC methods directly (not over a real gRPC
// connection) — same pattern the store/policy layers already use elsewhere
// in this file, since the RPC methods themselves contain all the logic
// worth testing; the gRPC transport is generated code.

func TestGetProcessState_UnknownPidReturnsNotFound(t *testing.T) {
	cp := newTestControlPlane(t)
	_, err := cp.GetProcessState(context.Background(), &pb.PidRequest{Pid: 999})
	if err == nil {
		t.Fatal("expected NotFound error for untracked pid, got nil")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want codes.NotFound", status.Code(err))
	}
}

func TestGetProcessState_TrackedPidReturnsState(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 42, Comm: "bash", Zone: ipc.ZoneSafe})

	resp, err := cp.GetProcessState(context.Background(), &pb.PidRequest{Pid: 42})
	if err != nil {
		t.Fatalf("GetProcessState: %v", err)
	}
	if resp.Pid != 42 || resp.Comm != "bash" {
		t.Errorf("got pid=%d comm=%q, want 42/bash", resp.Pid, resp.Comm)
	}
}

func TestVerifyAuditChain_IntactAfterLogging(t *testing.T) {
	cp := newTestControlPlane(t)
	if err := cp.audit.Log("TEST_ACTION", "subject", "actor", "reason"); err != nil {
		t.Fatalf("audit.Log: %v", err)
	}

	resp, err := cp.VerifyAuditChain(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !resp.ChainIntact {
		t.Errorf("chain_intact=false, want true (error=%q)", resp.Error)
	}
	if resp.EntriesVerified != 1 {
		t.Errorf("entries_verified=%d, want 1", resp.EntriesVerified)
	}
}

func TestExportAuditLog_ReturnsLoggedEntries(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.audit.Log("TEST_ACTION", "subject", "actor", "reason")

	resp, err := cp.ExportAuditLog(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("ExportAuditLog: %v", err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(resp.Entries))
	}
	if resp.Entries[0].Action != "TEST_ACTION" {
		t.Errorf("got action=%q, want TEST_ACTION", resp.Entries[0].Action)
	}
}

func TestOverrideZone_UnknownPidReturnsNotFound(t *testing.T) {
	cp := newTestControlPlane(t)
	_, err := cp.OverrideZone(context.Background(), &pb.ZoneOverrideRequest{Pid: 999, Zone: pb.Zone_SUSPICIOUS})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want codes.NotFound", status.Code(err))
	}
}

func TestOverrideZone_TrackedPidUpdatesZone(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 7, Comm: "x", Zone: ipc.ZoneSafe})

	resp, err := cp.OverrideZone(context.Background(), &pb.ZoneOverrideRequest{
		Pid: 7, Zone: pb.Zone_BORDERLANDS, Reason: "test",
	})
	if err != nil {
		t.Fatalf("OverrideZone: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected Success=true")
	}
	cs, _ := cp.store.GetProcessState(7)
	if cs.Zone != ipc.ZoneBorderlands {
		t.Errorf("got zone=%v, want BORDERLANDS", cs.Zone)
	}
}

// --- BUG-012: SetContainment/SubmitAgentDecision must validate the target
// PID exists and throttle repeated calls from the same caller. ---

func TestSetContainment_UnknownPidReturnsNotFound(t *testing.T) {
	cp := newTestControlPlane(t)
	_, err := cp.SetContainment(context.Background(), &pb.ContainmentRequest{Pid: 999, Level: pb.ContainmentLevel_TERMINATE})
	if status.Code(err) != codes.NotFound {
		t.Errorf("got code %v, want codes.NotFound", status.Code(err))
	}
}

func TestSetContainment_TrackedPidPassesExistenceCheck(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 42, Comm: "bash", Zone: ipc.ZoneSafe})

	_, err := cp.SetContainment(context.Background(), &pb.ContainmentRequest{Pid: 42, Level: pb.ContainmentLevel_TERMINATE})
	// No sensor is connected in this test environment, so the call still
	// fails — but downstream of the existence check, not from it. This
	// distinguishes "pid not found" (caller error) from "no sensor
	// connected" (infra error) rather than conflating the two.
	if status.Code(err) == codes.NotFound {
		t.Errorf("got NotFound for a tracked pid, want the request to pass the existence check (err=%v)", err)
	}
}

func TestSetContainment_ThrottlesRepeatedCalls(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 42, Comm: "bash"})

	cp.SetContainment(context.Background(), &pb.ContainmentRequest{Pid: 42, Level: pb.ContainmentLevel_TERMINATE})
	_, err := cp.SetContainment(context.Background(), &pb.ContainmentRequest{Pid: 42, Level: pb.ContainmentLevel_TERMINATE})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("got code %v on immediate second call, want codes.ResourceExhausted", status.Code(err))
	}
}

func TestSubmitAgentDecision_UnknownPidRejected(t *testing.T) {
	cp := newTestControlPlane(t)
	resp, err := cp.SubmitAgentDecision(context.Background(), &pb.AgentDecision{
		Pid: 999, Action: "CGROUP", Confidence: 0.9, AgentId: "a1", AuthorizedBy: []string{"patroller"},
	})
	if err != nil {
		t.Fatalf("SubmitAgentDecision: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false for an untracked pid")
	}
	if !strings.Contains(resp.Message, "no tracked process") {
		t.Errorf("got message %q, want it to mention the untracked pid", resp.Message)
	}
}

func TestSubmitAgentDecision_ThrottlesRepeatedCallsPerAgent(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 1, Comm: "x"})

	req := &pb.AgentDecision{Pid: 1, Action: "CGROUP", Confidence: 0.9, AgentId: "flooder", AuthorizedBy: []string{"patroller"}}
	cp.SubmitAgentDecision(context.Background(), req)
	resp, err := cp.SubmitAgentDecision(context.Background(), req)
	if err != nil {
		t.Fatalf("SubmitAgentDecision: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false on immediate second call from the same agent")
	}
	if !strings.Contains(resp.Message, "throttled") {
		t.Errorf("got message %q, want it to mention throttling", resp.Message)
	}
}

// --- BUG-010: AuthorizedBy is caller-supplied and must be checked against
// a real allowlist before a destructive action is acted on. ---

func TestSubmitAgentDecision_UnrecognizedAuthorizedByRejectedForDestructiveAction(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 1, Comm: "x"})

	resp, err := cp.SubmitAgentDecision(context.Background(), &pb.AgentDecision{
		Pid: 1, Action: "TERMINATE", Confidence: 0.99, AgentId: "attacker",
		AuthorizedBy: []string{"totally-not-a-real-agent"},
	})
	if err != nil {
		t.Fatalf("SubmitAgentDecision: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false for an unrecognized authorized_by identity on a destructive action")
	}
	if !strings.Contains(resp.Message, "no recognized agent identity") {
		t.Errorf("got message %q, want it to mention the unrecognized identity", resp.Message)
	}
}

func TestSubmitAgentDecision_RecognizedAuthorizedByPassesGate(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 1, Comm: "x"})

	resp, err := cp.SubmitAgentDecision(context.Background(), &pb.AgentDecision{
		Pid: 1, Action: "CGROUP", Confidence: 0.9, AgentId: "containment-1",
		AuthorizedBy: []string{"containment"},
	})
	if err != nil {
		t.Fatalf("SubmitAgentDecision: %v", err)
	}
	// No sensor connected in this test env, so enforcement itself still
	// fails downstream — the point here is it got past the allowlist gate
	// rather than being rejected for the identity itself.
	if strings.Contains(resp.Message, "no recognized agent identity") {
		t.Errorf("got message %q, want the recognized identity to pass the allowlist gate", resp.Message)
	}
}

func TestSubmitAgentDecision_NonDestructiveActionSkipsAllowlistGate(t *testing.T) {
	cp := newTestControlPlane(t)
	cp.store.UpsertProcessState(&ipc.ProcessStateMsg{PID: 1, Comm: "x"})

	resp, err := cp.SubmitAgentDecision(context.Background(), &pb.AgentDecision{
		Pid: 1, Action: "QUARANTINE", Confidence: 0.9, AgentId: "executor-1",
		AuthorizedBy: []string{"unrecognized-but-harmless-here"},
	})
	if err != nil {
		t.Fatalf("SubmitAgentDecision: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true for a non-destructive/unmatched action regardless of authorized_by, got message=%q", resp.Message)
	}
}

// --- §2.12 step 5: RecordSSHSession, the audit-tie-in callback for the
// ForceCommand wrapper script (see docs/architecture/boot_sequence_spec.md
// §3). Deliberately narrow — only two fixed actions, not an
// arbitrary-action write endpoint. ---

func TestRecordSSHSession_SessionStartLogsAudit(t *testing.T) {
	cp := newTestControlPlane(t)
	before := auditCount(t, cp)

	_, err := cp.RecordSSHSession(context.Background(), &pb.SSHSessionEvent{
		Principal:  "operator",
		RemoteAddr: "10.0.0.5 51234 10.0.0.1 2222",
		Event:      "session_start",
	})
	if err != nil {
		t.Fatalf("RecordSSHSession: %v", err)
	}
	if got := auditCount(t, cp); got != before+1 {
		t.Errorf("audit_log count = %d, want %d", got, before+1)
	}

	var action string
	if err := cp.store.DB().QueryRow(`SELECT action FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action); err != nil {
		t.Fatalf("query last audit action: %v", err)
	}
	if action != "SSH_SESSION_START" {
		t.Errorf("got action=%q, want SSH_SESSION_START", action)
	}
}

func TestRecordSSHSession_SessionEndLogsAudit(t *testing.T) {
	cp := newTestControlPlane(t)
	_, err := cp.RecordSSHSession(context.Background(), &pb.SSHSessionEvent{
		Principal: "operator", Event: "session_end",
	})
	if err != nil {
		t.Fatalf("RecordSSHSession: %v", err)
	}
	var action string
	cp.store.DB().QueryRow(`SELECT action FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action)
	if action != "SSH_SESSION_END" {
		t.Errorf("got action=%q, want SSH_SESSION_END", action)
	}
}

func TestRecordSSHSession_UnknownEventRejected(t *testing.T) {
	cp := newTestControlPlane(t)
	before := auditCount(t, cp)

	_, err := cp.RecordSSHSession(context.Background(), &pb.SSHSessionEvent{
		Principal: "operator", Event: "delete_everything",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("got code %v, want codes.InvalidArgument", status.Code(err))
	}
	if got := auditCount(t, cp); got != before {
		t.Errorf("audit_log count = %d, want unchanged at %d (rejected event must not be logged)", got, before)
	}
}

func TestReloadPolicy_ViaRPC(t *testing.T) {
	cp := newTestControlPlane(t)
	resp, err := cp.ReloadPolicy(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected Success=true reloading empty policy path, got message=%q", resp.Message)
	}
}

// --- ReloadWorkloads (docs/features/CWP.md — the Go-side sender for a
// kernel/sensor pipeline that was already implemented and verified in
// kb-core; this RPC is the piece that lets an operator actually push a
// workload registry into it). ---

func TestReloadWorkloads_NoWorkloadsPathConfiguredFails(t *testing.T) {
	cp := newTestControlPlane(t) // constructed with workloadsPath=""
	resp, err := cp.ReloadWorkloads(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("ReloadWorkloads: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false with no --workloads path configured")
	}
}

func TestReloadWorkloads_ValidFileReturnsCount(t *testing.T) {
	dir := t.TempDir()
	workloadsPath := dir + "/workloads.yaml"
	if err := os.WriteFile(workloadsPath, []byte("critical_workloads:\n  - path: /usr/bin/postgres\n"), 0644); err != nil {
		t.Fatalf("write workloads.yaml: %v", err)
	}

	cp, err := New(":memory:", "", "", workloadsPath, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(cp.store.Close)

	resp, err := cp.ReloadWorkloads(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("ReloadWorkloads: %v", err)
	}
	if !resp.Success {
		t.Fatalf("expected Success=true, got message=%q", resp.Message)
	}
	if resp.WorkloadCount != 1 {
		t.Errorf("got workload_count=%d, want 1", resp.WorkloadCount)
	}

	var action string
	cp.store.DB().QueryRow(`SELECT action FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&action)
	if action != "CWP_WORKLOADS_RELOAD" {
		t.Errorf("got audit action=%q, want CWP_WORKLOADS_RELOAD", action)
	}
}

func TestReloadWorkloads_InvalidFileFails(t *testing.T) {
	dir := t.TempDir()
	workloadsPath := dir + "/workloads.yaml"
	if err := os.WriteFile(workloadsPath, []byte("critical_workloads:\n  - path: /usr/bin/x\n    identity_tier: not-a-real-tier\n"), 0644); err != nil {
		t.Fatalf("write workloads.yaml: %v", err)
	}

	cp, err := New(":memory:", "", "", "", "") // empty at construction time — loadWorkloadsOrEmpty tolerates the bad file
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(cp.store.Close)
	cp.workloadsPath = workloadsPath // simulate a file that became invalid after startup

	resp, err := cp.ReloadWorkloads(context.Background(), &pb.Empty{})
	if err != nil {
		t.Fatalf("ReloadWorkloads: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false for an invalid workloads.yaml")
	}
}
