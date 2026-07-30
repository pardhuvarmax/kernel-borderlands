package controlplane

import (
	"context"
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
