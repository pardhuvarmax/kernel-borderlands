package controlplane

import (
	"context"
	"fmt"

	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
)

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
		return &pb.ProcessState{}, nil
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
	cp.enforcer.Apply(req.Pid, req.Level)
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
	cp.audit.Log(
		fmt.Sprintf("AGENT_%s", d.Action),
		fmt.Sprintf("pid=%d agent=%s conf=%.2f auth=%v",
			d.Pid, d.AgentId, d.Confidence, d.AuthorizedBy),
		d.AgentId, "",
	)
	switch d.Action {
	case "TERMINATE":
		cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_TERMINATE)
	case "NAMESPACE":
		cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_NAMESPACE)
	case "SECCOMP":
		cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_SECCOMP)
	case "CGROUP":
		cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_CGROUP)
	}
	return &pb.DecisionAck{Success: true, Message: "executed"}, nil
}