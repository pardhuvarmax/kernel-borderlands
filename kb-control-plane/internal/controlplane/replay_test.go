package controlplane

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

// Offline replay of an attack-lab capture through the current kbd logic. Skipped unless KB_REPLAY_EVENTS is set:
//
//	KB_REPLAY_EVENTS=datasets/attack-lab/<run>/raw/events.jsonl KB_REPLAY_OUT=/path/out.json \
//	    go test -count=1 -run TestReplayCorpus ./internal/controlplane
//
// It feeds the recorded feed events (process_state and zone_transition, in receive order) to OnProcessState and
// OnZoneTransition of a fresh in-memory ControlPlane in observe-only mode, so nothing is ever contained, and writes
// per-pid results: the audit rows produced, the BORDERLANDS alerts raised, and the counters. The recorded feed has no
// start times, so one constant per pid (its first timestamp) stands in; this replays decisions, not PID-reuse timing.
// Compare with the capture's own kbd_audit table to see what a change adds or removes.
func TestReplayCorpus(t *testing.T) {
	in := os.Getenv("KB_REPLAY_EVENTS")
	if in == "" {
		t.Skip("set KB_REPLAY_EVENTS to replay a corpus")
	}
	t.Setenv("KB_OBSERVE_ONLY", "1")
	cp := newTestControlPlane(t)
	alerts := make(chan *pb.Alert, 1<<20)
	cp.alertMu.Lock()
	cp.alertSubs = append(cp.alertSubs, alerts)
	cp.alertMu.Unlock()
	log.SetOutput(io.Discard) // one [AUDIT] line per row would drown the output
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zone := map[string]ipc.KBZone{"SAFE": ipc.ZoneSafe, "SUSPICIOUS": ipc.ZoneSuspicious, "BORDERLANDS": ipc.ZoneBorderlands}
	start := map[uint32]uint64{}
	feedTransitions := map[string]bool{} // "pid:TOZONE" for transitions present in the recorded feed
	var states, transitions int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e struct {
			Pid        uint32            `json:"pid"`
			Ppid       uint32            `json:"ppid"`
			Comm       string            `json:"comm"`
			EventType  string            `json:"event_type"`
			ScoreDelta float64           `json:"score_delta"`
			Ts         uint64            `json:"ts"`
			Metadata   map[string]string `json:"metadata"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Pid == 0 {
			continue // gap markers and other non-event lines
		}
		if _, ok := start[e.Pid]; !ok {
			start[e.Pid] = e.Ts
		}
		switch e.EventType {
		case "process_state":
			msg := &ipc.ProcessStateMsg{PID: e.Pid, PPID: e.Ppid, Comm: e.Comm, StartTimeNs: start[e.Pid], LastUpdatedNs: e.Ts,
				EMAScore: e.ScoreDelta, Zone: zone[e.Metadata["zone"]]}
			if v, err := strconv.ParseUint(e.Metadata["uid"], 10, 32); err == nil {
				msg.UID = uint32(v)
			}
			if v, err := strconv.ParseUint(e.Metadata["event_count"], 10, 32); err == nil {
				msg.EventCount = uint32(v)
			}
			msg.CompositeScore, _ = strconv.ParseFloat(e.Metadata["composite"], 64)
			for i, name := range ipc.DimNames {
				msg.DimScore[i], _ = strconv.ParseFloat(e.Metadata["dim_"+name], 64)
			}
			cp.OnProcessState(msg)
			states++
		case "zone_transition":
			to := zone[e.Metadata["to_zone"]]
			cp.OnZoneTransition(&ipc.ZoneTransitionMsg{PID: e.Pid, StartTimeNs: start[e.Pid], FromZone: zone[e.Metadata["from_zone"]],
				ToZone: to, Score: e.ScoreDelta, TsNs: e.Ts})
			feedTransitions[fmt.Sprintf("%d:%s", e.Pid, to)] = true
			transitions++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	rows, err := cp.store.DB().Query(`SELECT action, subject FROM audit_log WHERE action LIKE 'ZONE_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type row struct {
		Pid         uint32 `json:"pid"`
		Action      string `json:"action"`
		Synthesised bool   `json:"synthesised"`
	}
	var audit []row
	for rows.Next() {
		var action, subject string
		if err := rows.Scan(&action, &subject); err != nil {
			t.Fatal(err)
		}
		var pid uint32
		if i := strings.Index(subject, "pid="); i >= 0 {
			v, _ := strconv.ParseUint(strings.Fields(subject[i+4:])[0], 10, 32)
			pid = uint32(v)
		}
		to := action[strings.LastIndex(action, "_TO_")+4:]
		audit = append(audit, row{Pid: pid, Action: action, Synthesised: !feedTransitions[fmt.Sprintf("%d:%s", pid, zone[to])]})
	}
	// containment decisions: observe-only turns them into OBSERVE_ONLY_WOULD_* entries, the allowlist into ALLOWLIST_EXEMPT_*
	crows, err := cp.store.DB().Query(`SELECT action, subject FROM audit_log WHERE action LIKE 'OBSERVE_ONLY_WOULD_%' OR action LIKE 'ALLOWLIST_EXEMPT_%' OR action LIKE 'CWP_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer crows.Close()
	type crow struct {
		Pid     uint32 `json:"pid"`
		Action  string `json:"action"`
		Subject string `json:"subject"`
	}
	var contain []crow
	for crows.Next() {
		var action, subject string
		if err := crows.Scan(&action, &subject); err != nil {
			t.Fatal(err)
		}
		var pid uint32
		if i := strings.Index(subject, "pid="); i >= 0 {
			v, _ := strconv.ParseUint(strings.Fields(subject[i+4:])[0], 10, 32)
			pid = uint32(v)
		}
		contain = append(contain, crow{Pid: pid, Action: action, Subject: subject})
	}
	var alertPids []uint32
	for len(alerts) > 0 {
		alertPids = append(alertPids, (<-alerts).Pid)
	}
	stale, first := cp.TransitionCounters()
	drops, _ := cp.FanoutDrops()
	out := map[string]any{"events_file": in, "states": states, "transitions": transitions, "audit": audit, "borderlands_alert_pids": alertPids,
		"containment_decisions": contain, "first_sight_transitions": first, "stale_skipped": stale, "fanout_drops": drops}
	if p := os.Getenv("KB_REPLAY_OUT"); p != "" {
		b, _ := json.Marshal(out)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("replayed %d states and %d transitions: %d audit rows (%d synthesised), %d BORDERLANDS alerts, stale=%d", states, transitions, len(audit), first, len(alertPids), stale)
}
