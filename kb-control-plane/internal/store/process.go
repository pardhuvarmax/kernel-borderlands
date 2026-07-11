package store

import (
	"log"

	"github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

// CachedState is the L1, in-memory mirror of a process_state row — the
// authoritative live copy per ADR-1. SQLite is the durable async copy,
// consulted only for audit/history/recovery, never on the hot path.
type CachedState struct {
	PID, PPID, UID             uint32
	Comm                       string
	StartTimeNs, LastUpdatedNs uint64
	DimScore                   [ipc.DimCount]float64
	CompositeScore             float64
	EMAScore                   float64
	SyscallEntropyLifetime     float64
	Zone                       ipc.KBZone
	EventCount                 uint32
	Containment                int32
}

const l2FlushBuffer = 4096

type zoneTransitionWrite struct {
	msg  *ipc.ZoneTransitionMsg
	comm string
}
type removeWrite struct{ pid uint32 }
type containmentWrite struct {
	pid   uint32
	level int32
}

func (s *Store) initL1() {
	s.l2Pipe = make(chan any, l2FlushBuffer)
	go s.flushL2Worker()
}

// flushL2Worker drains async writes to SQLite off the hot path. A single
// goroutine keeps writes serialized, consistent with SetMaxOpenConns(1).
func (s *Store) flushL2Worker() {
	defer close(s.l2Done)
	for item := range s.l2Pipe {
		var err error
		switch v := item.(type) {
		case *ipc.ProcessStateMsg:
			err = s.upsertProcessStateSQL(v)
		case zoneTransitionWrite:
			err = s.insertZoneTransitionSQL(v.msg, v.comm)
		case removeWrite:
			_, err = s.db.Exec(`DELETE FROM process_state WHERE pid=?`, v.pid)
		case containmentWrite:
			_, err = s.db.Exec(`UPDATE process_state SET containment=? WHERE pid=?`, v.level, v.pid)
		}
		if err != nil {
			log.Printf("[Store] L2 flush error: %v", err)
		}
	}
}

// UpsertProcessState updates L1 synchronously (the hot path the IPC
// ingestion loop calls on every ProcessState message) and enqueues the
// durable SQLite write asynchronously. Never blocks on disk I/O; if the
// pipe is full, L1 remains correct and only the durable copy lags.
func (s *Store) UpsertProcessState(msg *ipc.ProcessStateMsg) error {
	s.l1.Store(msg.PID, &CachedState{
		PID: msg.PID, PPID: msg.PPID, UID: msg.UID, Comm: msg.Comm,
		StartTimeNs: msg.StartTimeNs, LastUpdatedNs: msg.LastUpdatedNs,
		DimScore: msg.DimScore, CompositeScore: msg.CompositeScore,
		EMAScore: msg.EMAScore, SyscallEntropyLifetime: msg.SyscallEntropyLifetime,
		Zone: msg.Zone, EventCount: msg.EventCount,
	})

	select {
	case s.l2Pipe <- msg:
	default:
		log.Printf("[Store] L2 pipe full — durable write dropped for pid=%d (L1 still authoritative)", msg.PID)
	}
	return nil
}

func (s *Store) upsertProcessStateSQL(msg *ipc.ProcessStateMsg) error {
	_, err := s.db.Exec(`
        INSERT INTO process_state
            (pid,ppid,comm,uid,start_time_ns,last_updated_ns,
             dim_process,dim_syscall,dim_privilege,dim_file,dim_network,dim_memory,
             composite_score,ema_score,syscall_entropy_lifetime,zone,event_count)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(pid) DO UPDATE SET
            ppid=excluded.ppid, comm=excluded.comm, uid=excluded.uid,
            start_time_ns=excluded.start_time_ns, last_updated_ns=excluded.last_updated_ns,
            dim_process=excluded.dim_process, dim_syscall=excluded.dim_syscall,
            dim_privilege=excluded.dim_privilege, dim_file=excluded.dim_file,
            dim_network=excluded.dim_network, dim_memory=excluded.dim_memory,
            composite_score=excluded.composite_score, ema_score=excluded.ema_score,
            syscall_entropy_lifetime=excluded.syscall_entropy_lifetime,
            zone=excluded.zone, event_count=excluded.event_count
    `,
		msg.PID, msg.PPID, msg.Comm, msg.UID,
		msg.StartTimeNs, msg.LastUpdatedNs,
		msg.DimScore[0], msg.DimScore[1], msg.DimScore[2],
		msg.DimScore[3], msg.DimScore[4], msg.DimScore[5],
		msg.CompositeScore, msg.EMAScore, msg.SyscallEntropyLifetime,
		int(msg.Zone), msg.EventCount,
	)
	return err
}

// RemoveProcess evicts from L1 immediately; the durable delete is async.
func (s *Store) RemoveProcess(pid uint32) error {
	s.l1.Delete(pid)
	select {
	case s.l2Pipe <- removeWrite{pid: pid}:
	default:
	}
	return nil
}

// InsertZoneTransition updates L1's zone view synchronously and queues the
// durable audit-trail row asynchronously.
func (s *Store) InsertZoneTransition(msg *ipc.ZoneTransitionMsg, comm string) error {
	if v, ok := s.l1.Load(msg.PID); ok {
		updated := *v.(*CachedState)
		updated.Zone = msg.ToZone
		s.l1.Store(msg.PID, &updated)
	}

	select {
	case s.l2Pipe <- zoneTransitionWrite{msg: msg, comm: comm}:
	default:
		log.Printf("[Store] L2 pipe full — zone_transition audit row dropped for pid=%d", msg.PID)
	}
	return nil
}

func (s *Store) insertZoneTransitionSQL(msg *ipc.ZoneTransitionMsg, comm string) error {
	_, err := s.db.Exec(`
        INSERT INTO zone_transitions
            (pid, start_time_ns, comm, from_zone, to_zone, ema_score, ts_ns)
        VALUES (?,?,?,?,?,?,?)
    `, msg.PID, msg.StartTimeNs, comm, int(msg.FromZone), int(msg.ToZone), msg.Score, msg.TsNs)
	return err
}

// VerifyStartTime is the PID-reuse guard. L1 is checked first — the ~30-50ns
// hot path, since it holds the live authoritative copy. SQLite is only
// consulted on an L1 miss (e.g. immediately after a restart, before Restore
// has run or for a PID the daemon never saw a ProcessState message for).
func (s *Store) VerifyStartTime(pid uint32, startTimeNs uint64) (bool, error) {
	if v, ok := s.l1.Load(pid); ok {
		return v.(*CachedState).StartTimeNs == startTimeNs, nil
	}
	var stored uint64
	err := s.db.QueryRow(`SELECT start_time_ns FROM process_state WHERE pid=?`, pid).Scan(&stored)
	if err != nil {
		return false, err
	}
	return stored == startTimeNs, nil
}

// GetProcessState serves reads from L1 only — this is what grpc.go's
// GetProcessState RPC now calls instead of querying SQLite per request.
func (s *Store) GetProcessState(pid uint32) (*CachedState, bool) {
	v, ok := s.l1.Load(pid)
	if !ok {
		return nil, false
	}
	return v.(*CachedState), true
}

// ListZone serves reads from L1. O(n) over tracked processes — acceptable
// here since this backs the operator/dashboard RPC, not the ingestion path.
func (s *Store) ListZone(zone ipc.KBZone) []*CachedState {
	var out []*CachedState
	s.l1.Range(func(_, v any) bool {
		if cs := v.(*CachedState); cs.Zone == zone {
			out = append(out, cs)
		}
		return true
	})
	return out
}

// SetContainment updates L1 synchronously and queues the durable write —
// used by the operator SetContainment RPC.
func (s *Store) SetContainment(pid uint32, level int32) {
	if v, ok := s.l1.Load(pid); ok {
		updated := *v.(*CachedState)
		updated.Containment = level
		s.l1.Store(pid, &updated)
	}
	select {
	case s.l2Pipe <- containmentWrite{pid: pid, level: level}:
	default:
	}
}

// Restore performs the cold-start recovery sweep from ADR-1's "Volatile
// Memory Risk" mitigation: rebuild L1 from the last durable SQLite state
// before the eBPF ingestion hook goes live, so VerifyStartTime/reads don't
// wrongly miss for processes the daemon was already tracking pre-restart.
func (s *Store) Restore() error {
	rows, err := s.db.Query(`
        SELECT pid,ppid,comm,uid,start_time_ns,last_updated_ns,
               dim_process,dim_syscall,dim_privilege,dim_file,dim_network,dim_memory,
               composite_score,ema_score,syscall_entropy_lifetime,zone,event_count,containment
        FROM process_state
    `)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var cs CachedState
		var zone int
		if err := rows.Scan(
			&cs.PID, &cs.PPID, &cs.Comm, &cs.UID, &cs.StartTimeNs, &cs.LastUpdatedNs,
			&cs.DimScore[0], &cs.DimScore[1], &cs.DimScore[2], &cs.DimScore[3], &cs.DimScore[4], &cs.DimScore[5],
			&cs.CompositeScore, &cs.EMAScore, &cs.SyscallEntropyLifetime, &zone, &cs.EventCount, &cs.Containment,
		); err != nil {
			log.Printf("[Store] restore scan: %v", err)
			continue
		}
		cs.Zone = ipc.KBZone(zone)
		s.l1.Store(cs.PID, &cs)
		count++
	}
	log.Printf("[Store] L1 restored from L2: %d processes", count)
	return nil
}

// ListAll returns all processes currently tracked in L1 memory.
func (s *Store) ListAll() []*CachedState {
	var out []*CachedState
	s.l1.Range(func(_, v any) bool {
		out = append(out, v.(*CachedState))
		return true
	})
	return out
}