package store

import (
	"database/sql"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS process_state (
    pid                      INTEGER PRIMARY KEY,
    ppid                     INTEGER NOT NULL DEFAULT 0,
    comm                     TEXT    NOT NULL DEFAULT '',
    uid                      INTEGER NOT NULL DEFAULT 0,
    start_time_ns            INTEGER NOT NULL DEFAULT 0,
    last_updated_ns          INTEGER NOT NULL DEFAULT 0,
    dim_process              REAL    NOT NULL DEFAULT 0,
    dim_syscall              REAL    NOT NULL DEFAULT 0,
    dim_privilege            REAL    NOT NULL DEFAULT 0,
    dim_file                 REAL    NOT NULL DEFAULT 0,
    dim_network              REAL    NOT NULL DEFAULT 0,
    dim_memory               REAL    NOT NULL DEFAULT 0,
    composite_score          REAL    NOT NULL DEFAULT 0,
    ema_score                REAL    NOT NULL DEFAULT 0,
    syscall_entropy_lifetime REAL    NOT NULL DEFAULT 0,
    zone                     INTEGER NOT NULL DEFAULT 0,
    event_count              INTEGER NOT NULL DEFAULT 0,
    containment              INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS zone_transitions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    pid           INTEGER NOT NULL,
    start_time_ns INTEGER NOT NULL DEFAULT 0,
    comm          TEXT    NOT NULL DEFAULT '',
    from_zone     INTEGER NOT NULL,
    to_zone       INTEGER NOT NULL,
    ema_score     REAL    NOT NULL,
    ts_ns         INTEGER NOT NULL,
    actioned      INTEGER NOT NULL DEFAULT 0,
    action_taken  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ns      INTEGER NOT NULL,
    action     TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    actor      TEXT    NOT NULL DEFAULT 'SYSTEM',
    reason     TEXT    NOT NULL DEFAULT '',
    prev_hash  TEXT    NOT NULL,
    entry_hash TEXT    NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_ps_zone   ON process_state(zone);
CREATE INDEX IF NOT EXISTS idx_zt_pid    ON zone_transitions(pid);
CREATE INDEX IF NOT EXISTS idx_zt_ts     ON zone_transitions(ts_ns);
CREATE INDEX IF NOT EXISTS idx_audit_ts  ON audit_log(ts_ns);
`

// Store implements ADR-1's two-tier architecture:
//   L1 — sync.Map, authoritative for live enforcement (~30-50ns access)
//   L2 — SQLite (WAL), durable persistence/audit/history, async cold path
//
// No enforcement decision may synchronously depend on disk I/O — every
// method below that's on the ingestion hot path writes L1 first and
// enqueues the durable write; reads that back enforcement (VerifyStartTime,
// GetProcessState, ListZone) are served from L1 only.
type Store struct {
	db *sql.DB

	l1     sync.Map // pid uint32 -> *CachedState
	l2Pipe chan any // async write-behind queue to SQLite
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA temp_store=MEMORY;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, err
		}
	}

	if _, err = db.Exec(schema); err != nil {
		return nil, err
	}

	// Single-writer discipline (ADR-1 §3): removes file-lock contention on
	// the async flush worker. Concurrent readers (dashboard, kb-aads) still
	// work via WAL's shared-memory (-shm) reads.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	s := &Store{db: db}
	s.initL1()

	log.Printf("[Store] Ready: %s (L1/L2 hybrid, WAL)", path)
	return s, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() {
	close(s.l2Pipe)
	s.db.Close()
}