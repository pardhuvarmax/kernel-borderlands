package audit

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts_ns      INTEGER NOT NULL,
			action     TEXT    NOT NULL,
			subject    TEXT    NOT NULL,
			actor      TEXT    NOT NULL DEFAULT 'SYSTEM',
			reason     TEXT    NOT NULL DEFAULT '',
			prev_hash  TEXT    NOT NULL,
			entry_hash TEXT    NOT NULL UNIQUE
		)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func TestVerifyChainIntactAfterLogging(t *testing.T) {
	db := newTestDB(t)
	a := New(db)
	if err := a.Log("ACTION_A", "subj", "actor", "reason"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := a.Log("ACTION_B", "subj2", "actor", "reason2"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	ok, count, err := a.VerifyChain()
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok || count != 2 {
		t.Errorf("got ok=%v count=%d, want true/2", ok, count)
	}
}

func TestVerifyChainDetectsTamperedHash(t *testing.T) {
	db := newTestDB(t)
	a := New(db)
	a.Log("ACTION_A", "subj", "actor", "reason")

	if _, err := db.Exec(`UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}

	ok, _, err := a.VerifyChain()
	if ok {
		t.Errorf("expected chain_intact=false after tampering with entry_hash directly (err=%v)", err)
	}
}

// BUG-005 regression: VerifyChain used to discard rows.Scan()'s error, so a
// scan failure (unexpected type, corrupted row) would fall through to
// hashing zero-valued fields and reporting a misleading "chain broken"
// verdict instead of surfacing the real I/O/schema error.
func TestVerifyChainReturnsScanErrorNotFalseTamperVerdict(t *testing.T) {
	db := newTestDB(t)
	a := New(db)
	a.Log("ACTION_A", "subj", "actor", "reason")

	// ts_ns has INTEGER affinity, but SQLite still accepts a non-numeric
	// TEXT value verbatim when it can't be losslessly converted — scanning
	// that into the Go int64 var in VerifyChain fails.
	if _, err := db.Exec(`UPDATE audit_log SET ts_ns = 'not-a-number' WHERE id = 1`); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}

	ok, _, err := a.VerifyChain()
	if err == nil {
		t.Fatal("expected a scan error to be returned, got nil error")
	}
	if ok {
		t.Error("got chain_intact=true on a scan failure, want false")
	}
	// Distinguish this from the "chain broken" tamper verdict: pre-fix,
	// the discarded Scan error would fall through to hashing zero-valued
	// fields and reporting a hash mismatch instead of the real cause.
	if got := err.Error(); got == "chain broken at entry 1" {
		t.Errorf("got the generic tamper-mismatch message %q, want the underlying Scan error surfaced instead", got)
	}
}

// ---- rows.Err() regression (BUG-005's other half) -----------------------
//
// The Scan-error path above was already handled correctly before this fix.
// The actual gap: sql.Rows.Next() returns false both on ordinary
// exhaustion AND on a genuine driver/cursor-level error mid-iteration —
// the real error in the latter case is only available via rows.Err(),
// called AFTER the loop exits, which VerifyChain never did. Reproducing
// that specific failure mode needs a fault-injecting driver.Rows wrapper,
// since go-sqlite3's in-memory backend has no built-in way to fail an
// in-progress cursor read.

type errInjectingRows struct {
	driver.Rows
	failAfter int
	seen      int
}

func (r *errInjectingRows) Next(dest []driver.Value) error {
	if r.seen >= r.failAfter {
		return errors.New("injected cursor I/O error")
	}
	r.seen++
	return r.Rows.Next(dest)
}

type errInjectingStmt struct {
	driver.Stmt
	failAfter int
}

func (s *errInjectingStmt) Query(args []driver.Value) (driver.Rows, error) {
	rows, err := s.Stmt.Query(args)
	if err != nil {
		return nil, err
	}
	return &errInjectingRows{Rows: rows, failAfter: s.failAfter}, nil
}

type errInjectingConn struct {
	driver.Conn
	failAfter int
}

func (c *errInjectingConn) Prepare(query string) (driver.Stmt, error) {
	stmt, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &errInjectingStmt{Stmt: stmt, failAfter: c.failAfter}, nil
}

type errInjectingDriver struct {
	driver.Driver
	failAfter int
}

func (d *errInjectingDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	return &errInjectingConn{Conn: conn, failAfter: d.failAfter}, nil
}

func init() {
	// failAfter=1: the first row scans normally, the second Next() call
	// (which would fetch row 2) fails instead — exactly the "error
	// mid-cursor, not at exhaustion" shape rows.Err() exists to surface.
	sql.Register("sqlite3_errinject", &errInjectingDriver{Driver: &sqlite3.SQLiteDriver{}, failAfter: 1})
}

func TestVerifyChainSurfacesCursorErrorInsteadOfFalseSuccess(t *testing.T) {
	db, err := sql.Open("sqlite3_errinject", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`
		CREATE TABLE audit_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts_ns      INTEGER NOT NULL,
			action     TEXT    NOT NULL,
			subject    TEXT    NOT NULL,
			actor      TEXT    NOT NULL DEFAULT 'SYSTEM',
			reason     TEXT    NOT NULL DEFAULT '',
			prev_hash  TEXT    NOT NULL,
			entry_hash TEXT    NOT NULL UNIQUE
		)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	a := New(db)
	if err := a.Log("ACTION_A", "subj", "actor", "reason"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := a.Log("ACTION_B", "subj2", "actor", "reason2"); err != nil {
		t.Fatalf("Log: %v", err)
	}

	ok, count, err := a.VerifyChain()
	if err == nil {
		t.Fatal("expected the injected cursor error to be returned via rows.Err(), got nil error")
	}
	if ok {
		t.Errorf("got chain_intact=true (count=%d) on a genuine cursor I/O error — this is the false-confidence bug BUG-005's rows.Err() fix closes: an interrupted scan must never be reported as a clean, complete verification", count)
	}
}
