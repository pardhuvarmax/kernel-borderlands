package audit

import (
    "crypto/sha256"
    "database/sql"
    "fmt"
    "log"
    "sync"
    "time"

    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

type Logger struct {
    db       *sql.DB
    mu       sync.Mutex
    prevHash string
}

func New(db *sql.DB) *Logger {
    a := &Logger{db: db, prevHash: "genesis"}
    var h string
    if err := db.QueryRow(
        `SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`,
    ).Scan(&h); err == nil {
        a.prevHash = h
    }
    return a
}

func (a *Logger) Log(action, subject, actor, reason string) error {
    a.mu.Lock()
    defer a.mu.Unlock()

    ts := time.Now().UnixNano()
    content := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
        ts, action, subject, actor, reason, a.prevHash)
    hash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))

    _, err := a.db.Exec(`
        INSERT INTO audit_log (ts_ns,action,subject,actor,reason,prev_hash,entry_hash)
        VALUES (?,?,?,?,?,?,?)
    `, ts, action, subject, actor, reason, a.prevHash, hash)
    if err != nil { return err }

    log.Printf("[AUDIT] %s | %s | %s...", action, subject, hash[:16])
    a.prevHash = hash
    return nil
}

func (a *Logger) LogZoneTransition(msg *ipc.ZoneTransitionMsg, comm string) error {
    action  := fmt.Sprintf("ZONE_%s_TO_%s", msg.FromZone, msg.ToZone)
    subject := fmt.Sprintf("pid=%d comm=%s score=%.2f start_ns=%d",
        msg.PID, comm, msg.Score, msg.StartTimeNs)
    return a.Log(action, subject, "SYSTEM_AUTO", "behavioral_threshold")
}

func (a *Logger) VerifyChain() (bool, int, error) {
    rows, err := a.db.Query(`
        SELECT ts_ns,action,subject,actor,reason,prev_hash,entry_hash
        FROM audit_log ORDER BY id ASC
    `)
    if err != nil { return false, 0, err }
    defer rows.Close()

    prev, count := "genesis", 0
    for rows.Next() {
        var ts int64
        var action, subject, actor, reason, prevH, entryH string
        rows.Scan(&ts, &action, &subject, &actor, &reason, &prevH, &entryH)

        content := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
            ts, action, subject, actor, reason, prev)
        expected := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
        if expected != entryH {
            return false, count, fmt.Errorf("chain broken at entry %d", count+1)
        }
        prev = entryH
        count++
    }
    return true, count, nil
}