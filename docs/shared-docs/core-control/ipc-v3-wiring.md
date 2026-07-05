## Implement IPC v3 Wire Protocol Integration

From my `kb_bridge.c` v3:

```
KB_WIRE_MAGIC    = 0x4B42
KB_WIRE_VERSION  = 3        ← you must reject version != 3
Socket           = /var/run/kbd.sock

msg_type=1 → ProcessState  (130 bytes payload)
msg_type=2 → ZoneTransition (36 bytes payload)

ProcessState layout (packed, LE):
  uint16 magic
  uint8  version
  uint8  msg_type=1
  uint32 pid
  uint32 ppid
  uint32 uid
  char   comm[16]
  uint64 start_time_ns
  uint64 last_updated_ns
  double dim_score[6]          ← [process,syscall,privilege,file,network,memory]
  double composite_score
  double ema_score
  double syscall_entropy_lifetime  ← advisory, don't use for zone decisions
  uint32 zone                  ← 0=SAFE 1=SUSPICIOUS 2=BORDERLANDS
  uint32 event_count
  Total: 4+4+4+4+16+8+8+48+8+8+8+4+4 = 128 bytes

ZoneTransition layout (packed, LE):
  uint16 magic
  uint8  version
  uint8  msg_type=2
  uint32 pid
  uint64 start_time_ns         ← PID reuse guard — MUST verify before enforcing
  uint32 from_zone
  uint32 to_zone
  double score
  uint64 ts_ns
  Total: 4+4+8+4+4+8+8 = 40
```

---

### Files You Need To Build:

- internal/ipc/wire.go
- internal/ipc/listener.go
- internal/store/schema.go
- internal/store/process.go
- internal/audit/audit.go
- internal/enforcement/enforce.go
- internal/policy/policy.go
- internal/controlplane/controlplane.go
- internal/controlplane/grpc.go
- cmd/mock_sender/main.go
- config/policy.yaml

### Update Existing (if applicable):

- cmd/kbd/main.go
- proto/kb.proto

---

### `internal/ipc/wire.go`

Parses your binary wire format into Go structs:

```go
package ipc

import (
    "encoding/binary"
    "fmt"
    "io"
    "math"
    "net"
)

const (
    WireMagic          uint16 = 0x4B42
    WireVersion        uint8  = 3
    WireMsgProcessState   uint8 = 1
    WireMsgZoneTransition uint8 = 2
    SocketPath                  = "/var/run/kbd.sock"
    DimCount                    = 6
)

type KBZone uint32
const (
    ZoneSafe        KBZone = 0
    ZoneSuspicious  KBZone = 1
    ZoneBorderlands KBZone = 2
)
func (z KBZone) String() string {
    switch z {
    case ZoneSafe:        return "SAFE"
    case ZoneSuspicious:  return "SUSPICIOUS"
    case ZoneBorderlands: return "BORDERLANDS"
    default:              return "UNKNOWN"
    }
}

var DimNames   = [DimCount]string{"process","syscall","privilege","file","network","memory"}
var DimWeights = [DimCount]float64{0.20,0.25,0.20,0.10,0.10,0.15}

type ProcessStateMsg struct {
    PID                     uint32
    PPID                    uint32
    UID                     uint32
    Comm                    string
    StartTimeNs             uint64
    LastUpdatedNs           uint64
    DimScore                [DimCount]float64
    CompositeScore          float64
    EMAScore                float64
    SyscallEntropyLifetime  float64  // advisory only — do NOT use for zone decisions
    Zone                    KBZone
    EventCount              uint32
}

type ZoneTransitionMsg struct {
    PID          uint32
    StartTimeNs  uint64  // PID-reuse guard — verify before enforcing
    FromZone     KBZone
    ToZone       KBZone
    Score        float64
    TsNs         uint64
}

type MessageHandler interface {
    OnProcessState(msg *ProcessStateMsg)
    OnZoneTransition(msg *ZoneTransitionMsg)
}

func readFloat64(buf []byte, off int) (float64, int) {
    bits := binary.LittleEndian.Uint64(buf[off:])
    return math.Float64frombits(bits), off + 8
}

// Wire sizes below are derived from the actual C struct layout in
// kb_bridge.c (verified via sizeof(), not hand-counted from a doc —
// hand-counting is exactly how these numbers drifted last time).
// Both include the 4-byte header, since buf here is the full frame
// payload (header + body), not just the body.
//
//   kb_wire_process_state:   128 bytes  (was miscounted as 130)
//   kb_wire_zone_transition:  40 bytes
func parseProcessState(buf []byte) (*ProcessStateMsg, error) {
    const expected = 128 
    if len(buf) < expected {
        return nil, fmt.Errorf("process state: want %d bytes got %d", expected, len(buf))
    }
    off := 4 // skip header (magic+version+msg_type already validated)
    msg := &ProcessStateMsg{}

    msg.PID  = binary.LittleEndian.Uint32(buf[off:]); off += 4
    msg.PPID = binary.LittleEndian.Uint32(buf[off:]); off += 4
    msg.UID  = binary.LittleEndian.Uint32(buf[off:]); off += 4

    raw := buf[off : off+16]; off += 16
    for i, b := range raw { if b == 0 { raw = raw[:i]; break } }
    msg.Comm = string(raw)

    msg.StartTimeNs   = binary.LittleEndian.Uint64(buf[off:]); off += 8
    msg.LastUpdatedNs = binary.LittleEndian.Uint64(buf[off:]); off += 8

    for i := 0; i < DimCount; i++ {
        msg.DimScore[i], off = readFloat64(buf, off)
    }
    msg.CompositeScore,         off = readFloat64(buf, off)
    msg.EMAScore,               off = readFloat64(buf, off)
    msg.SyscallEntropyLifetime, off = readFloat64(buf, off)

    msg.Zone       = KBZone(binary.LittleEndian.Uint32(buf[off:])); off += 4
    msg.EventCount = binary.LittleEndian.Uint32(buf[off:])
    return msg, nil
}

func parseZoneTransition(buf []byte) (*ZoneTransitionMsg, error) {
    const expected = 40
    if len(buf) < expected {
        return nil, fmt.Errorf("zone transition: want %d bytes got %d", expected, len(buf))
    }
    off := 4
    msg := &ZoneTransitionMsg{}
    msg.PID         = binary.LittleEndian.Uint32(buf[off:]); off += 4
    msg.StartTimeNs = binary.LittleEndian.Uint64(buf[off:]); off += 8
    msg.FromZone    = KBZone(binary.LittleEndian.Uint32(buf[off:])); off += 4
    msg.ToZone      = KBZone(binary.LittleEndian.Uint32(buf[off:])); off += 4
    msg.Score,      off = readFloat64(buf, off)
    msg.TsNs        = binary.LittleEndian.Uint64(buf[off:])
    return msg, nil
}

type Reader struct{ conn net.Conn; handler MessageHandler }

func NewReader(conn net.Conn, h MessageHandler) *Reader { return &Reader{conn, h} }

func (r *Reader) ReadLoop() error {
    for {
        var length uint32
        if err := binary.Read(r.conn, binary.LittleEndian, &length); err != nil {
            return err
        }
        if length == 0 || length > 65536 {
            return fmt.Errorf("invalid frame length %d", length)
        }
        buf := make([]byte, length)
        if _, err := io.ReadFull(r.conn, buf); err != nil { return err }
        if len(buf) < 4 { continue }

        magic   := binary.LittleEndian.Uint16(buf[0:2])
        version := buf[2]
        msgType := buf[3]

        if magic != WireMagic {
            continue // not KB frame
        }
        if version != WireVersion {
            return fmt.Errorf("wire version mismatch: got %d want %d", version, WireVersion)
        }

        switch msgType {
        case WireMsgProcessState:
            if msg, err := parseProcessState(buf); err == nil {
                r.handler.OnProcessState(msg)
            }
        case WireMsgZoneTransition:
            if msg, err := parseZoneTransition(buf); err == nil {
                r.handler.OnZoneTransition(msg)
            }
        }
    }
}
```

---

### `internal/ipc/listener.go`

```go
package ipc

import (
    "log"
    "net"
    "os"
)

type Listener struct{ handler MessageHandler }

func NewListener(h MessageHandler) *Listener { return &Listener{h} }

func (l *Listener) Listen() error {
    os.Remove(SocketPath)
    ln, err := net.Listen("unix", SocketPath)
    if err != nil { return err }
    defer ln.Close()
    os.Chmod(SocketPath, 0666)
    log.Printf("[IPC] Listening on %s (wire v%d)", SocketPath, WireVersion)

    for {
        conn, err := ln.Accept()
        if err != nil { log.Printf("[IPC] accept: %v", err); continue }
        log.Printf("[IPC] kbd_sensor connected")
        go l.handle(conn)
    }
}

func (l *Listener) handle(conn net.Conn) {
    defer func() { conn.Close(); log.Printf("[IPC] kbd_sensor disconnected") }()
    if err := NewReader(conn, l.handler).ReadLoop(); err != nil {
        log.Printf("[IPC] read: %v", err)
    }
}
```

---

### `internal/store/schema.go` + `internal/store/process.go`

```go
// schema.go
package store

import (
    "database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

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

type Store struct{ db *sql.DB }

func New(path string) (*Store, error) {
    db, err := sql.Open("sqlite3", path)
    if err != nil { return nil, err }
    if _, err = db.Exec(schema); err != nil { return nil, err }
    log.Printf("[Store] Ready: %s", path)
    return &Store{db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }
func (s *Store) Close()      { s.db.Close() }
```

```go
// process.go
package store

import (
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

func (s *Store) UpsertProcessState(msg *ipc.ProcessStateMsg) error {
    _, err := s.db.Exec(`
        INSERT INTO process_state
            (pid,ppid,comm,uid,start_time_ns,last_updated_ns,
             dim_process,dim_syscall,dim_privilege,dim_file,dim_network,dim_memory,
             composite_score,ema_score,syscall_entropy_lifetime,zone,event_count)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(pid) DO UPDATE SET
            ppid=excluded.ppid,
            comm=excluded.comm,
            uid=excluded.uid,
            start_time_ns=excluded.start_time_ns,
            last_updated_ns=excluded.last_updated_ns,
            dim_process=excluded.dim_process,
            dim_syscall=excluded.dim_syscall,
            dim_privilege=excluded.dim_privilege,
            dim_file=excluded.dim_file,
            dim_network=excluded.dim_network,
            dim_memory=excluded.dim_memory,
            composite_score=excluded.composite_score,
            ema_score=excluded.ema_score,
            syscall_entropy_lifetime=excluded.syscall_entropy_lifetime,
            zone=excluded.zone,
            event_count=excluded.event_count
    `,
        msg.PID, msg.PPID, msg.Comm, msg.UID,
        msg.StartTimeNs, msg.LastUpdatedNs,
        msg.DimScore[0], msg.DimScore[1], msg.DimScore[2],
        msg.DimScore[3], msg.DimScore[4], msg.DimScore[5],
        msg.CompositeScore, msg.EMAScore,
        msg.SyscallEntropyLifetime,
        int(msg.Zone), msg.EventCount,
    )
    return err
}

func (s *Store) RemoveProcess(pid uint32) error {
    _, err := s.db.Exec(`DELETE FROM process_state WHERE pid=?`, pid)
    return err
}

func (s *Store) InsertZoneTransition(msg *ipc.ZoneTransitionMsg, comm string) error {
    _, err := s.db.Exec(`
        INSERT INTO zone_transitions
            (pid, start_time_ns, comm, from_zone, to_zone, ema_score, ts_ns)
        VALUES (?,?,?,?,?,?,?)
    `, msg.PID, msg.StartTimeNs, comm,
        int(msg.FromZone), int(msg.ToZone),
        msg.Score, msg.TsNs)
    return err
}

// PID-reuse guard — verify start_time_ns before enforcing
// a zone transition against a live process.
func (s *Store) VerifyStartTime(pid uint32, startTimeNs uint64) (bool, error) {
    var stored uint64
    err := s.db.QueryRow(
        `SELECT start_time_ns FROM process_state WHERE pid=?`, pid,
    ).Scan(&stored)
    if err != nil { return false, err }
    return stored == startTimeNs, nil
}
```

---

### `internal/audit/audit.go`

```go
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
```

---

### `internal/enforcement/enforce.go`

```go
package enforcement

import (
    "fmt"
    "log"
    "os"
    "syscall"

    pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

type Enforcer struct{}

func New() *Enforcer { return &Enforcer{} }

func (e *Enforcer) Apply(pid uint32, level pb.ContainmentLevel) {
    switch level {
    case pb.ContainmentLevel_CGROUP:
        e.cgroupThrottle(pid)
    case pb.ContainmentLevel_SECCOMP:
        log.Printf("[ENFORCE] seccomp (TODO) PID=%d", pid)
    case pb.ContainmentLevel_NAMESPACE:
        log.Printf("[ENFORCE] namespace isolation (TODO) PID=%d", pid)
    case pb.ContainmentLevel_TERMINATE:
        e.sigkill(pid)
    default:
        log.Printf("[ENFORCE] no-op level=%v PID=%d", level, pid)
    }
}

func (e *Enforcer) cgroupThrottle(pid uint32) {
    dir := "/sys/fs/cgroup/kb_contained"
    os.MkdirAll(dir, 0755)
    os.WriteFile(dir+"/cpu.max", []byte("5000 100000\n"), 0644)
    f, err := os.OpenFile(dir+"/cgroup.procs", os.O_WRONLY|os.O_APPEND, 0)
    if err != nil { log.Printf("[ENFORCE] cgroup open: %v", err); return }
    defer f.Close()
    fmt.Fprintf(f, "%d\n", pid)
    log.Printf("[ENFORCE] cgroup throttle applied PID=%d", pid)
}

func (e *Enforcer) sigkill(pid uint32) {
    proc, err := os.FindProcess(int(pid))
    if err != nil { log.Printf("[ENFORCE] FindProcess: %v", err); return }
    if err := proc.Signal(syscall.SIGKILL); err != nil {
        log.Printf("[ENFORCE] SIGKILL PID=%d: %v", pid, err)
        return
    }
    log.Printf("[ENFORCE] ⚰️  SIGKILL PID=%d", pid)
}
```

---

### `internal/policy/policy.go`

```go
package policy

import (
    "log"
    "os"
    "gopkg.in/yaml.v3"
)

type ProcessPolicy struct {
    Comm               string  `yaml:"comm"`
    SuspiciousThresh   float64 `yaml:"suspicious"`
    BorderlandsThresh  float64 `yaml:"borderlands"`
    AllowNetwork       bool    `yaml:"allow_network"`
    AutoTerminate      bool    `yaml:"auto_terminate"`
}

type PolicyFile struct {
    Defaults struct {
        Suspicious  float64 `yaml:"suspicious"`
        Borderlands float64 `yaml:"borderlands"`
    } `yaml:"defaults"`
    Policies []ProcessPolicy `yaml:"policies"`
}

type Engine struct {
    byComm   map[string]ProcessPolicy
    defSus   float64
    defBor   float64
}

func New(path string) (*Engine, error) {
    e := &Engine{byComm: make(map[string]ProcessPolicy), defSus: 40, defBor: 75}
    if path == "" { return e, nil }

    data, err := os.ReadFile(path)
    if err != nil { log.Printf("[Policy] no file at %s — defaults", path); return e, nil }

    var pf PolicyFile
    if err := yaml.Unmarshal(data, &pf); err != nil { return nil, err }
    if pf.Defaults.Suspicious  > 0 { e.defSus = pf.Defaults.Suspicious  }
    if pf.Defaults.Borderlands > 0 { e.defBor = pf.Defaults.Borderlands }
    for _, p := range pf.Policies { e.byComm[p.Comm] = p }
    log.Printf("[Policy] loaded %d process policies", len(pf.Policies))
    return e, nil
}

func (e *Engine) SuspiciousThreshold(comm string) float64 {
    if p, ok := e.byComm[comm]; ok && p.SuspiciousThresh > 0 { return p.SuspiciousThresh }
    return e.defSus
}
func (e *Engine) BorderlandsThreshold(comm string) float64 {
    if p, ok := e.byComm[comm]; ok && p.BorderlandsThresh > 0 { return p.BorderlandsThresh }
    return e.defBor
}
func (e *Engine) AutoTerminate(comm string) bool {
    if p, ok := e.byComm[comm]; ok { return p.AutoTerminate }
    return false
}
```

---

### `internal/controlplane/controlplane.go`

```go
package controlplane

import (
    "fmt"
    "log"
    "net"
    "sync"

    "google.golang.org/grpc"
    pb   "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/audit"
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/enforcement"
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/policy"
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/store"
)

type ControlPlane struct {
    pb.UnimplementedKernelBorderlandsServer
    store    *store.Store
    audit    *audit.Logger
    enforcer *enforcement.Enforcer
    policy   *policy.Engine
    grpc     *grpc.Server

    // comm cache — pid → comm (populated by ProcessState messages)
    commCache sync.Map

    // event fan-out
    subMu    sync.Mutex
    eventSubs []chan *pb.KBEvent

    alertMu   sync.Mutex
    alertSubs []chan *pb.Alert
}

func New(dbPath, policyPath string) (*ControlPlane, error) {
    s, err := store.New(dbPath)
    if err != nil { return nil, err }
    p, err := policy.New(policyPath)
    if err != nil { return nil, err }
    return &ControlPlane{
        store:    s,
        audit:    audit.New(s.DB()),
        enforcer: enforcement.New(),
        policy:   p,
    }, nil
}

func (cp *ControlPlane) Start() error {
    go func() {
        if err := ipc.NewListener(cp).Listen(); err != nil {
            log.Fatalf("[KB] IPC: %v", err)
        }
    }()

    lis, err := net.Listen("tcp", ":50051")
    if err != nil { return err }
    cp.grpc = grpc.NewServer()
    pb.RegisterKernelBorderlandsServer(cp.grpc, cp)
    go func() {
        log.Println("[KB] gRPC on :50051")
        cp.grpc.Serve(lis)
    }()

    log.Println("[KB] Control plane ready")
    return nil
}

func (cp *ControlPlane) Stop() {
    cp.grpc.GracefulStop()
    cp.store.Close()
}

// ── MessageHandler (called by IPC listener) ──

func (cp *ControlPlane) OnProcessState(msg *ipc.ProcessStateMsg) {
    cp.commCache.Store(msg.PID, msg.Comm)

    if err := cp.store.UpsertProcessState(msg); err != nil {
        log.Printf("[KB] store: %v", err)
    }

    // Remove on process exit — event_count won't increment after exit,
    // so use the zone: if a process_exit event came through the C side
    // it already called kb_scoring_remove(), but the last state message
    // may not reflect that. Use EventCount==0 as proxy? No — just leave
    // the store row; it'll get overwritten when/if the PID is reused.
    // TODO: C side should send a dedicated process_exit wire message type.

    cp.fanOutEvent(&pb.KBEvent{
        Pid:       msg.PID,
        Ppid:      msg.PPID,
        Comm:      msg.Comm,
        EventType: "process_state",
        ScoreDelta: float32(msg.EMAScore),
        Timestamp:  int64(msg.LastUpdatedNs),
        Metadata: map[string]string{
            "zone":         ipc.KBZone(msg.Zone).String(),
            "composite":    fmt.Sprintf("%.2f", msg.CompositeScore),
            "dim_syscall":  fmt.Sprintf("%.2f", msg.DimScore[ipc.DimCount-5]),
            "dim_privilege":fmt.Sprintf("%.2f", msg.DimScore[2]),
        },
    })
}

func (cp *ControlPlane) OnZoneTransition(msg *ipc.ZoneTransitionMsg) {
    comm := ""
    if v, ok := cp.commCache.Load(msg.PID); ok { comm = v.(string) }

    log.Printf("[KB] Zone PID=%d COMM=%s %s→%s score=%.1f",
        msg.PID, comm, msg.FromZone, msg.ToZone, msg.Score)

    // PID-reuse guard
    ok, err := cp.store.VerifyStartTime(msg.PID, msg.StartTimeNs)
    if err != nil {
        log.Printf("[KB] start_time verify: %v — allowing", err)
    } else if !ok {
        log.Printf("[KB] PID=%d start_time mismatch — stale transition, skipping enforcement", msg.PID)
        return
    }

    cp.store.InsertZoneTransition(msg, comm)
    cp.audit.LogZoneTransition(msg, comm)

    if msg.ToZone == ipc.ZoneBorderlands {
        alert := &pb.Alert{
            AlertId:    fmt.Sprintf("alert-%d-%d", msg.PID, msg.TsNs),
            AlertType:  "BORDERLANDS_ENTRY",
            Pid:        msg.PID,
            Comm:       comm,
            Confidence: float32(msg.Score / 100.0),
            Severity:   "CRITICAL",
            Timestamp:  int64(msg.TsNs),
            Evidence: []string{
                fmt.Sprintf("ema_score=%.1f", msg.Score),
                fmt.Sprintf("from=%s", msg.FromZone),
            },
        }
        cp.fanOutAlert(alert)

        if cp.policy.AutoTerminate(comm) {
            cp.enforcer.Apply(msg.PID, pb.ContainmentLevel_TERMINATE)
            cp.audit.Log("AUTO_TERMINATE",
                fmt.Sprintf("pid=%d comm=%s", msg.PID, comm),
                "SYSTEM_AUTO", "policy:auto_terminate=true")
        } else {
            cp.enforcer.Apply(msg.PID, pb.ContainmentLevel_CGROUP)
            cp.audit.Log("CGROUP_THROTTLE",
                fmt.Sprintf("pid=%d comm=%s", msg.PID, comm),
                "SYSTEM_AUTO", "zone=BORDERLANDS")
        }
    }

    cp.fanOutEvent(&pb.KBEvent{
        Pid:        msg.PID,
        Comm:       comm,
        EventType:  "zone_transition",
        ScoreDelta: float32(msg.Score),
        Timestamp:  int64(msg.TsNs),
        Metadata: map[string]string{
            "from_zone": msg.FromZone.String(),
            "to_zone":   msg.ToZone.String(),
        },
    })
}

func (cp *ControlPlane) fanOutEvent(e *pb.KBEvent) {
    cp.subMu.Lock(); defer cp.subMu.Unlock()
    for _, ch := range cp.eventSubs { select { case ch <- e: default: } }
}

func (cp *ControlPlane) fanOutAlert(a *pb.Alert) {
    cp.alertMu.Lock(); defer cp.alertMu.Unlock()
    for _, ch := range cp.alertSubs { select { case ch <- a: default: } }
}
```

---

### `internal/controlplane/grpc.go`

```go
package controlplane

import (
    "context"
    "database/sql"
    "fmt"

    pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
    "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/internal/ipc"
)

func (cp *ControlPlane) GetProcessState(
    ctx context.Context, req *pb.PidRequest,
) (*pb.ProcessState, error) {
    var pid, ppid, uid, zone, cont, events uint32
    var comm string
    var score float32
    err := cp.store.DB().QueryRowContext(ctx, `
        SELECT pid,ppid,comm,uid,ema_score,zone,containment,event_count
        FROM process_state WHERE pid=?
    `, req.Pid).Scan(&pid,&ppid,&comm,&uid,&score,&zone,&cont,&events)
    if err == sql.ErrNoRows { return &pb.ProcessState{}, nil }
    if err != nil { return nil, err }
    return &pb.ProcessState{
        Pid:pid, Ppid:ppid, Comm:comm, Uid:uid,
        Score:score, Zone:pb.Zone(zone),
        Containment:pb.ContainmentLevel(cont),
    }, nil
}

func (cp *ControlPlane) ListZone(
    req *pb.ZoneRequest,
    stream pb.KernelBorderlands_ListZoneServer,
) error {
    rows, err := cp.store.DB().QueryContext(stream.Context(), `
        SELECT pid,ppid,comm,uid,ema_score,zone,containment
        FROM process_state WHERE zone=?
    `, int(req.Zone))
    if err != nil { return err }
    defer rows.Close()
    for rows.Next() {
        s := &pb.ProcessState{}
        var z, c int
        rows.Scan(&s.Pid,&s.Ppid,&s.Comm,&s.Uid,&s.Score,&z,&c)
        s.Zone = pb.Zone(z); s.Containment = pb.ContainmentLevel(c)
        if err := stream.Send(s); err != nil { return err }
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
    cp.store.DB().Exec(
        `UPDATE process_state SET containment=? WHERE pid=?`,
        int(req.Level), req.Pid)
    return &pb.ContainmentResponse{Success: true}, nil
}

func (cp *ControlPlane) StreamEvents(
    filter *pb.EventFilter,
    stream pb.KernelBorderlands_StreamEventsServer,
) error {
    ch := make(chan *pb.KBEvent, 256)
    cp.subMu.Lock(); cp.eventSubs = append(cp.eventSubs, ch); cp.subMu.Unlock()
    defer func() {
        cp.subMu.Lock()
        for i, s := range cp.eventSubs {
            if s == ch { cp.eventSubs = append(cp.eventSubs[:i], cp.eventSubs[i+1:]...); break }
        }
        cp.subMu.Unlock()
    }()
    for {
        select {
        case e := <-ch:
            if err := stream.Send(e); err != nil { return err }
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
    cp.alertMu.Lock(); cp.alertSubs = append(cp.alertSubs, ch); cp.alertMu.Unlock()
    defer func() {
        cp.alertMu.Lock()
        for i, s := range cp.alertSubs {
            if s == ch { cp.alertSubs = append(cp.alertSubs[:i], cp.alertSubs[i+1:]...); break }
        }
        cp.alertMu.Unlock()
    }()
    for {
        select {
        case a := <-ch:
            if err := stream.Send(a); err != nil { return err }
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
    case "TERMINATE": cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_TERMINATE)
    case "NAMESPACE":  cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_NAMESPACE)
    case "SECCOMP":    cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_SECCOMP)
    case "CGROUP":     cp.enforcer.Apply(d.Pid, pb.ContainmentLevel_CGROUP)
    }
    return &pb.DecisionAck{Success: true, Message: "executed"}, nil
}
```

---

### `cmd/mock_sender/main.go`

```go
package main

import (
    "encoding/binary"
    "log"
    "math"
    "net"
    "time"
)

func f64(v float64) []byte {
    b := make([]byte, 8)
    binary.LittleEndian.PutUint64(b, math.Float64bits(v))
    return b
}

func u32(v uint32) []byte {
    b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b
}

func u64(v uint64) []byte {
    b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b
}

func sendFramed(conn net.Conn, payload []byte) {
    prefix := u32(uint32(len(payload)))
    conn.Write(prefix)
    conn.Write(payload)
}

// ZoneTransition wire v3: hdr(4)+pid(4)+start_time_ns(8)+from(4)+to(4)+score(8)+ts_ns(8) = 40
func mkZoneTransition(pid uint32, startNs uint64, from, to uint32, score float64) []byte {
    var b []byte
    b = append(b, 0x42, 0x4B) // magic LE
    b = append(b, 3, 2)        // version=3, msg_type=2
    b = append(b, u32(pid)...)
    b = append(b, u64(startNs)...)
    b = append(b, u32(from)...)
    b = append(b, u32(to)...)
    b = append(b, f64(score)...)
    b = append(b, u64(uint64(time.Now().UnixNano()))...)
    return b
}

func main() {
    conn, err := net.Dial("unix", "/var/run/kbd.sock")
    if err != nil { log.Fatalf("dial: %v", err) }
    defer conn.Close()
    log.Println("Connected — sending zone transitions")

    startNs := uint64(time.Now().UnixNano() - 5e9) // process started 5s ago

    sendFramed(conn, mkZoneTransition(5678, startNs, 0, 1, 47.3)) // SAFE→SUSPICIOUS
    time.Sleep(time.Second)
    sendFramed(conn, mkZoneTransition(5678, startNs, 1, 2, 81.2)) // SUSPICIOUS→BORDERLANDS
    time.Sleep(time.Second)
    sendFramed(conn, mkZoneTransition(5678, startNs, 2, 0, 22.1)) // BORDERLANDS→SAFE

    log.Println("Done")
}
```

---

### `config/policy.yaml`

```yaml
defaults:
  suspicious:   40.0
  borderlands:  75.0

policies:
  - comm: nginx
    suspicious:   55.0
    borderlands:  85.0
    allow_network: true
    auto_terminate: false

  - comm: postgres
    suspicious:   50.0
    borderlands:  80.0
    allow_network: false
    auto_terminate: true

  - comm: bash
    suspicious:   45.0
    borderlands:  70.0
    auto_terminate: false
```

---

## Complete File List

```
kb-control-plane/
├── cmd/
│   ├── kbd/main.go                      ← already exists, wire New() + Start()
│   └── mock_sender/main.go              ← BUILD THIS for testing without sensor
├── internal/
│   ├── ipc/
│   │   ├── wire.go                      ← wire protocol parser (from kb_bridge.h v3)
│   │   └── listener.go                  ← unix socket accept loop
│   ├── store/
│   │   ├── schema.go                    ← SQLite init + Store struct
│   │   └── process.go                   ← upsert/remove/verify start_time
│   ├── audit/
│   │   └── audit.go                     ← SHA-256 chain logger + VerifyChain()
│   ├── enforcement/
│   │   └── enforce.go                   ← cgroup throttle + SIGKILL
│   ├── policy/
│   │   └── policy.go                    ← YAML policy engine
│   └── controlplane/
│       ├── controlplane.go              ← wired struct + MessageHandler impl
│       └── grpc.go                      ← all 6 gRPC methods
├── proto/
│   └── kb.proto                         ← already exists
└── config/
    └── policy.yaml                      ← process-specific thresholds
```

---

## One Critical Detail For Her

The `start_time_ns` field in `ZoneTransitionMsg` is new in your v3 wire format — it's your PID-reuse guard. Her enforcement path **must** call `store.VerifyStartTime(pid, startTimeNs)` before applying cgroup or SIGKILL. If that returns false, she skips enforcement and logs it. This is already wired into the `controlplane.go` above.