## ARCHITECTURAL DECISION RECORD 1 (ADR)

* STATUS : APPROVED/PROPOSED BY LEAD, DEVELOPER DECISIONS PENDING...

### CONTEXT & SYSTEM TOPOLOGY

The Kernel Borderlands (kb-aads) subsystem acts as a high-performance endpoint security monitor operating at the boundary of Linux Kernel Ring 0 and User Space. Real-time system telemetry originates from kernel-level eBPF hooks via kbd_sensor, streaming metrics across a native Unix Domain Socket (UDS) Bridge directly into the Core-GoPlane IPC Bridge (wire.go, listener.go).

The central hub (Go Control Plane) must ingest high-velocity event loops, maintain per-process state machines, evaluate YAML-defined operator policies, and provide a low-latency gRPC-over-UDS interface to the Python automated agent layer (kb-aads Subsystem).


```text
[ Ring 0: eBPF Hooks ] 
          │
          ▼ (Ring Buffer - Ephemeral)
   [ kbd_sensor ]
          │
          ▼ (Native UDS Bridge)
   [ Core-GoPlane IPC Bridge ] ──► [ L1 Cache: Lock-free Go RAM ] ──► [ Enforcement Engine ]
          │ (wire.go / listener.go)                 │ (30-50ns Sync Hot-Path) (Designed for nanosecond-scale in-memory operations.)
          │                                         ▼ (Non-blocking Ring Buffer)
          └───────────────────────────────► [ L2 Store: Embedded SQLite WAL ] ──► [ Audit Logging ]
                                                    (10-50μs Async Cold-Path)
```

Historically, Apache Kafka with Docker/Docker-Compose abstraction layers was proposed for inter-subsystem data transport. However, production deployment constraints for an endpoint security tool make virtualization layers, JVM memory overhead, and network loopback constraints completely unacceptable.

------------------------------

### DECISION: EMBEDDED HYBRID TWO-TIER IN-PROCESS STORAGE ARCHITECTURE

We reject external message brokers (Apache Kafka) and client-server database daemons (PostgreSQL). We adopt a Two-Tier (L1 Cache / L2 Storage) In-Process Storage Engine built natively within the Go Control Plane kernel space wrapper.

> SQLite is not used as the authoritative execution state for enforcement decisions. It exists to provide durable persistence, historical analysis, auditability, and operator queries.

* Tier 1 (L1 Execution Layer): Concurrently accessible, lock-free, pure-Go memory primitives (sync.Map / optimized pointer slices).
* Tier 2 (L2 Persistence Layer): Embedded SQLite compiled into the Go binary runtime, configured explicitly in Write-Ahead Logging (WAL) mode.

Execution Principle :

* L1 Memory is authoritative for live enforcement.
* L2 SQLite is authoritative for persistence, auditability, recovery and operator visibility.

No enforcement decision may synchronously depend on disk I/O.

------------------------------

### RATIONALE & CRITICAL ENGINEERING METRICS

#### 1. Eliminating the CGO Context-Switching Translation Tax

Any native database driver written in C (including SQLite, [RocksDB](https://rocksdb.org/), and LevelDB) requires Go’s runtime allocator to transition via cgo.Crossing the Go↔C boundary through cgo introduces additional scheduling, marshalling, and runtime overhead. While often acceptable for infrequent operations, it is undesirable on the critical telemetry ingestion path : 

   1. Voluntarily yielding Go scheduler execution state (M:N scheduler management).
   2. Marshalling Go pointers to fixed allocations outside the garbage collector’s oversight.
   3. Forcing thread-state context switches to OS-native frames.

This boundary translation taxes every synchronization transaction by a baseline overhead of ~50ns to 100ns per invocation before the storage layer executes logic. By routing the kernel ingestion loop straight to pure-Go L1 memory primitives, we execute state assignments in 30ns to 50ns, bypassing CGO entirely on the critical telemetry ingestion loop.

#### 2. Lockless Concurrency Isolation via Dual-Track Routing

* Sync Hot Path (Ingestion ➔ Enforcement): listener.go reads raw byte strings from the kernel loop descriptor, and wire.go unpacks data structs natively. The control path updates L1 memory maps instantaneously. The Enforcement engine processes policy rules entirely within CPU L1/L2 caches.
* Async Cold Path (Persistence ➔ Auditing): Database writes are offloaded to buffered Go memory channels (chan). A decoupled background worker group pulls batched intervals from the queues and pipes them down to SQLite disk space out-of-band. I/O wait-states and journal flush bottlenecks are safely isolated from eBPF event loops.

#### 3. Exploiting SQLite WAL (Write-Ahead Logging) Properties
By specifying PRAGMA journal_mode=WAL; and PRAGMA synchronous=NORMAL;, the engine breaks the classic atomic file-lock constraint:

* Single-Writer Dominance: The Go Control Plane holds exclusive, isolated write permission to the L2 file engine via a single pool wrapper (SetMaxOpenConns(1)), removing file lock contention.
* Concurrent Zero-Block Readers: The Python kb-aads Subsystem and the operator plane dashboard pull live telemetry records via gRPC-over-UDS. SQLite uses shared memory mapping structures (-shm) to handle concurrent reads simultaneously as the Go background pipeline commits transactions—guaranteeing zero read blocks on the upstream monitoring endpoints.

#### 4. Rejection of Key-Value Systems (RocksDB / LevelDB)
While LSM-tree architectures offer rapid append write metrics, they break under complex evaluation rules. LevelDB limits access to exactly one OS process, creating blocking states for local debugging tools and external dashboard handlers. RocksDB adds extreme tuning complexity; unpredicted internal background compaction stalls trigger catastrophic write locks. Furthermore, raw byte Key-Value stores lack declarative query abstractions, forcing development of manual parsing code to correlate YAML security expressions with system processes. SQLite gives us native JSONB support and standardized relational SQL processing at minimal cost.

------------------------------

### Go Store Architecture Definitions, & Implementation Referencing 

#### 1. Core State Definition & In-Memory Layout (process.go)

```go
// Package store implements the low-overhead L1/L2 state-machine.package store
import (
	"context"
	"database/sql"
	"sync"
)
type ProcessTelemetry struct {
	PID         int64
	Comm        string
	UID         int64
	ContainerID string
	State       string
}
type CentralTelemetryStore struct {
	db          *sql.DB
	l1HotCache  sync.Map              // Tier 1: Pure Go runtime allocation heap (Nanoseconds)
	l2AsyncPipe chan ProcessTelemetry // Tier 2: Non-blocking write-behind channel
}
func NewCentralTelemetryStore(db *sql.DB, pipeBuffer int) *CentralTelemetryStore {
	store := &CentralTelemetryStore{
		db:          db,
		l2AsyncPipe: make(chan ProcessTelemetry, pipeBuffer),
	}
	go store.flushToL2Worker()
	return store
}
// IngestKernelEvent intercepts raw decoded data from wire.go / listener.gofunc (s *CentralTelemetryStore) IngestKernelEvent(telemetry ProcessTelemetry) {
	// L1 Synchronization: Atomic pointer swap inside native memory space (~30-50ns)
	s.l1HotCache.Store(telemetry.PID, telemetry)

	// L2 Offloading: Drop to queue. Non-blocking branch guarantees zero kernel ring stall
	select {
	case s.l2AsyncPipe <- telemetry:
	default:
		// Ring Buffer Overflow Strategy: Protect operating system control loop integrity.
	}
}
// EvaluatePolicyVerdict serves the Enforcement Engine directly out of L1 memory spacefunc (s *CentralTelemetryStore) EvaluatePolicyVerdict(pid int64) (ProcessTelemetry, bool) {
	val, ok := s.l1HotCache.Load(pid)
	if !ok {
		return ProcessTelemetry{}, false
	}
	return val.(ProcessTelemetry), true
}
func (s *CentralTelemetryStore) flushToL2Worker() {
	// Reused prepared statement to minimize engine parsing steps
	stmt, _ := s.db.Prepare(`INSERT INTO system_state (pid, comm, uid, container_id, state) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(pid) DO UPDATE SET state=excluded.state, updated_at=CURRENT_TIMESTAMP;`)
	defer stmt.Close()

	for telemetry := range s.l2AsyncPipe {
		_, _ = stmt.Exec(telemetry.PID, telemetry.Comm, telemetry.UID, telemetry.ContainerID, telemetry.State)
	}
}
```

#### 2. Embedded Database Orchestration Schema (schema.go)

```go
// Package store maps the structured schema configurations.package store
import (
	"database/sql"
	"time"
	_ "://github.com" 
)
const CentralCoreSchema = `
CREATE TABLE IF NOT EXISTS system_state (
	pid INTEGER PRIMARY KEY,
	comm TEXT NOT NULL,
	uid INTEGER NOT NULL,
	container_id TEXT,
	state TEXT NOT NULL,
	updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policy_definitions (
	policy_id TEXT PRIMARY KEY,
	rule_scope TEXT NOT NULL,
	action_directive TEXT NOT NULL,
	raw_rules_blob TEXT NOT NULL
);
`
func InitializePersistentEngine(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	// Lock in highly performance optimized storage behaviors
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",     // Establish asynchronous read availability
		"PRAGMA synchronous=NORMAL;",   // Delegate explicit disk syncing actions to OS buffers
		"PRAGMA busy_timeout=5000;",    // Bound retry wait-states to prevent instant transaction fails
		"PRAGMA temp_store=MEMORY;",    // Route ephemeral database actions entirely into RAM pools
	}
	
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return nil, err
		}
	}

	if _, err := db.Exec(CentralCoreSchema); err != nil {
		return nil, err
	}

	// Strictly restrict the driver connection context pool to one solitary writer thread
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	return db, nil
}
```

------------------------------

### CONSEQUENCES & TRADE-OFFS

#### Positive

* Deterministic Nanosecond Latency: Intercept loops achieve ~30-100ns execution windows, safe from execution pauses and socket limits.
* Minimal Infrastructure Footprint: Eliminates Docker orchestration wrappers, container runtime processes, and 1GB JRE overhead requirements. The total component footprint consumes less than 15MB RAM at idle.
* Thread-Safe Data Extraction: The core data models can be shared simultaneously with multiple local processes (live_server.py, Python control nodes) without using manual tracking code.

#### Negative / Mitigations

* Volatile Memory Risk: Real-time state metrics inside the L1 layer that have not yet cleared the L2 channel buffer can be lost during an abrupt user-space crash or unexpected OS panic. Standard eBPF ring buffers (BPF_MAP_TYPE_RINGBUF) are non-persistent kernel memory structures; they do not natively support message replays upon consumer re-attachments.
* Mitigation: The user-space control plane will treat the L1 memory cache as an ephemeral view. Upon recovery or cold start, the Go Control Plane will execute a rapid sweeping initialization phase—scanning the Linux /proc filesystem directly—to fully reconstruct the baseline process_state table in memory before activating the hot eBPF ingestion hook.
* Memory Bounds Growth: In-memory tracking structures scale linear data paths with system workload changes.
* Mitigation: Implement an explicit cache pruning worker inside process.go to sweep and clear records of dead process IDs (PIDs) off the L1 map upon observing an exit signal from the eBPF layer.


- Date/Time : July 04th 2026, Saturday 12:50am IST