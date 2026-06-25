
<img align="right" width="300" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

**Kernel Borderlands + AADS Technical Requirements**

**System Requirements:**

**Development Machine (each member)**
- OS: Ubuntu 22/24.04 LTS (mandatory, not optional)
- RAM: minimum 16GB recommended
- Storage: minimum 50GB free
- Linux Kernel: 5.8+ (BTF + BPF ring buffer support)

**Lab/Attack VM**
- Isolated network environment
- Multiple VMs for attack simulation
- VMware/VirtualBox/QEMU
- Snapshot capability for repeatable experiments

**GPU**
- University HPC preferred
- Fallback: Google Colab Pro / RunPod
- Minimum: 8GB VRAM for QLoRA fine-tuning
- Target models: Phi-3 Mini / Qwen2.5 3B / Mistral 7B

---

## 1. KB Layer — C + Go

**eBPF / Kernel (C)**
```
Kernel 5.8+ with BTF support
libbpf (latest stable)
bpftool
clang/LLVM 12+
linux-headers matching kernel version
CO-RE (Compile Once Run Everywhere)
BPF Type Format (BTF)
```

**Hook Points Required**
```
tracepoint:syscalls (entry/exit)
tracepoint:sched (fork, exec, exit)
kprobe:commit_creds (privilege changes)
bpf_lsm (file access)
tracepoint:net (network activity)
kprobe:mmap_region (memory mapping)
```

**Control Plane (Go)**
```
Go 1.21+
gRPC + protobuf
SQLite (process state store)
PostgreSQL (audit logs)
Cobra CLI framework
YAML parser (policy engine)
SHA-256 (audit chain hashing)
```

**Containment Primitives**
```
Linux Namespaces (mnt, net, user)
Seccomp (libseccomp)
Cgroup v2
prctl()
setns()
SIGKILL
```

---

## 2. AADS Layer — Python

**Core Runtime**
```
Python 3.11+
asyncio (agent concurrency)
gRPC + protobuf (KB communication)
Pydantic (data validation)
FastAPI (internal API)
```

**MARL (Multi-Agent Reinforcement Learning)**
```
Ray RLlib 2.x
stable-baselines3
Gymnasium (environment definition)
NumPy
PyTorch 2.x
```

**Agent Communication**
```
Apache Kafka (event bus)
ZeroMQ (agent-to-agent messaging)
Protocol Buffers (message serialization)
```

**Consensus & Quorum**
```
Custom weighted voting implementation
Raft consensus (simplified)
Python threading / asyncio
```

**Rogue Agent Detection**
```
Anomaly scoring per agent
Behavioral threshold monitoring
Sandbox isolation logic
Kill switch implementation
```

**Fine-tuning Pipeline**
```
Hugging Face Transformers 4.x
PEFT (LoRA/QLoRA)
bitsandbytes (4-bit quantization)
Datasets library
TRL (training library)
Accelerate
Weights & Biases (experiment tracking)
```

**Dataset Generation**
```
Custom collection scripts
Metasploit Framework
Common Linux exploit tools
ADFA-LD (supplementary)
BETH Dataset (supplementary)
Label studio or custom labeling tool
```

---

## 3. Event Bus & Infrastructure

```
Apache Kafka 3.x
ZooKeeper (Kafka dependency)
OR Kafka KRaft mode (no ZooKeeper)
Redis (shared state / pheromone trails)
PostgreSQL 15+
SQLite 3.x
Docker + Docker Compose (local dev)
```

---

## 4. Dashboard — React + TypeScript

**Core**
```
Node.js 20+
React 18+
TypeScript 5+
Vite (build tool)
```

**UI Components**
```
Tailwind CSS
shadcn/ui
Recharts (graphs/charts)
D3.js (swarm topology network graph)
Lucide React (icons)
```

**Real-time**
```
WebSockets (native or socket.io)
React Query (data fetching)
Zustand (state management)
```

**Specific Screens Requiring Special Libraries**
```
Swarm Topology → D3.js force graph
Role Distribution → Recharts pie/line
Quorum & Consensus → Recharts + custom voting UI
Pheromone Visualization → D3.js
Knowledge Graph → D3.js or Cytoscape.js
System Heartbeat → Recharts line chart
```

---

## 5. Security & Governance

```
RBAC implementation (custom)
JWT tokens (API authentication)
TLS 1.3 (all inter-service communication)
HSM-backed API tokens (or simulated)
SHA-256 chained audit logs (blockchain-style)
Append-only audit log design
Immutable audit trail verification
```

---

## 6. DevOps & Tooling

**Version Control**
```
Git
GitHub / GitLab
Branch strategy: main, dev, feature branches
```

**Containerization**
```
Docker
Docker Compose (full stack local)
```

**Testing**
```
Go: built-in testing + testify
Python: pytest
React: Jest + React Testing Library
Integration: custom attack simulation scripts
```

**Documentation**
```
Swagger/OpenAPI (API docs)
Markdown (technical docs)
Draw.io or similar (architecture diagrams)
```

**Monitoring (dev)**
```
Prometheus (metrics)
Grafana (optional, internal monitoring)
Weights & Biases (ML training)
```

---

## 7. Communication Interfaces

**KB ↔ AADS**
```
gRPC (primary)
Protocol Buffers v3
Unix socket (local) or TCP (distributed)
```

**AADS Internal**
```
Kafka topics:
  - role-changes
  - agent-updates
  - consensus-events
  - health-checks
  - anomaly-alerts
ZeroMQ (direct agent messaging)
```

**Dashboard ↔ Backend**
```
REST API (FastAPI)
WebSocket (real-time streaming)
JSON (data format)
```

---

## 8. Minimum Viable Environment

To run the full stack locally:
```
RAM: 32GB recommended (16GB minimum, will be tight)
CPU: 8 cores recommended
Storage: 100GB free
OS: Ubuntu 22.04
Docker + Docker Compose
Kernel 5.8+
```

---


