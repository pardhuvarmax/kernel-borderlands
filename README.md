# Kernel Borderlands (KB)

**Behavioral Defense at Ring Zero with Agent-Assisted Orchestration**

Kernel Borderlands (KB) is a kernel-level runtime defense framework designed to detect, classify, and contain anomalous process behavior directly at **Ring 0** on Linux systems. Rather than relying solely on signatures or predefined rules, KB continuously observes kernel telemetry through **eBPF instrumentation**, constructs behavioral context, and coordinates an intelligent multi-agent defense architecture capable of adaptive runtime response.

The project combines kernel observability, behavioral analytics, distributed agent orchestration, reinforcement learning, and modern systems programming into a unified security platform intended for research, experimentation, and next-generation host defense.

---

# Repository Structure

| Directory           | Language           | Description                                                                            |
| ------------------- | ------------------ | -------------------------------------------------------------------------------------- |
| `kb-core/`          | C (eBPF)           | Kernel instrumentation layer and telemetry collection.                                 |
| `kb-control-plane/` | Go                 | Control plane daemon (`kbd`) responsible for event coordination and system management. |
| `kb-aads/`          | Python             | Autonomous Agent Defense Swarm (AADS), behavioral reasoning, and MARL infrastructure.  |
| `kb-dashboard/`     | React / TypeScript | Web dashboard for visualization and monitoring.                                        |
| `kb-tui/`           | Go                 | Terminal-based management interface built with Bubble Tea.                             |
| `kb-checker/`       | Rust               | Script analysis and safety verification engine.                                        |
| `docs/`             | Markdown / PDF     | Technical documentation, architecture, installation guides, and project papers.        |
| `scripts/`          | Bash / Python      | Installation utilities, automation, testing, and attack-lab tooling.                   |

---

# Getting Started

Complete installation instructions, dependency setup, project architecture, development workflow, and contributor documentation are maintained within the project's documentation.

**Please Begin with:**

```text
docs/README.md
```

The documentation provides:

* Installation and environment setup
* Software and hardware requirements
* System architecture
* Kernel hook points and telemetry pipeline
* Team organization
* Technical whitepaper and project synopsis
* Development workflow and future project documentation

Once the environment has been prepared, the primary services can be started using:

```bash
# Control Plane
cd kb-control-plane
go run cmd/kbd/main.go

# Autonomous Agent Defense Swarm
cd kb-aads
python main.py

# Dashboard
cd kb-dashboard
npm run dev
```

---

# Documentation

The complete documentation for Kernel Borderlands is located in the `docs/` directory.

The recommended reading order for new contributors is:

1. `docs/README.md`
2. `docs/installation.md`
3. `docs/requirements.md`
4. `docs/hookpoints.md`
5. `docs/kb-team.md`
6. `docs/KB.pdf`
7. `docs/KB_Synopsis-1.pdf`

---

# License

This project is currently under active development. Licensing information will be published as the project matures.
