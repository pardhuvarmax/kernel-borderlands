<img align="right" width="350" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

Kernel Borderlands (KB) is a kernel-level runtime defense framework designed to detect, classify, and contain anomalous process behavior directly at **Ring 0** on Linux systems. Rather than relying solely on signatures or predefined rules, KB continuously observes kernel telemetry through **eBPF instrumentation**, constructs behavioral context, and coordinates an intelligent multi-agent defense architecture capable of adaptive runtime response.

The project combines kernel observability, behavioral analytics, distributed agent orchestration, reinforcement learning, and modern systems programming into a unified security platform intended for research, experimentation, and next-generation host defense.

![Linux-Kernel](https://img.shields.io/badge/Linux-5.8+-black?logo=linux)
![eBPF](https://img.shields.io/badge/eBPF(C)-CO--RE-blue)
![libbpf](https://img.shields.io/badge/libbpf-Latest-purple)
![Go](https://img.shields.io/badge/Go-Control--Plane-00ADD8?logo=go)
![Python](https://img.shields.io/badge/Python-AADS-3776AB?logo=python)
![License](https://img.shields.io/github/license/pardhuvarmax/kernel-borderlands)
![Status](https://img.shields.io/badge/Status-Active-success)

---

### Repository Structure

| Directory           | Language           | Description                                                                            |
| ------------------- | ------------------ | -------------------------------------------------------------------------------------- |
| `kb-core/`          | C (eBPF)           | Kernel instrumentation layer and telemetry collection.                                 |
| `kb-control-plane/` | Go                 | Control plane daemon (`kbd`) responsible for event coordination and system management. |
| `kb-aads/`          | Python             | Autonomous Agent Defense Swarm (AADS), behavioral reasoning, and MARL infrastructure.  |
| `kb-op/kb-dashboard/` | React / TypeScript | Web dashboard for visualization and monitoring.                                        |
| `kb-op/kb-tui/`       | Go                 | Terminal-based management interface built with Bubble Tea.                             |
| `kb-op/kb-mcp/`       | Go / Rust          | Model Context Protocol (MCP) server for AI agent tool integration.                     |
| `kb-checker/`       | Rust               | Script analysis and safety verification engine.                                        |
| `docs/`             | Markdown / PDF     | Technical documentation, architecture, installation guides, and project papers.        |
| `scripts/`          | Bash / Python      | Installation utilities, automation, testing, and attack-lab tooling.                   |

---

### Getting Started

Complete installation instructions, dependency setup, project architecture, development workflow, and contributor documentation are maintained within the project's documentation.

**Please Begin with:**

[Kernel Borderlands Wiki](../../wiki)


The wiki provides:

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
cd kb-op/kb-dashboard
npm run dev
```
