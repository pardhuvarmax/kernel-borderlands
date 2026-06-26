<img align="right" width="200" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

**Team Kernel Borderlands**

- K. Pardhu — 2311CS040089
- K. Tejaswini — 2311CS040077
- K. Karthik - 2311CS040080
- 



## KB Team Information

Kernel Borderlands (KB) is developed collaboratively across multiple engineering disciplines, including Linux kernel development, systems programming, eBPF, artificial intelligence, cybersecurity, distributed systems, backend engineering, frontend development, and user experience.

The project follows a **subsystem ownership model**, where each major component has a **Primary Maintainer** responsible for its architecture, implementation, documentation, testing, and long-term maintenance. Contributors from other subsystems participate as **Collaborators**, providing cross-domain expertise, subsystem integration, testing, validation, and feature implementation.

Kernel Borderlands is architecturally centered around **two primary engineering pillars**:

* **kb-core** — The systems and runtime foundation of the project kb.
* **kb-aads** — The AADS Subsystem, providing the intelligence layer of project kb.

All remaining subsystems extend, orchestrate, validate, or provide operational interfaces for these two foundational components.

---

## Project Architecture

```text
                           Kernel Borderlands

                    ┌─────────────────────────────┐
                    │          kb-core            │
                    │ Systems Runtime & eBPF      │
                    │ Framework                   │
                    │ Lead: Pardhu Varma          │
                    └─────────────┬───────────────┘
                                  │
                ┌─────────────────┴─────────────────┐
                │                                   │
                ▼                                   ▼
        kb-aads                           kb-control-plane
 Autonomous Agentic              Orchestration & Communication
  Defense System                         Services
  Lead: Karthik                      Lead: Tejaswini
                │                                   ▲
                └───────────────┬───────────────────┘
                                │
                                ▼
                         Agent Coordination
                         Policy Execution
                         Event Processing
                                │
                                ▼
                         kb-checker
                  Validation & Safety Engine
                   Lead: Pardhu Varma
                                │
                ┌───────────────┴───────────────┐
                │                               │
                ▼                               ▼
         kb-dashboard                      kb-tui
   Dashboard & Visualization       Terminal User Interface
        Lead: Rupa                 Lead: Tejaswini

                                ▲
                                │
                           scripts
            Development Automation & Testing
                    Lead: Karthik
```

---

## Subsystem Ownership

### kb-core

**Primary Maintainer**

**Pardhu Varma** — **Systems & Security**

Responsible for the overall systems architecture and runtime foundation of Kernel Borderlands, including Linux kernel development, eBPF instrumentation, CO-RE portability, libbpf integration, userspace runtime (`kbd`), telemetry infrastructure, event processing, verifier compatibility, cross-kernel portability, runtime performance, framework architecture, and long-term maintenance of the core subsystem.

**Collaborator**

**Karthik** — **Systems Integration & Subsystem Testing**

Contributes kernel testing, runtime validation, subsystem integration testing, regression testing, compatibility verification, and collaborative development of the core framework.

---

### kb-aads

**Primary Maintainer**

**Karthik** — **AI & Agentic Systems**

Responsible for the complete Autonomous Agentic Defense System (AADS), including autonomous agents, AI architecture, multi-agent coordination, decision engines, behavioral intelligence, offensive security research, attack simulation, agent communication, and long-term development of the AADS subsystem.

**Collaborator**

**Pardhu Varma** — **ML & Systems**

Contributes machine learning integration, systems integration, runtime compatibility, and collaborative implementation between the AI subsystem and the KB runtime.

---

### kb-control-plane

**Primary Maintainer**

**Tejaswini** — **Defensive Security, Control & Communication Pipelines**

Responsible for distributed communication, orchestration services, control-plane architecture, backend coordination, defensive security implementation, service communication pipelines, and operational infrastructure.

**Collaborator**

**Pardhu Varma** — **Security & gRPC Support**

Contributes security architecture, gRPC infrastructure, backend integration, runtime communication, and collaborative systems development.

---

### kb-checker

**Primary Maintainer**

**Pardhu Varma** — **Systems & Security (Rust)**

Responsible for the Rust-based validation framework, safety engine, policy verification, rule evaluation, static analysis, secure execution validation, and long-term maintenance of the checker subsystem.

**Collaborator**

**Tejaswini** — **Defensive Security**

Contributes defensive security implementation, validation support, and security policy integration.

---

### kb-dashboard

**Primary Maintainer**

**Rupa** — **Design & Frontend**

Responsible for dashboard architecture, frontend engineering, visualization, user interface design, user experience, and long-term maintenance of the dashboard subsystem.

**Collaborator**

**Tejaswini** — **Frontend & Backend**

Contributes backend integration, frontend implementation, API connectivity, and collaborative feature development.

---

### kb-tui

**Primary Maintainer**

**Tejaswini** — **Golang & TUI Design**

Responsible for the Go implementation, Bubble Tea architecture, Wish SSH integration, operator workflows, terminal interface implementation, and long-term maintenance of the KB Terminal User Interface.

**Collaborator**

**Rupa** — **TUI Design & CLI Tooling**

Contributes terminal user experience, CLI tooling, interaction design, interface layout, and usability improvements.

---

### scripts

**Primary Maintainer**

**Karthik** — **Testing & Offensive Security**

Responsible for development automation, attack simulation, offensive security workflows, testing infrastructure, experiment automation, dataset tooling, environment setup, reproducible testing, and long-term maintenance of the scripts subsystem.

**Collaborators**

**Pardhu Varma** — **Testing & Safety Validation**

Contributes runtime validation, safety verification, systems testing, and testing support.

**Tejaswini** — **Defensive Security Implementation**

Contributes defensive security validation, security testing, and implementation support.

**Rupa** — **Environment & Dataset Processing**

Contributes environment provisioning, dataset processing, workflow automation, and development tooling.

---

## Engineering Domains

The following table summarizes technical ownership across the primary engineering disciplines within Kernel Borderlands.

| Engineering Domain          | Technical Lead   |
| --------------------------- | ---------------- |
| Systems Architecture        | **Pardhu Varma** |
| Linux Kernel Development    | **Pardhu Varma** |
| eBPF Framework              | **Pardhu Varma** |
| Runtime Infrastructure      | **Pardhu Varma** |
| Rust Systems Development    | **Pardhu Varma** |
| AI & Agentic Systems        | **Karthik**      |
| Autonomous Defense Systems  | **Karthik**      |
| Offensive Security Research | **Karthik**      |
| Testing & Attack Simulation | **Karthik**      |
| Control Plane Architecture  | **Tejaswini**    |
| Distributed Communication   | **Tejaswini**    |
| Defensive Security          | **Tejaswini**    |
| Terminal User Interface     | **Tejaswini**    |
| Dashboard Architecture      | **Rupa**         |
| Frontend Engineering        | **Rupa**         |
| UI/UX Design                | **Rupa**         |
| CLI & Terminal Experience   | **Rupa**         |

---

## Responsibility Model

Every Kernel Borderlands subsystem designates a **Primary Maintainer** who serves as the technical owner of that subsystem.

Primary Maintainers are responsible for:

* Technical architecture and subsystem design
* Long-term ownership and maintenance
* Feature planning and implementation
* Code quality and review
* Documentation and developer guidance
* Testing strategy and validation
* Performance optimization
* Release readiness

Collaborators contribute through:

* Cross-subsystem integration
* Feature implementation
* Domain-specific expertise
* Testing and validation
* Documentation improvements
* Performance optimization
* Collaborative development

This engineering model establishes clear ownership of every major subsystem while encouraging close collaboration between systems engineering, artificial intelligence, security research, backend services, frontend engineering, and operational tooling throughout the Kernel Borderlands ecosystem.
