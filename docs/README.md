<img align="right" width="240" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

**Quick Start**

Clone the repository and run the automated installation script to prepare a complete Kernel Borderlands development environment.

```bash
git clone <repository-url>
cd kernel-borderlands

chmod +x scripts/setup/install.sh
./scripts/setup/install.sh
```

The installer is responsible for preparing the development environment by installing required dependencies, creating the Python virtual environment, downloading and building external libraries such as **libbpf**, and configuring the individual project components. Once the installation completes successfully, you can begin working on any component of the framework.

---

# Documentation

Kernel Borderlands is accompanied by a collection of technical documentation located in the `docs/` directory. These documents describe the framework from both architectural and implementation perspectives and should be used as the primary reference throughout development.

### `docs/README.md`

Acts as the documentation index for the project. It provides an overview of the available documentation and serves as the recommended starting point for new contributors before exploring individual components.

### `docs/installation.md`

Provides detailed installation instructions, supported platforms, required software versions, dependency management, environment preparation, troubleshooting, and the complete setup workflow required to build and run Kernel Borderlands.

### `docs/requirements.md`

Defines the software stack, hardware recommendations, compiler requirements, runtime dependencies, development tools, and version requirements for every subsystem within the project.

### `docs/cross-kernel-portability.md`

Documents the cross-kernel portability architecture of KB. It explains how the framework achieves compatibility across multiple Linux kernels through BPF Compile Once – Run Everywhere (CO-RE), BTF, libbpf, runtime capability discovery, and feature fallback mechanisms. The document describes the portability architecture, kernel compatibility model, distribution support, runtime initialization pipeline, capability resolution process, architecture support, and developer guidelines for implementing portable eBPF instrumentation modules.

### `docs/hookpoints.md`

Describes the Linux kernel hook points monitored by Kernel Borderlands, including the associated eBPF instrumentation strategy, kernel events of interest, telemetry collection mechanisms, and behavioral observation pipeline used by the framework.

### `docs/kb-team.md`

Documents the project organization, contributor responsibilities, development roles, ownership of individual components, collaboration workflow, and communication structure followed by the Kernel Borderlands team.

### `docs/KB.pdf`

The primary technical whitepaper describing the motivation, design philosophy, architecture, behavioral security model, subsystem interactions, implementation details, and long-term vision of Kernel Borderlands.

### `docs/KB_Synopsis-1.pdf`

A condensed overview of the project intended for quick reference. It summarizes the project's objectives, core architecture, research motivation, expected outcomes, and high-level design decisions without requiring the reader to navigate the complete whitepaper.

---

Developers are encouraged to review the documentation before contributing to the project. While the source code serves as the implementation, the documents contained within `docs/` define the intended architecture, design principles, development workflow, and technical direction of Kernel Borderlands. Reading them beforehand will provide a clearer understanding of how the individual components interact to form the complete behavioral defense framework.
