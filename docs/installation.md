<img align="right" width="135" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

**Installation**

This guide explains how to set up a complete Kernel Borderlands development environment.

# System Requirements

## Supported Platforms

* Ubuntu 22.04+
* Arch Linux
* Other modern Linux distributions (may require package adjustments)

Windows and macOS are **not** supported for kernel development. They may be used for frontend or documentation development only.

---

# Required Software

| Component  | Version |
| ---------- | ------- |
| Git        | Latest  |
| Python     | 3.11+   |
| Go         | 1.23+   |
| Node.js    | 20+     |
| Rust       | Stable  |
| Clang/LLVM | 18+     |
| Make       | Latest  |

---

# Clone the Repository

```bash
git clone <repository-url>
cd kernel-borderlands
```

---

# Automatic Installation

The recommended installation method is:

```bash
chmod +x scripts/setup/install.sh
./scripts/setup/install.sh
```

The installer automatically:

* Installs required system packages
* Creates the Python virtual environment
* Installs Python dependencies
* Downloads and builds **libbpf**
* Installs Go dependencies
* Installs Node.js packages
* Prepares Rust tooling

---

# libbpf

Kernel Borderlands depends on **libbpf** for eBPF development.

The repository intentionally **does not include libbpf**.

During installation, the setup script automatically:

```text
Clone libbpf
↓
Compile libbpf
↓
Prepare it for KB
```

If the directory already exists, it will not be downloaded again.

---

# Python Environment

Activate the virtual environment:

```bash
cd kb-aads

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```

---

# Go Components

```bash
cd kb-control-plane

go mod download
```

---

# Dashboard

```bash
cd kb-dashboard

npm install
```

---

# Rust Components

```bash
cd kb-checker

cargo build
```

---

# Running Kernel Borderlands

## Control Plane

```bash
cd kb-control-plane

go run cmd/kbd/main.go
```

---

## Agent Swarm

```bash
cd kb-aads

source venv/bin/activate

python main.py
```

---

## Dashboard

```bash
cd kb-dashboard

npm run dev
```

---

# Updating

Pull the latest changes:

```bash
git pull
```

Update Python packages if necessary:

```bash
pip install -r kb-aads/requirements.txt
```

Update Go modules:

```bash
cd kb-control-plane

go mod tidy
```

Update Node packages:

```bash
cd kb-dashboard

npm install
```

---

# Troubleshooting

## Missing libbpf

Run:

```bash
./scripts/setup/install.sh
```

---

## Python Import Errors

Ensure the virtual environment is active:

```bash
source kb-aads/venv/bin/activate
```

---

## Go Module Errors

```bash
go mod tidy
```

---

## Permission Errors

Kernel Borderlands requires elevated privileges for loading eBPF programs.

Run privileged components using:

```bash
sudo
```

where required.

---

# Next Steps

After installation, continue with:

* `development.md` — Development workflow
* `architecture.md` — System architecture
* `kb-team.md` — Team roles and responsibilities
* `contributing.md` — Contribution guidelines
