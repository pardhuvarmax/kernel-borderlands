# Cross-Kernel Portability

## Overview

The Knowledge Base (KB) is designed to operate on any Linux kernel that provides sufficient eBPF support without maintaining kernel-specific implementations. This portability is achieved through **BPF Compile Once – Run Everywhere (CO-RE)**, **BTF (BPF Type Format)**, **libbpf**, runtime feature detection, and capability-based fallbacks.

Unlike traditional kernel modules, which depend on exact kernel versions and kernel structure layouts, KB targets **kernel capabilities** rather than specific Linux releases.

The objective is that a single source tree and a single behavioral implementation can execute across multiple kernel versions with minimal or no modification.

---

# Portability Architecture

```
                 Source Code
                      │
                      ▼
                clang -target bpf
                      │
                      ▼
                CO-RE Object (.o)
                      │
                      ▼
              libbpf Skeleton Loader
                      │
        ┌─────────────┴─────────────┐
        │                           │
        ▼                           ▼
   Runtime Capability        BTF Relocations
      Detection                    │
        │                          ▼
        └─────────────► Kernel-specific Object
                               │
                               ▼
                          eBPF Verifier
                               │
                               ▼
                         Program Attached
```

The compilation process is independent of the target kernel. Kernel-specific adaptation occurs entirely during program loading.

---

# Compile Once – Run Everywhere (CO-RE)

CO-RE allows a single compiled eBPF object to execute on multiple Linux kernel versions without recompilation.

Traditional eBPF programs embed assumptions regarding kernel memory layouts.

For example:

```c
task->real_parent->tgid
```

This assumes:

* `real_parent` exists
* the field offset is unchanged
* `task_struct` layout is identical

These assumptions break whenever kernel developers modify internal structures.

CO-RE eliminates this dependency.

Instead of embedding offsets, LLVM emits relocation records describing:

* structure name
* field name
* type information

During loading, libbpf resolves these relocations using the target kernel's BTF metadata.

Example relocation:

```
task_struct.real_parent.tgid

↓

Offset: 0x4B8 (Kernel A)

↓

Offset: 0x4F0 (Kernel B)
```

The source code remains unchanged.

---

# BTF (BPF Type Format)

BTF provides compact runtime metadata describing kernel types.

Instead of exposing only raw addresses, BTF exposes semantic information:

```
task_struct

Fields
------
pid
comm
real_parent
signal
cred
...
```

Each field includes:

* offset
* size
* type
* alignment

libbpf uses this metadata to resolve CO-RE relocations before verifier execution.

If BTF is unavailable, relocation cannot occur and CO-RE programs cannot be safely loaded.

---

# Safe Kernel Memory Access

All accesses to kernel structures **must** use CO-RE accessors.

Incorrect:

```c
task->real_parent->tgid;
```

Correct:

```c
BPF_CORE_READ(task, real_parent, tgid);
```

Reasons:

* Offset resolved at load time
* Architecture independent
* Compatible across kernel versions
* Verifier friendly

Direct dereferencing of kernel structures is prohibited unless absolutely required.

---

# Runtime Feature Detection

Kernel version numbers alone are insufficient for determining feature availability.

Enterprise distributions frequently backport functionality without updating the reported kernel version.

Example:

```
Kernel 5.15

Ubuntu
✓ Ring Buffer
✓ LSM
✓ BTF

Enterprise Distribution
✗ Ring Buffer
✗ LSM
✓ BTF
```

For this reason KB performs runtime capability probing rather than relying exclusively on version numbers.

Feature discovery includes:

* Program types
* Map types
* Helper functions
* BTF availability
* CO-RE support
* Kernel hooks

Example:

```c
libbpf_probe_bpf_map_type(...)
libbpf_probe_bpf_prog_type(...)
```

These probes determine which instrumentation modules may be enabled.

---

# Capability-Based Loading

Each instrumentation component declares the kernel capabilities required for execution.

Example:

```
File Access Monitor

Requirements

Program Type
------------
LSM

Maps
----
Ring Buffer

Helpers
-------
probe_read
```

The loader compares these requirements against detected kernel capabilities.

```
Detected

✓ LSM
✓ Ring Buffer
✓ probe_read

↓

Module Enabled
```

Otherwise:

```
Detected

✗ LSM
✓ Ring Buffer

↓

Fallback Selected
```

This approach avoids hardcoding kernel-version checks throughout the codebase.

---

# Graceful Feature Degradation

Missing optional kernel features must not prevent the KB from operating.

Instead, unsupported functionality is replaced by compatible alternatives.

Example:

```
Preferred Hook

LSM
```

Fallback order:

```
LSM

↓

fentry

↓

Tracepoint

↓

kprobe
```

Likewise:

```
Ring Buffer

↓

Perf Event Buffer
```

Each instrumentation module defines acceptable fallback implementations.

Only modules with no compatible implementation are disabled.

---

# BTF Discovery

During startup, the loader searches for kernel BTF information.

Lookup order:

```
1.
/sys/kernel/btf/vmlinux

↓

2.
Configured external BTF directory

↓

3.
Bundled BTF archive

↓

Failure
```

External BTF archives improve compatibility with vendor kernels that omit embedded BTF despite supporting eBPF.

---

# Kernel Compatibility

KB targets **kernel capabilities** rather than specific Linux kernel versions.

Linux kernel version is treated only as an initial compatibility indicator. Final compatibility is determined during runtime through capability discovery performed by libbpf and the KB loader.

The following matrix describes the expected compatibility guarantees.

| Kernel Version | eBPF | BTF | CO-RE | Status | Notes |
|----------------|------|------|--------|----------|------------------------------------------------|
| < 4.18 | ❌ | ❌ | ❌ | Unsupported | Missing modern eBPF infrastructure. |
| 4.18 – 5.1 | ✓ | ❌ | ❌ | Unsupported | eBPF available, but no BTF or CO-RE support. |
| 5.2 – 5.7 | ✓ | Partial | Partial | Experimental | Limited CO-RE functionality. Some modules may be disabled. |
| 5.8 – 5.14 | ✓ | ✓ | ✓ | Supported | Minimum officially supported kernel series. |
| 5.15 – 6.x | ✓ | ✓ | ✓ | Recommended | Full feature set. Preferred deployment target. |
| Latest Mainline | ✓ | ✓ | ✓ | Fully Supported | Best compatibility with modern eBPF features. |

> **Note**
>
> Enterprise distributions frequently backport kernel functionality while retaining older kernel version numbers. As a result, reported kernel versions may not accurately reflect available eBPF capabilities.

---

# Distribution Compatibility

KB is designed to be **distribution-agnostic**. Compatibility is determined by the availability of required eBPF runtime capabilities rather than by the Linux distribution itself.

The primary requirements are:

- Linux kernel **5.8 or newer**
- BTF support
- CO-RE compatible kernel
- libbpf
- Required eBPF program and map types

Distributions shipping kernels with equivalent backported functionality are also supported.

---

## Official Compatibility Matrix

| Distribution | Status | Notes |
|--------------|--------|------------------------------------------------------------|
| Ubuntu 24.04 LTS | ⭐ Primary Development Platform | Primary development, testing and validation environment. |
| Ubuntu 22.04 LTS | ⭐ Fully Supported | Recommended LTS deployment target. |
| Debian 12+ | ✓ Fully Supported | Modern kernel with stable CO-RE support. |
| Fedora 40+ | ✓ Fully Supported | Excellent upstream eBPF ecosystem. |
| Arch Linux | ✓ Fully Supported | Continuously compatible with latest kernel releases. |
| openSUSE Tumbleweed | ✓ Fully Supported | Modern rolling-release distribution. |
| RHEL 9+ | ✓ Supported | Verify BTF availability on vendor kernels. |
| Rocky Linux 9+ | ✓ Supported | Compatible with appropriate BTF configuration. |
| AlmaLinux 9+ | ✓ Supported | Same compatibility considerations as RHEL. |
| Amazon Linux 2023 | ✓ Supported | Verify enabled kernel features before deployment. |
| Oracle Linux 9+ | ✓ Supported | Requires BTF-enabled kernel configuration. |
| Alpine Linux | ⚠ Experimental | musl userspace supported; kernel configuration may vary. |
| NixOS | ⚠ Experimental | Supported when kernel exposes required eBPF capabilities. |

---

## Compatibility Policy

KB does **not** maintain distribution-specific implementations.

Instead, every deployment undergoes runtime capability validation during initialization.

The runtime verifies:

- Kernel version
- BTF availability
- CO-RE relocation support
- libbpf compatibility
- Supported eBPF program types
- Supported map types
- Helper function availability
- Optional kernel features (LSM, fentry/fexit, kfuncs, etc.)

Only after successful validation are instrumentation modules loaded.

---

## Vendor Kernels

Many enterprise Linux distributions backport modern eBPF functionality into older kernel release branches.

For example:

| Distribution | Reported Kernel | Effective Capability |
|--------------|-----------------|----------------------|
| Ubuntu 22.04 | 5.15 LTS | Modern CO-RE support |
| RHEL 9 | 5.14 | Extensive enterprise backports |
| Amazon Linux 2023 | 6.x | Modern eBPF feature set |

For this reason, KB never assumes capabilities solely from the reported kernel version.

Runtime feature discovery is always treated as the authoritative source.

---

## Unsupported Configurations

The following environments are currently unsupported:

- Linux kernels older than **5.8**
- Kernels compiled without eBPF support
- Kernels without BTF metadata
- Systems where CO-RE relocations cannot be performed
- Custom kernels missing required eBPF program or map types

Initialization will terminate before loading any eBPF programs if mandatory runtime requirements cannot be satisfied.

---

## Development Environment

KB is developed and continuously validated on:

```text
Distribution : Ubuntu 22/24.04 LTS
Compiler     : Clang/LLVM
Loader       : libbpf
Architecture : x86_64
Kernel        : Latest Ubuntu HWE/Mainline during development
```

Although Ubuntu serves as the primary development platform, KB is engineered to remain portable across any Linux distribution providing the required eBPF runtime capabilities.

---

## Runtime Capability Validation

Before loading any eBPF object, KB validates that the running kernel satisfies the minimum runtime requirements.

| Capability | Required | Purpose |
|------------|:--------:|---------|
| eBPF VM | ✓ | Core execution environment |
| BTF | ✓ | CO-RE relocation metadata |
| libbpf | ✓ | Userspace loader |
| CO-RE Relocations | ✓ | Cross-kernel portability |
| Hash / Array Maps | ✓ | Core map infrastructure |
| Ring Buffer | Preferred | High-performance telemetry transport |
| Perf Event Buffer | Fallback | Legacy telemetry transport |
| Tracepoints | Preferred | Stable instrumentation interface |
| kprobes | Fallback | Generic kernel instrumentation |
| LSM Hooks | Optional | Security instrumentation |
| fentry/fexit | Optional | Low-overhead tracing |
| kfunc Support | Optional | Advanced kernel integration |

If any mandatory capability is unavailable, initialization terminates before verifier submission.

Optional capabilities are handled through the fallback mechanism described below.

---

## Capability Resolution

Each instrumentation module declares the kernel capabilities it requires.

Example:

```yaml
Module:
    File Access Monitor

Requirements:
    Program Type:
        LSM

    Map Type:
        Ring Buffer

    Helpers:
        bpf_probe_read_kernel
        bpf_get_current_pid_tgid
```

During initialization, the runtime constructs a capability profile:

```text
Kernel Capability Profile

Program Types
--------------
✓ Tracepoint
✓ kprobe
✗ LSM
✓ fentry

Maps
--------------
✓ Hash
✓ Array
✓ Ring Buffer

Helpers
--------------
✓ probe_read_kernel
✓ get_current_pid_tgid
✓ ringbuf_output

Features
--------------
✓ BTF
✓ CO-RE
✓ BPF Links
```

The module loader compares the declared requirements against the detected capability profile.

```
Requirements Satisfied?
          │
     ┌────┴────┐
     │         │
    Yes        No
     │         │
     ▼         ▼
 Load Module   Resolve Fallback
```

---

## Fallback Policy

KB attempts to preserve behavioral semantics whenever possible.

Preferred fallback order:

```
LSM
 ↓
fentry
 ↓
Tracepoint
 ↓
kprobe
```

Telemetry transport:

```
Ring Buffer
      ↓
Perf Event Buffer
```

Modules without a compatible fallback are marked unavailable and excluded from deployment.

The remaining instrumentation pipeline continues without interruption.

---

## Supported Architectures

KB currently supports the following architectures.

| Architecture | Status | Notes |
|--------------|--------|--------------------------------|
| x86_64 | ✓ Supported | Primary development platform |
| ARM64 (AArch64) | ✓ Supported | Cloud, SBCs, ARM servers |
| RISC-V | ✓ Supported | Supported where kernel eBPF is available |
| ARMv7 | Experimental | Limited testing |

Architecture differences affect instruction generation only.

Behavioral semantics, CO-RE relocations, and runtime capability detection remain identical across supported platforms.

---

# Runtime Initialization

Every KB startup performs the following sequence.

```
                           KB Runtime Initialization
┌────────────────────────────────────────────────────────────────────────────┐
│                           Process Startup (kbd)                           │
└────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Load Configuration & Profiles  │
                     │ • config.yaml                  │
                     │ • module manifests             │
                     │ • policy definitions           │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Detect Host Environment        │
                     │ • Kernel release              │
                     │ • Architecture               │
                     │ • Distribution              │
                     │ • Privileges                │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Discover BTF                  │
                     │                              │
                     │ 1. /sys/kernel/btf/vmlinux   │
                     │ 2. External BTF Archive      │
                     │ 3. Bundled BTF Cache         │
                     └────────────────────────────────┘
                                      │
                        BTF Found? ───┴─────── No ─────► Abort Initialization
                                      │
                                     Yes
                                      ▼
                     ┌────────────────────────────────┐
                     │ Load CO-RE Objects            │
                     │ • Open skeletons             │
                     │ • Parse ELF                 │
                     │ • Parse relocation records  │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Probe Kernel Capabilities      │
                     │                              │
                     │ Program Types                │
                     │ Map Types                    │
                     │ Helper Functions             │
                     │ BTF Features                 │
                     │ LSM / Tracing / XDP          │
                     │ Ring Buffer Support          │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Build Capability Profile       │
                     │                              │
                     │ KernelCapabilities {          │
                     │   BTF                        │
                     │   CORE                       │
                     │   RingBuf                    │
                     │   LSM                        │
                     │   Tracepoints                │
                     │   kprobes                    │
                     │   fentry                     │
                     │   Helpers[]                  │
                     │ }                            │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Module Compatibility Pass      │
                     │                              │
                     │ Compare requirements against  │
                     │ detected capabilities         │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Resolve Fallbacks             │
                     │                              │
                     │ LSM → fentry                 │
                     │      → tracepoint            │
                     │      → kprobe                │
                     │                              │
                     │ RingBuf → PerfBuffer         │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Apply CO-RE Relocations        │
                     │                              │
                     │ Resolve structure layouts     │
                     │ Patch field offsets           │
                     │ Finalize eBPF objects         │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Verifier Preparation          │
                     │                              │
                     │ Create maps                  │
                     │ Prepare links                │
                     │ Configure globals            │
                     └────────────────────────────────┘
                                      │
                                      ▼
                     ┌────────────────────────────────┐
                     │ Kernel Verification           │
                     │                              │
                     │ Load Programs                │
                     │ Verify Safety                │
                     │ Verify Maps                  │
                     └────────────────────────────────┘
                                      │
                       Verification Failed?
                           │                    │
                          Yes                  No
                           │                    ▼
                           │        ┌────────────────────────────┐
                           │        │ Attach eBPF Programs       │
                           │        │ • Tracepoints              │
                           │        │ • kprobes                  │
                           │        │ • LSM                      │
                           │        │ • XDP                      │
                           │        └────────────────────────────┘
                           │                    │
                           ▼                    ▼
                 Log Failure & Exit      Runtime Ready
                                              │
                                              ▼
                               Begin Telemetry Collection.
```

Initialization terminates only when mandatory requirements cannot be satisfied.

```
Phase 1 ─ Environment Discovery
────────────────────────────────────────────
• Load configuration
• Detect kernel
• Detect architecture
• Locate BTF

            │
            ▼

Phase 2 ─ Capability Discovery
────────────────────────────────────────────
• Probe program types
• Probe map types
• Probe helpers
• Probe kernel features

            │
            ▼

Phase 3 ─ Compatibility Resolution
────────────────────────────────────────────
• Build capability profile
• Resolve module dependencies
• Select fallbacks
• Disable unsupported modules

            │
            ▼

Phase 4 ─ CO-RE Preparation
────────────────────────────────────────────
• Load skeleton
• Apply relocations
• Create maps
• Configure globals

            │
            ▼

Phase 5 ─ Deployment
────────────────────────────────────────────
• Kernel verifier
• Attach programs
• Initialize event channels
• Start telemetry runtime
```

---

# Portability Guidelines

All new instrumentation modules **must** comply with the following rules.

### Mandatory

* Use CO-RE relocation helpers.
* Avoid hardcoded kernel offsets.
* Probe optional kernel features before use.
* Declare module capability requirements.
* Provide fallbacks whenever technically feasible.
* Assume vendor kernels may differ from upstream.
* Target capabilities rather than kernel versions.

### Prohibited

* Hardcoded structure offsets.
* Direct kernel pointer dereferencing.
* Version-only compatibility checks.
* Architecture-specific assumptions.
* Compile-time selection of kernel implementations.
