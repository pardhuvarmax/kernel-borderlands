# Automated eBPF JIT Signature Lifecycle (Packaging & Deployment)

**Document Version:** 1.0  
**Component:** `kb-checker` / Build & Packaging Pipeline  
**Status:** Architecture Blueprint & Implementation Guide  

---

## 1. Overview & Goal

The `kb-checker` watchdog queries active kernel memory to compute the SHA-256 JIT hashes of loaded eBPF programs, validating them against `/etc/kb/ebpf_policies.json`. 

To maintain security while supporting hands-off production deployments (where the software is installed via package managers and runs automatically on boot), **we must avoid manual hash registration and prevent the running daemon from writing its own signatures (self-signing vulnerability).**

This document details the architecture to automate signature generation at build time, distribute them securely via target OS packages (`.deb` / `.rpm`), and enforce read-only validation at runtime.

---

## 2. Secure Packaging Architecture

```text
    [ Developer Build Machine ]                 [ Target Production Host ]
  ┌─────────────────────────────┐             ┌─────────────────────────────┐
  │   Compile BPF bytecode      │             │                             │
  │            │                │             │                             │
  │            ▼                │             │                             │
  │  Compute ELF text hashes    │             │                             │
  │            │                │             │                             │
  │            ▼                │             │                             │
  │ Generate ebpf_policies.json │             │                             │
  │            │                │             │                             │
  │            ▼                │             │                             │
  │ Build DEB / RPM Package ────┼───(Install)─┼─▶ Writes /etc/kb/policies   │
  │ (includes signed signatures)│             │   (Marked Read-Only)        │
  │                             │             │             │               │
  └─────────────────────────────┘             │             ▼               │
                                              │   kbd_sensor loaded on boot │
                                              │             │               │
                                              │             ▼               │
                                              │   kb-checker verifies keys  │
                                              │   (Read-Only validation)    │
                                              └─────────────────────────────┘
```

### 2.1 The Rules of Trust
1. **The Build System is the Root of Trust:** The cryptographic JIT signatures must be computed on the secure compile server and sealed into the deployment package.
2. **Read-Only Enforces Integrity:** The `/etc/kb/` directory and `/etc/kb/ebpf_policies.json` file must be owned by `root:root` and set to `0444` (read-only) on the target host.
3. **No Daemon Self-Signing:** The `kb-checker` daemon must never have write access to `/etc/kb/ebpf_policies.json` at runtime.

---

## 3. Step-by-Step Implementation Guide

### Step 1: Automating Hash Generation during Compile (`kb-core`)
Update the `kb-core/Makefile` or create a post-compile script (`scripts/generate_signatures.py`) that extracts the raw program bytecode sections from the compiled `.o` files before they are stripped, hashes them, and outputs `/etc/kb/ebpf_policies.json`.

Example python script structure:
```python
import json
import hashlib
from elftools.elf.elffile import ELFFile

def extract_and_hash_sec(elf_path, sec_name):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        section = elffile.get_section_by_name(sec_name)
        if section:
            data = section.data()
            return hashlib.sha256(data).hexdigest()
    return None

# Generate map to serialize to ebpf_policies.json
signatures = {
    "kb_lsm_file_open": extract_and_hash_sec("kbd_sensor.bpf.o", "lsm/file_open"),
    "kb_handle_exit": extract_and_hash_sec("kbd_sensor.bpf.o", "tracepoint/syscalls/sys_exit_exit"),
}
```

### Step 2: Sealing Hashes into the OS Package (`.deb` / `.rpm`)
When building the Debian package using `dpkg-deb`:
1. Include the generated `ebpf_policies.json` inside the package directory layout at `/etc/kb/ebpf_policies.json`.
2. Configure permissions in the package specification file or `debian/rules` file:
   ```bash
   chown -R root:root debian/kernel-borderlands/etc/kb
   chmod 0644 debian/kernel-borderlands/etc/kb/ebpf_policies.json
   ```

### Step 3: Removing Self-Signing Logic in `kb-checker`
Once packaging is implemented, modify `kb-checker/src/integrity/mod.rs` to remove the default template-writing fallback. 
* If `/etc/kb/ebpf_policies.json` is missing or contains invalid zeroes, the daemon should immediately fail and raise a high-severity alert rather than creating a default template file.

---

## 4. Acceptance Criteria for Deployment Testing

1. Installing the `.deb`/`.rpm` file automatically creates `/etc/kb/ebpf_policies.json` with correct production hashes.
2. The `kb-checker` daemon runs successfully on boot immediately after installation without any manual intervention.
3. Attempts to write or modify `/etc/kb/ebpf_policies.json` by unprivileged users or the checker process itself are denied by filesystem permissions.
4. Manually altering the loaded eBPF programs in kernel memory triggers immediate quarantine and audit events.
