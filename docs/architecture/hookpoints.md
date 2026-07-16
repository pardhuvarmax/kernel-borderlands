<img align="right" width="200" src="https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749" alt="Kernel Borderlands">

Looking at the existing hook points:  

- `tracepoint:syscalls` — (all syscall entry/exit),
- `tracepoint:sched` — (fork, exec, exit), 
- `kprobe:commit_creds` — (privilege changes), 
- `bpf_lsm` — (sensitive file access), 
- `tracepoint:net` — (network connections), and 
- `kprobe:mmap_region` — (memory mapping with executable flags). 

Captured events are emitted into a perf ring buffer for zero-copy delivery to userland.

here are additions worth considering:

**Process & Execution**
- `kprobe:do_execveat_common` — catches `execveat()` (exec from file descriptor), a common LOLBin evasion vector
- `tracepoint:sched:sched_process_ptrace` — detects ptrace attachment between processes (debugger injection, GDB-based exploitation)
- `kprobe:kernel_clone` — lower-level than sched tracepoints; catches clone flags like `CLONE_NEWUSER` (unprivileged namespace abuse)

**Privilege & Credential**
- `kprobe:security_capable` — fires on every capability check, not just credential changes; catches capability probing behavior
- `kprobe:set_user` — tracks UID transitions that bypass `commit_creds` in some paths
- `kprobe:override_creds` / `kprobe:revert_creds` — used by kernel subsystems but also abusable for temporary privilege escalation

**Memory & Code Injection**
- `kprobe:__do_mmap` — finer-grained than `mmap_region`; catches anonymous executable mappings (shellcode staging)
- `uprobe` on `libc:dlopen` — detects dynamic library injection into running processes
- `kprobe:process_vm_writev` — direct cross-process memory write; almost exclusively used for injection

**File & Filesystem**
- `kprobe:vfs_write` on `/proc/*/mem` — writing to another process's memory via procfs
- `lsm:inode_rename` — detects file rename tricks (log tampering, binary swapping)
- `kprobe:security_inode_create` — catches creation of files in sensitive directories (`/etc`, `/bin`, `/lib`)
- `lsm:file_open` on `/etc/shadow`, `/etc/sudoers`, `/root/.ssh/` — targeted credential file surveillance. `/etc/passwd` is deliberately excluded from the tracked list: it carries no credential material on a shadow-password system and is opened by nearly every UID-resolving userland tool (`ls -l`, `id`, `ps`, `sudo`, `ssh`, ...). Every process's reads of tracked paths are flagged for behavioral scoring (`KB_EV_SHADOW_ACCESS`/`KB_EV_SUDOERS_ACCESS`/`KB_EV_PASSWD_ACCESS`/`KB_EV_SSH_KEY_ACCESS`) regardless of containment state — that detection is always on. The hard `-EACCES` block is **containment-triggered, not blanket**: it only applies to a process an operator has already put into containment at level ≥2 (Seccomp), same as every other LSM hook in this file. An earlier version blocked every process unconditionally, which made `sudo`/PAM (which must read `/etc/sudoers`/`/etc/shadow` on every invocation) indistinguishable from a system-wide outage the moment the sensor ran — fixed to be containment-scoped instead. This compiled-in list is a floor, not a ceiling: operators can add further paths via `sensitive_paths` in `config/policy.yaml` (validated and pushed to the sensor by `kbd` at connect time — see `internal/policy/policy.go` and `internal/ipc/sensitive_paths.go`); the floor itself can never be narrowed via config, only extended.

**Network**
- `kprobe:tcp_connect` — lower level than tracepoint:net; captures the full socket struct including destination IP/port before the syscall returns
- `kprobe:udp_sendmsg` — catches DNS exfiltration and C2 over UDP which `tracepoint:net` may miss
- `lsm:socket_bind` on privileged ports — detects listener setup by non-privileged processes post-escalation

**Kernel Integrity**
- `kprobe:kallsyms_lookup_name` — rootkits use this to resolve kernel symbol addresses at runtime
- `kprobe:ftrace_set_filter` — catches attempts to hook or manipulate the kernel's own tracing subsystem
- `kprobe:module_put` / `kprobe:try_module_get` — monitors LKM reference counting; relevant if a rootkit tries to load a module alongside KB

**Timers & Scheduling (Persistence Detection)**
- `kprobe:mod_timer` — detects unusual timer registration (used for persistence callbacks)
- `tracepoint:irq:softirq_entry` on unusual vectors — can flag deferred execution tricks

The highest-value additions for KB specifically are `process_vm_writev`, `security_capable`, `do_execveat_common`, and the `/proc/*/mem` write hook — those four cover injection and privilege probing patterns that the current hook set leaves partially blind to.
