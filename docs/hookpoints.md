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
- `lsm:file_open` on `/etc/passwd`, `/etc/sudoers`, `/root/.ssh/` — targeted credential file surveillance

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
