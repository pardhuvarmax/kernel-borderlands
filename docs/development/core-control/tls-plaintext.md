# eBPF TLS Plaintext Payload Extraction

To overcome the blind spot of encrypted network transport (TLS/SSL) without introducing heavy proxy components (like Envoy or MitM proxying with custom certificates), we have implemented a high-performance, distro-agnostic **eBPF Plaintext TLS Inspector** inside the `kb-core` unified sensor.

---

## 1. How It Works

Applications encrypt network payloads using user-space libraries (like OpenSSL) or statically compiled runtimes (like Go's `crypto/tls`). By placing **eBPF Uprobes** on these functions, we read the memory buffer **before encryption** (on writes) or **after decryption** (on reads):

```
+-----------------------------------------------------------+
| User Space                                                |
|                                                           |
|  [ Web Server / Go App / Python ]                         |
|        │                                                  |
|        ▼ (Plaintext Payload)                              |
|   OpenSSL SSL_write() / Go crypto/tls.(*Conn).Write()     |
|        │  ▲                                               |
|        │  │ ◄────────── [ eBPF Uprobe Hooks Intercept ]   |
|        ▼  │                                               |
+--------┼──┼-----------------------------------------------+
| Kernel │  │                                               |
|        ▼  │ (Captures 127 bytes raw memory copy)          |
|    [ eBPF Uprobe Programs ] ──► [ perf/ringbuf ] ──► Log  |
|        │                                                  |
|        ▼ (Encrypted Network Frames)                       |
|    sys_send / Socket Layer                                |
+-----------------------------------------------------------+
```

---

## 2. Core Implementation Components

### A. eBPF Hooks (`kbd_sensor.bpf.c`)
Defined two uprobe hooks at the end of [kbd_sensor.bpf.c](file:///home/emergence/Desktop/kernel-borderlands/kb-core/ebpf/kbd_sensor.bpf.c):
1. **`kb_ssl_write`**: Intercepts OpenSSL's `SSL_write`. Uses the standard System V ABI to read the plaintext buffer pointer from the `RSI` register (`PT_REGS_PARM2`) and the buffer size from `RDX` (`PT_REGS_PARM3`).
2. **`kb_go_tls_write`**: Intercepts Go's register-based calling convention (Go ABIInternal). Reads the plaintext slice pointer from `RBX` (`ctx->bx`) and length from `RCX` (`ctx->cx`).
3. **Data Packing**: Cops up to `127` bytes of plaintext into `e->filename` (reusing the field to preserve the 128-byte wire contract size), sets `e->flags` to the original length, and sets `e->event_type` to `9` (`tls_plaintext`).

### B. Dynamic Library & Binary Resolver (`kbd_sensor.c`)
To achieve distro-agnostic library resolution and support statically compiled binaries:
1. **Distro-Agnostic OpenSSL Hooking**: Scans a comprehensive array of standard directory targets (`/lib/x86_64-linux-gnu/libssl.so.3`, `/usr/lib/libssl.so.3`, etc.). Once resolved, it parses the ELF section tables of the library to dynamically find the offset of `SSL_write`, attaching the uprobe manually.
2. **Statically Compiled Go Hooking**: When a process executes, the userspace loader parses `/proc/[pid]/exe` as an ELF object. If it contains the Go TLS symbols `crypto/tls.(*Conn).Write` or `crypto/tls.(*Conn).write`, it extracts the function's virtual offset and attaches the Go uprobe program specifically to that process binary.

---

## 3. Performance Overhead & Mitigations (Ptax)

### The Context-Switching Tax
Uprobes require a user-to-kernel execution trap, which costs approximately **1.5 to 2.5 microseconds** per invocation. For extremely high-throughput web servers (e.g., 100k requests/sec), raw uprobes can impose a measurable CPU overhead.

### Mitigations Built-in
1. **Capped Buffer Copying**: We copy a maximum of `127` bytes of the payload (sufficient for HTTP headers, REST payloads, and C2 commands), minimizing kernel memory allocation and copying time.
2. **Selective Attaching**: Instead of attaching system-wide to every process, our Go uprobe is attached **only** dynamically to processes triggering execution events.
3. **Future Optimization**: In production, the uprobes can be toggled on/off dynamically. The sensor can keep them disabled at boot, and only attach the uprobes to a specific PID when that process enters `SUSPICIOUS` or `BORDERLANDS` states, eliminating the performance tax entirely for healthy processes.
