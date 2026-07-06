# Headers

Shared definition files and public API headers for `kb-core`.

---

## Core Headers

*   **`vmlinux.h`**: Auto-generated type definitions compiled from system kernel BTF (compiled from host BTF schema).
*   **`kb_common.h`**: Data structures shared between kernel-space (`kbd_sensor.bpf.c`) and userspace (`kbd_sensor.c`).
*   **`kb_events.h`**: Event type constant IDs and definitions.
*   **`kb_scoring.h`**: Public API structures and methods for the advisory composite scoring engine.
*   **`kb_behavior.h`**: Behavioral state enums (`kb_behavior_state_t`) and transition result structures.
*   **`kb_evidence.h`**: Process evidence flag bitmasks and sequence queues.
*   **`kb_rules.h`**: Dynamic and static rule table layouts and binary wire transfer schemas (`struct kb_wire_attack_rule`).

---

## Generating vmlinux.h
To dump the active kernel BTF data into a C header file, run:
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```
*(This is already automated in the parent `Makefile` via `make vmlinux`).*
