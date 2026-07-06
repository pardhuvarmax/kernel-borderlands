# Build & Test Scripts

Helper scripts to simplify build, test, and lifecycle operations in `kb-core`.

---

## Script Index

*   **`build.sh`**: Helper script that automates the generation of `vmlinux.h`, builds the eBPF programs, generates skeleton files (`.skel.h`), and compiles all userspace collectors and sensor binaries.
*   **`clean.sh`**: Deletes all compiled binaries, object files, skeleton headers, and temporary directories.
*   **`test.sh`**: Automates compiling and running all behavior engine unit test suites.
*   **`attach.sh`**: Automatically loads and attaches the unified sensor programs for rapid debugging/observation.

---

## Execution
Run scripts from the `kb-core/` directory:
```bash
./scripts/build.sh
./scripts/test.sh
```
