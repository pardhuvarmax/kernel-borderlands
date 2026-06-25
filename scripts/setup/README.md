# Setup Scripts

- `install.sh`        — Install all dependencies
- `install_ebpf.sh`   — eBPF toolchain (clang, libbpf, bpftool)
- `install_go.sh`     — Go 1.22+
- `install_python.sh` — Python 3.11 + venv
- `install_node.sh`   — Node.js 20+
- `install_rust.sh`   — Rust + cargo
- `install_kafka.sh`  — Apache Kafka + ZooKeeper
- `install_redis.sh`  — Redis
- `verify.sh`         — Verify all dependencies installed correctly

## Run
```bash
chmod +x scripts/setup/install.sh
./scripts/setup/install.sh
```
