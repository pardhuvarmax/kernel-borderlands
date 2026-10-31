# cmd/kbd

`main.go`: the `kbd` daemon entry point. Parses the flags (`--db`, `--policy`, `--rules`, `--workloads`, `--allowlist`, `--http-addr`, `--grpc-socket`, ...), builds the control plane (`../../internal/controlplane`), loads the allowlist, starts it and signals systemd readiness. Flag reference: `kbd --help`; configuration files: [`../../config/`](../../config/).
