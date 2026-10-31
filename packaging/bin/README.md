# bin

`kbagents`: launcher script for the agent swarm (installed to `/usr/bin`). It picks a Python interpreter (`/opt/kb/venv` first), runs `main.py` from `/usr/lib/kb/aads` with `--config /etc/kb/agents.yaml`, and exits with install instructions if `ray` or `grpcio` are missing. Used by `../systemd/kbagents.service`.
