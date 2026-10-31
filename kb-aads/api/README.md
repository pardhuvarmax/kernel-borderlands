# api

`status_server.py`: a minimal, read-only HTTP status server for the swarm, started on a background thread from `../main.py`. `kbd` proxies it as `/api/agents` so the dashboard's Rogue Management page has real data. Address and port come from `KB_AADS_STATUS_HOST` / `KB_AADS_STATUS_PORT` (default `127.0.0.1:8601`).
