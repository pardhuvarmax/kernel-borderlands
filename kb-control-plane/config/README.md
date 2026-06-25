# Configuration Files

- `kb.yaml`        — Main daemon configuration
- `policy.yaml`    — Default behavioral policies
- `allowlist.yaml` — Process allowlists

## Example kb.yaml
```yaml
grpc_port: 50051
scoring:
  alpha: 0.3
  thresholds:
    suspicious: 40
    borderlands: 75
enforcement:
  mode: permissive  # permissive | enforcing
audit:
  path: /var/log/kb/audit.log
  remote_siem: ""
```
