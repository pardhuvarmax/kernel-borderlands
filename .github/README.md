# .github

Repository automation and community files.

| Path | Purpose |
| --- | --- |
| `workflows/ci.yml` | Multi-subsystem build and test validation (Go, Python, Rust, Node); see the comments at the top of the file for scope |
| `workflows/retry-pages-deploy.yml` | Re-runs a failed GitHub Pages build/deploy |
| `ISSUE_TEMPLATE/bug_report.md` | Template for something that behaves differently from the documentation |
| `ISSUE_TEMPLATE/feature_request.md` | Template for a proposed capability or change |

Local equivalents of the CI steps are in [`../docs/development/developer-commands.md`](../docs/development/developer-commands.md). Report vulnerabilities as described in [`../SECURITY.md`](../SECURITY.md), not as public issues; contribution rules are in [`../CONTRIBUTING.md`](../CONTRIBUTING.md).

*(This README lives here, not inside `workflows/` or `ISSUE_TEMPLATE/`: GitHub restricts creating files under `workflows/` without the `workflow` token scope and can treat Markdown files in `ISSUE_TEMPLATE/` as issue templates.)*
