# Security Policy

We take the security of **Kernel Borderlands** seriously. If you believe you have found a security vulnerability, please report it to us responsibly using the procedure outlined below.

---

## Supported Versions

Only the latest release version of Kernel Borderlands is actively supported with security updates. We recommend all deployments run the latest stable release.

| Version | Supported          |
| ------- | ------------------ |
| v1.0.x  | :white_check_mark: |
| < v1.0  | :x:                |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues.**

Instead, report vulnerabilities privately to ensure they can be patched before public disclosure:

1. Send an email to the maintainers at **pardhuvarmax@users.noreply.github.com** or **teamkbdevelopers@gmail.com** with the subject line: `SECURITY VULNERABILITY: [Brief Summary]`.
2. Include the following details in your email:
   * **Description**: A detailed description of the vulnerability and its potential impact.
   * **Subsystem Affected**: e.g., `kb-core` (LSM bypass), `kb-control-plane` (privilege escalation), or `kb-checker` (watchdog evasion).
   * **Proof of Concept (PoC)**: Step-by-step instructions, logs, code, or terminal commands to reproduce the issue.
   * **Environment Details**: Linux kernel version, distribution, and eBPF configuration.

We will acknowledge receipt of your vulnerability report as swiftly as we can (typically within 12 to 24 hours, and no later than 48 hours) and provide a preliminary response detailing the next steps.

---

## Security Response Process

Once a vulnerability report is received and confirmed:

1. **Investigation**: The core maintainers will investigate the vulnerability to determine its scope and severity.
2. **Mitigation Development**: We will develop a security patch in a private fork/workspace.
3. **Coordination**: If the vulnerability affects third-party systems or downstream distributions, we will coordinate disclosure.
4. **Release & Advisory**: We will release a patched version and publish a GitHub Security Advisory detailing the vulnerability, its impact, and recommended updates.

Thank you for helping keep Kernel Borderlands secure!
