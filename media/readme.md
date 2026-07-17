# Kernel Borderlands — Media Assets

This directory serves as the centralized repository for visual assets, demonstrations, and design media used across the Kernel Borderlands (KB) project documentation, reports, and READMEs.

[![Kernel Observability](https://img.shields.io/badge/Telemetry-eBPF%20CO--RE-blue)](#)
[![Security Control](https://img.shields.io/badge/Control--Plane-Go-00ADD8?logo=go)](#)
[![Visual Console](https://img.shields.io/badge/Console-Rust--TUI-success)](#)
[![Media Formats](https://img.shields.io/badge/Formats-MP4%20%7C%20GIF-blueviolet)](#)

---

## Directory Structure

The media workspace is organized as follows:

```text
media/
├── demoruns/
│   ├── kbrun.mp4         # Main end-to-end integration walkthrough
│   └── readme.md         # Detailed telemetry and test-run breakdown
└── readme.md             # This asset directory documentation
```

---

## Repository-Wide Visual Assets

While this root folder houses global demo runs, individual subsystems may maintain localized media folders for asset isolation. Below is an index of all media files currently maintained across the repository:

| Path / Reference | Type | Subsystem | Description |
| :--- | :--- | :--- | :--- |
| [`media/demoruns/kbrun.mp4`](file:///home/sicmundus/Desktop/Dev/kbworkspaces/project/kernel-borderlands/media/demoruns/kbrun.mp4) | Video (`.mp4`) | Root/Integration | End-to-end telemetry and verification run showing Kernel Sensor startup, Control Plane activation, `kb-tui` visual console monitoring, and sequential telemetry events/attack chain testing via `test_all_hooks.sh`. |
| [`kb-op/kb-tui/media/kbtui.gif`](file:///home/sicmundus/Desktop/Dev/kbworkspaces/project/kernel-borderlands/kb-op/kb-tui/media/kbtui.gif) | Animation (`.gif`) | Operator TUI | Quick preview of the Rust/Ratatui-based terminal management interface, demonstrating system telemetry loops and active alerts. |
| [`kb-op/kb-tui/media/kbtui.mp4`](file:///home/sicmundus/Desktop/Dev/kbworkspaces/project/kernel-borderlands/kb-op/kb-tui/media/kbtui.mp4) | Video (`.mp4`) | Operator TUI | Full-length high-quality recording of the TUI console, showing state management, policies, and process lists. |
| [System Banner / Logo](https://github.com/user-attachments/assets/ba4fdc53-151c-4477-b146-bc37b6859749) | Image (`.png`) | Global | High-resolution project logo depicting the "Ring 0 Defense Ring" concept, used as a header in project READMEs. |

---

## Guidelines for Adding & Updating Media

To ensure that the visual documentation remains high-quality, professional, and accessible, contributors must adhere to the following standards when committing new media:

### 1. File Format & Compression Standards
- **Video Demos**: Always save videos as `.mp4` using the H.264 video codec and AAC audio codec (if audio is included). Aim for **1080p (1920x1080)** or **720p (1280x720)** resolution to balance clarity and file size.
- **Short Previews / Animations**: Use highly-optimized `.gif` files or modern `.webp` animations. GIFs should be limited to 15-30 seconds and compressed using utilities like `gifsicle` to keep sizes under **10MB**.
- **Static Screenshots**: Use `.png` for user interface screens and system diagrams (for lossless clarity) and `.jpg` or `.webp` for photographs or high-complexity layouts.

### 2. Recording Best Practices
- **Clean VM Environment**: Capture demonstrations in isolated test VMs. Ensure all private IP addresses, credentials, environment paths, or host usernames that are not part of the public lab setup are hidden or cleared.
- **Terminal Sizing**: Set terminal dimensions to standard readable sizes (typically 120 columns by 30-40 rows) and use clear, high-contrast monospace fonts (e.g., *JetBrains Mono*, *Fira Code*, or *Inter*).
- **No Idle Time**: Edit out long compilation steps or idle wait times unless they illustrate real-time latency characteristics (such as telemetry latency, which should be explicitly pointed out).

### 3. Naming Conventions
- Maintain strictly lowercase filenames.
- Separate words using hyphens (`-`) or underscores (`_`), for example: `dashboard-alert-modal.png` or `ebpf_hook_diagram.webp`.

> [!IMPORTANT]
> Always supplement any committed video or image with a matching Markdown documentation description (like `readme.md`) in the same subdirectory, detailing what the file shows, how to reproduce it, and who is responsible for maintaining it.
