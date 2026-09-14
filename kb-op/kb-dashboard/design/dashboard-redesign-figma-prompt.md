# kb-dashboard Redesign — Figma / Figma-Make Generation Prompt

**Purpose of this document**: a single, paste-ready prompt for a Figma AI
design tool (Figma Make, "use_figma", or a human designer working in Figma)
to produce a complete, end-to-end redesign of `kb-op/kb-dashboard` in a
black-neon aesthetic. The current UI (`kb-op/kb-dashboard/src/App.tsx`,
`src/index.css`) is a flat dark-blue "admin panel" theme (`#0a0c10`
background, `#3b6fff` accent, Inter/JetBrains Mono) — functionally complete
(5 views, live SSE feed, real API calls to `kbd`) but visually generic.
This prompt is scoped to look/feel only — every data field, view, and
interaction listed below already exists in the running app; **do not invent
new features, only redesign the presentation of the ones listed**.

**Reference**: match the black-neon aesthetic of the old standalone-AADS
Figma design at `nimbus-bubble-19089060.figma.site` (glowing accent lines
on near-black glass panels). AADS is no longer its own product — it's one
subsystem (`kb-aads`, the agent swarm) inside the larger Kernel Borderlands
platform, alongside the eBPF sensor (`kb-core`), the Go control plane
(`kbd`), and the Rust safety watchdog (`kb-checker`). **The redesigned
dashboard must read as "security operations console for the whole
platform," not "AADS's dashboard"** — AADS/swarm data is one section among
several, not the entire product.

---

## 1. Brand & Mood

- **Genre**: SOC (security operations center) console / kernel-level
  intrusion-detection cockpit. Think airgapped datacenter NOC screens,
  Ghost in the Shell terminal UI, `htop`/`nvtop` reimagined as a AAA game
  HUD — not a SaaS admin panel, not Material Design, not friendly/rounded.
- **Feeling on load**: the operator should feel like they just walked into
  a locked-down control room mid-incident. Dense, information-forward,
  slightly cold. Never playful.
- **Motion philosophy**: idle state is calm (slow ambient pulses only);
  any state transition that represents a *real* security event (new
  alert, zone escalation, containment fired) gets a sharp, deliberate
  animation — the UI should visually "flinch" when something bad happens,
  not treat every update the same.

## 2. Color System

Base is a true near-black, not the current desaturated navy-black. Neon
accents are electric and saturated, used sparingly (as signal, not
decoration) against large fields of black/charcoal.

| Token | Hex | Usage |
| --- | --- | --- |
| `bg.void` | `#050507` | Page background, outside all panels |
| `bg.panel` | `#0b0c10` | Card/panel fill |
| `bg.panel-raised` | `#12141a` | Hovered rows, nested cards, input fields |
| `bg.panel-glass` | `rgba(12,14,20,0.72)` + backdrop-blur | Topbar, modals, overlays |
| `line.hair` | `rgba(255,255,255,0.06)` | Default panel borders |
| `line.neon` | see accent table | Active/focused panel borders — 1px solid + outer glow |
| `text.primary` | `#eef1f8` | Headings, primary values |
| `text.secondary` | `#8991a8` | Labels, captions |
| `text.dim` | `#454b5c` | Disabled, placeholder, timestamps |
| **`neon.cyan`** | `#00f6ff` | Primary accent — brand, focus states, kbd/control-plane data |
| **`neon.violet`** | `#b24bff` | Secondary accent — AADS/swarm agent data, ML confidence scores |
| **`neon.green`** | `#39ff8f` | SAFE zone, healthy status, success |
| **`neon.amber`** | `#ffcf3d` | SUSPICIOUS zone, warnings, degraded |
| **`neon.red`** | `#ff3b5c` | BORDERLANDS/QUARANTINED zone, critical alerts, containment fired |
| **`neon.magenta`** | `#ff2ee0` | Reserved for the rarest signal: active tampering / Scenario-A lockdown banner only — must never appear for routine events |

Glow rule: every neon color gets a matching `box-shadow`/`filter: drop-shadow`
at low opacity (12–20%) and 12–24px blur when it's marking something
*currently active or live* (a live data point, an open alert, the selected
nav item). Static/historical data of the same category gets the flat hex
with no glow — glow means "this is happening now," not "this is category X."

Background texture: a very faint (2–4% opacity) fixed scanline or grid
overlay across `bg.void`, plus a subtle radial vignette darkening the
corners — reinforces the "console" feel without competing with data.

## 3. Typography

- **UI/labels**: `Space Grotesk` or `Rajdhani` (geometric, slightly
  technical/futuristic) — replaces the current generic `Inter`.
- **Data/monospace**: keep a monospace family for all numeric/log content
  (PIDs, hashes, timestamps, log lines) — upgrade from `JetBrains Mono` to
  `JetBrains Mono` or `IBM Plex Mono`, rendered slightly larger and with
  wider letter-spacing (`0.02em`) for a terminal feel.
- **Scale**: keep information density high — this is not a marketing page.
  Body text 12–13px, panel titles 11px uppercase with `0.08em` letter
  spacing, large stat numbers 28–32px monospace with a subtle neon
  text-shadow matching their status color.

## 4. Global Shell (present on every view)

Redesign these three persistent regions — they wrap all 5 views below.

### 4.1 Topbar
- Left: KB wordmark/logotype (geometric, angular — suggest a hexagonal or
  circuit-trace mark, not a rounded logo) + "KERNEL BORDERLANDS" in
  tracked-out caps, small "CONTROL CONSOLE" subtitle beneath in dim text.
- Center-right: a live/simulated data-source toggle (the app currently
  toggles between real `kbd` SSE data and a simulated demo feed) — style
  as a physical-feeling toggle switch with a glowing dot indicating which
  mode is live, plus a small pulsing "LIVE" or "SIM" badge.
- Right: refresh icon, settings icon, and a connection-status indicator
  (Wifi/WifiOff from the current icon set) that glows green when connected
  to `kbd`'s API and pulses red/disconnected-gray otherwise.
- Glass panel background (`bg.panel-glass`), 1px bottom hairline in
  `line.hair`, fixed height ~52-56px.

### 4.2 Sidebar (left, ~220-240px)
- Nav items for the 5 views, each with an icon + label + optional count
  badge: **Processes**, **Alerts**, **Services**, **Telemetry**, **Console**.
- Active nav item: left-edge neon bar (2-3px, `neon.cyan`) + soft glow
  bleeding into the item's background, icon recolors to the accent.
- Inactive items: icon+label in `text.secondary`, no background.
- Badge (unread alert count, active-containment count): small pill, filled
  `neon.red` with glow when count > 0, ghost/outline gray when 0.
- Sidebar footer ("System" section): three zone-count rows (SAFE /
  SUSPICIOUS / CRITICAL, live numbers) plus an "L1 Cache: RESTORED" status
  line — style each row's value with its zone's neon color and a tiny
  glowing status dot, not just colored text.

### 4.3 Persistent Stat Row (top of every view's content area)
Four stat cards, visible regardless of active view: **Tracked Processes**,
**Safe Zone**, **Suspicious**, **Borderlands/Quarantine**. Each card:
- Icon in a soft-glowing colored chip (blue/cyan for tracked, green for
  safe, amber for suspicious, red for danger).
- Large monospace value with a matching neon text-glow.
- Small label + sub-caption (e.g. "Nominal processes", "Active containment").
- On value change: a brief (200-300ms) flash/pulse of the glow, not an
  abrupt jump — signals "this just updated" without being jarring.

## 5. View-by-View Redesign

All 5 views share the shell above; only the content-grid panels change.
Every panel gets: a glass/dark card (`bg.panel`, 1px `line.hair` border,
12-16px radius — sharp-ish corners, not pill-rounded, to keep the
technical feel), a header row with a small colored status dot + title +
a right-aligned tag/count, and consistent 16-20px internal padding.

### 5.1 Processes (default view)
- **Zone Trend Chart** (top-left, currently a `recharts` AreaChart of
  safe/suspicious/borderlands counts over the last 10 ticks): restyle as a
  layered neon area chart — each zone's area filled with a soft vertical
  gradient fading from its neon color at ~25% opacity down to transparent,
  with a crisp 1.5px glowing line at the top edge of each area. Grid lines
  near-invisible (`line.hair`), axis labels in `text.dim` monospace.
- **Tracked Processes table** (main panel): PID / command / UID / score /
  zone / started-at / actions (isolate/restore). Score column: render as a
  small horizontal glow-bar (like a health bar) colored by `scoreColor`,
  not just a number. Zone column: colored pill badge with a matching
  glow-dot, not plain text. Row hover: subtle `bg.panel-raised` fill +
  faint left-edge glow in the row's zone color. Isolate/restore action
  buttons: icon-only, ghost by default, filled+glowing on hover in
  `neon.red` (isolate) / `neon.green` (restore).
- **Service Health** (compact panel): small grid of service chips
  (kbd / kb-checker / kb-core / kb-aads / kb-tui / kb-dashboard), each a
  small glowing dot (green=up, amber=degraded, red=down) + name.
- **Threat Feed** (live alert stream): each alert as a compact card with
  severity-colored left border + glow, alert type, PID/comm, relative
  timestamp, expandable evidence list. New alerts entering the feed should
  animate in with a brief slide+glow-flash, not a plain fade.
- **Audit Console** (log tail): true terminal styling — monospace, black
  background even darker than surrounding panels, colored log-level
  prefixes (`[INFO]` dim, `[WARN]` amber, `[CRIT]` red with glow),
  blinking block cursor at the end of the visible feed.

### 5.2 Alerts
Full-width **All Threat Alerts** table/list — same alert-card styling as
the Processes view's Threat Feed but denser, sortable/filterable by
severity and zone. Add a severity-distribution mini-bar at the top (count
of INFO/WARNING/CRITICAL as three glowing horizontal segments).

### 5.3 Services
Full **System Services** grid — one detail card per `kb-op` subsystem
component (not just a status dot: show version/uptime/last-heartbeat if
available in the data), plus the Audit Console (health-probe-focused feed)
below it. This is the view where the platform's multi-language nature
(Go/Rust/C/Python/TS) should read visually — consider a small language-tag
chip per service card (e.g. "Go", "Rust", "C/eBPF", "Python", "TS") in a
muted neutral tone so it doesn't compete with status colors.

### 5.4 Telemetry
- **Zone Distribution — Extended**: a larger, longer-window version of the
  zone trend chart from Processes, same neon-area treatment, plus the
  three latency metric cards (eBPF Intercept Latency, gRPC Health Probe
  RTT, AADS Consensus Latency) — this is the one place `kb-aads`/swarm
  data (violet accent) should visually stand out against the rest of the
  platform's cyan/green/amber/red, reinforcing "AADS is a subsystem with
  its own signal, not the whole page." Render each latency metric as a
  small radial gauge or sparkline with a glow proportional to how close
  it is to its threshold, not just a bare number.

### 5.5 Console
Full-height **Audit Console — Full Feed**: the terminal treatment from
§5.1 blown up to fill the view, with a sticky filter/search bar styled as
a glowing command-line input (blinking caret, monospace placeholder text
like `grep zone=BORDERLANDS`).

## 6. Components to Design as Reusable Elements

Design these once, as a small system, then apply everywhere above:
1. **Neon status dot** — 3 sizes (6/8/10px), 5 colors, with/without glow.
2. **Zone pill** (SAFE/SUSPICIOUS/BORDERLANDS/QUARANTINED) — colored
   outline + dim fill + dot.
3. **Stat card** — icon chip + value + label + sub-caption, as in §4.3.
4. **Alert card** — severity-bordered, expandable evidence list.
5. **Score/health bar** — thin horizontal glow-bar, 0-100 scale.
6. **Panel header** — dot + title + right-aligned tag, used on every panel.
7. **Nav item** (sidebar) — icon + label + optional glowing badge.
8. **Terminal/log line** — leveled color prefixes, monospace.
9. **Toggle switch** (live/simulated data source).
10. **Empty/loading/error states** for every panel type above — a panel
    with no data yet (dashboard just opened, waiting on first API
    response) should show a subtle pulsing skeleton in the panel's own
    color family, not a generic spinner; a panel whose API call failed
    (kbd unreachable) should show a dim red "disconnected" state with a
    retry affordance, not blank/broken layout.

## 7. Responsiveness & States

- Target is primarily a wide desktop console (this is an ops tool, not a
  mobile-first product) — design at 1440px and 1920px canvases as primary,
  but the sidebar should collapse to icon-only under ~1100px rather than
  breaking the grid.
- Design both the "live/connected" and "simulated/demo" data states for at
  least the Processes view, since the app already supports toggling
  between them (§4.1) — the simulated state should look identical in
  chrome, differing only in the "SIM" badge, so operators can't mistake
  demo data for real telemetry by a styling difference.

## 8. What NOT to change

This is a visual redesign, not a feature redesign — do not add new nav
items, new API endpoints, new metrics, or restructure the 5-view
information architecture. Every field named above already exists in
`kb-op/kb-dashboard/src/App.tsx`; the deliverable is new visual treatment
for existing data, ready to hand to a frontend engineer to re-implement in
the existing React + `recharts` + `lucide-react` stack (or note explicitly
in the Figma file anywhere a proposed effect — e.g. glow filters, scanline
overlay — would need a new CSS technique not currently used in
`src/index.css`).
