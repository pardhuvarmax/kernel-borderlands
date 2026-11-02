# LID-DS 2021 Setup Notes (Tier 3, Attack Lab Plan) — 2026-11-02

Status: **environment provisioned, image builds partially working, no capture run yet**.
Per `scripts/attack-lab/README.md`'s "Real exploits: LID-DS 2021" section and the Attack
Lab Plan (`~/Downloads/Kernel Borderlands Attack Lab Plan.md`, Nov 1 2026), LID-DS lives in
its own checkout on `kbvm` (`~/LID-DS`), **never copied into this repo** (GPL-3.0). This
doc records what was done there and what's still broken, so the next session doesn't have
to rediscover it. `lidds_runner.py` itself (the KB-side integration, MIT/project-licensed)
is already committed — see `scripts/attack-lab/lidds_runner.py` and its README section.

## What's provisioned on kbvm

- `python3.7` (deadsnakes PPA, noble build `3.7.17-1+noble2` — Ubuntu 24.04 doesn't ship it)
- `sysdig` (apt, `0.36.0+repack-1`; DKMS `scap` kernel module built and loaded for
  `6.8.0-147-generic`) — no Secure Boot issue, this VM boots BIOS/CSM, not UEFI
- `~/LID-DS`: cloned from `https://github.com/LID-DS/LID-DS` (commit `5b8e4143...`,
  2026-08-29). `venv37` (python3.7 venv) with `requirements.txt` installed and
  `pip install -e .` done (`lid-ds==2.2.0`)
- `emergence` added to the `kb` group (needed for `/run/kb/kba.sock`, same as the
  scripted-scenario lab)

## Docker image build results (`build_all.sh`, 15 scenarios)

| Status | Scenarios |
| --- | --- |
| Complete (victim+normal+exploit) | CVE-2020-9484 |
| Partial (2/3 images) | CVE-2012-2122, CVE-2017-12635_6, CVE-2017-7529, CVE-2019-5418, ZipSlip |
| Minimal (1/3) | EPS_CWE-434, PHP_CWE-434 |
| Failed (0/3) | Bruteforce_CWE-307, CVE-2014-0160 (Heartbleed), CVE-2018-3760, CVE-2020-13942, CVE-2020-23839, CWE-89-SQL-injection, Juice-Shop |

## Known blockers (in the vendored `~/LID-DS` checkout, not this repo)

1. **`ubuntu:13.04` base image (Heartbleed `victim/Dockerfile`, Bruteforce_CWE-307)** — Docker
   Hub removed schema-1 manifest support; `docker pull ubuntu:13.04` fails outright
   (`support Docker Image manifest version 2, schema 1 has been removed`), including with
   `DOCKER_BUILDKIT=0`. **Not resolved.** Needs either a re-pushed schema-2 mirror (verify
   provenance before trusting one) or rebuilding the image from an archived layer tarball.
2. **Debian stretch (`debian:9.2`) / buster (`debian:10`) EOL apt repos** — `deb.debian.org`
   and `security.debian.org` no longer serve stretch/buster; **fixed** by overwriting
   `/etc/apt/sources.list` in each affected Dockerfile with `archive.debian.org` entries
   marked `[trusted=yes]` (archive's stretch Release is signed with expired/missing keys,
   so plain apt trust fails) plus `Acquire::Check-Valid-Until "false"` in a new
   `/etc/apt/apt.conf.d/99archive`. Applied to 16 Dockerfiles across 11 scenarios (every
   `FROM debian:9.2`/`FROM debian:10` in the checkout). This fix is **local to kbvm's
   `~/LID-DS` checkout only** — re-cloning LID-DS loses it; reapply before rebuilding.
3. **Chrome/glibc incompatibility (blocks most "normal"-traffic containers)** — the shared
   `normal/Dockerfile` template (debian:9.2 + `xvfb` + `google-chrome-stable`, used by ~11
   scenarios) installs *current* Chrome from Google's live apt repo, which needs
   `glibc >= 2.25`; stretch ships `glibc 2.24`. Confirmed via a direct rebuild of
   `Bruteforce_CWE-307/normal` (succeeds through blocker #2's fix, fails here). **Not
   resolved** — needs either a pinned old Chrome `.deb` compatible with stretch's glibc (if
   still hosted anywhere) or swapping the normal-traffic generator to a different headless
   browser/base image. This is where investigation stopped (see "Next steps").
4. Two `COPY`-step failures (`"/filesplits": not found`, `"/images": not found`) seen in the
   original `build_all.log` — not triaged; likely a missing data file expected by a specific
   scenario's build context (not yet identified which scenario).

## A real, independent finding from this session: kbvm disk exhaustion

While debugging the above, `kbvm`'s root filesystem hit **100% full (0 bytes free)** during
repeated `docker build` attempts across concurrent sessions (this one + another Claude Code
session's `kb-core` work, both building/running on the same VM). GNOME's own "Low Disk
Space" notification fired at 982.6 MB remaining, ~30 minutes before actual exhaustion.
`docker builder prune -f` reclaimed ~7GB; free space is workable (~2GB) but tight — expect
to prune again before further LID-DS build attempts. This is a credible contributing factor
to the VM freezes/`ext4` damage found and `fsck`'d earlier in this session (see
`CHANGELOG.md`/session history for 2026-11-02); not confirmed as *the* cause of any specific
freeze, since free space wasn't checked at the time, but worth monitoring going forward —
`df -h /` before any build-heavy work on kbvm.

## Next steps, in priority order

1. Decide how to spend further effort on blocker #3 (Chrome/glibc) — it's the highest-
   leverage fix (blocks ~11 scenarios' normal-traffic container) but open-ended (archived
   Chrome build may not exist; may need a different browser-automation approach entirely).
2. Resolve blocker #1 (`ubuntu:13.04`) separately — affects Heartbleed and Bruteforce
   specifically; same two-phase-network-posture caveat applies once a real exploit scenario
   is ready to run (see §3 below).
3. Triage the two `COPY` failures (#4) once a scenario needing them is identified.
4. **Before any real `lidds_runner.py --ack-isolated` run** (not just image builds): confirm
   `kbvm` is network-isolated (host-only, `vboxnet0`, no default route — this session set
   that up and verified it from outside the guest; see networking section of the session
   history) and `kbd` is in the mode you intend (observe-only still needs the operator's
   explicit go-ahead per `[[kbvm-environment]]`/`Attack-LabTest-Suite.md` §6.2, same
   standing rule as the scripted-scenario lab).

## Documentation consulted

`scripts/attack-lab/README.md` (its "Real exploits: LID-DS 2021" section, added this
session), `docs/development/Attack-LabTest-Suite.md` (stage model, promotion gates),
`docs/development/attack-lab-cve-repro/2026-11-cycle1-scoping.md` (isolation-design
precedent for real-exploit work), the Attack Lab Plan document (Tier 3 / LID-DS re-run
procedure).
