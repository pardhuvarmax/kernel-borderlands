# LID-DS 2021 Setup Notes (Tier 3, Attack Lab Plan) — 2026-11-02, updated 2026-11-03

Status: **11 of 15 scenarios build cleanly (victim+normal+exploit, or normal+exploit
where the scenario has no victim image); 2 partial (missing only `normal`); 2 blocked
(`ubuntu:13.04`). No capture run yet; `kbvm` needs to be re-isolated to host-only before
one — see "Next steps" below.**
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

**First pass** (before any fix) is kept below for history. **Current state**, after the
blocker #2/#3 fixes (archive repos, Chromium swap) plus a second round that found and
fixed the archive-repo fix missing from 5 **victim** Dockerfiles whose base image sits on
an EOL Debian release indirectly (`vulhub/rails:5.0.7`, `ruby:2.5.1`,
`apache/unomi:1.5.1`, `vulnerables/web-dvwa` ×2) — the first fix pass only patched
Dockerfiles that `FROM debian:9.2`/`debian:10` directly, missing these. Confirmed by
running `/etc/os-release` inside each base image (bypassing its custom `ENTRYPOINT` with
`docker run --entrypoint sh`): all 5 are Debian 9 (stretch). Verified by rebuilding each
scenario's own `./build_images.sh` end to end, not just a standalone `docker build`.

| Status (current) | Scenarios |
| --- | --- |
| Complete (victim+normal+exploit, or normal+exploit where no victim is used) | CVE-2012-2122, CVE-2017-12635_6, CVE-2017-7529, CVE-2018-3760, CVE-2019-5418, CVE-2020-13942, CVE-2020-23839, CVE-2020-9484, CWE-89-SQL-injection, Juice-Shop, PHP_CWE-434 |
| Partial (2/3 — missing `normal` only) | EPS_CWE-434 (blocker #4, `/images` COPY error — not yet identified which scenario's Dockerfile this actually belongs to; a grep for `images`-named COPY lines across all 15 scenarios found nothing besides `EPS_CWE-434/exploit`'s unrelated, already-working `COPY image_0501.eps`), ZipSlip (blocker #4, confirmed: `ZipSlip/normal/Dockerfile` does `COPY filesplits/ /home/filesplits/` but that directory doesn't exist in the checkout — a missing data file, not a config fix) |
| Blocked (`ubuntu:13.04`, blocker #1) | Bruteforce_CWE-307 (victim + exploit — exploit also separately fails in the vendored Metasploit `bundle install` step, exit 5, not triaged), CVE-2014-0160/Heartbleed (victim + exploit, same two blockers) |

**Relevance to KB, if prioritizing which blockers to chase further:** KB's eBPF sensor
hooks (`docs/architecture/hookpoints.md`) see process fork/exec, privilege changes,
sensitive-file access, and network connections — not in-memory/protocol-only flaws.
Bruteforce and Heartbleed are the two lowest-relevance scenarios against that hook set
(Heartbleed is a pure in-memory OpenSSL read overrun with no process/file/privilege
signature; Bruteforce is mostly repeated auth/network connections). The `ubuntu:13.04`
and Metasploit-build blockers were deliberately left unfixed this round on that basis —
the 11 now-complete scenarios already cover the higher-relevance RCE/file-access/
path-traversal cases (CVE-2020-9484 Tomcat deserialization, CVE-2020-13942 Unomi
expression injection, CVE-2017-12635_6 CouchDB priv-esc→RCE, EPS/PHP_CWE-434 file
upload, ZipSlip path-traversal write, CVE-2019-5418/CVE-2018-3760 Rails path traversal
reads).

<details>
<summary>First build pass (before blocker #2/#3 fixes) — kept for history</summary>

| Status (first pass, pre-fix) | Scenarios |
| --- | --- |
| Complete (victim+normal+exploit) | CVE-2020-9484 |
| Partial (2/3 images) | CVE-2012-2122, CVE-2017-12635_6, CVE-2017-7529, CVE-2019-5418, ZipSlip |
| Minimal (1/3) | EPS_CWE-434, PHP_CWE-434 |
| Failed (0/3) | Bruteforce_CWE-307, CVE-2014-0160 (Heartbleed), CVE-2018-3760, CVE-2020-13942, CVE-2020-23839, CWE-89-SQL-injection, Juice-Shop |

</details>

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
   **2026-11-03 follow-up:** this first pass only caught Dockerfiles that `FROM debian:X`
   directly. 5 victim Dockerfiles `FROM` a third-party image itself built on an EOL Debian
   release — `CVE-2018-3760/victim` (`vulhub/rails:5.0.7`), `CVE-2019-5418/victim`
   (`ruby:2.5.1`), `CVE-2020-13942/victim` (`apache/unomi:1.5.1`), `CWE-89-SQL-injection/victim`
   and `PHP_CWE-434/victim` (both `vulnerables/web-dvwa`) — and needed the same fix applied
   separately. Confirmed each base image's codename (`docker run --rm --entrypoint sh <image>
   -c "cat /etc/os-release"`, bypassing the image's own `ENTRYPOINT`, which otherwise runs
   its app server instead of the detection command) before patching: all 5 are Debian 9
   (stretch). All 5 now build; see the results table above.
3. **Chrome/glibc incompatibility (blocked most "normal"/browser-driving containers)** — the
   shared `normal/Dockerfile` template (debian:9.2 + `xvfb` + `google-chrome-stable`, used by
   13 Dockerfiles across 10 scenarios, 12 of them via Selenium + `chromedriver`, 1 via plain
   `webbrowser.open()`) installs *current* Chrome from Google's live apt repo, which needs
   `glibc >= 2.25`; stretch ships `glibc 2.24`. **Fixed**, confirmed by a clean rebuild of
   `CVE-2018-3760/normal` (previously failed here): swapped `google-chrome-stable` for
   Debian stretch's own archived `chromium` + `chromium-driver` packages (both
   `73.0.3683.75-1~deb9u1`, version-matched since they're built together in the same stretch
   snapshot — installs via the same `archive.debian.org` fix from blocker #2, no Google repo
   needed at all). Also: removed each Dockerfile's redundant manual
   `chromedriver.storage.googleapis.com/2.42/...` download (pinned to an old, Chrome-66-era
   driver that conflicted with the apt-installed one); pinned `pip3 install 'selenium<4'`
   (classic API — Selenium 4's "Selenium Manager" tries to auto-download/match a driver
   online at runtime, which both isn't needed here and would need internet during actual
   scenario runs, defeating the isolation requirement in `[[kbvm-environment]]`/the Attack Lab
   Plan's safety rules); added `chrome_options.binary_location = "/usr/bin/chromium"`
   explicitly in all 13 client scripts so ChromeDriver never has to guess the browser binary.
   **Caveat for any write-up that cites this as reproducing LID-DS**: the "normal" traffic
   these containers generate now comes from **Chromium, not Google Chrome** — different
   build, different default behaviour (rendering engine lineage is shared, but telemetry,
   default flags, and version are not identical to what LID-DS's original published dataset
   used). A reviewer familiar with LID-DS could reasonably flag this as a deviation from the
   benchmark if it's presented as an unqualified reproduction; say explicitly that
   browser-driven "normal" traffic was regenerated with Chromium due to the glibc
   incompatibility, not with the original Chrome build.
4. Two `COPY`-step failures (`"/filesplits": not found`, `"/images": not found`) seen in the
   original `build_all.log`. **2026-11-03: one triaged.** `/filesplits` is
   `ZipSlip/normal/Dockerfile`'s `COPY filesplits/ /home/filesplits/` — the `filesplits/`
   directory is genuinely absent from the checkout, a missing data file rather than a config
   problem; needs sourcing or regenerating, not yet done. `/images` is still unidentified: a
   grep for `images`-named `COPY` lines across all 15 scenarios' Dockerfiles found only
   `EPS_CWE-434/exploit/Dockerfile`'s `COPY image_0501.eps` (singular file, already builds
   fine) — not the error's source. The failure recurs in rebuild logs around a
   `debian:9.2`+archive-fix+`curl/python3/pip` sequence that looks like `EPS_CWE-434/normal`,
   but that Dockerfile's only `COPY` (per direct inspection) is `COPY normal.py
   /home/normal.py` — no `images` reference. Needs a fresh, isolated `docker build` of just
   that one Dockerfile with full output to pin down the real source.

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

1. ~~Finish the rebuild.~~ **Done 2026-11-03** — 11/15 scenarios now build complete, 2
   partial, 2 blocked; see the results table above.
2. Resolve blocker #1 (`ubuntu:13.04`) and the Metasploit `bundle install` failure, if
   Heartbleed/Bruteforce turn out to be needed after all — deliberately deprioritized this
   round as the two lowest-relevance scenarios against KB's eBPF hook set (no process
   exec/file-access/privilege-change signature; see the "Relevance to KB" note above).
3. Identify the scenario behind the `/images` COPY failure (still open — see blocker #4),
   and source/regenerate ZipSlip's missing `filesplits/` data directory.
4. **Before any real `lidds_runner.py --ack-isolated` run** (not just image builds): confirm
   `kbvm` is network-isolated (host-only, `vboxnet0`, no default route — this session set
   that up and verified it from outside the guest; see networking section of the session
   history) and `kbd` is in the mode you intend (observe-only still needs the operator's
   explicit go-ahead per `[[kbvm-environment]]`/`Attack-LabTest-Suite.md` §6.2, same
   standing rule as the scripted-scenario lab).
5. Carry the Chrome→Chromium substitution caveat (blocker #3) into any paper/report text
   that cites LID-DS as the reproduced benchmark.

## Documentation consulted

`scripts/attack-lab/README.md` (its "Real exploits: LID-DS 2021" section, added this
session), `docs/development/Attack-LabTest-Suite.md` (stage model, promotion gates),
`docs/development/attack-lab-cve-repro/2026-11-cycle1-scoping.md` (isolation-design
precedent for real-exploit work), the Attack Lab Plan document (Tier 3 / LID-DS re-run
procedure).
