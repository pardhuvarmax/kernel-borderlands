# OAN — Cost-Reduced Build (`oan-cheap.md`, alt.)

**Version:** 0.1 (proposal)
**Component:** Alternate BOM/configuration for the [Out-of-Band Attestation Node](oan-hardware-appliance.md) — modifies its reference bill of materials, not its architecture
**Status:** Proposed — not implemented, not built, not tested. This is a costing exercise, not a new design: it takes the Model B shared-chassis BOM from `oan-hardware-appliance.md` §9–§10 and asks "which line items can shrink, and which ones shouldn't."

---

# 1. Purpose

`oan-hardware-appliance.md`'s bill of materials is priced off retail dev boards and off-the-shelf modules — reasonable defaults for a first bench build, not the cheapest possible build. For a budget-constrained group (a college club funding this out of pocket, for instance) it's worth separating "genuinely free savings" from "savings that quietly weaken what OAN is for," so nobody cuts the wrong corner without realizing it.

This document does not propose a different architecture. Every component still fills the same role described in `oan-hardware-appliance.md` §4 — this only substitutes cheaper parts for some of them.

---

# 2. Principle: Not All Cuts Are Equal

Every option below is tagged:

- **Free** — cheaper part, same guarantee. No trade-off against anything `oan-hardware-appliance.md` §2's design philosophy (Out-of-Band / Independent / Hardware Rooted / Fail-Safe) depends on.
- **Trade-off** — cheaper, but gives up something the reference design was specifically built to provide. Needs an explicit yes, not a default.

---

# 3. Cost-Reduction Levers

## 3.1 SBC: Raspberry Pi 4/5 → Pi Zero 2 W — **Free**

The SBC's job (§4.1) is attestation engine + policy + dashboard for up to 5 hosts, at heartbeat cadence, not heavy compute. A Pi Zero 2 W handles that. $35–$80 → $15–$20.

## 3.2 Display: drop it — **Free**

Already marked optional in the reference BOM (§4.6) — it's a read-only reflection of state the SBC/STM32 already hold, not an input to any decision. Zero functional loss for a non-demo deployment. $5–$10 → $0.

## 3.3 Relay: per-channel modules → shared multi-channel board — **Free**

A 5–8 channel relay/PDU board amortizes better than 5 loose single-relay modules, same as a rack PDU does at real scale. ~$6/channel → ~$4–$6/channel.

## 3.4 STM32: Nucleo dev board → bare "Blue Pill" clone — **Mostly free, one caveat**

The reference BOM's $10–$25 range leans toward official ST Nucleo boards. A bare F103C8 "Blue Pill" clone is commonly $2–$5 *even at single-unit retail* — this isn't a bulk-quantity discount, it's a different (cheaper, less supported) part. Caveat: Blue Pill clones have a known reputation for inconsistent quality control; test a unit before committing a whole chassis's channels to one batch. $10–$25 → $3–$6.

## 3.5 ESP32: DevKitC breakout → bare WROOM module — **Free, more integration work**

Same chip, no breakout convenience (USB-serial, prototyping headers) — fine if you're already building a custom chassis rather than a loose dev-board bench mockup. $6–$10 → $3–$5.

## 3.6 OOB dongle: FTDI → generic CP2102 clone — **Free**

Same function, cheaper brand. $8 → $3–$5.

## 3.7 TPM: discrete hardware module → firmware TPM (fTPM) — **Verdict: not worth it, especially on Pi**

This is the one lever that looked biggest on paper ($20–$40 → $0) and turns out not to be a real option once you look at what it costs to actually get it, and what it buys even if you do.

**fTPM isn't something you buy — it's a feature that has to already exist in the SoC.** Intel chips have had it built in since ~2014 (Intel PTT, a BIOS toggle, genuinely free). Raspberry Pi does not ship one. The Pi's ARM cores support TrustZone at the silicon level, but there's no enabled fTPM stack — getting one running means porting OP-TEE and standing up a TPM2 command stack as a Trusted Application inside it, which requires reworking Pi's non-standard boot chain to bring up the secure world before Linux starts. That's a real embedded-firmware research project with no guaranteed timeline, not a checkbox. (Support maturity for this on Pi 5's newer SoC specifically is unconfirmed.)

**Even if that engineering effort succeeded, it wouldn't fully deliver what's being given up.** An OP-TEE-based fTPM is still TrustZone-level *logical* isolation on the same physical chip as the SBC — not the physical separation a discrete TPM chip provides. A sufficiently deep SBC compromise has a real path to it that it doesn't have to a chip on a different bus entirely.

**The money at stake doesn't justify either the risk or the (Pi) engineering cost.** The TPM is $20–$40 of a $74–$148 shared-chassis cost (§4) — roughly 15–20% of it, or **$4–$8 per host** once amortized across a Pentagon's 5 hosts. That's smaller than the wiring line item per host (§4). And there's a self-undermining angle specific to this project: OAN exists because software-rooted trust (`kb-checker` alone, on the host) isn't considered good enough — that's the entire reason to build a separate physical appliance. Making OAN's *own* root of trust a software/firmware construct sharing silicon with the SBC reintroduces, at OAN's own foundation, the exact category of weakness OAN was built to route around on the host side. On Intel N100 specifically, this is even sharper: fTPM is already sitting free on any stock Intel PC — if that guarantee were considered acceptable, there'd be no need to build OAN's separate hardware at all.

**Verdict:** keep the discrete TPM in both the reference and cheap BOMs. fTPM is documented here as a rejected option, not a live cost-reduction lever — see §6.

## 3.8 Bulk sourcing — **Doesn't apply at Pentagon (5-host) scale**

Real bulk/wholesale pricing tiers (direct-from-manufacturer, distributor quantity breaks) generally start around 50–100+ units. A single Pentagon chassis needs 5 STM32 channels — below that threshold, "bulk" buys at most a modest 10–20% combined-shipping discount, not the 3–5x reduction bulk implies. The savings above (§3.1–§3.7) come from choosing cheaper *parts*, not from order volume. Bulk sourcing becomes a real lever only at lab/fleet scale (multiple chassis), covered in `oan-hardware-appliance.md` §9.2.

## 3.9 INR: flat conversion → domestic sourcing — **Free, and probably already true**

`oan-hardware-appliance.md` §10 prices INR at a flat ~₹87/USD conversion of US retail prices, explicitly flagged as approximate. Domestic Indian sourcing (Robu.in, Robocraze, and similar resellers) for these commodity boards often comes in under that flat conversion, since it isn't paying US retail markup + import duty stacked together. The figures below still use the flat ₹87/USD conversion for consistency with the reference doc — treat them as an upper bound, not a floor.

---

# 4. Cost-Reduced BOM (Model B, shared chassis, Pentagon/5-host cap)

Applying §3.1–§3.6 and §3.9 (i.e. **not** the TPM trade-off — discrete TPM kept, per §6):

| Component | Reference cost | Cheap cost (USD) | Cheap cost (INR) |
|---|---|---|---|
| SBC (Pi Zero 2 W) | $35–$80 | $15–$20 | ₹1,305–₹1,740 |
| microSD | $8 | $6–$8 | ₹520–₹700 |
| ESP32 (bare WROOM) | $6–$10 | $3–$5 | ₹260–₹435 |
| Discrete TPM 2.0 (kept — see §6) | $20–$40 | $15–$20 | ₹1,305–₹1,740 |
| Display | $5–$10 | $0 (dropped) | ₹0 |
| **Shared once, per chassis** | $74–$148 | **$39–$53** | **₹3,393–₹4,611** |
| STM32 (bare Blue Pill clone) | $10–$25 | $3–$6 | ₹261–₹522 |
| Relay (shared multi-channel board, per channel) | $6 | $4–$6 | ₹348–₹522 |
| OOB dongle (generic clone) | $8 | $3–$5 | ₹261–₹435 |
| Wiring/connectors | $8 | $5–$6 | ₹435–₹522 |
| **Per host** | $32–$47 | **$15–$23** | **₹1,305–₹2,001** |

---

# 5. Cost-Reduced Totals by Config

Same single/triple/pentagon shape as `oan-hardware-appliance.md` §9.3, recomputed with the cheap BOM above:

| Config | Hosts | Reference total | Cheap total (USD) | Cheap total (INR) |
|---|---|---|---|---|
| Single | 1 | $106–$195 | $54–$76 | ₹4,698–₹6,612 |
| Triple | 3 | $170–$289 | $84–$122 | ₹7,308–₹10,614 |
| Pentagon (cap) | 5 | $234–$383 | $114–$168 | ₹9,918–₹14,616 |

**Per person, team of 10, Pentagon config:** $11.40–$16.80 / ₹992–₹1,462 — down from $23.40–$38.30 / ₹2,036–₹3,332 on the reference BOM.

These totals keep the discrete TPM per §3.7's verdict. Skipping it (fTPM) would land Pentagon around $99–$148 / ₹8,613–₹12,876, ~$9.90–$14.80/person — but that number is included here only to show the trade-off isn't large enough to matter, not as an available option. It also isn't reliably achievable on a Pi-based chassis at all without the OP-TEE engineering project described in §3.7.

---

# 6. What Not to Cut

Two things this document deliberately does **not** offer as savings, even though they're the largest remaining line items:

- **The discrete TPM.** It's the one component whose entire job is being the thing a compromised host can't fake. Swapping it for software (fTPM) doesn't just save money, it removes the property the design is named for ("Hardware-Assisted Independent Trust," per `oan-hardware-appliance.md`'s own title) — and per §3.7's verdict, on a Pi-based chassis it isn't even a real free option, just an uncertain firmware-engineering project traded for a guarantee that ends up weaker anyway. If budget forces this trade-off despite that, it should be a stated, deliberate decision by whoever owns the deployment — not a default in this document.
- **The STM32 split itself.** Nothing here proposes folding the watchdog/relay logic back onto the SBC to save the ~$3–$6 board cost. That reintroduces the exact "watchdog shares Linux's failure domain" problem `oan-hardware-appliance.md` §4.2.1 explains the STM32 exists to avoid — a few dollars isn't worth giving that up.

Everything actually costed as "free" in §3 (SBC size, display, relay board consolidation, bare-module ESP32/STM32, generic dongle) is free specifically because none of it touches OAN's threat model — it only touches which physical part happens to implement an already-decided role.

---

# 7. Open Questions

1. **Blue Pill clone quality control (§3.4)** — needs an actual batch tested before committing a real chassis's 5 channels to one supplier; no testing has been done, this is a sourcing risk noted, not resolved.
2. **Whether a bare-WROOM ESP32 (§3.5) needs additional passive components** (antenna, decoupling caps) beyond the module itself to match the DevKitC's out-of-box reliability — not itemized here.
3. ~~The fTPM trade-off (§3.7) is deliberately left as an option, not a decision.~~ **Resolved this pass:** discrete TPM stays in both BOMs. fTPM is rejected — not practically free on a Pi-based chassis (would need an unproven OP-TEE/TPM2-TA port), and even if built, delivers a weaker guarantee than the $4–$8/host it would save is worth. Remains a live question only if the SBC is genuinely an Intel N100 (where fTPM is a free BIOS toggle) — even there, §3.7 recommends keeping the discrete TPM, since the point of building OAN at all is to exceed what's already free on stock hardware.

---

# 8. Relationship to Existing Documentation

This document is an appendix to [`oan-hardware-appliance.md`](oan-hardware-appliance.md) — it does not change that document's architecture, threat model, or open questions (§14 there still applies in full), only its BOM pricing (§9–§10 there). Where this document is silent on a component, the reference BOM's choice stands. It also does not touch [`oan-fms.md`](oan-fms.md) at all — fleet management cost isn't in scope here.
