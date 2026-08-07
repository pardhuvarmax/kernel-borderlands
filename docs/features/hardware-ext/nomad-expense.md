# NOMAD — Expense Breakdown (`nomad-expense.md`)

**Version:** 0.1
**Component:** Cost reference for the [Node Out-of-Band Module for Attestation & Defense](nomad-hardware-appliance.md), Model B (shared chassis, up to 5-host Pentagon cap)
**Status:** Costing exercise only — not a build target, not a sourcing quote. Combines the Model B totals from `nomad-hardware-appliance.md` §9 with the cost-reduced BOM from `nomad-cheap.md` §4–5, and adds a per-person split for a 10- and 15-member team.

---

## 1. Shared Chassis + Per-Host Add-On Cost

The shared chassis (SBC, microSD, ESP32, TPM, display) is bought **once**. Every host added on top only pays the per-host add-on (STM32 channel, relay tap, OOB link, wiring) — capped at 5 hosts per chassis (Pentagon).

### 1.1 Reference BOM (retail parts)

| Item | Cost (USD) | Cost (INR) |
|---|---|---|
| **Shared chassis** (SBC, microSD, ESP32, TPM, display) — paid once | $74–148 | ₹6,440–12,880 |
| **Per-host add-on** (STM32 + relay channel + OOB link + wiring) | $32–47 | ₹2,785–4,090 |

| Config | Hosts | Chassis + (hosts × add-on) | **Total (USD)** | **Total (INR)** |
|---|---|---|---|---|
| Single | 1 | $74–148 + 1×($32–47) | **$106–195** | **₹9,220–16,965** |
| Triple | 3 | $74–148 + 3×($32–47) | **$170–289** | **₹14,790–25,145** |
| Pentagon (cap) | 5 | $74–148 + 5×($32–47) | **$234–383** | **₹20,360–33,320** |

### 1.2 Cheap BOM (cost-reduced parts, discrete TPM kept)

| Item | Cost (USD) | Cost (INR) |
|---|---|---|
| **Shared chassis** (Pi Zero 2W, ESP32 bare, discrete TPM, no display) — paid once | $39–53 | ₹3,393–4,611 |
| **Per-host add-on** (Blue Pill clone, shared relay board, generic dongle, wiring) | $15–23 | ₹1,305–2,001 |

| Config | Hosts | Chassis + (hosts × add-on) | **Total (USD)** | **Total (INR)** |
|---|---|---|---|---|
| Single | 1 | $39–53 + 1×($15–23) | **$54–76** | **₹4,698–6,612** |
| Triple | 3 | $39–53 + 3×($15–23) | **$84–122** | **₹7,308–10,614** |
| Pentagon (cap) | 5 | $39–53 + 5×($15–23) | **$114–168** | **₹9,918–14,616** |

**Pattern:** chassis cost is fixed no matter how many hosts you add (up to 5), so every extra host after the first only costs the cheap add-on slice — this is why Pentagon beats Single on a per-host basis even though its total is higher.

---

## 2. Per-Person Split — Team of 10 vs. Team of 15

### 2.1 Reference BOM

| Config | Hosts | Total (USD) | Per person ÷10 | Per person ÷15 |
|---|---|---|---|---|
| Single | 1 | $106–195 | $10.60–19.50 | $7.07–13.00 |
| Triple | 3 | $170–289 | $17.00–28.90 | $11.33–19.27 |
| Pentagon | 5 | $234–383 | $23.40–38.30 | $15.60–25.53 |

| Config | Hosts | Total (INR) | Per person ÷10 | Per person ÷15 |
|---|---|---|---|---|
| Single | 1 | ₹9,220–16,965 | ₹922–1,697 | ₹615–1,131 |
| Triple | 3 | ₹14,790–25,145 | ₹1,479–2,515 | ₹986–1,676 |
| Pentagon | 5 | ₹20,360–33,320 | ₹2,036–3,332 | ₹1,357–2,221 |

### 2.2 Cheap BOM

| Config | Hosts | Total (USD) | Per person ÷10 | Per person ÷15 |
|---|---|---|---|---|
| Single | 1 | $54–76 | $5.40–7.60 | $3.60–5.07 |
| Triple | 3 | $84–122 | $8.40–12.20 | $5.60–8.13 |
| Pentagon | 5 | $114–168 | $11.40–16.80 | $7.60–11.20 |

| Config | Hosts | Total (INR) | Per person ÷10 | Per person ÷15 |
|---|---|---|---|---|
| Single | 1 | ₹4,698–6,612 | ₹470–661 | ₹313–441 |
| Triple | 3 | ₹7,308–10,614 | ₹731–1,061 | ₹487–708 |
| Pentagon | 5 | ₹9,918–14,616 | ₹992–1,462 | ₹661–974 |

---

## 3. Takeaway

Going from 10 to 15 members drops everyone's share by a third. Since Pentagon covers 5 hosts for a modest per-person bump over Single, a 15-person team splitting a Pentagon chassis on the cheap BOM lands around **₹661–974 each** — cheaper per person than a 10-person team splitting even a Single unit (₹470–661), which only covers 1 host instead of 5.

---

## 4. Relationship to Existing Documentation

Figures here are derived directly from [`nomad-hardware-appliance.md`](nomad-hardware-appliance.md) §9–§10 (reference BOM, Model B) and [`nomad-cheap.md`](nomad-cheap.md) §4–§5 (cost-reduced BOM). This document adds no new architecture or design decisions — it only reorganizes existing cost figures into chassis/add-on and per-person views. INR figures use the same approximate ~₹87/USD flat conversion used in both source documents; treat as an upper bound, not a sourcing quote.
