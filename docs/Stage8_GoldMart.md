# Stage 8 — Gold Mart (dbt)

The business-facing marts the app reads: a ranked **prospect list** and a
per-company **drill-down**, with technical signals translated into sales language.

---

## 1. Models

| Model | Materialization | Grain | What |
|---|---|---|---|
| `gold.gold_companies` | table | one company | Ranked prospects: score, segment, country, region, signals (incl. **KEV/EPSS**), **reasons** |
| `gold.gold_company_services` | view | one service | Every exposed service of a prospect (detail-page drill-down), incl. per-service **`technologies`** (cpe-derived — fuller than `product`) |
| `gold.gold_prospects` | table | one company | **Serving model** the app reads: `gold_companies` + cached firmographics (`company_profile`) + pitch (`company_pitch`), joined by dbt |

Code: [`transform/models/gold/`](../transform/models/gold). The pitch/profile enrichers
*read* `gold_companies` and write to `enrichment.*`; `gold_prospects` joins them back so
the app never reads `enrichment` directly and there is no build cycle.

---

## 2. What makes a prospect (the filter)

`gold_companies` = `silver_company_candidates` ⨝ `enrichment.entity_labels`, keeping
only rows where:

- `entity_class in ('business', 'infra')` — LLM-verified. **v4:** infrastructure /
  hosting providers are kept too, tagged with `entity_class`. They are not noise but a
  distinct ICP segment (hosts / ISPs / datacenters are themselves high-surface cybersecurity
  buyers). The app **defaults to businesses-only** and exposes infra behind an *"Include
  infrastructure / hosting providers"* toggle — so the "see past the hosting layer" default
  is preserved while the fuller universe is one click away.
- `not flagged` — passed the guardrails (confidence + IP cross-check). This is a
  **label-quality** gate, orthogonal to the business-vs-infra choice, so it still excludes.
- **≥ 1 security signal** — CVE / EOL / DB / self-signed / VPN / IoT / breach
  (exposed-but-clean companies are not prospects — nothing to sell them).

So the mart is *has a reason to buy* ∩ *is a classified entity* — business by default,
infrastructure on demand.

---

## 3. Reason translation (rep-friendly)

Technical signals → plain sales language, built as a `reasons` list in SQL:

| Signal | Reason shown to the rep |
|---|---|
| `has_breach` | "Signs of active compromise (malware / C2)" |
| `kev_count` | "N actively-exploited (CISA KEV) vulnerabilities" |
| `cve_count` | "N known software vulnerabilities" |
| `has_db` | "Database exposed to the internet" |
| `has_eol` | "Running unsupported / end-of-life software" |
| `has_selfsigned` | "Weak or self-signed SSL certificate" |
| `has_vpn` / `has_iot` | "VPN / remote access exposed" / "Exposed IoT devices" |
| `has_rdp` / `has_telnet` | "Remote Desktop (RDP) exposed" / "Telnet (unencrypted admin) exposed" |
| `has_smb` / `has_ftp` | "SMB / file-sharing exposed" / "FTP exposed" (from the port inventory) |
| `exposed_panels` | "Admin / control panel exposed: cPanel/WHM, Plesk…" (from the HTTP title) |

The rep sees *why to call*, not CVE numbers on ports.

---

## 4. dbt tests

Run with `dbt build` (models + tests together). Current tests:

- `gold_companies.domain` — **not_null**, **unique** (one row per prospect)
- `gold_companies.segment` — **accepted_values** (commercial/education/government/nonprofit/other)
- `gold_companies.score` — **not_null**
- `gold_company_services.domain` — **not_null**

All passing (models + tests).

---

## 5. Result & coverage

- **3,973 business prospects** after a wide enrichment run (3,260 commercial, 353 education,
  210 nonprofit, 88 government, 62 other); **3,439** carry an actively-exploited
  (CISA KEV) CVE. Real companies/universities surface with clean reasons
  (`vt.edu`, `nextpertise.nl`, `accesskenya.com`, `unibocconi.it`…).
- **v4:** with infrastructure kept as a segment, the mart is **~6,654** (3,973 business +
  2,681 infra); the app shows the 3,973 by default and the full 6,654 when the infra toggle
  is on. Reasons/score/tech profile are identical across both — only the classification
  (and, for infra, the absence of a generated pitch/profile) differs.
- **Coverage note:** the prospect count grows with `ENRICH_TOP_N` — the LLM
  verifies the top-scoring candidates (the head that actually surfaces in the UI),
  not all 500k (which would be ~33 h of LLM calls and pointless for low-score
  companies). Cached, so coverage can be extended anytime.
