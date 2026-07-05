# Stage 8 — Gold Mart (dbt)

The business-facing marts the app reads: a ranked **prospect list** and a
per-company **drill-down**, with technical signals translated into sales language.

---

## 1. Models

| Model | Materialization | Grain | What |
|---|---|---|---|
| `gold.gold_companies` | table | one company | Ranked prospects: score, segment, country, region, signals (incl. **KEV/EPSS**), **reasons** |
| `gold.gold_company_services` | view | one service | Every exposed service of a prospect (detail-page drill-down) |
| `gold.gold_prospects` | table | one company | **Serving model** the app reads: `gold_companies` + cached firmographics (`company_profile`) + pitch (`company_pitch`), joined by dbt |

Code: [`transform/models/gold/`](../transform/models/gold). The pitch/profile enrichers
*read* `gold_companies` and write to `enrichment.*`; `gold_prospects` joins them back so
the app never reads `enrichment` directly and there is no build cycle.

---

## 2. What makes a prospect (the filter)

`gold_companies` = `silver_company_candidates` ⨝ `enrichment.entity_labels`, keeping
only rows where:

- `entity_class = 'business'` — LLM-verified real company (infra dropped),
- `not flagged` — passed the guardrails (confidence + IP cross-check),
- **≥ 1 security signal** — CVE / EOL / DB / self-signed / VPN / IoT / breach
  (exposed-but-clean companies are not prospects — nothing to sell them).

So the mart is the intersection of *is a real business* and *has a reason to buy*.

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

- **3,973 prospects** after a wide enrichment run (3,260 commercial, 353 education,
  210 nonprofit, 88 government, 62 other); **3,439** carry an actively-exploited
  (CISA KEV) CVE. Real companies/universities surface with clean reasons
  (`vt.edu`, `nextpertise.nl`, `accesskenya.com`, `unibocconi.it`…).
- **Coverage note:** the prospect count grows with `ENRICH_TOP_N` — the LLM
  verifies the top-scoring candidates (the head that actually surfaces in the UI),
  not all 500k (which would be ~33 h of LLM calls and pointless for low-score
  companies). Cached, so coverage can be extended anytime.
