# Stage 8 — Gold Mart (dbt)

The business-facing marts the app reads: a ranked **prospect list** and a
per-company **drill-down**, with technical signals translated into sales language.

---

## 1. Models

| Model | Materialization | Grain | What |
|---|---|---|---|
| `gold.gold_companies` | table | one company | Ranked prospects: score, segment, country, signals, **reasons** |
| `gold.gold_company_services` | view | one service | Every exposed service of a prospect (detail-page drill-down) |

Code: [`transform/models/gold/`](../transform/models/gold).

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

All passing (9/9 nodes incl. tests).

---

## 5. Result & coverage

- **53 prospects** from the first top-500 enrichment (35 commercial, 14 education,
  1 government, 3 other). Real companies/universities surface with clean reasons
  (`vt.edu`, `nextpertise.nl`, `accesskenya.com`, `unibocconi.it`…).
- **Coverage note:** the prospect count grows with `ENRICH_TOP_N` — the LLM
  verifies the top-scoring candidates (the head that actually surfaces in the UI),
  not all 500k (which would be ~33 h of LLM calls and pointless for low-score
  companies). Cached, so coverage can be extended anytime.
