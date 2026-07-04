# Stage 9 — App (Streamlit dashboard)

The demo: a sales-facing dashboard for prospecting. It reads the **Gold marts** and
the **cached LLM enrichment** (labels + pitches) and lets a rep filter, rank, and
open a company to see *why* it's a lead. **No live LLM** — the app only reads
materialized/cached tables.

Code: [`app/app.py`](../app/app.py) · run: `uv run streamlit run app/app.py`.

---

## 1. What it shows

| Area | Content |
|---|---|
| **KPIs** | Prospects (filtered), actively-compromised, total CVEs, countries |
| **Sidebar filters** | Segment · Country · Signal type · Min score · Domain search — **cascading** (each filter's options reflect the ones above, so no dead options) |
| **Prospect list** | Clickable **AgGrid** table ranked by lead score — domain, segment, country (full name), score, #CVEs, top reasons. Click a row → detail opens above. |
| **Company detail** | Score / segment / country / confidence, **Score breakdown** (per-signal points), **Buying signals** (plain-English reasons), **Suggested outreach pitch** (cached, grounded), **View exposed surface** drill-down, **Contacts (via Firmable)** placeholder |

## 2. Rep workflow

Filter to my territory / segment → open a top-scored company → read the buying
signals + the suggested pitch (which cites the real CVEs/products) → call.

## 3. Key UI decisions

- **Clickable table = AgGrid.** Streamlit's native options don't fit: `LinkColumn`
  opens a new tab; `st.dataframe(on_select=…)` forces a selection-indicator column.
  AgGrid gives same-tab, click-any-row, no extra column. Cost: one dependency.
- **Country names** come from a dbt **seed** (`reference.country_codes`, ISO-3166),
  joined in gold — reference data as version-controlled seed, not hard-coded.
- **Score breakdown** mirrors the SQL scoring formula so a rep can see exactly why a
  score is what it is (kills the "why is 1 CVE worth 102?" confusion — the points
  come from the *other* signals).
- **Suggested pitch** is pre-generated + cached (see [Stage 7](Stage7_LLMEnrichment.md));
  the app never calls the LLM live, so the demo is shareable with no API key.

## 4. Data-display notes (not bugs)

- **Most services show `product = None`.** Shodan fingerprints a product for only
  ~15% of services; the rest are just an open port + banner. The value is the
  **aggregate** signal per company (has CVEs / DB exposed / EOL), not a product on
  every row.
- **Unusual high ports** (e.g. 12371) reflect the specific Shodan scan-slice noted
  in [Stage 1](Stage1_DataDiscovery.md#5-limitations--roadmap-data).

## 5. Hosting

The full warehouse (~3 GB) is too big to deploy. For hosting we publish a small
**serving DB** with just the Gold tables + cached enrichment (labels, pitches) — a
few MB — and point the app at it. The app already reads only `gold.*` and
`enrichment.company_pitch`, so this is a config swap (Stage 11).
