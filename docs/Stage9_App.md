# Stage 9 — App (Streamlit dashboard)

The demo: a sales-facing dashboard for prospecting. It reads a single serving model
**`gold.gold_prospects`** (prospects + cached firmographics + pitch, joined by dbt)
plus `gold.gold_company_services` for the drill-down, and lets a rep filter, rank, and
open a company to see *why* it's a lead. **No live LLM, and the app reads only gold** —
never the `enrichment.*` tables directly.

Code: [`app/app.py`](../app/app.py) · run: `uv run streamlit run app/app.py`.

---

## 1. What it shows

| Area | Content |
|---|---|
| **KPIs** | Prospects · actively-exploited (KEV) · actively-compromised · total CVEs · countries |
| **Sidebar filters** | Segment · **Region** (ANZ/APAC/EMEA/Americas territory) · Country · **Well-enriched only** · Signal type · Min score · Domain search — **cascading** (no dead options) |
| **Prospect list** | Clickable **AgGrid** table by lead score — **Company** (extracted org), domain, segment, country, score, **KEV**, #CVEs, top reasons. **Actively-compromised rows tinted red, KEV-exposed amber.** Click a row → detail above. |
| **Company detail** | Score / segment / country / confidence / **peak exploit prob. (EPSS)**, **Score breakdown**, **Firmographics** (industry, **notable exposure** = interpreted tech, footprint, emails), **Buying signals**, **Suggested outreach pitch** (KEV/EPSS/org-grounded), **View exposed surface**, **Contacts (via Firmable)** |
| **Region breakdown** | Prospects-by-region chart (sales territory view) |

## 2. Rep workflow

Filter to my region/segment → scan the red (compromised) / amber (KEV) rows → open a
top company → read buying signals + the pitch (cites real actively-exploited CVEs) → call.

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
**serving DB** (`build_serving_db.py`) with just `gold.gold_prospects` +
`gold.gold_company_services` — ~2 MB — and point the app at it (it auto-prefers the
serving DB when present). Since the app reads only gold, this is a clean config swap.
