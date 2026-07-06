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
| **Filters** | Clickable **region chart** (ANZ/APAC/EMEA/Americas territory, with a country count) · **Segment** · **Country** · **Company** search · **Security-signals chips** (KEV, CVEs, DB exposed, EOL, self-signed, VPN, IoT, compromise) · **Technology chips** (web server, database, AI/ML, ICS/OT, DevOps…). Chips are **count-labelled and click-to-filter** — the landscape *is* the filter; everything **cascades**. |
| **Prospect list** | Clickable **AgGrid** table by lead score — **Company** (extracted org, falls back to domain) · Segment · Country · Score · **Total Services · Exposed IPs · KEV/CVEs · Security Signals · Technologies**. Emphasized header, centered cells. Click a row → detail above. |
| **Company detail** | Importance-ordered **stat tiles** (Lead Score · KEV · CVEs · Peak EPSS · Total Services / Exposed IPs · Segment · Country · Distinct Technologies · Confidence) · **Score-breakdown bar chart** · **Products / Technologies bars + Transport donut** · per-company **Technologies distribution** · **Company Profile & Signals** (why-they're-a-fit incl. a competitive-displacement angle, targeting signals, tech footprint, emails) · **structured outreach pitch (v5)** rendered as markdown · **View Exposed Surface** (per-service technologies + CVEs) · Contacts (via Firmable) |

## 2. Rep workflow

Filter to my territory/segment → narrow with the **Security-signals / Technology chips**
(e.g. "KEV + runs a competitor firewall") → open a top company → read the profile,
*why they're a fit*, and the structured pitch (cites real actively-exploited CVEs and,
where present, a displacement angle) → call.

## 3. Key UI decisions

- **Clickable table = AgGrid.** Streamlit's native options don't fit: `LinkColumn`
  opens a new tab; `st.dataframe(on_select=…)` forces a selection-indicator column.
  AgGrid gives same-tab, click-any-row, no extra column. Cost: one dependency.
- **Filters as count-labelled chips.** Security signals and technologies render as
  clickable chips showing how many prospects carry each — the distribution and the
  filter are the same control, so a rep sees the landscape and narrows it in one place.
- **Score breakdown = bar chart.** The additive score is shown as a per-signal bar chart
  (mirrors the SQL formula) so a rep sees exactly what drives it — kills the "why is 1
  CVE worth 102?" confusion (the points come from the *other* signals).
- **Country names** come from a dbt **seed** (`reference.country_codes`, ISO-3166),
  joined in gold — reference data as version-controlled seed, not hard-coded.
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
`gold.gold_company_services` — ~4 MB — and point the app at it (it auto-prefers the
serving DB when present). Since the app reads only gold, this is a clean config swap.
