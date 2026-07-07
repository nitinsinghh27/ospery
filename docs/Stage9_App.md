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
| **Filters** | A compact **filter bar** on the main page (keeps the results table full-width). Row 1: a **Business-Only Prospects** toggle (off by default → the full universe incl. infrastructure/hosting; on = the "see past the hosting layer" view) + a **Company search**. Row 2: five **popover facets** — **Territory** (clickable region chart + Country), **Hosting** (provider, count-labelled), **Security** (KEV, CVEs, DB exposed, EOL, self-signed, VPN, IoT, compromise), **Technology** (a specific tech/version search — mongodb, `openssh 7`, `python 2` — + web server/database/AI-ML/ICS-OT/Legacy-EOL/DevOps categories), **Exposure** (internet-exposed services — RDP/SMB/Telnet/DB/K8s — and exposed admin panels — cPanel/WHM, Plesk, firewall & router logins). Each facet opens on click and overlays, so the table never reflows; every option is **count-labelled and click-to-filter**, and the whole landscape **cascades** with the scope toggle. |
| **Prospect list** | Clickable **AgGrid** table by lead score — **Company** (extracted org, falls back to domain) · Segment · Country · Score · **Total Services · Exposed IPs · KEV/CVEs · Security Signals · Technologies · Hosting** (normalized cloud/CDN, else the dominant network owner). Emphasized header, centered cells. Click a row → detail above. A **Download target list (CSV)** button exports the *currently-filtered* prospects (company · product@version + CVEs · exposure · reasons) as a campaign-ready list — so a rep filters to a competitor tech and hands sales an account list. |
| **Company detail** | Importance-ordered **stat tiles** (Lead Score · KEV · CVEs · Peak EPSS · Total Services / Exposed IPs · Segment · Country · Distinct Technologies · Confidence) · **Score-breakdown bar chart** · **Products / Technologies bars** (all entries, uniform width, in equal fixed-height **scrollable** panels) · per-company **Technologies distribution** · a **Sales Prospect Intelligence** brief (deterministic, no LLM — see §3; incl. **Vulnerable Software** — the exact `product@version` + its CVEs, the low-level displacement hook) · the cached **structured outreach pitch** rendered as markdown · an always-on **Exposed Surface** table (IP · Port · Transport · Product · Version · Technologies · **Server** · **Network owner** · Tags · CVEs · Country · Scanned) · Contacts (via Firmable) |

## 2. Rep workflow

Filter to my territory/segment → narrow with the **Security-signals / exposed-service /
admin-panel chips** (e.g. "KEV + RDP exposed", or "runs cPanel") → open a top company →
read the **Sales Prospect Intelligence** brief (risk level, why-they're-a-fit themes, why-now
triggers, top risks, ready-to-use talking points) → call.

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
- **Sales Prospect Intelligence = a deterministic (no-LLM) narrative.** The detail's
  headline section transforms the cached telemetry into a sales-ready brief — an
  **Executive Summary** (risk level, priority score, outreach priority), **Why They're a
  Fit** (findings grouped into business themes), **Why Now** (timing triggers), an
  **Attack Surface Overview** (exposed services grouped, not dumped), **Top Risk Signals**
  (top 5 by business impact), and **Sales Talking Points** (observation / risk / opener).
  It's pure rules over the row's fields — every line traces to evidence, nothing is
  invented, and a section is omitted when its evidence is absent. This is the primary
  sales artefact; the LLM pitch is kept but de-emphasized.
- **All entries, scrollable.** The Products / Technologies bars show *every* distinct
  entry (uniform bar width) inside equal fixed-height scroll panels — a 50-technology
  company scrolls instead of truncating, and the two panels stay the same size.
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
`gold.gold_company_services` — ~13 MB (grew from ~4 MB once infrastructure prospects and
their many services were included) — and point the app at it (it auto-prefers the serving
DB when present). Since the app reads only gold, this is a clean config swap.
