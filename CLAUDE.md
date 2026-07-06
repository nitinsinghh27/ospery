# CLAUDE.md — Osprey

Sales intelligence for cybersecurity vendors: turn Shodan internet-exposure scans
into a ranked list of prospect companies (with reasons), so a sales team knows
who to target and why. Built as a take-home for **Firmable (Senior Data Engineer,
Sourcing)**.

## Stack

- **DuckDB** — analytical warehouse (one file: `data/warehouse/osprey.duckdb`). Production analogue: Snowflake/BigQuery.
- **dbt (dbt-duckdb)** — SQL transforms (silver, gold) in `transform/`.
- **Python 3.12 + uv** — ingestion, LLM enrichment, orchestration (`osprey/`).
- **LLM** — Claude via the Claude CLI transport: **Haiku** (entity classification) + **Sonnet** (firmographic extraction, pitches); structured output, evals, cost/latency traces.
- **Dagster** — orchestration (thin asset layer over the pipeline steps; `[tool.dagster]`).
- **Third-party feeds** — CISA **KEV** (actively-exploited CVEs) + FIRST **EPSS** (exploit probability), joined in silver.

## Architecture (medallion)

```
source .zst -> BRONZE (bronze.shodan_scans, Python)
            -> SILVER (dbt: silver_services, silver_company_candidates; KEV/EPSS-aware score)
            -> LLM ENRICHMENT (Python, cached: entity_labels + company_profile [firmographics] + company_pitch)
            -> GOLD (dbt: gold_companies + reasons; gold_prospects = mart + firmographics + pitch)
            -> APP (Streamlit, reads gold_prospects only)
```

## Directory map

```
osprey/            # Python package (shared platform + thin pipeline steps)
  config.py        #   central config (paths, model ids, thresholds)
  schemas.py       #   ALL Pydantic contracts (ShodanScan, EntityLabel, CompanyPitch, CompanyProfile)
  warehouse.py     #   the ONLY module that talks to DuckDB
  llm/             #   shared LLM platform: client (transport), prompts, runner, eval, eval_extract, trace
  pipelines/       #   dagster-agnostic steps: ingest_bronze, classify/enrich_entities, fetch_kev/epss,
                   #   extract_profiles, generate_pitches, build_serving_db
  orchestration/   #   Dagster asset definitions (thin wrappers over pipelines)
transform/         # dbt project (SQL: silver, gold; seeds, tests) - NOT a Python package
data/
  analysis/        #   ad-hoc discovery SQL (with embedded OUTPUT comments) - not pipeline
  evals/           #   labelled eval sets for the LLM classifier / extractor
  samples/         #   inspection samples (git-ignored — raw banners contain leaked secrets)
  warehouse/       #   osprey.duckdb (git-ignored)
  serving/         #   osprey_serving.duckdb (small gold-only DB for hosting; committed)
docs/              # one Stage doc per stage + context/ + helper_commands.md
app/               # Streamlit dashboard (shipped; hosted on Streamlit Cloud)
```

## How to run

All commands (env, ingestion, dbt, enrichment, eval, DB access) live in
[`docs/helper_commands.md`](docs/helper_commands.md). Quick refs:
`uv sync` · `uv run python -m osprey.pipelines.ingest_bronze` ·
`uv run dbt run --project-dir transform --profiles-dir transform` ·
`uv run python -m osprey.pipelines.enrich_entities` · `uv run python -m osprey.llm.eval`.

## Conventions

- **`pipelines/` are dagster-agnostic pure functions**; `orchestration/` wraps them as assets (testable, orchestrator-swappable).
- **`schemas.py`** is the single source of truth for data contracts *and* the Bronze DuckDB DDL.
- **`warehouse.py`** is the only DuckDB access layer. **dbt** owns SQL transforms (`transform/`), not Python.
- **LLM discipline**: rules first, LLM only for the residual; versioned prompts (`ENTITY_PROMPT_VERSION`); labelled evals in `data/evals/`; results cached in `enrichment.entity_labels` (idempotent — the app never calls the LLM live).
- **Warehouse is single-writer** — run pipeline steps in dependency order (Dagster handles this); no concurrent writers on the file.
- **Every stage gets a `docs/StageN_*.md`**; discovery numbers are SQL-backed (queries live in `data/analysis/` with their outputs embedded).

## Status

**v1 + v2 shipped & hosted.** Pipeline: discovery -> bronze -> silver (KEV/EPSS-aware
score) -> LLM classification + eval -> enrichment (labels + firmographic extraction
w/ eval + grounded pitches) -> gold mart + dbt tests -> serving `gold_prospects` ->
Streamlit app (hosted on Streamlit Cloud) -> LLM observability/traces -> Dagster lineage
(thin) -> serving DB -> Architecture/README/ProblemAndApproach + SKILL.md.
**v2 highlights:** third-party connectors **CISA KEV** (actively-exploited, +30 score) and
**FIRST EPSS** (exploit probability, per-prospect peak); **prospect universe expanded
to ~3,973** (wider entity classification); **richer pitch v4** (KEV/EPSS/org-grounded);
app: company column, red/amber row-marking, tech-interpretation, region (ANZ/APAC/EMEA/
Americas) territory filter, peak-EPSS, well-enriched filter.
**v3 highlights:** **deterministic technology extraction** (`silver_company_tech`,
NO LLM) — parses Shodan's own fingerprints (`cpe23`/`product`/`http_server`) + tags
(`cloud`/`cdn`/`database`/`ai`/`ics`/`devops`) into a per-company tech profile (web
stack, infra/CDN/cloud, DB, **exposed AI/ML**, ICS/OT); surfaced in gold + app
(AI/ML KPI, Technology filter, tech-profile detail, AI/ICS reasons). The
**technographic layer** for ICP fit + competitive displacement. SQL-backed:
`data/analysis/tech_signals.sql`.
**Backlog:** CVSS/NVD severity (rate-limited API), contact data (via Firmable),
firmographic ICP, recurring ingestion, CSV/CRM export, chat, CSM.

## Working agreement (for the assistant)

- **Never invent experience/capabilities.** Distinguish what the project actually
  demonstrates vs. what's aspirational. Be honest about gaps (e.g. no crawling —
  data was provided).
- **Be direct and critical** (staff-engineer level): explain trade-offs, flag
  risks, challenge weak assumptions. Prioritize correctness, then simplicity.
- **Ground claims in evidence** — numbers come from real queries/eval runs, not
  guesses. Surface caveats.
- Keep the prototype **simple and reproducible** (clone -> `uv sync` -> run); note
  the production-scale path rather than over-building it.
