# CLAUDE.md — Osprey

Sales intelligence for cybersecurity vendors: turn Shodan internet-exposure scans
into a ranked list of prospect companies (with reasons), so a sales team knows
who to target and why. Built as a take-home for **Firmable (Senior Data Engineer,
Sourcing)**.

## Stack

- **DuckDB** — analytical warehouse (one file: `data/warehouse/osprey.duckdb`). Production analogue: Snowflake/BigQuery.
- **dbt (dbt-duckdb)** — SQL transforms (silver, gold) in `transform/`.
- **Python 3.12 + uv** — ingestion, LLM enrichment, orchestration (`osprey/`).
- **LLM** — Claude (Haiku) via the Claude CLI transport; structured output + evals.
- **Dagster** — orchestration (planned, Stage 10).

## Architecture (medallion)

```
source .zst -> BRONZE (bronze.shodan_scans, Python)
            -> SILVER (dbt: silver_services, silver_company_candidates)
            -> LLM ENRICHMENT (Python: top-N -> enrichment.entity_labels, cached)
            -> GOLD (dbt: gold_companies + reasons) -> APP (Streamlit)
```

## Directory map

```
osprey/            # Python package (shared platform + thin pipeline steps)
  config.py        #   central config (paths, model ids, thresholds)
  schemas.py       #   ALL Pydantic contracts (ShodanScan, EntityLabel)
  warehouse.py     #   the ONLY module that talks to DuckDB
  llm/             #   shared LLM platform: client (transport), prompts, runner, eval
  pipelines/       #   dagster-agnostic steps: ingest_bronze, classify_entities, enrich_entities
  orchestration/   #   Dagster definitions (planned)
transform/         # dbt project (SQL: silver, gold) - NOT a Python package
data/
  analysis/        #   ad-hoc discovery SQL (with embedded OUTPUT comments) - not pipeline
  evals/           #   labelled eval sets for the LLM classifier
  samples/         #   inspection samples
  warehouse/       #   osprey.duckdb (git-ignored)
docs/              # one Stage doc per stage + context/ + helper_commands.md
app/               # Streamlit dashboard (planned)
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

**v1 complete.** Stages 1–11 done: discovery -> bronze -> silver -> LLM
classification + eval -> enrichment (labels + grounded pitches) -> gold mart + dbt
tests -> Streamlit app (AgGrid, score breakdown, cached pitches) -> Dagster lineage
(thin/illustrative) -> serving DB + hosting prep -> Architecture.md + README +
ProblemAndApproach. **Remaining:** actual Streamlit Cloud deploy (needs GitHub +
account auth). **v2:** KEV/NVD severity ranking, contact data (via Firmable),
firmographic ICP, recurring ingestion (freshness), LLM extraction from banners,
CSV/CRM export, chat, CSM.

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
