# Architecture — Osprey

Sales intelligence for cybersecurity vendors: turn Shodan internet-exposure scans
into a ranked list of prospect companies (with reasons + grounded outreach pitches).
For the *why* (business problem, prospecting methodology, competitive landscape) see
[docs/ProblemAndApproach.md](docs/ProblemAndApproach.md).

---

## 1. Data flow (medallion)

```
  Shodan dump (.json.zst, ~9.2M services)
        │  Python streaming ingest (Pydantic contract → Arrow bulk insert)
        ▼
  ┌───────────────┐   BRONZE   raw, faithful, flat columns
  │ bronze.shodan │   (one row per scanned service)
  │    _scans     │
  └──────┬────────┘
         │  dbt (SQL): drop honeypots, unnest domains, aggregate signals,
         │             dedup, deterministic infra classifier, lead score
         ▼
  ┌──────────────────────────┐   SILVER   clean, per-company candidates
  │ silver_services (view)   │
  │ silver_company_candidates│──────────────┐
  └──────────────────────────┘              │ top-N by score
         │                                   ▼
         │                        ┌─────────────────────────┐  LLM ENRICHMENT (Python)
         │                        │ enrichment.entity_labels│  business/infra + segment,
         │                        │  (cached, versioned)    │  rules-first, LLM residual,
         │                        └──────────┬──────────────┘  guardrails
         │                                   │
         ▼                                   ▼
  ┌───────────────────────────────────────────────┐   GOLD   prospect marts
  │ gold_companies   (ranked prospects + reasons)  │
  │ gold_company_services (per-company drill-down) │◄── reference.country_codes (dbt seed)
  └──────┬─────────────────────────────────┬──────┘
         │  grounded CVEs+versions          │
         ▼                                  │
  ┌─────────────────────────┐  LLM PITCHES │
  │ enrichment.company_pitch│  (Sonnet,    │
  │  (cached, versioned)    │   grounded)  │
  └──────────┬──────────────┘              │
             ▼                             ▼
        ┌──────────────────────────────────────┐
        │  Streamlit app  (reads cached tables, │
        │  never calls the LLM live)            │
        └──────────────────────────────────────┘
```

**Key invariant:** the LLM runs only during offline enrichment builds. The app reads
**cached, materialized** tables — so the demo is deterministic, reproducible, and
shareable with no API key.

## 2. Stack & why

| Concern | Choice | Rationale (prototype → production analogue) |
|---|---|---|
| Warehouse | **DuckDB** (one file) | Zero-ops analytical engine; single-file is perfect for a prototype. Prod: Snowflake/BigQuery. |
| Transforms | **dbt (dbt-duckdb)** | SQL transforms with tests + lineage; portable to any warehouse. |
| Ingestion / enrichment | **Python 3.12 + uv** | Streaming ingest, LLM orchestration; uv = fast, reproducible env (no Docker needed for a prototype). |
| LLM | **Claude via CLI transport** | Uses existing login (no API key to share); one swappable transport module. Haiku for classification, Sonnet for pitches. |
| Contracts | **Pydantic** | Single source of truth: schema → DuckDB DDL → Arrow schema → validation. |
| Orchestration | **Dagster** (thin, illustrative) | One-time batch needs no scheduler; shows lineage + that steps are orchestrator-agnostic. |
| App | **Streamlit + AgGrid** | Fast sales-facing dashboard; AgGrid for clickable rows. |

## 3. Module map (what owns what)

```
osprey/                       # Python package (platform + thin pipeline steps)
  config.py                   #   all paths, model ids, thresholds, vendor context
  schemas.py                  #   ALL Pydantic contracts + Bronze DuckDB DDL
  warehouse.py                #   the ONLY module that talks to DuckDB
  llm/                        #   shared LLM platform
    client.py                 #     CLI transport (swap this for the API in prod)
    prompts.py                #     versioned prompts (entity, pitch)
    runner.py                 #     batched + concurrent structured-output runner
    eval.py                   #     labelled-eval scoring (precision/recall/F1)
  pipelines/                  #   dagster-agnostic pure functions:
    ingest_bronze.py          #     stream .zst → bronze
    classify_entities.py      #     TLD rule + LLM classify
    enrich_entities.py        #     top-N → entity_labels (cached)
    generate_pitches.py       #     gold → grounded pitches (cached)
    build_serving_db.py       #     export small deployable DB
  orchestration/
    definitions.py            #   Dagster assets wrapping the pipeline steps
transform/                    # dbt project (SQL only; NOT a Python package)
  models/silver/ · gold/      #   the medallion SQL + tests (schema.yml)
  seeds/country_codes.csv     #   reference data (ISO country names)
app/app.py                    # Streamlit dashboard (reads gold + cached pitches)
data/serving/                 # small committed serving DB (for hosting)
```

## 4. Stage-wise build map (planning summary)

Each stage has a `docs/StageN_*.md` with SQL-backed numbers.

| Stage | Doc | Primary files | Output |
|---|---|---|---|
| 1 Data discovery | Stage1 | `data/analysis/*.sql`, `data/samples/` | schema + strategy |
| 2 Setup | Stage2 | `pyproject.toml`, `uv.lock` | reproducible env |
| 3 Raw ingestion | Stage3 | `pipelines/ingest_bronze.py`, `schemas.py`, `warehouse.py` | `bronze.shodan_scans` (9.1M) |
| 4 Company resolution | Stage4 | `data/analysis/company_resolution.sql` | domain-as-company thesis |
| 5 Entity classification | Stage5 | `pipelines/classify_entities.py`, `llm/*`, `data/evals/` | classifier + eval |
| 6 Silver transform | Stage6 | `transform/models/silver/*.sql` | candidates + score (503k) |
| 7 LLM enrichment | Stage7 | `pipelines/enrich_entities.py`, `generate_pitches.py` | labels + pitches (cached) |
| 8 Gold mart | Stage8 | `transform/models/gold/*.sql`, `schema.yml` | 829 prospects + reasons |
| 9 App | Stage9 | `app/app.py` | Streamlit dashboard |
| 10 Orchestration | (this doc §5) | `orchestration/definitions.py` | Dagster lineage |
| 11 Hosting | (this doc §6) | `build_serving_db.py`, `requirements.txt` | serving DB + deploy |

## 5. Orchestration (why thin)

This is a **one-time batch** — no scheduled ingestion, no recurring interdependent
jobs, no backfills/SLAs, one day of data. A scheduler would be over-engineering.

What we do instead: keep every step a **pure, orchestrator-agnostic function** in
`pipelines/`, and expose them as a thin Dagster asset graph
(`orchestration/definitions.py`) purely to show the lineage:

```
bronze_scans → silver_models → entity_labels → gold_models → company_pitches
```

**Production path:** the same graph gains a **schedule** and a **sensor** on new
Shodan dumps; the steps themselves don't change. This is the payoff of the
pipelines-vs-orchestration split.

## 6. Hosting

The full warehouse is GBs (bronze/silver). The app reads only `gold.*` +
`enrichment.company_pitch`, so `build_serving_db.py` exports those into a **~2 MB
serving DB** that is committed and deployed. The app auto-prefers the serving DB when
present. Deploy target: Streamlit Community Cloud (`app/app.py`, Python 3.12,
`requirements.txt` app-only subset) — no API key, no live LLM.

## 7. Design decisions & trade-offs

- **Rules first, LLM for the residual.** Deterministic infra classifier + TLD rules
  handle the bulk; the LLM refines only the top-N head where errors are visible.
  Cheap, and the LLM earns its cost.
- **LLM as a production system, not a toy.** Versioned prompts, labelled evals,
  confidence gating + deterministic guardrails, cached/idempotent outputs, grounded
  (never-invented) CVE citations.
- **Single-writer warehouse.** Steps run in dependency order; the app connects
  read-only. (Prod: a real warehouse removes this constraint.)
- **Transparency over black-box.** The lead score is an explainable additive formula,
  surfaced in-app as a breakdown — no unexplainable numbers.

## 8. Honest limitations & roadmap (v2)

- **Coverage:** LLM labels only the top-N head → 829 verified prospects, not the full
  75k signal-bearing candidates. Enrich deeper to grow.
- **Severity:** CVEs counted, not weighted by *actively exploited* → **KEV/NVD** join.
- **No contacts / firmographics** → **Firmable** join (people) + firmographic ICP.
- **Freshness:** a single-day scan slice; production needs recurring ingestion.
- **Score weights** are a heuristic prior, not calibrated on conversion data.
- **Ethical framing:** exposure ≠ certainty; outreach language stays "we noticed",
  not accusatory, to respect false-positive risk.
