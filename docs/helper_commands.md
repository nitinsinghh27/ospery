# Helper Commands

All the commands to run this project — environment, ingestion, samples,
warehouse access, and analysis. Copy-paste ready.

> Source file (Shodan scans): `"/Users/nitin/Downloads/test_scans.json.zst copy"`
> Warehouse (DuckDB): `data/warehouse/osprey.duckdb` — table `bronze.shodan_scans`

---

## 1. Environment (uv)

```bash
uv sync                     # build the environment from uv.lock
uv add <package>            # add a dependency (updates pyproject + lock)
uv add --dev <package>      # add a dev dependency
uv run <command>            # run a command inside the environment
```

---

## 2. Ingestion — load Bronze (`bronze.shodan_scans`)

```bash
# Full file (~8 min, ~9.2M rows). Full-reload: recreates the table each run.
uv run python -m osprey.pipelines.ingest_bronze

# Quick test slice (first N records)
uv run python -m osprey.pipelines.ingest_bronze --limit 200000

# Options
uv run python -m osprey.pipelines.ingest_bronze \
  --source "/Users/nitin/Downloads/test_scans.json.zst copy" \
  --db data/warehouse/osprey.duckdb \
  --limit 50000 \
  --batch-size 20000
```

---

## 3. Samples (`data/samples/`)

```bash
# Peek: pretty-print the first few records
zstd -dc "/Users/nitin/Downloads/test_scans.json.zst copy" | head -5 \
  | uv run python -c "import sys,json;[print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin]"

# Write a human-readable JSON sample (first 500 records) into data/samples/
zstd -dc "/Users/nitin/Downloads/test_scans.json.zst copy" | head -500 \
  | uv run python -c "import sys,json;json.dump([json.loads(l) for l in sys.stdin],open('data/samples/sample_500_records.json','w'),indent=2)"

# Write a compressed working sample (first 200k records) into data/samples/
zstd -dc "/Users/nitin/Downloads/test_scans.json.zst copy" | head -200000 \
  | zstd -q -o data/samples/sample_200k.jsonl.zst
```

---

## 4. Warehouse access (DuckDB)

```bash
# Python (always available via our uv env) — single query
uv run python -c "import duckdb; print(duckdb.connect('data/warehouse/osprey.duckdb', read_only=True).sql('SELECT count(*) FROM bronze.shodan_scans'))"

# DuckDB CLI (optional; install once with: brew install duckdb)
duckdb data/warehouse/osprey.duckdb
#   D SELECT count(*) FROM bronze.shodan_scans;
#   D .quit
```

---

## 5. Analysis — run the profiling queries

```bash
# DuckDB CLI: run the whole file
duckdb data/warehouse/osprey.duckdb -c ".read data/analysis/data_profiling.sql"

# Python: run each statement in the file (strips comments first, so ';' inside
# comments doesn't break the split)
uv run python -c "
import duckdb
con = duckdb.connect('data/warehouse/osprey.duckdb', read_only=True)
sql = open('data/analysis/data_profiling.sql').read()
code = '\n'.join(l for l in sql.splitlines() if not l.lstrip().startswith('--'))
for stmt in code.split(';'):
    if stmt.strip():
        print(con.sql(stmt))
"
```

---

## 6. Transform — dbt (silver + gold)

Run from the repo root (paths in the profile are relative to it).

```bash
uv run dbt debug --project-dir transform --profiles-dir transform     # connection check
uv run dbt run   --project-dir transform --profiles-dir transform     # build all models
uv run dbt build --project-dir transform --profiles-dir transform     # models + tests
uv run dbt test  --project-dir transform --profiles-dir transform     # tests only

# a single model / layer
uv run dbt run --select silver_company_candidates --project-dir transform --profiles-dir transform
uv run dbt run --select gold --project-dir transform --profiles-dir transform
```

> **Build order (dependency-driven).** silver joins the KEV catalog, and
> `gold_prospects` joins the cached pitch + firmographics (produced by steps that
> *read* `gold_companies`) — so the full order is:
> ```
> python -m osprey.pipelines.fetch_kev                    # 0. KEV reference (silver needs it)
> dbt run --select silver                                 #    silver (KEV-aware score)
> python -m osprey.pipelines.enrich_entities              #    entity labels
> dbt run --select gold_companies gold_company_services   # 1. core prospect list
> python -m osprey.pipelines.generate_pitches             #    pitches (reads gold_companies)
> python -m osprey.pipelines.extract_profiles             #    firmographics (reads gold_companies)
> dbt run --select gold_prospects                         # 2. final serving model
> ```
> Dagster (§9) encodes this ordering as assets.

---

## 7. Reference data + LLM enrichment + eval

```bash
# Fetch reference feeds (run before dbt silver — silver joins them into the score).
uv run python -m osprey.pipelines.fetch_kev      # CISA KEV (actively-exploited CVEs)
uv run python -m osprey.pipelines.fetch_epss     # FIRST EPSS (exploit probability per CVE)
```


```bash
# Classify the top-N candidates (business/infra + segment) -> enrichment.entity_labels
# Cached + idempotent: re-runs skip already-labelled domains.
uv run python -m osprey.pipelines.enrich_entities --top-n 3000

# Measure the classifier against the labelled eval sets
uv run python -m osprey.llm.eval                                    # clear set
uv run python -m osprey.llm.eval data/evals/entity_classification_hard.jsonl   # hard set

# LLM observability — cost / latency / token report from the call traces
uv run python -m osprey.llm.trace                                   # overall + per-task

# Generate cached sales pitches for gold prospects -> enrichment.company_pitch
# Reads gold.gold_companies, so run AFTER dbt gold. Cached + idempotent.
uv run python -m osprey.pipelines.generate_pitches                 # all prospects
uv run python -m osprey.pipelines.generate_pitches --limit 100     # only the top-N

# Extract firmographics (org, industry, tech stack, emails) from exposed banners
# -> enrichment.company_profile. Rules (regex emails) + LLM (Sonnet, semantic). Cached.
uv run python -m osprey.pipelines.extract_profiles                 # all prospects
uv run python -m osprey.llm.eval_extract                           # score org_name P/R
```

> Note: the Claude CLI runs under Node 22 (see `osprey/llm/client.py`). The app
> reads the **cached** labels and pitches — it never calls the LLM live.

---

## 8. App (Streamlit dashboard)

```bash
uv run streamlit run app/app.py                        # http://localhost:8501
uv run streamlit run app/app.py --server.port 8502     # custom port
```

Reads the Gold marts (`gold.gold_companies`, `gold.gold_company_services`) — no
live LLM. Stop any running dbt/enrichment first (DuckDB is single-writer).

---

## 9. Orchestration — Dagster (illustrative lineage)

The pipeline is a one-time batch, so no scheduler is needed; this thin asset layer
just shows the lineage and that the steps are orchestrator-agnostic.

```bash
uv run dagster dev            # open the asset graph (uses [tool.dagster] in pyproject)
# lineage: bronze_scans -> silver_models -> entity_labels -> gold_models -> company_pitches
```

---

## 10. Serving DB + hosting

```bash
# Build the small (~2 MB) deployable DB with just gold + cached pitches.
uv run python -m osprey.pipelines.build_serving_db      # -> data/serving/osprey_serving.duckdb
```

The app auto-prefers `data/serving/osprey_serving.duckdb` when present, else the full
local warehouse. To host on **Streamlit Community Cloud**: push the repo (incl. the
committed serving DB) to GitHub → New app → entry point `app/app.py`, Python 3.12 →
it installs `requirements.txt` (the app-only subset) and serves the cached DB (no LLM,
no API key).
