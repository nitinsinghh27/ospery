# Stage 2 — Project & Environment Setup

Set up a reproducible project foundation and lock in the core tooling before any
pipeline code is written.

---

## 1. What this stage produced

- **`pyproject.toml`** — project metadata + dependencies, pinned to **Python 3.12**
  (the version Dagster and dbt fully support).
- **`uv.lock`** — exact, reproducible lock of Python + every package.
- **`.venv/`** — the project environment (managed by uv, git-ignored).
- **`.gitignore`** — keeps the 8.5 GB source file, generated warehouse
  (`*.duckdb`), and local samples out of the repo.
- **`README.md`** — one-command setup (`uv sync`) for reviewers.
- **Installed:** `duckdb`, `zstandard` (Stage 3 core) · `ruff`, `pytest` (dev).
  Dagster and dbt are added later, when their stages begin.

---

## 2. Tooling choices

### uv — environment & dependency management

- A single fast tool that manages the **Python version, the virtual environment,
  and a lockfile** together — no separate pyenv / venv / pip-tools stack.
- **Reproducible by default:** `uv.lock` pins everything, so a reviewer runs
  `uv sync` and gets the identical environment, including the right Python.
- The current modern standard for Python projects; fast enough that adding a
  dependency and re-locking is near-instant.

### DuckDB — analytical warehouse

- **Columnar (OLAP)**, which matches this workload exactly: scanning millions of
  scan rows and aggregating them up into per-company signals.
- **Embedded** — it's a library and a file, so there's nothing to run or operate;
  the whole warehouse ships inside the project.
- **Reads the data directly, out-of-core** — it can stream newline-delimited
  JSON and write Parquet without loading everything into memory, which is what
  makes the ~5–10M records tractable on a laptop.
- **First-class `dbt-duckdb` adapter**, so the raw → bronze → silver → gold models
  are plain dbt.
- Clean **production analogue**: the same dbt models would run on
  Snowflake / BigQuery / Databricks at larger scale.

### zstandard (Python)

- Decompresses the `.zst` stream **in-process**, so reading the source file needs
  no external CLI — the entire pipeline is reproducible from the Python
  environment alone.

---

## 3. Reproducibility

- `uv sync` rebuilds the exact environment from `uv.lock` on any machine.
- Data and generated artifacts are git-ignored; only code, config, docs, and the
  small inspection sample are versioned.
- Application containerization (a Dockerfile) is introduced at the **deployment**
  stage, for hosting the final app.
