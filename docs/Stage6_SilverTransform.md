# Stage 6 — Silver Transform (dbt on DuckDB)

Encode the validated analysis logic (from [Stage 4](Stage4_CompanyResolution.md)
and `data/analysis/`) as **dbt models** — the Silver layer that turns Bronze into
per-company candidate prospects with signals and a score.

---

## 1. dbt project layout

The dbt project is a self-contained sibling of the Python package (dbt = SQL, not
importable Python — see [Architecture](../README.md)):

```
transform/
├── dbt_project.yml            # profile=osprey; silver models default to views
├── profiles.yml               # dbt-duckdb → data/warehouse/osprey.duckdb
├── macros/
│   └── generate_schema_name.sql   # use "silver"/"gold" as-is (not main_silver)
└── models/
    ├── sources.yml            # bronze.shodan_scans declared as a source
    └── silver/
        ├── silver_services.sql            # cleaned service grain (view)
        └── silver_company_candidates.sql  # per-company signals + score (table)
```

**Run (from repo root):**
```bash
uv run dbt run --project-dir transform --profiles-dir transform
uv run dbt debug --project-dir transform --profiles-dir transform   # connection check
```

Bronze is created by Python, so dbt reads it via a **`source`** (not a model). In
Dagster, this source maps to the Python bronze asset (Stage 10).

---

## 2. Models

| Model | Materialization | Grain | Rows |
|---|---|---|---|
| `silver.silver_services` | **view** (no storage — a filtered projection) | one scanned service | 9,102,783 |
| `silver.silver_company_candidates` | **table** (small aggregate) | one company (domain) | 503,856 |

- **`silver_services`** — drops `honeypot` decoys (94,240) and keeps only the
  columns Silver needs. A view, so zero storage cost.
- **`silver_company_candidates`** — unnests `domains`, aggregates each domain's
  services into signals (`has_cve`, `cve_count`, `has_eol`, `has_db`,
  `has_selfsigned`, `has_vpn`, `has_iot`, `has_breach`, `hosts`, `services`),
  applies the **deterministic classifier** (`hosts >= 1000 OR infra-keyword →
  infra`, excluded), and computes the **lead score**.

---

## 3. Key decisions

- **View vs table:** pass-through/filter models are views (free); aggregates are
  tables. Keeps the 3.1 GB warehouse from ballooning.
- **Clean schema names** via a `generate_schema_name` macro override — models land
  in `silver` / `gold`, not dbt's default `main_silver`.
- **Logic parity:** the deterministic classifier + score are the exact rules
  validated in `data/analysis/` — dbt is the productionized version, the analysis
  SQL was the scratchpad.

---

## 4. Verified & expected state

- `silver_services` = 9,102,783 (= 9,197,023 Bronze − 94,240 honeypots ✓).
- `silver_company_candidates` = 503,856 companies.
- **Expected (not a bug):** the top of the score is still leaked infra
  (`netia.com.pl`, `hvvc.us`, `bell.ca`, `ukfast.net`…) — deterministic rules
  can't catch mid-size hosts/ISPs, whose aggregated signals inflate their score.
  This is exactly what **Stage 7 (LLM enrichment)** cleans.
- **Note:** the attack-surface bonus gives every company `score > 0`; a real
  *prospect* requires ≥1 security signal — the **Gold** layer applies that filter.
