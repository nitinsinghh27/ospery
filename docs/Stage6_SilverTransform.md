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
    ├── sources.yml            # bronze.shodan_scans + reference.kev/epss as sources
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
| `silver.silver_company_tech` | **table** (tech profile) | one company (domain) | 505,987 |

- **`silver_services`** — drops `honeypot` decoys (94,240) and keeps only the
  columns Silver needs. A view, so zero storage cost.
- **`silver_company_candidates`** — unnests `domains`, aggregates each domain's
  services into signals (`has_cve`, `cve_count`, `has_eol`, `has_db`,
  `has_selfsigned`, `has_vpn`, `has_iot`, `has_breach`, `hosts`, `services`), joins
  the **CISA KEV** and **FIRST EPSS** reference feeds for `kev_count` / `has_kev` /
  `max_epss`, applies the **deterministic classifier** (`hosts >= 1000 OR
  infra-keyword → infra`, excluded), and computes the **KEV-aware lead score**.
- **`silver_company_tech`** — a **deterministic technology profile** per company
  (**no LLM**). Shodan already fingerprints technologies (`product`, `http_server`,
  `cpe23`) and tags services (`cloud`/`cdn`/`database`/`ai`/`ics`/`devops`…); this
  model parses and categorises them into per-company flags (`has_ai_ml`, `has_ics`,
  `has_devops`, `has_cdn`, `has_cloud`, `has_database_tech`, `has_cms`, …), a named
  `tech_names` list (from `cpe23`), and a readable `tech_categories` list. Powers
  technographic ICP targeting, competitive-displacement plays, and the **exposed
  AI/ML** trigger. Numbers backed by
  [`data/analysis/tech_signals.sql`](../data/analysis/tech_signals.sql).
  **v4 — deeper extraction (still no LLM):** the same model also emits
  **`versioned_tech`** (concrete `product version`, e.g. "OpenSSH 7.4" — Shodan reports a
  version on ~5% of services and in ~21% of cpe23 rows), **`legacy_tech`** + **`has_legacy`**
  (version-gated end-of-life stacks — Python 2.x / PHP ≤5 / OpenSSH <7 / Apache 2.2 /
  MySQL 5.x — plus Shodan's own `eol-product`/`eol-os` tags), **`hosting_providers`**
  (normalized cloud/CDN from the network owner: AWS/GCP/Azure/Cloudflare/Hetzner…), and
  **`hosting_network`** (the dominant ISP/AS operator via `mode(isp)` — present for ~99% of
  prospects, so "where are they hosted" is rarely blank). SQL-backed in
  [`data/analysis/extraction_v4.sql`](../data/analysis/extraction_v4.sql).
  **Exposure surface:** the port inventory names risky internet-facing services
  (`exposed_services` + `has_rdp`/`has_telnet`/`has_ftp`/`has_smb`) — the sharpest cyber
  trigger ("your RDP/SMB/database is reachable"); 2,798 prospects expose ≥1. `ssl_issuers`
  carries the certificate authorities. *(Honest null result: a deterministic org name from
  the cert subject `O=` was attempted but prospect certs are CN-only — 0/97k carry an O=
  field — so it was dropped rather than shipped empty.)*
  **HTTP-title mining:** `exposed_panels` + `has_admin_panel` name internet-facing
  **management/control panels** from the page title (cPanel/WHM 524, Synology 289, Plesk 260,
  3CX 199, MikroTik/pfSense/SonicWall/Fortinet firewall logins, Grafana/Portainer/MinIO
  consoles…) — 1,366 prospects expose one, a high-value cyber target. `city_count` = distinct
  cities the hosts sit in (avg 4.27, max 289), a rough size/distribution proxy. The `asn`
  column was **removed** as redundant (org/isp already carry the network owner) — a deliberate
  cleanup, not left as a dead column.

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
