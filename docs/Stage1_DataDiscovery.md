# Stage 1 — Data Discovery

Understand the raw Shodan dataset and define how it lands into a raw layer.

---

## 1. The Data

| Property | Value |
|---|---|
| Source | Shodan network scans (https://www.shodan.io) |
| File | `test_scans.json.zst` |
| Size | ~8.5 GB compressed (~50–100 GB uncompressed, estimated) |
| Format | Zstandard-compressed, **newline-delimited JSON** (one scan per line) |
| Grain | **One record = one service on one IP:port at one point in time** |

At this size the file is never fully decompressed or loaded into memory. It is
read as a stream: `zstd -dc test_scans.json.zst | <line-by-line reader>`.

A 500-record spread (every 400th record across a 200k sample) is committed for
inspection: [`data/samples/sample_500_records.json`](../data/samples/sample_500_records.json).

---

## 2. JSON Schema

One record is a nested JSON object. All fields below, with how often they appear
(measured over ~200k sampled records):

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `ip_str` / `ip` | str / int | ~100% | IP address (string + integer form) |
| `port` | int | 100% | Open port |
| `transport` | str | 100% | `tcp` / `udp` |
| `timestamp` | str | 100% | When the scan was taken |
| `hash` | int | 100% | Shodan banner hash |
| `data` | str | 100% | Raw service banner text |
| `org` | str | 100% | **Network owner** — usually infra/CDN, ⚠️ not the business |
| `isp` | str | 100% | Internet service provider |
| `asn` | str | 98% | Autonomous System Number |
| `domains` | list | 100% field / ~67% non-empty | Registered domain(s) — **empty ~33%** |
| `hostnames` | list | 100% | Full hostname(s) |
| `location` | dict | 100% | Geo: `country_name`, `country_code`, `city`, `region_code`, lat/long, postal |
| `_shodan` | dict | 100% | Scan metadata: `module` (which scanner ran), `id`, `crawler`, `ptr` |
| `opts` | dict | 100% | Scan options; may hold `vulns`, `heartbleed`, `modbus` |
| `os` | null | 100% | **Always null in this dataset** — no OS fingerprint |
| `tags` | list | 55.8% | Labels: `cloud`, `cdn`, `eol-product`, `eol-os`, `honeypot`, `self-signed`, `database`, `vpn`, `iot`, `vulnerable` |
| `cloud` | dict | 29.4% | Cloud provider / region metadata |
| `http` | dict | 23.7% | Web details: `server`, `title`, `headers`, `html`, `waf`, `securitytxt`, `components` |
| `cpe` / `cpe23` | list | ~18% | Standardized product identifiers |
| `product` | str | 15.9% | Detected software name (e.g. `nginx`, `OpenSSH`) |
| `ssl` | dict | 7.9% | TLS details incl. **`cert`** (subject/issuer — a possible identity source) |
| `version` | str | 6.7% | Software version (feeds EOL / CVE reasoning) |
| `vulns` | dict | 2.2% | **Known CVEs** — strongest single buying signal |
| `info` | str | 2.2% | Extra product info |
| protocol/device modules | dict | <1% each | Per-service enrichment: `ssh`, `ntp`, `snmp`, `ftp`, `dns`, `mysql`, `mongodb`, `redis`, `rdp_encryption`, `smb`, `elastic`, `kubernetes`, and device fingerprints (`hikvision`, `mikrotik_routeros`, `fortinet`, `sonicwall`, `hp_ilo`, …) |

Notable nested content: **`ssl.cert`** (subject/issuer — may reveal the real
company even when `org`/`domains` are infra), **`http.server`/`http.title`**
(web tech fingerprint), **`_shodan.module`** (which scan type produced the row).

---

## 3. Observations from Samples

Signal coverage (~200k sampled records): 67.2% have a usable domain · 15.9% have
`product` · 7.9% have `ssl` · **2.2% have CVEs** · 24,855 unique domains ·
10,904 unique orgs.

1. **`org` is not the company.** Top orgs are all infrastructure — Google (56k),
   Incapsula (37k), Aliyun, Korea Telecom, Cloudflare. Grouping leads by `org`
   gives a useless prospect list.

2. **Company identity lives in `domains` — but domains need cleaning too.** Top
   domains are also infra: `googleusercontent.com` (55k), `incapdns.net` (29k),
   `amazonaws.com`, `flyio.net`. Real businesses are in the long tail
   (`walmart.com`, `spectrum.com`, + ~25k unique domains). A domain counts as a
   company only after stripping a provider/CDN blocklist. (`ssl.cert` subject is
   a promising secondary identity source.)

3. **The port profile is unusual.** Top ports are `6998, 5252, 7547, 4369`
   before the usual `443/80` — this is a specific slice of scans, not a random
   internet sample.

4. **Honeypots are noise.** ~1% of records are `honeypot`-tagged decoys; they
   must be filtered or they become fake leads.

5. **`os` is uniformly null** — don't rely on OS fingerprint anywhere.

6. **Buying signals are present and countable:** `vulns` (CVEs), `eol-product` /
   `eol-os`, `self-signed` certs, exposed `database`/`vpn`/`iot`/`rdp`.

**Gaps to close later:** is the head of the file representative or is it ordered?
How many real companies remain after the infra blocklist? What exactly are ports
`6998`/`5252`?

---

## 4. Strategy to Build the Raw Layer

The analytical warehouse is **DuckDB** (columnar, out-of-core, `dbt-duckdb`
adapter; the production equivalent would be Snowflake / BigQuery / Databricks).
Stream the file, flatten each record into a **flat DuckDB table** with real typed
columns, keeping only the necessary fields. Multi-valued fields become `LIST`
(array) columns. The rare deep enrichment (full `ssl.chain`, the <1%
protocol/device modules) is dropped at this layer — nothing downstream needs it,
and it keeps the raw table clean and drift-proof.

**Proposed raw table (`raw_scans`):**

| Column | Type | Source |
|---|---|---|
| `ip_str` | VARCHAR | `ip_str` |
| `port` | INTEGER | `port` |
| `transport` | VARCHAR | `transport` |
| `scanned_at` | TIMESTAMP | `timestamp` |
| `org` | VARCHAR | `org` |
| `isp` | VARCHAR | `isp` |
| `asn` | VARCHAR | `asn` |
| `domains` | VARCHAR[] | `domains` |
| `hostnames` | VARCHAR[] | `hostnames` |
| `country_code` | VARCHAR | `location.country_code` |
| `city` | VARCHAR | `location.city` |
| `region` | VARCHAR | `location.region_code` |
| `shodan_module` | VARCHAR | `_shodan.module` |
| `product` | VARCHAR | `product` |
| `version` | VARCHAR | `version` |
| `cpe23` | VARCHAR[] | `cpe23` |
| `tags` | VARCHAR[] | `tags` |
| `vulns` | VARCHAR[] | `vulns` (CVE ids) |
| `http_server` | VARCHAR | `http.server` |
| `http_title` | VARCHAR | `http.title` |
| `ssl_cert_subject` | VARCHAR | `ssl.cert` subject |
| `ssl_cert_issuer` | VARCHAR | `ssl.cert` issuer |
| `banner` | VARCHAR | `data` |
| `hash` | BIGINT | `hash` |

**Load approach:**

- **Let DuckDB read the stream, don't hand-batch.** DuckDB ingests
  newline-delimited JSON out-of-core (`read_json`), so we point it at the
  decompressed stream and `SELECT` only the columns above straight into
  `raw_scans` — the engine handles memory and parsing. (Fallback: stream in
  Python and use DuckDB's Appender if we need custom malformed-line handling.)
- **Flatten deterministically.** Pure projection into the columns above — no
  cleaning, filtering, or LLM here.
- **Grain preserved.** One row per scanned service (`ip:port` + scan time); no
  dedup or company rollup yet.
- **Deferred to later stages:** entity resolution (domain = company), infra and
  honeypot filtering, dedup, lead scoring, enrichment, and any LLM use — these
  belong in the bronze/silver layers.

Landing → bronze → downstream models will be orchestrated with **Dagster** and
transformed with **dbt** (on DuckDB) in later stages.

---

## 5. Limitations & roadmap (data)

- **Single snapshot.** Every scan falls in one ~1.7-hour window
  (`2026-05-12 03:20–05:00`). This is the *right* shape for prospecting — a
  salesperson wants "who is exposed **now**", not history — and the volume is
  ample (9.2M services, 500k+ companies, 75k prospects with a signal), so insights
  are statistically meaningful. But there is **no time dimension**, so we cannot
  detect **trend / trigger events** ("newly exposed", "got worse", "new CVE
  appeared") — which are the *strongest* sales triggers. (`scanned_at` therefore
  has no analytical value here.)
- **Selection bias.** The unusual top ports (`2087` Plesk, `7547` TR-069)
  indicate this is a **specific Shodan scan-slice, not a random/full-internet
  sample**. Insights are valid for the captured population; we don't over-generalize
  to "all companies".
- **Production roadmap.** Ingest **periodic snapshots** → compute **deltas** →
  emit *"newly exposed / newly vulnerable"* alerts. That turns the tool from a
  static list into "who to call, why, **and when**" (real-time signals).
