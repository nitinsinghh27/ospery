"""Data-access layer — the only module that talks to DuckDB.

Rows are inserted the columnar way: each batch becomes a PyArrow table that DuckDB
appends in one shot (`INSERT ... SELECT`). Row-by-row `executemany` is an
anti-pattern in a columnar engine and is orders of magnitude slower.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import duckdb
import pyarrow as pa

from osprey.config import (
    BRONZE_TABLE,
    ENRICHMENT_TABLE,
    EPSS_TABLE,
    KEV_TABLE,
    PITCH_TABLE,
    PROFILE_TABLE,
    WAREHOUSE_DB,
)
from osprey.schemas import duckdb_ddl, duckdb_types

# DuckDB type -> PyArrow type, so batches match the table exactly (incl. all-null
# columns, which naive inference would otherwise type as null).
_ARROW_TYPES: dict[str, pa.DataType] = {
    "VARCHAR": pa.string(),
    "INTEGER": pa.int32(),
    "BIGINT": pa.int64(),
    "TIMESTAMP": pa.timestamp("us"),
    "VARCHAR[]": pa.list_(pa.string()),
}

ARROW_SCHEMA = pa.schema(
    [pa.field(name, _ARROW_TYPES[dt]) for name, dt in duckdb_types().items()]
)


def connect(db_path: Path = WAREHOUSE_DB) -> duckdb.DuckDBPyConnection:
    """Open (creating parent dirs) a DuckDB connection at `db_path`."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return duckdb.connect(str(db_path))


def create_raw_table(con: duckdb.DuckDBPyConnection, table: str = BRONZE_TABLE) -> None:
    """(Re)create the Shodan scans table in the `bronze` schema from the model."""
    con.execute("CREATE SCHEMA IF NOT EXISTS bronze")
    con.execute(duckdb_ddl(table))


def _scrub(value: object) -> object:
    """Replace invalid UTF-8 (e.g. lone surrogates in raw banners) so Arrow can encode."""
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, list):
        return [_scrub(item) for item in cast("list[object]", value)]
    return value


def append_rows(
    con: duckdb.DuckDBPyConnection,
    rows: list[dict[str, object]],
    table: str = BRONZE_TABLE,
) -> None:
    """Bulk-append a batch of column-keyed dicts via a columnar Arrow insert.

    Fast path builds the Arrow table directly; only if a batch contains invalid
    UTF-8 do we scrub it and retry, so the common case pays no cleaning cost.
    """
    if not rows:
        return
    try:
        batch = pa.Table.from_pylist(rows, schema=ARROW_SCHEMA)
    except (UnicodeEncodeError, pa.ArrowInvalid):
        cleaned = [{k: _scrub(v) for k, v in row.items()} for row in rows]
        batch = pa.Table.from_pylist(cleaned, schema=ARROW_SCHEMA)
    con.register("_batch", batch)
    con.execute(f"INSERT INTO {table} SELECT * FROM _batch")
    con.unregister("_batch")


# --- Enrichment cache (LLM entity labels) ------------------------------------

def create_entity_labels_table(con: duckdb.DuckDBPyConnection) -> None:
    """Create the enrichment cache table (idempotent — preserves prior labels)."""
    con.execute("CREATE SCHEMA IF NOT EXISTS enrichment")
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {ENRICHMENT_TABLE} (
            domain          VARCHAR,
            entity_class    VARCHAR,
            segment         VARCHAR,
            confidence      DOUBLE,
            reason          VARCHAR,
            source          VARCHAR,
            prompt_version  VARCHAR,
            flagged         BOOLEAN,
            flag_reason     VARCHAR,
            PRIMARY KEY (domain, prompt_version)
        )
    """)


def cached_domains(con: duckdb.DuckDBPyConnection, prompt_version: str) -> set[str]:
    """Domains already labelled for this prompt version (so re-runs skip them)."""
    rows = con.execute(
        f"SELECT domain FROM {ENRICHMENT_TABLE} WHERE prompt_version = ?", [prompt_version]
    ).fetchall()
    return {str(r[0]) for r in rows}


def upsert_entity_labels(con: duckdb.DuckDBPyConnection, rows: list[tuple[object, ...]]) -> None:
    """Insert new label rows; existing (domain, prompt_version) keys are left as-is."""
    if not rows:
        return
    con.executemany(
        f"INSERT INTO {ENRICHMENT_TABLE} VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING", rows
    )


# --- Enrichment cache (LLM sales pitches) ------------------------------------

def create_company_pitch_table(con: duckdb.DuckDBPyConnection) -> None:
    """Create the pitch cache table (idempotent — preserves prior pitches)."""
    con.execute("CREATE SCHEMA IF NOT EXISTS enrichment")
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {PITCH_TABLE} (
            domain          VARCHAR,
            pitch           VARCHAR,
            prompt_version  VARCHAR,
            PRIMARY KEY (domain, prompt_version)
        )
    """)


def cached_pitch_domains(con: duckdb.DuckDBPyConnection, prompt_version: str) -> set[str]:
    """Domains that already have a pitch for this prompt version (re-runs skip them)."""
    rows = con.execute(
        f"SELECT domain FROM {PITCH_TABLE} WHERE prompt_version = ?", [prompt_version]
    ).fetchall()
    return {str(r[0]) for r in rows}


def upsert_company_pitch(con: duckdb.DuckDBPyConnection, rows: list[tuple[object, ...]]) -> None:
    """Insert new pitch rows; existing (domain, prompt_version) keys are left as-is."""
    if not rows:
        return
    con.executemany(
        f"INSERT INTO {PITCH_TABLE} VALUES (?,?,?) ON CONFLICT DO NOTHING", rows
    )


# --- Reference data (CISA KEV catalog) ---------------------------------------

def replace_kev(con: duckdb.DuckDBPyConnection, rows: list[tuple[object, ...]]) -> None:
    """Full-reload the KEV reference table (external catalog, replaced wholesale)."""
    con.execute("CREATE SCHEMA IF NOT EXISTS reference")
    con.execute(f"""
        CREATE OR REPLACE TABLE {KEV_TABLE} (
            cve_id            VARCHAR PRIMARY KEY,
            vendor            VARCHAR,
            product           VARCHAR,
            date_added        DATE,
            known_ransomware  BOOLEAN
        )
    """)
    if rows:
        con.executemany(f"INSERT INTO {KEV_TABLE} VALUES (?,?,?,?,?)", rows)


def replace_epss(con: duckdb.DuckDBPyConnection, csv_path: str) -> int:
    """Full-reload EPSS scores from a decompressed CSV (line 1 is a #meta comment).
    Uses DuckDB's native CSV reader — 345k rows load in one shot, no row-by-row insert."""
    con.execute("CREATE SCHEMA IF NOT EXISTS reference")
    con.execute(f"""
        CREATE OR REPLACE TABLE {EPSS_TABLE} AS
        SELECT cve AS cve_id, epss::DOUBLE AS epss, percentile::DOUBLE AS percentile
        FROM read_csv('{csv_path}', skip=1, header=true, auto_detect=true)
    """)
    return con.execute(f"SELECT count(*) FROM {EPSS_TABLE}").fetchone()[0]  # type: ignore[index]


# --- Enrichment cache (LLM firmographic profiles) ----------------------------

def create_company_profile_table(con: duckdb.DuckDBPyConnection) -> None:
    """Create the firmographic-profile cache table (idempotent)."""
    con.execute("CREATE SCHEMA IF NOT EXISTS enrichment")
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {PROFILE_TABLE} (
            domain          VARCHAR,
            org_name        VARCHAR,
            industry        VARCHAR,
            tech_stack      VARCHAR[],
            contact_emails  VARCHAR[],
            prompt_version  VARCHAR,
            PRIMARY KEY (domain, prompt_version)
        )
    """)


def cached_profile_domains(con: duckdb.DuckDBPyConnection, prompt_version: str) -> set[str]:
    """Domains that already have a profile for this prompt version (re-runs skip them)."""
    rows = con.execute(
        f"SELECT domain FROM {PROFILE_TABLE} WHERE prompt_version = ?", [prompt_version]
    ).fetchall()
    return {str(r[0]) for r in rows}


def upsert_company_profile(con: duckdb.DuckDBPyConnection, rows: list[tuple[object, ...]]) -> None:
    """Insert new profile rows; existing (domain, prompt_version) keys are left as-is."""
    if not rows:
        return
    con.executemany(
        f"INSERT INTO {PROFILE_TABLE} VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING", rows
    )
