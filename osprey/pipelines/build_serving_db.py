"""Build a small, deployable serving DB from the full warehouse.

The full warehouse (~GBs of bronze/silver) is too big to host. The app only reads
the Gold marts and the cached pitches, so we copy just those into a tiny DuckDB file
that can be committed and deployed (e.g. Streamlit Community Cloud). The app points at
this serving DB automatically when it exists (see `app/app.py`).

    uv run python -m osprey.pipelines.build_serving_db
"""

from __future__ import annotations

from pathlib import Path

import duckdb

from osprey.config import WAREHOUSE_DB

SERVING_DB = Path("data/serving/osprey_serving.duckdb")

# Only what the app reads — gold is the single serving contract (pitch + firmographics
# are already joined into gold_prospects by dbt, so no enrichment tables needed here).
_TABLES = [
    ("gold", "gold_prospects"),
    ("gold", "gold_company_services"),
]


def build_serving_db(src: Path = WAREHOUSE_DB, dst: Path = SERVING_DB) -> dict[str, int]:
    """Copy the app-facing tables from `src` into a fresh, minimal DB at `dst`."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()

    # Write into the fresh serving DB (primary); attach the warehouse AS `osprey`
    # (its own catalog name) so gold views resolve their internal `osprey.*` refs.
    con = duckdb.connect(str(dst))
    con.execute(f"ATTACH '{src}' AS osprey (READ_ONLY)")
    counts: dict[str, int] = {}
    for schema, table in _TABLES:
        con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
        con.execute(f"CREATE TABLE {schema}.{table} AS SELECT * FROM osprey.{schema}.{table}")
        row = con.execute(f"SELECT count(*) FROM {schema}.{table}").fetchone()
        counts[f"{schema}.{table}"] = int(row[0]) if row else 0
    con.execute("DETACH osprey")
    con.close()
    return counts


def main() -> None:
    counts = build_serving_db()
    size_mb = SERVING_DB.stat().st_size / 1e6
    print(f"Built {SERVING_DB} ({size_mb:.1f} MB)")
    for name, n in counts.items():
        print(f"  {name:28s} {n} rows")


if __name__ == "__main__":
    main()
