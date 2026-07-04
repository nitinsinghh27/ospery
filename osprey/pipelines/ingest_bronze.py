"""Pipeline step: stream the compressed Shodan file into the Bronze table.

Pipeline: read .zst line by line -> flatten each record to the ShodanScan shape ->
validate/coerce via the model -> batch-append to DuckDB. A full-reload: the table
is recreated each run, so re-running is idempotent. Pure function (no Dagster).

CLI:
    uv run python -m osprey.pipelines.ingest_bronze --limit 200000   # quick test
    uv run python -m osprey.pipelines.ingest_bronze                  # full file
"""

from __future__ import annotations

import argparse
import io
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import zstandard as zstd
from pydantic import ValidationError

from osprey.config import INGEST_BATCH_SIZE, SOURCE, WAREHOUSE_DB
from osprey.schemas import ShodanScan
from osprey.warehouse import append_rows, connect, create_raw_table


def flatten(rec: dict[str, Any]) -> dict[str, object]:
    """Map one raw Shodan record onto the flat ShodanScan field names.

    Only nested-path extraction lives here; type coercion (timestamp string ->
    datetime) is handled by the ShodanScan model.
    """
    loc: dict[str, Any] = rec.get("location") or {}
    http: dict[str, Any] = rec.get("http") or {}
    shodan: dict[str, Any] = rec.get("_shodan") or {}
    ssl: dict[str, Any] = rec.get("ssl") or {}
    cert: dict[str, Any] = ssl.get("cert") or {}
    subject: dict[str, Any] = cert.get("subject") or {}
    issuer: dict[str, Any] = cert.get("issuer") or {}
    vulns: dict[str, Any] = rec.get("vulns") or {}

    return {
        "ip_str": rec.get("ip_str"),
        "port": rec.get("port"),
        "transport": rec.get("transport"),
        "scanned_at": rec.get("timestamp"),
        "org": rec.get("org"),
        "isp": rec.get("isp"),
        "asn": rec.get("asn"),
        "domains": rec.get("domains") or [],
        "hostnames": rec.get("hostnames") or [],
        "country_code": loc.get("country_code"),
        "city": loc.get("city"),
        "region": loc.get("region_code"),
        "shodan_module": shodan.get("module"),
        "product": rec.get("product"),
        "version": rec.get("version"),
        "cpe23": rec.get("cpe23") or [],
        "tags": rec.get("tags") or [],
        "vulns": list(vulns.keys()),
        "http_server": http.get("server"),
        "http_title": http.get("title"),
        "ssl_cert_subject": subject.get("CN"),
        "ssl_cert_issuer": issuer.get("O"),
        "banner": rec.get("data"),
        "hash": rec.get("hash"),
    }


def _stream_lines(source: Path) -> Iterator[str]:
    """Yield decoded JSON lines from a .zst file without decompressing to disk."""
    dctx = zstd.ZstdDecompressor()
    with open(source, "rb") as fh:
        reader = dctx.stream_reader(fh)
        yield from io.TextIOWrapper(reader, encoding="utf-8")


def _to_record(rec: dict[str, Any]) -> dict[str, object]:
    """Flatten + validate a record into a column-keyed dict for the Arrow batch."""
    return dict(ShodanScan.model_validate(flatten(rec)))


def ingest_bronze(
    source: Path = SOURCE,
    db_path: Path = WAREHOUSE_DB,
    limit: int | None = None,
    batch_size: int = INGEST_BATCH_SIZE,
    log_every: int = 500_000,
) -> dict[str, object]:
    """Full-reload the Bronze table from the source file. Returns run stats."""
    con = connect(db_path)
    create_raw_table(con)

    total = inserted = errors = 0
    batch: list[dict[str, object]] = []
    started = time.perf_counter()

    for line in _stream_lines(source):
        if limit is not None and total >= limit:
            break
        total += 1
        try:
            batch.append(_to_record(json.loads(line)))
            inserted += 1
        except (json.JSONDecodeError, ValidationError):
            errors += 1
            continue

        if len(batch) >= batch_size:
            append_rows(con, batch)
            batch.clear()
        if total % log_every == 0:
            rate = total / (time.perf_counter() - started)
            print(f"  ...{total:,} read | {inserted:,} inserted | "
                  f"{errors:,} errors | {rate:,.0f} rows/s")

    append_rows(con, batch)
    con.close()

    elapsed = time.perf_counter() - started
    return {
        "read": total,
        "inserted": inserted,
        "errors": errors,
        "elapsed_s": round(elapsed, 1),
        "rows_per_s": round(total / elapsed) if elapsed else 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Load Shodan scans into the Bronze table.")
    ap.add_argument("--source", type=Path, default=SOURCE)
    ap.add_argument("--db", type=Path, default=WAREHOUSE_DB)
    ap.add_argument("--limit", type=int, default=None, help="stop after N records (testing)")
    ap.add_argument("--batch-size", type=int, default=INGEST_BATCH_SIZE)
    args = ap.parse_args()

    print(f"Ingesting {args.source}\n     into {args.db}"
          + (f" (limit {args.limit:,})" if args.limit else ""))
    stats = ingest_bronze(args.source, args.db, args.limit, args.batch_size)
    print("\nDone:")
    for key, value in stats.items():
        print(f"  {key:12s} {value:,}" if isinstance(value, int) else f"  {key:12s} {value}")


if __name__ == "__main__":
    main()
