"""Pipeline step: fetch FIRST's EPSS (Exploit Prediction Scoring System) scores.

EPSS gives each CVE a probability (0-1) that it will be exploited in the next 30 days
— a data-driven prioritization signal that complements KEV (confirmed exploitation)
and CVSS (severity). One free gzipped CSV covers every published CVE (~345k rows),
loaded via DuckDB's native reader. Another third-party-data connector.

    uv run python -m osprey.pipelines.fetch_epss
"""

from __future__ import annotations

import gzip
import tempfile
import urllib.request
from pathlib import Path

from osprey.config import EPSS_URL, WAREHOUSE_DB
from osprey.warehouse import connect, replace_epss


def fetch_epss(url: str = EPSS_URL, db_path: Path = WAREHOUSE_DB, timeout: int = 60) -> dict[str, object]:
    """Download the EPSS catalog and full-reload `reference.epss`. Returns run stats."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (trusted feed)
        csv_bytes = gzip.decompress(resp.read())

    # DuckDB reads from a path; stage the decompressed CSV to a temp file.
    with tempfile.NamedTemporaryFile("wb", suffix=".csv", delete=False) as tmp:
        tmp.write(csv_bytes)
        tmp_path = tmp.name

    con = connect(db_path)
    try:
        count = replace_epss(con, tmp_path)
    finally:
        con.close()
        Path(tmp_path).unlink(missing_ok=True)
    return {"epss_cves": count}


def main() -> None:
    print("Fetching FIRST EPSS scores...")
    stats = fetch_epss()
    print("\nDone:")
    for key, value in stats.items():
        print(f"  {key:14s} {value}")


if __name__ == "__main__":
    main()
