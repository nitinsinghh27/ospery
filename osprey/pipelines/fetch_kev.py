"""Pipeline step: fetch CISA's Known Exploited Vulnerabilities (KEV) catalog.

A free, no-auth third-party feed of CVEs *actively exploited in the wild* — the
strongest CVE signal for prioritization (far more urgent than "a CVE exists"). This
is the third-party-data-connector pattern: fetch → normalize → load as a reference
table that dbt joins into the lead score.

    uv run python -m osprey.pipelines.fetch_kev
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from osprey.config import KEV_URL, WAREHOUSE_DB
from osprey.warehouse import connect, replace_kev


def fetch_kev(url: str = KEV_URL, db_path: Path = WAREHOUSE_DB, timeout: int = 30) -> dict[str, object]:
    """Download the KEV catalog and full-reload `reference.kev`. Returns run stats."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (trusted gov URL)
        payload = json.load(resp)

    vulns = payload.get("vulnerabilities", [])
    rows: list[tuple[object, ...]] = [
        (
            v.get("cveID"),
            v.get("vendorProject"),
            v.get("product"),
            v.get("dateAdded"),
            v.get("knownRansomwareCampaignUse", "").lower() == "known",
        )
        for v in vulns
        if v.get("cveID")
    ]

    con = connect(db_path)
    replace_kev(con, rows)
    con.close()
    return {
        "catalog_version": payload.get("catalogVersion", "?"),
        "kev_cves": len(rows),
        "ransomware_linked": sum(1 for r in rows if r[4]),
    }


def main() -> None:
    print("Fetching CISA KEV catalog...")
    stats = fetch_kev()
    print("\nDone:")
    for key, value in stats.items():
        print(f"  {key:18s} {value}")


if __name__ == "__main__":
    main()
