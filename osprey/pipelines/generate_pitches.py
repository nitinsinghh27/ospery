"""Pipeline step: generate a short, rep-ready sales pitch for each gold prospect.

Reads the final prospect list (`gold.gold_companies`) plus the per-service drill-down
(`gold.gold_company_services`) so each pitch can cite REAL CVEs tied to the actual
product/version we observed — grounded, never invented. Results are cached in
`enrichment.company_pitch` (idempotent): re-runs only generate pitches for new
domains, and the app reads the cached pitches — it never calls the LLM live.

    uv run python -m osprey.pipelines.generate_pitches
    uv run python -m osprey.pipelines.generate_pitches --limit 100
"""

from __future__ import annotations

import argparse
from functools import partial
from pathlib import Path
from typing import cast

import duckdb

from osprey.config import (
    PITCH_BATCH_SIZE,
    PITCH_MAX_CVES,
    PITCH_MODEL,
    VENDOR_PITCH_CONTEXT,
    WAREHOUSE_DB,
)
from osprey.llm.prompts import PITCH_PROMPT_VERSION, build_pitch_prompt
from osprey.llm.runner import run_structured
from osprey.schemas import CompanyPitch
from osprey.warehouse import (
    cached_pitch_domains,
    connect,
    create_company_pitch_table,
    upsert_company_pitch,
)

# One product/version and the real CVEs found on it.
CveEntry = tuple[str, str | None, list[str]]


def _cve_year(cve: str) -> int:
    """Extract the year from a CVE id (CVE-YYYY-NNNN) so we can prefer recent ones."""
    try:
        return int(cve.split("-")[1])
    except (IndexError, ValueError):
        return 0


def _cve_snippet(entries: list[CveEntry], max_cves: int) -> str:
    """Build a grounded 'product version (CVE-…, CVE-…)' snippet, newest CVEs first.

    Caps the number of cited CVEs; an old CVE-2007 is far less compelling than a
    recent one, so products are ordered by their newest CVE.
    """
    all_cves: set[str] = set()
    scored: list[tuple[int, str, str | None, list[str]]] = []
    for product, version, cves in entries:
        all_cves.update(cves)
        recent = sorted(cves, key=_cve_year, reverse=True)
        if recent:
            scored.append((_cve_year(recent[0]), product, version, recent))
    if not scored:
        return ""

    scored.sort(key=lambda x: x[0], reverse=True)
    parts: list[str] = []
    cited = 0
    for _, product, version, recent in scored:
        if cited >= max_cves:
            break
        take = recent[: min(2, max_cves - cited)]
        cited += len(take)
        pv = f"{product} {version}".strip() if version else product
        parts.append(f"{pv} ({', '.join(take)})")
    tail = f"; +{len(all_cves) - cited} more CVEs" if len(all_cves) > cited else ""
    return "; ".join(parts) + tail


def _cve_map(con: duckdb.DuckDBPyConnection) -> dict[str, list[CveEntry]]:
    """Per-domain list of (product, version, CVEs) from the gold service drill-down."""
    rows = con.execute(
        "SELECT domain, product, version, vulns FROM gold.gold_company_services "
        "WHERE product IS NOT NULL AND len(vulns) > 0"
    ).fetchall()
    out: dict[str, list[CveEntry]] = {}
    for domain, product, version, vulns in rows:
        cves = cast("list[str]", vulns) if isinstance(vulns, (list, tuple)) else []
        out.setdefault(str(domain), []).append((str(product), version, cves))
    return out


def _descriptor(row: tuple[object, ...], cve_snippet: str) -> str:
    """Serialize one gold_companies row into a compact line for the pitch prompt."""
    domain, segment, country, score, confidence, reasons = row
    items = cast("list[object]", reasons) if isinstance(reasons, (list, tuple)) else []
    signals = "; ".join(str(r) for r in items) if items else "no strong signals"
    line = (f"domain={domain} | segment={segment} | country={country} | "
            f"lead_score={score} | confidence={confidence} | signals: {signals}")
    if cve_snippet:
        line += f" | notable_cves: {cve_snippet}"
    return line


def generate_pitches(
    limit: int | None = None, db_path: Path = WAREHOUSE_DB
) -> dict[str, object]:
    """Generate + cache pitches for gold prospects. Returns run stats."""
    con = connect(db_path)
    create_company_pitch_table(con)
    version = PITCH_PROMPT_VERSION
    already = cached_pitch_domains(con, version)

    sql = ("SELECT domain, segment, country_name, score, classification_confidence, reasons "
           "FROM gold.gold_companies ORDER BY score DESC")
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    companies = con.execute(sql).fetchall()
    cve_by_domain = _cve_map(con)

    pending = [c for c in companies if str(c[0]) not in already]
    descriptors = [
        _descriptor(c, _cve_snippet(cve_by_domain.get(str(c[0]), []), PITCH_MAX_CVES))
        for c in pending
    ]

    build_prompt = partial(build_pitch_prompt, solution=VENDOR_PITCH_CONTEXT)
    pitches = run_structured(
        descriptors, build_prompt, CompanyPitch,
        batch_size=PITCH_BATCH_SIZE, model=PITCH_MODEL,
    )
    valid = {str(c[0]) for c in pending}  # only keep pitches for domains we asked about
    rows: list[tuple[object, ...]] = [
        (p.domain, p.pitch, version) for p in pitches if p.domain in valid and p.pitch.strip()
    ]
    upsert_company_pitch(con, rows)
    con.close()

    return {
        "gold_prospects": len(companies),
        "skipped_cached": len(companies) - len(pending),
        "requested": len(pending),
        "generated": len(rows),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate LLM sales pitches for gold prospects.")
    ap.add_argument("--limit", type=int, default=None, help="only the top-N prospects")
    args = ap.parse_args()
    print(f"Generating pitches ({'top ' + str(args.limit) if args.limit else 'all'} prospects)...")
    stats = generate_pitches(args.limit)
    print("\nDone:")
    for key, value in stats.items():
        print(f"  {key:16s} {value}")


if __name__ == "__main__":
    main()
