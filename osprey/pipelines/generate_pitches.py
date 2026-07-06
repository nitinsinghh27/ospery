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


def _cve_snippet(entries: list[CveEntry], kev: set[str], epss: dict[str, float], max_cves: int) -> str:
    """Build a grounded, prioritized CVE snippet tagged with real exploitation status:
    'nginx 1.14.1: CVE-… [KEV, EPSS 94%]; …'. Ranks KEV first, then EPSS, then recency,
    so the pitch leads with the CVEs that actually matter."""
    flat: list[tuple[str, str | None, str, bool, float]] = []
    for product, version, cves in entries:
        for cve in cves:
            flat.append((product, version, cve, cve in kev, epss.get(cve, 0.0)))
    if not flat:
        return ""
    flat.sort(key=lambda x: (x[3], x[4], _cve_year(x[2])), reverse=True)

    parts: list[str] = []
    for product, version, cve, is_kev, ep in flat[:max_cves]:
        pv = f"{product} {version}".strip() if version else product
        tags = (["KEV"] if is_kev else []) + ([f"EPSS {round(ep * 100)}%"] if ep >= 0.05 else [])
        parts.append(f"{pv}: {cve}" + (f" [{', '.join(tags)}]" if tags else ""))
    tail = f"; +{len(flat) - len(parts)} more CVEs" if len(flat) > len(parts) else ""
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


def _kev_set(con: duckdb.DuckDBPyConnection) -> set[str]:
    """The KEV CVE ids (actively exploited)."""
    return {str(r[0]) for r in con.execute("SELECT cve_id FROM reference.kev").fetchall()}


def _epss_scores(con: duckdb.DuckDBPyConnection) -> dict[str, float]:
    """EPSS probability per CVE, limited to CVEs seen on gold prospects' services."""
    rows = con.execute(
        "SELECT cve_id, epss FROM reference.epss WHERE cve_id IN "
        "(SELECT DISTINCT unnest(vulns) FROM gold.gold_company_services)"
    ).fetchall()
    return {str(c): float(e) for c, e in rows}


# rival security-vendor product tokens (from the tech fingerprint) -> a displacement
# angle: the highest-value technographic signal for a security vendor's outreach.
_SECURITY_APPLIANCES = (
    "fortiweb", "fortios", "fortigate", "fortinet", "fortiproxy", "sonicwall", "pan-os",
    "paloalto", "sophos", "watchguard", "checkpoint", "check_point", "barracuda",
    "pfsense", "netscaler", "citrix", "cisco_asa",
)


def _security_appliance(techs: list[str]) -> str | None:
    """Return the detected competitor security-appliance product(s), if any."""
    hits = [t for t in techs if any(k in t.lower() for k in _SECURITY_APPLIANCES)]
    return ", ".join(sorted(set(hits))[:2]) if hits else None


def _descriptor(row: tuple[object, ...], cve_snippet: str) -> str:
    """Serialize one gold_prospects row into a compact line for the pitch prompt."""
    (domain, segment, country, score, confidence, reasons, org_name, industry,
     tech_names) = row
    items = cast("list[object]", reasons) if isinstance(reasons, (list, tuple)) else []
    signals = "; ".join(str(r) for r in items) if items else "no strong signals"
    line = (f"domain={domain} | org={org_name or '?'} | industry={industry or '?'} | "
            f"segment={segment} | country={country} | lead_score={score} | "
            f"confidence={confidence} | signals: {signals}")
    if cve_snippet:
        line += f" | notable_cves: {cve_snippet}"
    techs = [str(t) for t in cast("list[object]", tech_names)] if isinstance(tech_names, (list, tuple)) else []
    if techs:
        line += f" | technologies: {', '.join(techs[:10])}"
    appliance = _security_appliance(techs)
    if appliance:
        line += f" | competitor_appliance: {appliance}"
    return line


def generate_pitches(
    limit: int | None = None, db_path: Path = WAREHOUSE_DB
) -> dict[str, object]:
    """Generate + cache pitches for gold prospects. Returns run stats."""
    con = connect(db_path)
    create_company_pitch_table(con)
    version = PITCH_PROMPT_VERSION
    already = cached_pitch_domains(con, version)

    sql = ("SELECT domain, segment, country_name, score, classification_confidence, reasons, "
           "org_name, industry, tech_names FROM gold.gold_prospects ORDER BY score DESC")
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    companies = con.execute(sql).fetchall()
    cve_by_domain = _cve_map(con)
    kev, epss = _kev_set(con), _epss_scores(con)

    pending = [c for c in companies if str(c[0]) not in already]
    descriptors = [
        _descriptor(c, _cve_snippet(cve_by_domain.get(str(c[0]), []), kev, epss, PITCH_MAX_CVES))
        for c in pending
    ]

    build_prompt = partial(build_pitch_prompt, solution=VENDOR_PITCH_CONTEXT)
    pitches = run_structured(
        descriptors, build_prompt, CompanyPitch,
        batch_size=PITCH_BATCH_SIZE, model=PITCH_MODEL,
        task="pitch", prompt_version=version,
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
