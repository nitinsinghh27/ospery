"""Pipeline step: extract a firmographic profile for each gold prospect from the
noisy, unstructured evidence its exposed services leak (banners, page titles, server
headers, product fingerprints, TLS cert subjects).

This is the rule-vs-LLM split the sourcing role is about:
  - DETERMINISTIC (regex): contact emails — structure is regular, no LLM needed.
  - LLM (Sonnet): org name, industry, tech stack — semantic interpretation of messy
    text, with a labelled eval set holding it accountable (see osprey.llm.eval_extract).

Cached + idempotent in `enrichment.company_profile`; every call is traced.

    uv run python -m osprey.pipelines.extract_profiles
    uv run python -m osprey.pipelines.extract_profiles --limit 50
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from osprey.config import (
    BRONZE_TABLE,
    PROFILE_BANNER_CHARS,
    PROFILE_BATCH_SIZE,
    PROFILE_MAX_EVIDENCE_ROWS,
    PROFILE_MODEL,
    WAREHOUSE_DB,
)
from osprey.llm.prompts import EXTRACT_PROMPT_VERSION, build_extraction_prompt
from osprey.llm.runner import run_structured
from osprey.schemas import CompanyProfile
from osprey.warehouse import (
    cached_profile_domains,
    connect,
    create_company_profile_table,
    upsert_company_profile,
)

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
# Not real contacts: placeholders, and — importantly — SSH KEX/cipher identifiers
# (e.g. curve25519-sha256@libssh.org, aes256-gcm@openssh.com) that look like emails.
_JUNK_EMAIL_DOMAINS = ("example.com", "example.org", "sentinel.com", "localhost",
                       "openssh.com", "libssh.org")


def _emails(texts: list[str | None]) -> list[str]:
    """Deterministically pull contact emails from banners/certs (no LLM)."""
    found: set[str] = set()
    for text in texts:
        if text:
            found.update(m.lower() for m in _EMAIL_RE.findall(text))
    clean = [e for e in found if e.split("@")[-1] not in _JUNK_EMAIL_DOMAINS]
    return sorted(clean)[:5]


def _evidence(domain: str, rows: list[tuple[object, ...]]) -> tuple[str, list[str]]:
    """Build one evidence block (+ regex emails) for a domain from its service rows.

    rows: (http_title, http_server, product, version, ssl_cert_subject, banner)
    """
    # Sample signal-rich services first (title/cert/product identify the org), and do
    # it deterministically so a re-run yields the same evidence -> reproducible.
    def _rank(r: tuple[object, ...]) -> tuple[bool, bool, bool, str]:
        title, _server, product, _version, cert, _banner = r
        return (title is None, cert is None, product is None, str(r))

    ranked = sorted(rows, key=_rank)[:PROFILE_MAX_EVIDENCE_ROWS]
    titles, servers, products, certs, banners, raw = set(), set(), set(), set(), [], []
    for title, server, product, version, cert, banner in ranked:
        if title:
            titles.add(str(title)[:60])
        if server:
            servers.add(str(server)[:40])
        if product:
            products.add(f"{product} {version}".strip() if version else str(product))
        if cert:
            certs.add(str(cert)[:60])
        if banner:
            banners.append(str(banner)[:PROFILE_BANNER_CHARS])
        raw.append(str(banner or "") + " " + str(cert or ""))

    parts = [f"domain={domain}"]
    if titles:
        parts.append("titles: " + " | ".join(sorted(titles)))
    if servers:
        parts.append("servers: " + " | ".join(sorted(servers)))
    if products:
        parts.append("products: " + " | ".join(sorted(products)))
    if certs:
        parts.append("certs: " + " | ".join(sorted(certs)))
    if banners:
        parts.append("banners: " + " || ".join(banners[:3]))
    return "  ".join(parts), _emails(raw)


def extract_profiles(limit: int | None = None, db_path: Path = WAREHOUSE_DB) -> dict[str, object]:
    """Extract + cache firmographic profiles for gold prospects. Returns run stats."""
    con = connect(db_path)
    create_company_profile_table(con)
    version = EXTRACT_PROMPT_VERSION
    already = cached_profile_domains(con, version)

    sql = "SELECT domain FROM gold.gold_companies ORDER BY score DESC"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    domains = [str(r[0]) for r in con.execute(sql).fetchall()]
    pending = [d for d in domains if d not in already]
    if not pending:
        con.close()
        return {"gold_prospects": len(domains), "skipped_cached": len(domains), "generated": 0}

    # gather raw evidence for the pending domains in one bronze scan
    rows = con.execute(
        f"""
        SELECT unnest(domains) AS domain, http_title, http_server, product, version,
               ssl_cert_subject, banner
        FROM {BRONZE_TABLE}
        WHERE list_has_any(domains, ?)
        """,
        [pending],
    ).fetchall()

    pending_set = set(pending)
    by_domain: dict[str, list[tuple[object, ...]]] = {}
    for domain, *rest in rows:
        d = str(domain)
        if d in pending_set:
            by_domain.setdefault(d, []).append(tuple(rest))

    evidence: list[str] = []
    emails_by: dict[str, list[str]] = {}
    for domain in pending:
        block, emails = _evidence(domain, by_domain.get(domain, []))
        evidence.append(block)
        emails_by[domain] = emails

    profiles = run_structured(
        evidence, build_extraction_prompt, CompanyProfile,
        batch_size=PROFILE_BATCH_SIZE, model=PROFILE_MODEL,
        task="profile_extraction", prompt_version=version,
    )

    out_rows: list[tuple[object, ...]] = [
        (p.domain, p.org_name, p.industry, p.tech_stack, emails_by.get(p.domain, []), version)
        for p in profiles if p.domain in pending_set
    ]
    upsert_company_profile(con, out_rows)
    con.close()

    return {
        "gold_prospects": len(domains),
        "skipped_cached": len(domains) - len(pending),
        "requested": len(pending),
        "generated": len(out_rows),
        "with_org_name": sum(1 for p in profiles if p.org_name),
        "with_emails": sum(1 for d in emails_by if emails_by[d]),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract firmographic profiles for gold prospects.")
    ap.add_argument("--limit", type=int, default=None, help="only the top-N prospects")
    args = ap.parse_args()
    print(f"Extracting profiles ({'top ' + str(args.limit) if args.limit else 'all'} prospects)...")
    stats = extract_profiles(args.limit)
    print("\nDone:")
    for key, value in stats.items():
        print(f"  {key:16s} {value}")


if __name__ == "__main__":
    main()
