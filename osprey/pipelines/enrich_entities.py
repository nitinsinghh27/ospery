"""Pipeline step: LLM-enrich the top-N candidate companies.

Takes the highest-scoring candidates from Silver, labels each business/infra
(+ segment) — deterministic institutional-TLD rule first, LLM for the rest —
applies guardrails (confidence + provider-IP cross-check), and caches results in
`enrichment.entity_labels`, so re-runs only classify new domains (idempotent).

    uv run python -m osprey.pipelines.enrich_entities --top-n 500
"""

from __future__ import annotations

import argparse
from pathlib import Path

from osprey.config import CONFIDENCE_MIN, ENRICH_TOP_N, PROVIDER_IP_THRESHOLD, WAREHOUSE_DB
from osprey.llm.prompts import ENTITY_PROMPT_VERSION
from osprey.pipelines.classify_entities import classify_by_tld, classify_entities
from osprey.schemas import EntityLabel
from osprey.warehouse import (
    cached_domains,
    connect,
    create_entity_labels_table,
    upsert_entity_labels,
)


def _flag(label: EntityLabel, hosts: int) -> tuple[bool, str | None]:
    """Guardrails: cross-check LLM verdict against deterministic signals."""
    if label.entity_class == "business" and hosts >= PROVIDER_IP_THRESHOLD:
        return True, f"business but {hosts} IPs (provider-like)"
    if label.confidence < CONFIDENCE_MIN:
        return True, f"low confidence ({label.confidence:.2f})"
    return False, None


def enrich_top_candidates(
    top_n: int = ENRICH_TOP_N, db_path: Path = WAREHOUSE_DB
) -> dict[str, object]:
    """Classify + cache the top-N candidates. Returns run stats."""
    con = connect(db_path)
    create_entity_labels_table(con)
    version = ENTITY_PROMPT_VERSION
    already = cached_domains(con, version)

    candidates = con.execute(
        "SELECT domain, hosts FROM silver.silver_company_candidates "
        "ORDER BY score DESC, services DESC LIMIT ?",
        [top_n],
    ).fetchall()
    hosts_by = {str(d): int(h) for d, h in candidates}
    pending = [d for d in hosts_by if d not in already]

    labeled: list[tuple[EntityLabel, str]] = []  # (label, source)
    to_llm: list[str] = []
    for domain in pending:
        tld_label = classify_by_tld(domain)
        if tld_label is not None:
            labeled.append((tld_label, "tld"))
        else:
            to_llm.append(domain)
    labeled.extend((label, "llm") for label in classify_entities(to_llm))

    rows: list[tuple[object, ...]] = []
    flagged_count = 0
    for label, source in labeled:
        flagged, flag_reason = _flag(label, hosts_by.get(label.domain, 0))
        flagged_count += int(flagged)
        rows.append((label.domain, label.entity_class, label.segment, label.confidence,
                     label.reason, source, version, flagged, flag_reason))
    upsert_entity_labels(con, rows)
    con.close()

    return {
        "requested": len(candidates),
        "skipped_cached": len(hosts_by) - len(pending),
        "newly_labeled": len(labeled),
        "via_tld": sum(1 for _, s in labeled if s == "tld"),
        "via_llm": sum(1 for _, s in labeled if s == "llm"),
        "business": sum(1 for label, _ in labeled if label.entity_class == "business"),
        "infra": sum(1 for label, _ in labeled if label.entity_class == "infra"),
        "flagged": flagged_count,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM-enrich top-N candidate companies.")
    ap.add_argument("--top-n", type=int, default=ENRICH_TOP_N)
    args = ap.parse_args()
    print(f"Enriching top {args.top_n} candidates...")
    stats = enrich_top_candidates(args.top_n)
    print("\nDone:")
    for key, value in stats.items():
        print(f"  {key:16s} {value}")


if __name__ == "__main__":
    main()
