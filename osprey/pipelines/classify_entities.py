"""Pipeline step: classify domains as business vs infra (+ segment) via the LLM.

Pure function (no Dagster import) — testable and runnable on its own; the
orchestration layer wraps it as an asset.
"""

from __future__ import annotations

import re

from osprey.config import LLM_BATCH_SIZE
from osprey.llm.prompts import build_entity_prompt
from osprey.llm.runner import run_structured
from osprey.schemas import EntityLabel, Segment

# Reserved institutional TLDs are unambiguous — classify these by rule (no LLM).
# Fixes the eval-caught weakness where the LLM sometimes flipped gov/edu to infra.
_TLD_RULES: list[tuple[str, Segment]] = [
    (r"\.gov(\.[a-z]{2})?$", "government"),   # .gov, .gov.uk, .gov.in
    (r"\.gouv\.", "government"),              # .gouv.fr
    (r"\.mil(\.[a-z]{2})?$", "government"),
    (r"\.edu(\.[a-z]{2})?$", "education"),    # .edu, .edu.au
    (r"\.ac\.[a-z]{2}$", "education"),        # .ac.uk, .ac.in
]


def classify_by_tld(domain: str) -> EntityLabel | None:
    """Deterministic label for reserved institutional TLDs; None if not one."""
    lowered = domain.lower()
    for pattern, segment in _TLD_RULES:
        if re.search(pattern, lowered):
            return EntityLabel(
                domain=domain, entity_class="business", segment=segment,
                confidence=1.0, reason=f"Institutional TLD ({segment})",
            )
    return None


def classify_entities(domains: list[str], batch_size: int = LLM_BATCH_SIZE) -> list[EntityLabel]:
    """Return an EntityLabel for each classifiable domain (via the LLM)."""
    return run_structured(domains, build_entity_prompt, EntityLabel, batch_size)
