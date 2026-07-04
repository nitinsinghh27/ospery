"""Versioned prompts — all prompts live here. Bump the version on any wording
change so cached labels can be invalidated and eval results stay comparable."""

from __future__ import annotations

ENTITY_PROMPT_VERSION = "v1"

_ENTITY_INSTRUCTIONS = """You classify internet domains for a B2B cybersecurity sales tool.

For each domain decide `entity_class`:
- "infra"    = ONLY a provider whose IPs host OTHER companies: web/cloud hosting,
               CDN, WAF, ISP/telecom, DNS, domain registrar, or a default/placeholder
               certificate (localhost, plesk, traefik, example.com).
- "business" = ANY end-organization that owns its own systems and could buy a
               security product: a company, university, government body, or
               nonprofit. These ARE valid prospects (do NOT mark them infra just
               because they aren't a typical commercial account).

Also assign `segment`: commercial | education | government | nonprofit | other.

Return ONLY a compact JSON array, one object per input domain, no prose and no
markdown fences:
[{"domain": "...", "entity_class": "business|infra", "segment": "...",
  "confidence": 0.0-1.0, "reason": "<= 10 words"}]"""


def build_entity_prompt(domains: list[str]) -> str:
    """Compose the entity-classification prompt for a batch of domains."""
    listing = "\n".join(domains)
    return f"{_ENTITY_INSTRUCTIONS}\n\nDomains:\n{listing}"


# --- Sales-pitch generation --------------------------------------------------

PITCH_PROMPT_VERSION = "v3"


def _pitch_instructions(solution: str) -> str:
    """Pitch instructions, with the vendor's offering (`solution`) woven in."""
    return f"""You are a sales enablement writer for a B2B cybersecurity vendor.

Our offering: {solution}

For each company you get: domain, segment, country, lead_score, confidence, the
exposure signals we detected, and (when available) notable_cves — REAL CVEs tied
to specific products/versions found on their internet-facing systems.

Write a short, credible outreach pitch a sales rep can send:
- 3-4 sentences. Consultative and specific, NOT alarmist — no fear-mongering, no
  fake urgency, no "immediate risk!" language. Sound like a knowledgeable peer.
- Open with a concrete, verifiable observation. When notable_cves are given,
  reference 1-2 of them naming the product and version (e.g. "your public nginx
  1.18.0 is affected by CVE-2024-39929"). This specificity is what makes it land.
- Tailor to the segment (compliance/citizen-data for government; student & research
  data for education; uptime/customer-trust for commercial).
- Close by connecting the findings to how we help: position that our platform can
  address the full range of what we found — "these are exactly the kinds of gaps we
  help teams fix" — then a soft, specific reason to talk (e.g. a quick review of the
  exposed surface). Helpful, not a hard sell. No greeting, no signature.

Hard rules:
- Use ONLY the CVEs and versions provided. NEVER invent, guess, or add CVE IDs,
  products, or versions that are not in the input. If none are given, speak to the
  signals generally without citing any CVE.
- Do not dump long CVE lists — cite at most two, then it's fine to say "among
  others".

Return ONLY a compact JSON array, one object per input company, no prose and no
markdown fences:
[{{"domain": "...", "pitch": "..."}}]"""


def build_pitch_prompt(companies: list[str], solution: str) -> str:
    """Compose the pitch prompt for a batch of pre-formatted company descriptors."""
    listing = "\n".join(companies)
    return f"{_pitch_instructions(solution)}\n\nCompanies:\n{listing}"
