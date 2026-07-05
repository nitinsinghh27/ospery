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

PITCH_PROMPT_VERSION = "v4"


def _pitch_instructions(solution: str) -> str:
    """Pitch instructions, with the vendor's offering (`solution`) woven in."""
    return f"""You are a sales enablement writer for a B2B cybersecurity vendor.

Our offering: {solution}

For each company you get: domain, org (if identified), industry, segment, country,
lead_score, confidence, the exposure signals we detected, and (when available)
notable_cves — REAL CVEs tied to specific products/versions, tagged with:
  [KEV]      = on CISA's Known Exploited Vulnerabilities list (actively exploited now)
  [EPSS x%]  = modelled probability of exploitation in the next 30 days

Write a short, credible outreach pitch a sales rep can send:
- 3-4 sentences. Consultative and specific, NOT alarmist — no fear-mongering, no
  fake urgency. Sound like a knowledgeable peer.
- Open with a concrete, verifiable observation. When notable_cves are given, LEAD
  with a [KEV] or high-[EPSS] one, naming the product/version and WHY it matters
  (e.g. "your public nginx 1.18.0 is affected by CVE-2024-39929, which CISA lists as
  actively exploited"). That specificity + real exploitation status is what lands.
- If org/industry are known, address the company by name and tailor to the industry
  (compliance/citizen-data for government; student/research data for education;
  uptime/customer-trust for commercial).
- Close by connecting to how we help — "these are exactly the kinds of gaps we help
  teams fix" — then a soft, specific reason to talk. Helpful, not a hard sell. No
  greeting, no signature.

Hard rules:
- Use ONLY the data provided. NEVER invent or alter CVE IDs, products, versions,
  org names, or exploitation status. If no CVEs are given, speak to the signals
  generally without citing any CVE.
- Do not dump long CVE lists — cite at most two, then "among others" is fine.

Return ONLY a compact JSON array, one object per input company, no prose and no
markdown fences:
[{{"domain": "...", "pitch": "..."}}]"""


def build_pitch_prompt(companies: list[str], solution: str) -> str:
    """Compose the pitch prompt for a batch of pre-formatted company descriptors."""
    listing = "\n".join(companies)
    return f"{_pitch_instructions(solution)}\n\nCompanies:\n{listing}"


# --- Firmographic extraction from exposed banners ----------------------------

EXTRACT_PROMPT_VERSION = "v1"

_EXTRACT_INSTRUCTIONS = """You extract a firmographic profile for a company from the
noisy evidence its internet-exposed services leak: HTTP page titles, server headers,
product fingerprints, TLS certificate subjects, and raw banner snippets.

For each domain extract:
- "org_name": the real organization's name if identifiable from the evidence — NOT a
  hosting/CDN/ISP provider (e.g. Cloudflare, cPanel, AWS). null if not identifiable.
- "industry": a short sector label (e.g. telecom, university, e-commerce, healthcare,
  government, hosting, manufacturing). null if unclear.
- "tech_stack": concrete technologies/products visible in the evidence (e.g. nginx,
  Apache, WordPress, OpenSSH, Exim, MySQL). Normalized names, NO version numbers.

Hard rules:
- Use ONLY the evidence. NEVER invent an org name, industry, or technology that the
  evidence doesn't support. Prefer null / an empty list over a guess.
- Ignore generic junk titles ("Login", "Redirect", "Default Page", "Object Not Found",
  "Invalid URL"). Do not treat a hosting/CDN provider as the org.

Return ONLY a compact JSON array, one object per input domain, no prose and no
markdown fences:
[{"domain": "...", "org_name": "..."|null, "industry": "..."|null, "tech_stack": [...]}]"""


def build_extraction_prompt(evidence: list[str]) -> str:
    """Compose the firmographic-extraction prompt for a batch of evidence blocks."""
    listing = "\n".join(evidence)
    return f"{_EXTRACT_INSTRUCTIONS}\n\nCompanies:\n{listing}"
