# Stage 7 — LLM Enrichment (top-N → labels → cache)

Clean the head of the candidate list: label the top-N scoring companies
`business` / `infra` (+ segment), apply guardrails, and **cache** the results so
the demo/app read frozen labels (no live LLM). This is the step that finally
removes the leaked infra from the top of the prospect list.

---

## 1. Flow

```
silver_company_candidates (top-N by score)
   │  institutional TLD?  (.gov/.edu/.ac.*/.mil)
   ├── yes → deterministic label (business + segment, conf 1.0)   [classify_by_tld]
   └── no  → LLM classify (business/infra + segment)              [classify_entities]
             │
   guardrails: confidence < 0.7  OR  business & hosts ≥ 1000  → flag for review
             │
   upsert → enrichment.entity_labels   (PK domain+prompt_version → re-run skips)
```

Code: [`osprey/pipelines/enrich_entities.py`](../osprey/pipelines/enrich_entities.py)
(step) · [`classify_entities.py`](../osprey/pipelines/classify_entities.py)
(TLD rule + LLM) · cache helpers in [`osprey/warehouse.py`](../osprey/warehouse.py).

```bash
uv run python -m osprey.pipelines.enrich_entities --top-n 500
```

---

## 2. Why only the top-N

The LLM runs on a few hundred domains, not all 500k — errors are only visible at
the top of the ranked list, and top-N is cheap (~20 Haiku calls). The deterministic
classifier handles the bulk; the LLM refines the head. Rules for scale, LLM where
it earns it.

---

## 3. Guardrails (accountability)

- **Confidence gate:** predictions `< 0.7` → `flagged` (review, not auto-trusted).
- **Deterministic cross-check:** LLM says `business` but the domain spans
  `≥ 1000` IPs → contradiction with the footprint signal → `flagged`.
- **TLD rule first:** reserved TLDs never touch the LLM (fixes the eval-caught
  gov/edu flips; deterministic + 100% correct).

---

## 4. Idempotency & the demo

- Results cache to **`enrichment.entity_labels`**, keyed by `(domain, prompt_version)`.
  Re-runs skip already-labelled domains → same output.
- The **app reads the cached table — no live LLM at demo time**, so numbers are
  frozen and reproducible. LLM non-determinism exists only during the one-time
  enrichment build, never at serve time.
- Bump `ENTITY_PROMPT_VERSION` to invalidate + re-label on a prompt change.

---

## 5. Result (top-500 run)

| Stat | Value |
|---|---|
| Candidates labelled | 499 / 500 (1 dropped on schema validation) |
| Business | 100 |
| **Infra (leaked hosts caught)** | **399** |
| Via TLD rule | 11 |
| Via LLM | 488 |
| Flagged (guardrails) | 49 |

**Before:** top prospects were all hosting/ISP (`netia.com.pl`, `hvvc.us`,
`ukfast.net`…). **After:** real companies and institutions surface —
`vt.edu`, `rit.edu`, `unibocconi.it`, `accesskenya.com`, `enegan.it`,
`midlandcomputers.com` — with the infra demoted and each labelled with a reason.

**Honest caveats:** obscure small companies land at ~0.7 confidence (genuine hard
cases → review queue). Grow the eval set and re-run on prompt-version changes.

---

## 6. Second enrichment — sales pitches (grounded, cached)

A separate step turns each **gold prospect** into a short, rep-ready outreach pitch.
Same production discipline as the labels: versioned prompt, batched + concurrent,
cached, idempotent — the app reads the frozen pitch, never the LLM.

```
gold.gold_companies  (segment, country, score, confidence, reasons)
gold.gold_company_services  (product, version, REAL vulns per service)
        │  build a grounded descriptor per company
        │  (signals + "product version → actual CVEs", newest first, capped)
        ▼
   LLM (Sonnet) → 3-4 sentence pitch, segment-tailored, non-alarmist,
                  positions the vendor's offering (config: VENDOR_PITCH_CONTEXT)
        ▼
   upsert → enrichment.company_pitch  (PK domain+prompt_version → re-run skips)
```

Code: [`osprey/pipelines/generate_pitches.py`](../osprey/pipelines/generate_pitches.py) ·
prompt in [`osprey/llm/prompts.py`](../osprey/llm/prompts.py).

```bash
uv run python -m osprey.pipelines.generate_pitches          # all gold prospects
```

**Grounding vs hallucination (the key point):** CVE↔product pairing comes from our
own `gold_company_services` (each service's real `vulns`), never invented by the
model. A hard prompt rule forbids adding any CVE/version not in the input, so every
cited CVE is verifiable. CVEs are ranked and tagged with real exploitation status —
`[KEV]` (CISA actively-exploited) and `[EPSS x%]` (FIRST exploit probability) — so the
pitch leads with what actually matters; at most two are cited, then "among others".
Org/industry (from firmographics) let it address the company by name.

**Model:** Sonnet (`PITCH_MODEL`) — noticeably more consultative prose than Haiku.
**Result (`v4`):** every prospect gets a cached pitch grounded in real CVEs + KEV/EPSS
+ firmographics. Bump `PITCH_PROMPT_VERSION` to re-generate on a wording change.

---

## 7. Third enrichment — firmographic extraction from banners

The clearest demonstration of the sourcing role's core skill: **LLM structured
extraction from low-quality, unstructured text**. Each prospect's exposed services
leak `banner`, `http_title`, `http_server`, `product`, and `ssl_cert_subject` — messy
evidence we turn into a firmographic profile.

```
gold prospects → gather evidence (signal-rich services first, deterministic sample)
   ├── DETERMINISTIC (regex): contact_emails      [structure is regular → no LLM]
   └── LLM (Sonnet): org_name, industry, tech_stack [semantic → the LLM earns it]
   ▼
   upsert → enrichment.company_profile  (cached, versioned, idempotent)
```

Code: [`osprey/pipelines/extract_profiles.py`](../osprey/pipelines/extract_profiles.py) ·
eval: [`osprey/llm/eval_extract.py`](../osprey/llm/eval_extract.py).

**Rule-vs-LLM split (the JD's exact ask):** emails are a regular pattern → regex;
org/industry/tech need semantic interpretation of noisy text → LLM. The LLM is barred
(hard prompt rule) from inventing anything not in the evidence — null over a guess.

**Eval-driven — three real bugs the harness/run surfaced and fixed:**
1. **SSH cipher strings as "emails":** `curve25519-sha256@libssh.org` matched the email
   regex → blocklisted protocol domains.
2. **Null bytes in raw banners** crashed the subprocess transport → stripped in the
   client (defensive, protects every call).
3. **Non-deterministic, signal-blind sampling** (took arbitrary services) halved recall
   and broke reproducibility → sample **signal-rich services first, deterministically**.
   Eval on 11 labelled orgs: org_name **F1 59% → 100%** after the fix.

**Honest result:** on the (small, clear) labelled set, precision/recall = 100%. Across
all 829, only ~32% get an org name and ~9% an email — exposure data is sparse, so the
**demonstration value (rules-vs-LLM, evals, structured output, grounded) exceeds the
raw data value** here. That trade-off is the point, and it's stated, not hidden.
