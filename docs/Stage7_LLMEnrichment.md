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
cited CVE is verifiable. Recent CVEs are preferred (an old CVE-2011 is weak
outreach); at most two are cited, then "among others".

**Model:** Sonnet (`PITCH_MODEL`) — noticeably more consultative prose than Haiku.
**Result:** 829/829 prospects have a cached `v3` pitch. Bump `PITCH_PROMPT_VERSION`
to re-generate on a wording change.
