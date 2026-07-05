# Stage 5 — Entity Classification (business vs infra, + segment)

Classify each resolved domain as **`business`** (a real end-organization we can
sell to) or **`infra`** (a hosting / cloud / CDN / ISP / DNS provider whose IPs
serve *other* companies), and — for businesses — a **segment** so the dashboard
can categorise and weight them. Builds on the identity work in
[Stage 4](Stage4_CompanyResolution.md).

---

## 1. Why classification matters (proven, not assumed)

The lead score aggregates a company's signals. A **multi-tenant provider** that
leaks through the deterministic classifier accumulates *thousands of customers'*
signals, so it **dominates the top of the score** — the exact opposite of what a
rep wants. See [`signal_scoring.sql`](../data/analysis/signal_scoring.sql) Q3:
the raw top-20 were *all* leaked hosts/ISPs (`netia.com.pl`, `bell.ca`,
`poneytelecom.eu`…), with `cve_count` 200–1000 and every signal firing.

So clean classification is not cosmetic — it decides whether the product's
headline output is credible.

---

## 2. Two-stage approach (rules first, LLM where it earns it)

### Stage A — Deterministic (fast, bulk) — *done in Stage 4*

A domain is `infra` if `distinct_ips >= 1000` (generalises to providers we never
named) **or** it matches an infra keyword (low-IP site-builders / shared hosts /
junk certs). Result: 503,856 `business` domains, 2,131 `infra` (but ~72% of
rows). Conservative on keywords so real companies aren't wrongly killed.

**Ceiling (proven):** mid-size shared hosts / regional ISPs (`coreserver.jp`,
`justhost.com`, `megasrv.de`, `isp.net`…) have moderate IP counts and generic
names — rules can't separate them from real companies (walmart = 341 IPs), and a
`cve_count` heuristic only removes the largest. Whack-a-mole doesn't converge.

### Stage B — LLM classifier (the residual + the segment)

Run an LLM **only on the top-N candidates by score** (where errors are visible
and where it's cheap — a few hundred domains, not 500k).

- **Transport:** Claude CLI (`claude -p`) via a Node 22 wrapper — uses the
  existing Claude Code login, **no API key, no per-call cost setup**. Swappable
  to the Anthropic SDK/API in production (same interface). *(Node 22 is required —
  the CLI crashes on the machine's Node 25.)*
- **Model:** Haiku — cheap, fast, sufficient for classification.
- **Structured output (Pydantic):** `{domain, entity_class, segment, confidence, reason}`
  - `entity_class` ∈ `business | infra`
  - `segment` ∈ `commercial | education | government | nonprofit | other`
- **Prompt (versioned):** explicit definitions — *infra = provider only*;
  *any end-organization (incl. university, government, nonprofit) = business*.
- **Eval set (~40 hand-labelled domains):** measure precision/recall; the tricky
  cases (stanford=business, ISPs=infra, ambiguous flagged) live here.
- **Cached + committed outputs:** the app reads the cached labels → runs with no
  CLI/key. Reviewers can re-run with their own Claude Code login if they wish.

**First-test finding (why the eval set exists):** on a sample, the LLM nailed the
ISPs/hosts but mislabeled `stanford.edu` and `amazon.com` as infra ("not a sales
target" / "cloud"). Fix: the prompt now defines *infra = provider only* and
*end-orgs = business*, and the eval set pins these cases.

---

## 3. Segment handling (edu / govt / nonprofit)

Universities, government, and nonprofits **are** valid prospects (they have
security needs and budgets), so they stay `business`. But they behave differently
from commercial accounts, so we:

- **Categorise** them via `segment` — the dashboard can filter / group them
  separately.
- **Down-weight** them slightly in the lead score (an `org_type` modifier), so
  commercial prospects rank above equivalent edu/govt ones by default.

---

## 4. Eval results — measured, not trusted

How we justify the LLM output isn't hallucinated: two hand-labelled sets in
[`data/evals/`](../data/evals), scored by [`osprey/llm/eval.py`](../osprey/llm/eval.py)
(`uv run python -m osprey.llm.eval [path]`). Positive class = `business`, so a
false positive = infra leaking into prospects, a false negative = a real prospect
dropped.

| Eval set | Domains | Accuracy (per run) | Notes |
|---|---|---|---|
| `entity_classification.jsonl` (clear) | 41 | ~95–100% | run-to-run variance |
| `entity_classification_hard.jsonl` (ambiguous) | 20 | ~95–100% | leaked hosts correctly `infra` |

The **hard** set is the meaningful one: it contains the exact leaked hosts the
deterministic rules failed on (`coreserver.jp`, `justhost.com`, `megasrv.de`,
`1e100.net`, `hvvc.us`) and tricky-name real businesses (`serverfault.com`,
`hostelworld.com`) — the LLM classifies these correctly, validating the
"rules for the bulk, LLM for the residual" split.

**LLM output is non-deterministic** — re-running gives ~95–100%, not a fixed
100%. The eval immediately earned its keep by catching a systematic weakness:
`gov.uk` / `india.gov.in` sometimes flip to `infra` ("generic government portal")
— and at *high* confidence (0.90–0.95), so confidence-gating alone won't catch
them.

**Fix (eval-driven, deterministic where possible):** institutional TLDs are
reserved and unambiguous — `.gov` / `.gov.*` → government, `.edu` / `.ac.*` →
education, `.mil` → government. Pre-classify these by **rule** (100% correct, no
LLM) and send only the rest to the LLM. Plus a deterministic cross-check (LLM says
`business` but the domain spans >1000 IPs → flag for review).

**Honest caveats:** the sets are small (61) and hand-labelled by us. Production
discipline: grow the set, re-run on prompt-version change (drift), gate
low-confidence predictions to review, and track accuracy over time.

---

## 5. Status & next

- Stage A (deterministic) — ✅ done (Stage 4).
- Claude-CLI transport under Node 22 — ✅ validated.
- Prompt + Pydantic schema + generic runner + **eval (~95–100% on 61 domains)** — ✅ done.
- **Institutional-TLD deterministic pre-classification** (fixes govt/edu flips) — ✅ done (see [Stage 7](Stage7_LLMEnrichment.md)).
- **Top-N run + cache** (`entity_labels` table) + confidence/cross-check guardrails — ✅ done (Stage 7).
