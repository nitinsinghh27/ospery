---
name: add-llm-enricher
description: >
  Add a new cached, evaluated, traced LLM enrichment step to Osprey (e.g. classify,
  extract, or generate per-domain). Use when a task needs semantic interpretation the
  deterministic pipeline can't do. Encodes the rules-first + structured-output +
  versioned-prompt + cache + eval + trace pattern so every enricher is production-grade,
  not a one-off script. Invocable by engineers and agents.
---

# Add an LLM enrichment step

Osprey treats LLMs as production infrastructure. Every enricher follows the same shape;
copy an existing one (`classify_entities`, `generate_pitches`, `extract_profiles`) and
fill in the blanks. Do **not** hand-roll a bespoke LLM call — reuse `run_structured`.

## 0. Decide rules vs LLM first (the most important step)
- Deterministic structure (regex-able IDs, versions, emails, reserved TLDs) → **rules**.
- Genuine semantic interpretation of messy text → **LLM**, and only for the residual.
- Justify the split in the module docstring. Reaching for an LLM where a parser works
  is the anti-pattern this codebase rejects.

## 1. Contract — `osprey/schemas.py`
Add a Pydantic model for the LLM's structured output (semantic fields only; keep
rule-derived fields out of the model so the LLM can't hallucinate them).

## 2. Versioned prompt — `osprey/llm/prompts.py`
- Add `XILL_PROMPT_VERSION = "v1"` and a `build_*_prompt(items) -> str`.
- Instructions MUST include hard rules: "use ONLY the evidence; never invent; prefer
  null/empty over a guess"; return a compact JSON array, no prose/fences.
- Bump the version on any wording change (invalidates cache, keeps evals comparable).

## 3. Cache table — `osprey/warehouse.py`
Add `create_*_table` / `cached_*_domains` / `upsert_*`, keyed `PRIMARY KEY (domain,
prompt_version)` with `ON CONFLICT DO NOTHING` (idempotent — re-runs skip done rows).
`warehouse.py` is the ONLY module that touches DuckDB.

## 4. Pipeline — `osprey/pipelines/<name>.py`
- A dagster-agnostic pure function returning run stats.
- Read inputs, split rules-vs-LLM, then call:
  `run_structured(items, build_prompt, Model, batch_size=..., model=..., task="<name>",
   prompt_version=VERSION)` — this auto-batches, runs concurrently, validates, and
  **traces every call** (tokens/cost/latency) via `osprey/llm/trace.py`.
- Model choice: Haiku for cheap classification, Sonnet for nuanced extraction/prose.
- Skip already-cached domains; upsert results.

## 5. Eval — `data/evals/<name>.jsonl` + `osprey/llm/eval_*.py`
- Hand-label a small, clear ground-truth set.
- Score precision / recall / F1 (fuzzy-match free text; set-overlap for lists).
- Run it — the eval WILL surface bugs (it has: SSH-strings-as-emails, null-byte crashes,
  non-deterministic sampling). Fix them; re-run. No enricher ships without an eval.

## 6. Serve via gold, not the app — `transform/`
- Add the cache table as a dbt **source** (`models/sources.yml`).
- Join it into `gold_prospects` (NOT `gold_companies` — the enricher reads
  `gold_companies`, so joining there would cycle). The app reads gold only.
- Add dbt tests (`not_null`, `unique`) in `models/gold/schema.yml`.

## 7. Orchestrate — `osprey/orchestration/definitions.py`
Add a thin `@asset` wrapping the pipeline function, with correct `deps=[...]`.

## Checklist
- [ ] rules-vs-LLM split justified in the docstring
- [ ] Pydantic output schema (semantic fields only)
- [ ] versioned prompt with "never invent / null over guess" hard rules
- [ ] idempotent cache table keyed by (domain, prompt_version)
- [ ] pipeline uses `run_structured` with `task` + `prompt_version` (→ traced)
- [ ] labelled eval set + precision/recall, bugs fixed
- [ ] dbt source + `gold_prospects` join + tests; app reads gold only
- [ ] Dagster asset with deps
- [ ] `python -m osprey.llm.trace` shows the new task's cost/latency
