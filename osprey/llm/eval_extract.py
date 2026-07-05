"""Eval harness for firmographic extraction — holds the LLM accountable on real
labels (the JD's "measured precision/recall", not vibes).

Reads the cached `enrichment.company_profile` rows for the labelled domains and scores
`org_name` identification. Because org names are free text ("Virginia Tech" vs
"Virginia Polytechnic Institute"), matching is token-overlap fuzzy, not exact.

    uv run python -m osprey.pipelines.extract_profiles      # build profiles first
    uv run python -m osprey.llm.eval_extract                # then score them
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import duckdb

from osprey.config import WAREHOUSE_DB
from osprey.llm.prompts import EXTRACT_PROMPT_VERSION

EVAL_SET = Path("data/evals/profile_extraction.jsonl")
_STOP = {"of", "the", "and", "for", "a"}


def _tokens(s: str) -> set[str]:
    ascii_s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()  # strip accents
    return {t for t in re.sub(r"[^a-z0-9 ]", " ", ascii_s.lower()).split() if t not in _STOP}


def _org_match(pred: str | None, expected: str) -> bool:
    """Fuzzy: >= half of the expected distinctive tokens appear in the prediction."""
    if not pred:
        return False
    exp, got = _tokens(expected), _tokens(pred)
    if not exp:
        return False
    return len(exp & got) / len(exp) >= 0.5


def evaluate(path: Path = EVAL_SET, db_path: Path = WAREHOUSE_DB) -> dict[str, float]:
    labels = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    con = duckdb.connect(str(db_path), read_only=True)
    profiles = {
        str(d): (o, i)
        for d, o, i in con.execute(
            f"SELECT domain, org_name, industry FROM enrichment.company_profile "
            f"WHERE prompt_version = '{EXTRACT_PROMPT_VERSION}'"
        ).fetchall()
    }
    con.close()

    total = len(labels)
    predicted = correct = ind_correct = 0
    print(f"=== profile extraction eval ({total} labelled domains) ===")
    for row in labels:
        domain = row["domain"]
        pred_org, pred_ind = profiles.get(domain, (None, None))
        has_pred = bool(pred_org)
        ok = _org_match(pred_org, row["org_name"])
        predicted += int(has_pred)
        correct += int(ok)
        if pred_ind and row.get("industry") and _tokens(row["industry"]) & _tokens(pred_ind):
            ind_correct += 1
        mark = "OK " if ok else ("MISS" if has_pred else "null")
        print(f"  [{mark}] {domain:20s} exp={row['org_name'][:32]:32s} got={str(pred_org)[:32]}")

    precision = correct / predicted if predicted else 0.0
    recall = correct / total if total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    print("\n=== org_name ===")
    print(f"  precision {precision:.0%}  ({correct}/{predicted} predicted correct)")
    print(f"  recall    {recall:.0%}  ({correct}/{total} labelled found)")
    print(f"  F1        {f1:.0%}")
    print(f"=== industry match: {ind_correct}/{total} ({ind_correct/total:.0%}) ===")
    return {"precision": precision, "recall": recall, "f1": f1}


if __name__ == "__main__":
    evaluate()
