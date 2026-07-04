"""Eval harness for the entity classifier.

Runs the classifier against a hand-labelled set and reports accuracy, business
precision/recall, and segment accuracy — so the LLM output is *measured*, not
trusted. Mismatches are printed (with confidence + reason) for prompt debugging.

    uv run python -m osprey.llm.eval
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from osprey.pipelines.classify_entities import classify_entities

EVAL_SET = Path("data/evals/entity_classification.jsonl")


def load_eval_set(path: Path = EVAL_SET) -> list[dict[str, str]]:
    """Load the labelled eval set (one JSON object per line)."""
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def evaluate(path: Path = EVAL_SET) -> dict[str, object]:
    """Classify the eval domains and score predictions against the gold labels.

    Positive class = "business" (a prospect). So:
      - a false positive = infra wrongly kept as a prospect (junk lead)
      - a false negative = real business wrongly dropped (lost lead)
    """
    gold = load_eval_set(path)
    domains = [g["domain"] for g in gold]
    preds = {p.domain: p for p in classify_entities(domains)}

    tp = fp = tn = fn = 0
    seg_correct = seg_total = 0
    conf_sum = 0.0
    mismatches: list[dict[str, object]] = []
    missing: list[str] = []

    for g in gold:
        pred = preds.get(g["domain"])
        if pred is None:
            missing.append(g["domain"])
            continue
        conf_sum += pred.confidence
        gold_class, pred_class = g["entity_class"], pred.entity_class

        if gold_class == "business" and pred_class == "business":
            tp += 1
        elif gold_class == "infra" and pred_class == "business":
            fp += 1
        elif gold_class == "infra" and pred_class == "infra":
            tn += 1
        else:  # gold business, predicted infra
            fn += 1

        if gold_class != pred_class:
            mismatches.append({
                "domain": g["domain"], "gold": gold_class, "pred": pred_class,
                "confidence": pred.confidence, "reason": pred.reason,
            })

        if gold_class == "business" == pred_class and "segment" in g:
            seg_total += 1
            seg_correct += int(g["segment"] == pred.segment)

    scored = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "n": len(gold), "scored": scored, "missing": missing,
        "accuracy": (tp + tn) / scored if scored else 0.0,
        "business_precision": precision,
        "business_recall": recall,
        "business_f1": f1,
        "segment_accuracy": seg_correct / seg_total if seg_total else 0.0,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "avg_confidence": conf_sum / scored if scored else 0.0,
        "mismatches": mismatches,
    }


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else EVAL_SET
    r = evaluate(path)
    c = r["confusion"]
    print(f"Eval set: {path.name} | {r['n']} domains | scored: {r['scored']} | missing: {len(r['missing'])}")  # type: ignore[arg-type]
    print(f"\nAccuracy            : {r['accuracy']:.1%}")
    print(f"Business precision  : {r['business_precision']:.1%}  (infra leaking into prospects)")
    print(f"Business recall     : {r['business_recall']:.1%}  (real prospects kept)")
    print(f"Business F1         : {r['business_f1']:.1%}")
    print(f"Segment accuracy    : {r['segment_accuracy']:.1%}")
    print(f"Avg confidence      : {r['avg_confidence']:.2f}")
    print(f"\nConfusion (positive=business): TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}")  # type: ignore[index]
    if r["missing"]:
        print(f"\nMissing (no prediction): {r['missing']}")
    mismatches = r["mismatches"]
    if isinstance(mismatches, list) and mismatches:
        print(f"\nMismatches ({len(mismatches)}):")
        for m in mismatches:
            print(f"  {m['domain']:26} gold={m['gold']:8} pred={m['pred']:8} "
                  f"conf={m['confidence']:.2f}  {m['reason']}")
    else:
        print("\nNo mismatches ✓")


if __name__ == "__main__":
    main()
