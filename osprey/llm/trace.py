"""LLM observability — an append-only trace for every model call.

Every `run_claude()` call records prompt version, model, token usage, cost, latency,
and success. Traces go to a JSONL log: append-only and thread-safe, so the concurrent
runner never contends on the DuckDB single-writer lock. Summarize with:

    uv run python -m osprey.llm.trace          # cost/latency/precision-of-calls report

In production this becomes the observability layer the JD calls for — traces from day
one, cost ceilings with real token math, and drift detection when a model changes.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

TRACE_PATH = Path("data/traces/llm_traces.jsonl")
_LOCK = threading.Lock()


def record(
    *,
    task: str,
    prompt_version: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation_tokens: int,
    cache_read_tokens: int,
    cost_usd: float,
    latency_ms: int,
    ok: bool,
    error: str = "",
) -> None:
    """Append one trace row (thread-safe) for a single LLM call."""
    row = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "task": task,
        "prompt_version": prompt_version,
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_creation_tokens": cache_creation_tokens,
        "cache_read_tokens": cache_read_tokens,
        "cost_usd": round(cost_usd, 6),
        "latency_ms": latency_ms,
        "ok": ok,
        "error": error[:300],
    }
    line = json.dumps(row)
    with _LOCK:
        TRACE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(TRACE_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def _summary() -> None:
    """Print an observability report (overall + per-task) from the trace log."""
    import duckdb

    if not TRACE_PATH.exists():
        print(f"No traces yet at {TRACE_PATH}")
        return

    con = duckdb.connect()
    src = f"read_json_auto('{TRACE_PATH}')"
    overall = con.execute(f"""
        SELECT count(*) calls, sum(ok::int) ok,
               sum(input_tokens) in_tok, sum(output_tokens) out_tok,
               round(sum(cost_usd), 4) cost_usd,
               round(quantile_cont(latency_ms, 0.5)) p50_ms,
               round(quantile_cont(latency_ms, 0.95)) p95_ms
        FROM {src}
    """).fetchone()
    assert overall is not None
    calls, ok, in_tok, out_tok, cost, p50, p95 = overall
    print("=== LLM traces (overall) ===")
    print(f"  calls          {calls}  ({ok} ok, {calls - ok} failed)")
    print(f"  tokens         {in_tok:,} in / {out_tok:,} out")
    print(f"  cost           ${cost}")
    print(f"  latency        p50 {int(p50)}ms · p95 {int(p95)}ms")

    print("\n=== by task ===")
    rows = con.execute(f"""
        SELECT task, prompt_version, model, count(*) calls,
               round(sum(cost_usd), 4) spend, round(avg(latency_ms)) avg_ms
        FROM {src} GROUP BY 1,2,3 ORDER BY calls DESC
    """).fetchall()
    for task, ver, model, n, spend, avg_ms in rows:
        print(f"  {task:20s} {ver:4s} {model:26s} {n:>4} calls  ${spend}  {int(avg_ms)}ms avg")
    con.close()


if __name__ == "__main__":
    _summary()
