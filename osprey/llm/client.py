"""Transport: call the Claude CLI (`claude -p`) as a subprocess.

Uses the existing Claude Code login (no API key). Two environment quirks handled:
  1. The CLI must run under Node 22 — it crashes on this machine's Node 25.
  2. The CLI is invoked from *within* a Claude Code session, so the CLAUDE_CODE_*
     env vars are stripped to avoid nested-session interference.

In production this is the only module that changes — swap the subprocess call for
the Anthropic SDK/API; the rest of the pipeline is unaffected.
"""

from __future__ import annotations

import json
import os
import subprocess
import time

from osprey.config import LLM_MODEL, NODE22_BIN
from osprey.llm import trace

# Session/agent vars that must not leak into the nested CLI invocation.
_STRIP_ENV = (
    "CLAUDECODE", "CLAUDE_CODE_CHILD_SESSION", "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_EXECPATH", "CLAUDE_CODE_ENABLE_TASKS",
    "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING", "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_EFFORT", "AI_AGENT",
)


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _STRIP_ENV}
    env["PATH"] = NODE22_BIN + os.pathsep + env.get("PATH", "")
    return env


def run_claude(
    prompt: str,
    model: str = LLM_MODEL,
    timeout: int = 120,
    task: str = "",
    prompt_version: str = "",
) -> str:
    """Run one `claude -p` call, record a trace (tokens/cost/latency), return the text.

    Uses `--output-format json` so the CLI hands back real usage + cost + duration —
    no manual token math. Every call (success or failure) is logged to the trace.
    """
    prompt = prompt.replace("\x00", "")  # raw banners can carry null bytes; subprocess args can't
    started = time.perf_counter()

    def _trace(ok: bool, error: str = "", usage: dict[str, int] | None = None,
               cost: float = 0.0, latency_ms: int | None = None) -> None:
        u = usage or {}
        trace.record(
            task=task, prompt_version=prompt_version, model=model,
            input_tokens=u.get("input_tokens", 0), output_tokens=u.get("output_tokens", 0),
            cache_creation_tokens=u.get("cache_creation_input_tokens", 0),
            cache_read_tokens=u.get("cache_read_input_tokens", 0),
            cost_usd=cost, ok=ok, error=error,
            latency_ms=latency_ms if latency_ms is not None else int((time.perf_counter() - started) * 1000),
        )

    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--model", model, "--output-format", "json"],
            capture_output=True, text=True, env=_env(), timeout=timeout,
        )
    except Exception as exc:  # timeout / spawn failure
        _trace(ok=False, error=str(exc))
        raise

    if result.returncode != 0:
        _trace(ok=False, error=result.stderr[:300])
        raise RuntimeError(f"claude CLI failed ({result.returncode}): {result.stderr[:300]}")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        _trace(ok=False, error="non-JSON CLI output")
        raise RuntimeError(f"claude CLI returned non-JSON output: {result.stdout[:200]}")

    usage = payload.get("usage") or {}
    cost = float(payload.get("total_cost_usd") or 0.0)
    latency_ms = int(payload.get("duration_ms") or (time.perf_counter() - started) * 1000)
    ok = not payload.get("is_error", False)
    _trace(ok=ok, error="" if ok else str(payload.get("subtype", "")), usage=usage,
           cost=cost, latency_ms=latency_ms)
    if not ok:
        raise RuntimeError(f"claude CLI reported error: {payload.get('subtype')}")
    return str(payload.get("result", "")).strip()


def parse_json_array(text: str) -> list[dict[str, object]]:
    """Extract the JSON array from the model's reply (tolerates ```json fences)."""
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON array in model output: {text[:200]}")
    parsed: list[dict[str, object]] = json.loads(text[start : end + 1])
    return parsed
