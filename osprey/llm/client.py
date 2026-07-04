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

from osprey.config import LLM_MODEL, NODE22_BIN

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


def run_claude(prompt: str, model: str = LLM_MODEL, timeout: int = 120) -> str:
    """Run one `claude -p` call and return the raw stdout text."""
    result = subprocess.run(
        ["claude", "-p", prompt, "--model", model],
        capture_output=True, text=True, env=_env(), timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"claude CLI failed ({result.returncode}): {result.stderr[:300]}")
    return result.stdout.strip()


def parse_json_array(text: str) -> list[dict[str, object]]:
    """Extract the JSON array from the model's reply (tolerates ```json fences)."""
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON array in model output: {text[:200]}")
    parsed: list[dict[str, object]] = json.loads(text[start : end + 1])
    return parsed
