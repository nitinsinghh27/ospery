"""Generic LLM runner: batch items → one call per batch → validate each result
against a Pydantic model. Reused by any enricher (classification, industry, …)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar

from pydantic import BaseModel, ValidationError

from osprey.config import LLM_MAX_WORKERS, LLM_MODEL
from osprey.llm.client import parse_json_array, run_claude

T = TypeVar("T", bound=BaseModel)


def run_structured(
    items: list[str],
    build_prompt: Callable[[list[str]], str],
    model_cls: type[T],
    batch_size: int,
    max_workers: int = LLM_MAX_WORKERS,
    model: str = LLM_MODEL,
) -> list[T]:
    """Run `items` through the LLM in batches, returning validated `model_cls` rows.

    Batches run concurrently (calls are I/O-bound — each waits on the model), so a
    pool of workers is ~`max_workers`x faster than sequential. Malformed rows (fail
    JSON parse or schema validation) are skipped; failed batches are skipped too.
    """
    batches = [items[i : i + batch_size] for i in range(0, len(items), batch_size)]

    def run_one(chunk: list[str]) -> list[dict[str, object]] | None:
        return _call_batch(chunk, build_prompt, model)

    out: list[T] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for parsed in pool.map(run_one, batches):
            if parsed is None:  # batch failed after a retry — skip, don't cascade
                continue
            for obj in parsed:
                try:
                    out.append(model_cls(**obj))
                except (ValidationError, TypeError):
                    continue
    return out


def _call_batch(
    chunk: list[str], build_prompt: Callable[[list[str]], str], model: str = LLM_MODEL
) -> list[dict[str, object]] | None:
    """One LLM call + parse, with a single retry. Returns None if it still fails
    (empty output, timeout, unparseable) so the caller can skip that batch."""
    for _ in range(2):
        try:
            return parse_json_array(run_claude(build_prompt(chunk), model=model))
        except Exception:
            continue
    return None
