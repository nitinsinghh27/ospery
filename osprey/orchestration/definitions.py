"""Dagster orchestration — a thin asset layer over the existing pipeline steps.

This is ILLUSTRATIVE. The task is a one-time batch, so it needs no scheduler; the
value here is showing the lineage/DAG and that the pipeline steps are already
orchestrator-agnostic pure functions (`osprey/pipelines/*`) — Dagster just wires
them as assets. In production this same graph gains a schedule and a sensor on new
Shodan dumps; nothing in the steps themselves would change.

    uv run dagster dev -m osprey.orchestration.definitions      # open the asset graph

Lineage:  bronze_scans → silver_models → entity_labels → gold_models → company_pitches
"""
# NOTE: no `from __future__ import annotations` here — Dagster introspects the
# `context` parameter's real type at import, which stringized annotations break.

import subprocess

from dagster import AssetExecutionContext, Definitions, MaterializeResult, MetadataValue, asset

from osprey.config import ENRICH_TOP_N
from osprey.pipelines.enrich_entities import enrich_top_candidates
from osprey.pipelines.generate_pitches import generate_pitches
from osprey.pipelines.ingest_bronze import ingest_bronze


def _dbt(select: str) -> str:
    """Run a dbt selection from the repo root; raise on failure."""
    cmd = ["dbt", "run", "--select", select, "--project-dir", "transform", "--profiles-dir", "transform"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"dbt run --select {select} failed:\n{proc.stdout[-1000:]}\n{proc.stderr[-500:]}")
    return proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "ok"


@asset
def bronze_scans(context: AssetExecutionContext) -> MaterializeResult:
    """Raw Shodan scans streamed into bronze.shodan_scans (Python ingestion)."""
    stats = ingest_bronze()
    context.log.info(f"bronze: {stats}")
    return MaterializeResult(metadata={k: MetadataValue.int(int(v)) if isinstance(v, int) else MetadataValue.text(str(v)) for k, v in stats.items()})


@asset(deps=[bronze_scans])
def silver_models(context: AssetExecutionContext) -> MaterializeResult:
    """dbt silver layer: services + per-company candidates (dedup, signals, score)."""
    last = _dbt("silver")
    context.log.info(last)
    return MaterializeResult(metadata={"dbt": MetadataValue.text(last)})


@asset(deps=[silver_models])
def entity_labels(context: AssetExecutionContext) -> MaterializeResult:
    """LLM business/infra + segment labels for the top-N candidates (cached)."""
    stats = enrich_top_candidates(top_n=ENRICH_TOP_N)
    context.log.info(f"labels: {stats}")
    return MaterializeResult(metadata={k: MetadataValue.text(str(v)) for k, v in stats.items()})


@asset(deps=[entity_labels])
def gold_models(context: AssetExecutionContext) -> MaterializeResult:
    """dbt gold layer: the ranked prospect mart + per-company service drill-down."""
    last = _dbt("gold")
    context.log.info(last)
    return MaterializeResult(metadata={"dbt": MetadataValue.text(last)})


@asset(deps=[gold_models])
def company_pitches(context: AssetExecutionContext) -> MaterializeResult:
    """LLM sales pitches for each gold prospect, grounded in real CVEs (cached)."""
    stats = generate_pitches()
    context.log.info(f"pitches: {stats}")
    return MaterializeResult(metadata={k: MetadataValue.text(str(v)) for k, v in stats.items()})


defs = Definitions(assets=[bronze_scans, silver_models, entity_labels, gold_models, company_pitches])
