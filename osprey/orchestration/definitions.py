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
from osprey.pipelines.extract_profiles import extract_profiles
from osprey.pipelines.fetch_kev import fetch_kev
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


@asset
def kev_catalog(context: AssetExecutionContext) -> MaterializeResult:
    """CISA KEV (actively-exploited CVEs) fetched into reference.kev — joined by silver."""
    stats = fetch_kev()
    context.log.info(f"kev: {stats}")
    return MaterializeResult(metadata={k: MetadataValue.text(str(v)) for k, v in stats.items()})


@asset(deps=[bronze_scans, kev_catalog])
def silver_models(context: AssetExecutionContext) -> MaterializeResult:
    """dbt silver layer: services + per-company candidates (dedup, signals, KEV-aware score)."""
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
def gold_companies(context: AssetExecutionContext) -> MaterializeResult:
    """dbt gold core: the ranked prospect list + per-company service drill-down.
    Built before pitch/profile because those enrichment steps READ this list."""
    last = _dbt("gold_companies gold_company_services")
    context.log.info(last)
    return MaterializeResult(metadata={"dbt": MetadataValue.text(last)})


@asset(deps=[gold_companies])
def company_pitches(context: AssetExecutionContext) -> MaterializeResult:
    """LLM sales pitches for each gold prospect, grounded in real CVEs (cached)."""
    stats = generate_pitches()
    context.log.info(f"pitches: {stats}")
    return MaterializeResult(metadata={k: MetadataValue.text(str(v)) for k, v in stats.items()})


@asset(deps=[gold_companies])
def company_profiles(context: AssetExecutionContext) -> MaterializeResult:
    """Firmographics extracted from each prospect's exposed banners (rules + LLM, cached)."""
    stats = extract_profiles()
    context.log.info(f"profiles: {stats}")
    return MaterializeResult(metadata={k: MetadataValue.text(str(v)) for k, v in stats.items()})


@asset(deps=[company_pitches, company_profiles])
def gold_prospects(context: AssetExecutionContext) -> MaterializeResult:
    """dbt final serving model: prospects joined with the cached pitch + firmographics."""
    last = _dbt("gold_prospects")
    context.log.info(last)
    return MaterializeResult(metadata={"dbt": MetadataValue.text(last)})


defs = Definitions(assets=[
    bronze_scans, kev_catalog, silver_models, entity_labels, gold_companies,
    company_pitches, company_profiles, gold_prospects,
])
