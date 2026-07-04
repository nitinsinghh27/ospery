"""All Pydantic data contracts for the pipeline, in one place.

- `ShodanScan`  — the flat Bronze projection of a raw Shodan scan (also the single
  source of truth for the DuckDB table DDL and column order).
- `EntityLabel` — the LLM's structured verdict for a domain (business vs infra).

Class names disambiguate; import what you need: `from osprey.schemas import ...`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# Bronze — one scanned service, flattened
# =============================================================================

def _col(duckdb_type: str) -> Any:
    return Field(default=None, json_schema_extra={"duckdb": duckdb_type})


def _list_col(duckdb_type: str) -> Any:
    return Field(default_factory=list, json_schema_extra={"duckdb": duckdb_type})


class ShodanScan(BaseModel):
    """One scanned service, flattened to the columns of `bronze.shodan_scans`."""

    model_config = ConfigDict(extra="ignore")

    ip_str: str | None = _col("VARCHAR")
    port: int | None = _col("INTEGER")
    transport: str | None = _col("VARCHAR")
    scanned_at: datetime | None = _col("TIMESTAMP")
    org: str | None = _col("VARCHAR")
    isp: str | None = _col("VARCHAR")
    asn: str | None = _col("VARCHAR")
    domains: list[str] = _list_col("VARCHAR[]")
    hostnames: list[str] = _list_col("VARCHAR[]")
    country_code: str | None = _col("VARCHAR")
    city: str | None = _col("VARCHAR")
    region: str | None = _col("VARCHAR")
    shodan_module: str | None = _col("VARCHAR")
    product: str | None = _col("VARCHAR")
    version: str | None = _col("VARCHAR")
    cpe23: list[str] = _list_col("VARCHAR[]")
    tags: list[str] = _list_col("VARCHAR[]")
    vulns: list[str] = _list_col("VARCHAR[]")
    http_server: str | None = _col("VARCHAR")
    http_title: str | None = _col("VARCHAR")
    ssl_cert_subject: str | None = _col("VARCHAR")
    ssl_cert_issuer: str | None = _col("VARCHAR")
    banner: str | None = _col("VARCHAR")
    hash: int | None = _col("BIGINT")


# Column order — derived once, used by the DDL and the INSERT.
COLUMNS: list[str] = list(ShodanScan.model_fields.keys())


def duckdb_types() -> dict[str, str]:
    """Map each column to its DuckDB type (from the model's field metadata)."""
    types: dict[str, str] = {}
    for name, field in ShodanScan.model_fields.items():
        extra = field.json_schema_extra
        duck = cast("dict[str, Any]", extra).get("duckdb", "VARCHAR") if isinstance(extra, dict) else "VARCHAR"
        types[name] = str(duck)
    return types


def duckdb_ddl(table: str = "bronze.shodan_scans") -> str:
    """Generate the `CREATE OR REPLACE TABLE` statement from the model."""
    width = max(len(name) for name in COLUMNS)
    lines = [f"    {name:<{width}}  {duck_type}" for name, duck_type in duckdb_types().items()]
    return f"CREATE OR REPLACE TABLE {table} (\n" + ",\n".join(lines) + "\n)"


# =============================================================================
# Entity classification — the LLM's verdict for a domain
# =============================================================================

EntityClass = Literal["business", "infra"]
Segment = Literal["commercial", "education", "government", "nonprofit", "other"]


class EntityLabel(BaseModel):
    """The LLM's structured verdict for a single domain."""

    domain: str
    entity_class: EntityClass
    segment: Segment = "other"
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str


# =============================================================================
# Sales pitch — the LLM's "why this is a lead" narrative for a prospect
# =============================================================================

class CompanyPitch(BaseModel):
    """A short, rep-ready sales pitch generated (offline, cached) per prospect."""

    domain: str
    pitch: str
