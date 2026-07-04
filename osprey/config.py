"""Central configuration — paths, database, model ids, and tunables in one place
so nothing is hard-coded across the pipeline modules."""

from __future__ import annotations

from pathlib import Path

# --- Source & warehouse ------------------------------------------------------
SOURCE = Path("/Users/nitin/Downloads/test_scans.json.zst copy")
WAREHOUSE_DB = Path("data/warehouse/osprey.duckdb")
BRONZE_TABLE = "bronze.shodan_scans"

# --- Ingestion ---------------------------------------------------------------
INGEST_BATCH_SIZE = 20_000

# --- LLM (Claude CLI transport) ----------------------------------------------
NODE22_BIN = "/opt/homebrew/opt/node@22/bin"   # CLI needs Node 22 (crashes on 25)
LLM_MODEL = "claude-haiku-4-5-20251001"          # cheap classification
LLM_BATCH_SIZE = 25
LLM_MAX_WORKERS = 6                              # concurrent LLM calls (I/O-bound)

# --- Enrichment (LLM entity labels) ------------------------------------------
ENRICHMENT_TABLE = "enrichment.entity_labels"
ENRICH_TOP_N = 500                               # classify the top-N candidates by score
CONFIDENCE_MIN = 0.7                             # below this -> flag for review
PROVIDER_IP_THRESHOLD = 1000                     # business + >= this many IPs -> flag

# --- Enrichment (LLM sales pitches) ------------------------------------------
PITCH_TABLE = "enrichment.company_pitch"
PITCH_MODEL = "claude-sonnet-5"                  # better prose than Haiku for pitches
PITCH_BATCH_SIZE = 6                             # smaller batch: pitch output is longer
PITCH_MAX_CVES = 4                               # notable CVEs to ground the pitch in

# What the vendor sells — injected into the pitch so it positions "we can fix all
# of this". Swappable: any cyber vendor drops in their own offering and regenerates.
VENDOR_PITCH_CONTEXT = (
    "an end-to-end security platform that helps teams find and fix the full range of "
    "internet-facing exposures — known CVEs, exposed databases, end-of-life software, "
    "weak or self-signed certificates, exposed VPN/remote access, and active-compromise "
    "(malware/C2) signals — with prioritized, guided remediation across the board."
)
