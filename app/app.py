"""Osprey — sales intelligence dashboard (Streamlit).

Reads the Gold marts (prospect list + per-company drill-down). Click a domain to
open its detail. The app never calls the LLM — it reads cached, materialized tables.

    uv run streamlit run app/app.py
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, cast

import duckdb
import pandas as pd
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode

# Prefer the small committed serving DB (used when hosted); fall back to the full
# local warehouse for development. Both expose the same gold.* + enrichment tables.
_SERVING = Path("data/serving/osprey_serving.duckdb")
_WAREHOUSE = Path("data/warehouse/osprey.duckdb")
DB_PATH = str(_SERVING if _SERVING.exists() else _WAREHOUSE)

SCORE_HELP = (
    "Lead score (higher = hotter). Weighted sum of exposure signals: "
    "active-compromise +40, known CVEs +15 (plus up to +20 by count), "
    "database exposed +20, end-of-life software +15, self-signed cert +10, "
    "VPN/IoT +8 each, plus a small attack-surface bonus (up to +10)."
)
CONF_HELP = (
    "Confidence (0–100%) from the LLM that this domain is a real business (not a "
    "hosting/ISP provider). Predictions below 70% are flagged and excluded."
)
CVE_HELP = "Distinct known CVEs (public vulnerabilities) across the company's exposed services."

SIGNALS = {
    "Known CVEs": "has_cve", "End-of-life software": "has_eol",
    "Database exposed": "has_db", "Self-signed cert": "has_selfsigned",
    "VPN exposed": "has_vpn", "IoT exposed": "has_iot", "Active compromise": "has_breach",
}

st.set_page_config(page_title="Osprey — Sales Intelligence", layout="wide")


@st.cache_data(show_spinner="Loading prospects…")
def load_companies() -> pd.DataFrame:
    con = duckdb.connect(DB_PATH, read_only=True)
    df = con.sql("SELECT * FROM gold.gold_companies ORDER BY score DESC, services DESC").df()
    con.close()
    return df


@st.cache_data(show_spinner="Loading exposed services…")
def load_services(domain: str) -> pd.DataFrame:
    con = duckdb.connect(DB_PATH, read_only=True)
    df = con.execute(
        "SELECT ip_str, port, transport, product, version, tags, vulns "
        "FROM gold.gold_company_services WHERE domain = ? "
        "ORDER BY (product IS NULL), (len(vulns) = 0), port",  # informative rows first
        [domain],
    ).df()
    con.close()
    return df


@st.cache_data(show_spinner=False)
def load_pitches() -> dict[str, str]:
    """Cached, pre-generated LLM sales pitches (domain -> pitch). Empty if not run."""
    con = duckdb.connect(DB_PATH, read_only=True)
    try:  # read only the newest prompt version (older cached versions are kept but ignored)
        rows = con.execute(
            "SELECT domain, pitch FROM enrichment.company_pitch "
            "WHERE prompt_version = (SELECT max(prompt_version) FROM enrichment.company_pitch)"
        ).fetchall()
    except duckdb.Error:
        rows = []
    con.close()
    return {str(d): str(p) for d, p in rows}


companies = load_companies()
PITCHES = load_pitches()

st.title("Osprey — Sales Intelligence")
st.caption("Prospect cybersecurity buyers by their internet-facing exposure — who to target, and why.")

# --- Sidebar filters (cascading: each filter's options reflect the ones above,
#     so you never see a dead option that would return zero rows) --------------
st.sidebar.header("Filters")
view = companies

search = st.sidebar.text_input("Search domain")
if search:
    view = view.loc[view["domain"].str.contains(search, case=False, na=False)]

segments = st.sidebar.multiselect("Segment", sorted(view["segment"].unique()))
if segments:
    view = view.loc[view["segment"].isin(segments)]

countries = st.sidebar.multiselect("Country", sorted(view["country_name"].dropna().unique()))
if countries:
    view = view.loc[view["country_name"].isin(countries)]

present_signals = [label for label, col in SIGNALS.items()
                   if int(cast("pd.Series", view[col]).sum()) > 0]
chosen_signals = st.sidebar.multiselect("Must have signal", present_signals)
for label in chosen_signals:
    view = view.loc[view[SIGNALS[label]] == 1]

max_score = int(cast("pd.Series", view["score"]).max()) if len(view) else 0
min_score = st.sidebar.slider("Min score", 0, max(max_score, 1), 0)
view = view.loc[view["score"] >= min_score]

# --- KPIs --------------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Prospects", len(view))
c2.metric("Actively compromised", int(view["has_breach"].sum()),
          help="Companies with signs of active compromise (malware / C2).")
c3.metric("Total CVEs", int(view["cve_count"].sum()), help=CVE_HELP)
c4.metric("Countries", view["country_name"].nunique())

st.divider()


def score_breakdown(row: Any) -> list[tuple[str, int]]:
    """Recompute the score's component points (mirrors silver_company_candidates.sql)
    so a rep can see exactly why a score is what it is."""
    cve_count = int(row["cve_count"])
    services = int(row["services"])
    parts = [
        ("Active compromise (malware / C2)", 40 if row["has_breach"] else 0),
        (f"Known CVEs ({cve_count})", 15 + min(cve_count * 2, 20) if cve_count > 0 else 0),
        ("Database exposed", 20 if row["has_db"] else 0),
        ("End-of-life software", 15 if row["has_eol"] else 0),
        ("Weak / self-signed cert", 10 if row["has_selfsigned"] else 0),
        ("VPN / remote access exposed", 8 if row["has_vpn"] else 0),
        ("IoT / embedded exposed", 8 if row["has_iot"] else 0),
        (f"Attack surface ({services} services)", min(round(math.log2(services + 1) * 3), 10)),
    ]
    return [(label, pts) for label, pts in parts if pts > 0]


def render_detail(domain: str) -> None:
    """Inline company detail, shown when a domain is clicked."""
    row = companies[companies["domain"] == domain].iloc[0]
    with st.container(border=True):
        top, close = st.columns([6, 1])
        top.subheader(domain)
        if close.button("Close"):
            st.session_state["grid_nonce"] = st.session_state.get("grid_nonce", 0) + 1  # remount grid → clear selection
            st.rerun()

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Lead score", int(row["score"]), help=SCORE_HELP)
        m2.metric("Segment", str(row["segment"]))
        m3.metric("Country", str(row["country_name"]))
        m4.metric("Confidence", f'{row["classification_confidence"]:.0%}', help=CONF_HELP)

        with st.expander(f"Score breakdown ({int(row['score'])} points)"):
            breakdown = pd.DataFrame(score_breakdown(row), columns=["Signal", "Points"])
            st.dataframe(breakdown, hide_index=True, width="stretch")

        with st.expander("Buying signals", expanded=True):
            for reason in row["reasons"]:
                st.markdown(f"- {reason}")

        pitch = PITCHES.get(domain)
        if pitch:
            with st.expander("Suggested outreach pitch"):  # collapsed — click to expand
                st.markdown(
                    f'<div style="background-color: rgba(90,150,110,0.10); '
                    f'border-left: 3px solid #5a9670; padding: 12px 16px; '
                    f'border-radius: 6px; line-height: 1.5;">{pitch}</div>',
                    unsafe_allow_html=True,
                )

        # exposed services are loaded on demand (not fetched until requested)
        if st.button("View exposed surface", key=f"svc_{domain}"):
            st.session_state[f"show_svc_{domain}"] = True
        if st.session_state.get(f"show_svc_{domain}"):
            st.dataframe(load_services(domain), hide_index=True, width="stretch", height=240)

        st.info("**Contacts** — join this company (by domain) to Firmable's people "
                "data to surface the right decision-maker (CISO / IT head).")


# --- Detail slot: filled (above the table, same tab) when a company is opened -
detail_slot = st.container()

# --- Prospect list: click any row to open its detail (appears above) ---------
st.subheader(f"Prospects ({len(view)})")
st.caption("Click a row to open a company — its detail appears above.")

table = view[["domain", "segment", "country_name", "score", "cve_count", "reasons"]].reset_index(drop=True)
table["reasons"] = table["reasons"].apply(lambda r: "  •  ".join(list(r)))  # list -> readable cell

gb = GridOptionsBuilder.from_dataframe(table)
gb.configure_selection("single")  # click a row to select it (no checkbox)
gb.configure_column("domain", headerName="Domain")
gb.configure_column("segment", headerName="Segment")
gb.configure_column("country_name", headerName="Country")
gb.configure_column("score", headerName="Score")
gb.configure_column("cve_count", headerName="CVEs")
gb.configure_column("reasons", headerName="Top reasons", flex=2)
gb.configure_grid_options(rowHeight=40, headerHeight=44)

# bigger, more legible type + a slightly softer row shade
GRID_CSS = {
    ".ag-root-wrapper": {"border": "none"},
    ".ag-cell": {"font-size": "15px", "display": "flex", "align-items": "center"},
    ".ag-header-cell-text": {"font-size": "14px", "font-weight": "600"},
    ".ag-header-cell-label": {"justify-content": "center"},  # center header labels
    ".ag-row": {"background-color": "rgba(255,255,255,0.015)"},
    ".ag-row-hover": {"background-color": "rgba(255,255,255,0.06) !important"},
}
# fill more of the window: show up to ~15 rows, then the grid scrolls
grid_height = 44 + 40 * min(max(len(table), 1), 15)
grid = AgGrid(
    table, gridOptions=gb.build(),
    update_mode=GridUpdateMode.SELECTION_CHANGED,
    fit_columns_on_grid_load=True, theme="streamlit", custom_css=GRID_CSS,
    height=grid_height, key=f"grid_{st.session_state.get('grid_nonce', 0)}",
)

sel = grid["selected_rows"]
opened = None
if sel is not None and len(sel) > 0:
    opened = sel.iloc[0]["domain"] if isinstance(sel, pd.DataFrame) else sel[0]["domain"]
if opened:
    with detail_slot:
        render_detail(opened)
