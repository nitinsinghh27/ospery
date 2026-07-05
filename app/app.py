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
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode

# Prefer the small committed serving DB (used when hosted); fall back to the full
# local warehouse for development. Both expose the same gold.* + enrichment tables.
_SERVING = Path("data/serving/osprey_serving.duckdb")
_WAREHOUSE = Path("data/warehouse/osprey.duckdb")
DB_PATH = str(_SERVING if _SERVING.exists() else _WAREHOUSE)

SCORE_HELP = (
    "Lead score (higher = hotter). Weighted sum of exposure signals: "
    "active-compromise +40, actively-exploited (CISA KEV) +30, known CVEs +15 "
    "(plus up to +20 by count), database exposed +20, end-of-life software +15, "
    "self-signed cert +10, VPN/IoT +8 each, plus a small attack-surface bonus (up to +10)."
)
CONF_HELP = (
    "Confidence (0–100%) from the LLM that this domain is a real business (not a "
    "hosting/ISP provider). Predictions below 70% are flagged and excluded."
)
CVE_HELP = "Distinct known CVEs (public vulnerabilities) across the company's exposed services."

SIGNALS = {
    "Actively exploited (KEV)": "has_kev", "Known CVEs": "has_cve",
    "End-of-life software": "has_eol", "Database exposed": "has_db",
    "Self-signed cert": "has_selfsigned", "VPN exposed": "has_vpn",
    "IoT exposed": "has_iot", "Active compromise": "has_breach",
}
KEV_HELP = ("Companies with at least one CVE on CISA's Known Exploited Vulnerabilities "
            "catalog — actively exploited in the wild, not just theoretically vulnerable.")
EPSS_HELP = ("Peak EPSS (FIRST) across the company's CVEs — the highest modelled "
             "probability that one of its vulnerabilities is exploited within 30 days.")

st.set_page_config(page_title="Osprey — Sales Intelligence", layout="wide")


@st.cache_data(show_spinner="Loading prospects…")
def load_companies() -> pd.DataFrame:
    # gold_prospects is the single serving model: prospects + cached firmographics + pitch
    con = duckdb.connect(DB_PATH, read_only=True)
    df = con.sql("SELECT * FROM gold.gold_prospects ORDER BY score DESC, services DESC").df()
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


def _txt(v: object) -> str | None:
    """Scalar cell -> str or None (handles pandas NaN/None)."""
    return None if v is None or (isinstance(v, float) and pd.isna(v)) else str(v)


def _lst(v: object) -> list[str]:
    """List cell (tech_stack / emails) -> list[str] (handles None/NaN)."""
    if isinstance(v, str) or not hasattr(v, "__len__"):
        return []
    return [str(x) for x in cast("list[object]", v)]


# Turn a raw tech list into sales-relevant "notable exposure" — common web servers
# (nginx/Apache) tell a rep nothing; exposed cameras / NAS / remote-access do.
NOTABLE_TECH: list[tuple[tuple[str, ...], str]] = [
    (("hikvision", "dahua", "axis", "ip camera", "webcam", "nvr"), "Exposed IP cameras / IoT"),
    (("draytek", "mikrotik", "ubiquiti", "zyxel", "tp-link", "sonicwall", "fortigate",
      "fortinet", "cisco", "router"), "Network edge / firewall gear"),
    (("winrm", "rdp", "remote desktop", "vnc", "teamviewer", "anydesk"), "Exposed remote access"),
    (("synology", "qnap", "truenas", "nas"), "Internet-exposed NAS / storage"),
    (("mysql", "postgres", "mongodb", "redis", "elasticsearch", "mssql", "couchdb"),
     "Exposed database"),
    (("openvpn", "pptp", "ipsec", "wireguard", "fortivpn", "globalprotect"), "VPN endpoint"),
    (("exim", "postfix", "dovecot", "zimbra", "exchange", "smtp"), "Mail server exposed"),
]


def interpret_tech(tech: list[str]) -> list[str]:
    """Map a raw tech stack to sales-relevant exposure categories (deduped, ordered)."""
    low = " ".join(tech).lower()
    return [label for keywords, label in NOTABLE_TECH if any(k in low for k in keywords)]


companies = load_companies()

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

if "region" in view.columns:  # sales territory (ANZ/APAC/EMEA/Americas)
    regions = st.sidebar.multiselect("Region", sorted(view["region"].dropna().unique()))
    if regions:
        view = view.loc[view["region"].isin(regions)]

countries = st.sidebar.multiselect("Country", sorted(view["country_name"].dropna().unique()))
if countries:
    view = view.loc[view["country_name"].isin(countries)]

if st.sidebar.checkbox("Well-enriched only (has company profile)"):
    view = view.loc[view["org_name"].notna()]

present_signals = [label for label, col in SIGNALS.items()
                   if int(cast("pd.Series", view[col]).sum()) > 0]
chosen_signals = st.sidebar.multiselect("Must have signal", present_signals)
for label in chosen_signals:
    view = view.loc[view[SIGNALS[label]] == 1]

max_score = int(cast("pd.Series", view["score"]).max()) if len(view) else 0
min_score = st.sidebar.slider("Min score", 0, max(max_score, 1), 0)
view = view.loc[view["score"] >= min_score]

# --- KPIs --------------------------------------------------------------------
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Prospects", len(view))
c2.metric("Actively exploited (KEV)", int(view["has_kev"].sum()), help=KEV_HELP)
c3.metric("Actively compromised", int(view["has_breach"].sum()),
          help="Companies with signs of active compromise (malware / C2).")
c4.metric("Total CVEs", int(view["cve_count"].sum()), help=CVE_HELP)
c5.metric("Countries", view["country_name"].nunique())

if "region" in view.columns and len(view):
    with st.expander("Prospects by region (sales territory)"):
        st.bar_chart(view["region"].value_counts(), horizontal=True, height=200)

st.divider()


def score_breakdown(row: Any) -> list[tuple[str, int]]:
    """Recompute the score's component points (mirrors silver_company_candidates.sql)
    so a rep can see exactly why a score is what it is."""
    cve_count = int(row["cve_count"])
    kev_count = int(row["kev_count"])
    services = int(row["services"])
    parts = [
        ("Active compromise (malware / C2)", 40 if row["has_breach"] else 0),
        (f"Actively exploited — CISA KEV ({kev_count})", 30 if kev_count > 0 else 0),
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
    org_name, industry = _txt(row["org_name"]), _txt(row["industry"])
    tech, emails = _lst(row["tech_stack"]), _lst(row["contact_emails"])
    with st.container(border=True):
        top, close = st.columns([6, 1])
        top.subheader(domain)
        if org_name:
            top.caption(org_name)
        if close.button("Close"):
            st.session_state["grid_nonce"] = st.session_state.get("grid_nonce", 0) + 1  # remount grid → clear selection
            st.rerun()

        max_epss = float(row["max_epss"]) if pd.notna(row["max_epss"]) else 0.0
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Lead score", int(row["score"]), help=SCORE_HELP)
        m2.metric("Segment", str(row["segment"]))
        m3.metric("Country", str(row["country_name"]))
        m4.metric("Confidence", f'{row["classification_confidence"]:.0%}', help=CONF_HELP)
        m5.metric("Peak exploit prob.", f"{max_epss:.0%}", help=EPSS_HELP)

        with st.expander(f"Score breakdown ({int(row['score'])} points)"):
            breakdown = pd.DataFrame(score_breakdown(row), columns=["Signal", "Points"])
            st.dataframe(breakdown, hide_index=True, width="stretch")

        notable = interpret_tech(tech)
        if industry or notable or tech or emails:
            with st.expander("Firmographics (extracted from exposed services)"):
                if industry:
                    st.markdown(f"**Industry:** {industry}")
                if notable:
                    st.markdown("**Notable exposure:** " + " · ".join(notable))
                if tech:
                    st.markdown("**Technology footprint:** " + ", ".join(tech))
                if emails:
                    st.markdown("**Contact emails:** " + ", ".join(emails))

        with st.expander("Buying signals", expanded=True):
            for reason in row["reasons"]:
                st.markdown(f"- {reason}")

        pitch = _txt(row["pitch"])
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

cols = ["domain", "org_name", "segment", "country_name", "score", "kev_count",
        "cve_count", "reasons", "has_breach", "has_kev"]
table = view[cols].reset_index(drop=True)
table["company"] = table["org_name"].where(table["org_name"].notna(), table["domain"])
table["reasons"] = table["reasons"].apply(lambda r: "  •  ".join(list(r)))  # list -> readable cell
table = table[["company", "domain", "segment", "country_name", "score", "kev_count",
               "cve_count", "reasons", "org_name", "has_breach", "has_kev"]]

gb = GridOptionsBuilder.from_dataframe(table)
gb.configure_selection("single")  # click a row to select it (no checkbox)
gb.configure_column("company", headerName="Company", flex=1)
gb.configure_column("domain", headerName="Domain", flex=1)
gb.configure_column("segment", headerName="Segment")
gb.configure_column("country_name", headerName="Country")
gb.configure_column("score", headerName="Score")
gb.configure_column("kev_count", headerName="KEV")
gb.configure_column("cve_count", headerName="CVEs")
gb.configure_column("reasons", headerName="Top reasons", flex=2)
for hidden in ("org_name", "has_breach", "has_kev"):
    gb.configure_column(hidden, hide=True)
gb.configure_grid_options(rowHeight=40, headerHeight=44)
# interactivity: tint actively-compromised rows red, KEV-exposed rows amber
gb.configure_grid_options(getRowStyle=JsCode("""
    function(params) {
        if (params.data.has_breach == 1) return {'backgroundColor': 'rgba(220,60,60,0.16)'};
        if (params.data.has_kev == 1)    return {'backgroundColor': 'rgba(230,160,30,0.12)'};
        return null;
    }
"""))

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
    allow_unsafe_jscode=True,  # enables the row-tint JsCode
    height=grid_height, key=f"grid_{st.session_state.get('grid_nonce', 0)}",
)

sel = grid["selected_rows"]
opened = None
if sel is not None and len(sel) > 0:
    opened = sel.iloc[0]["domain"] if isinstance(sel, pd.DataFrame) else sel[0]["domain"]
if opened:
    with detail_slot:
        render_detail(opened)
