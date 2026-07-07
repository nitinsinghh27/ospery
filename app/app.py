"""Osprey — sales intelligence dashboard (Streamlit).

Reads the Gold marts (prospect list + per-company drill-down). Click a domain to
open its detail. The app never calls the LLM — it reads cached, materialized tables.

    uv run streamlit run app/app.py
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any, cast

import altair as alt
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
    "active-compromise +40, actively-exploited (CISA KEV) +30, known CVEs +15 "
    "(plus up to +20 by count), database exposed +20, end-of-life software +15, "
    "self-signed cert +10, VPN/IoT +8 each, plus a small attack-surface bonus (up to +10)."
)
CONF_HELP = (
    "Confidence (0–100%) from the LLM that this domain is a real business (not a "
    "hosting/ISP provider)."
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
SEGMENT_HELP = ("Segment (commercial / education / government / nonprofit / other) — "
                "assigned by the LLM entity classifier, with reserved TLDs (.edu/.gov) "
                "resolved deterministically by rule.")
COUNTRY_HELP = ("Country of the company's most-common exposed host (Shodan geo-IP), "
                "mapped to a full name via the ISO-3166 reference seed.")
AI_HELP = ("Companies exposing AI/ML tooling (Jupyter, Ollama, MLflow, vLLM, vector DBs, "
           "etc.) — detected deterministically from Shodan fingerprints/tags. A fresh, "
           "high-value trigger: an AI attack surface most vendors aren't yet targeting.")
TECH_HELP = ("Technology categories detected from Shodan's own fingerprints (product, "
             "http_server, cpe23) and tags — deterministic, no LLM. Use for technographic "
             "ICP targeting and competitive-displacement plays.")

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
    # `technologies` (per-service cpe fingerprint) is only present after a rebuild —
    # select it defensively so an older serving DB still works.
    has_tech = con.execute(
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_name = 'gold_company_services' AND column_name = 'technologies'"
    ).fetchone()
    tech_sel = ", technologies" if has_tech and has_tech[0] else ""
    df = con.execute(
        f"SELECT ip_str, port, transport, product, version{tech_sel}, http_server, isp, "
        "tags, vulns, country_code, scanned_at "
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


companies = load_companies()

st.title("Osprey — Sales Intelligence")
st.caption("Prospect cybersecurity buyers by their internet-facing exposure — who to target, and why.")
st.markdown(  # center the KPI metrics
    "<style>[data-testid='stMetric']{text-align:center;}"
    "[data-testid='stMetricValue']>div,[data-testid='stMetricLabel']>div"
    "{justify-content:center;}</style>",
    unsafe_allow_html=True,
)

# --- Filters: a horizontal bar of collapsible popovers on the main page (NOT a left
# sidebar, which would resize the results table). Each group opens on click and overlays,
# so the table keeps its full, stable width. A new extraction signal is just another
# popover — the bar scales without pushing anything down. Landscape counts track `book`.
st.markdown("##### Filters")
# Row 1 = inputs (toggle, company search, hosting dropdown — all free-text/select controls).
# Row 2 = facet popovers (grouped, multi-control filters). Two intentionally-distinct zones,
# each internally consistent — cleaner than forcing a lone dropdown to mimic a button.
_ftop = st.columns([2.0, 5.9, 2.1])  # toggle | spacer | search (shorter, right-aligned)
with _ftop[0]:
    business_only = st.toggle(
        "Business-Only Prospects", value=False,
        help="On = only LLM-verified businesses (hosting/ISP demoted — the 'see past the "
             "hosting layer' view). Off (default) = the full universe including "
             "infrastructure & hosting providers.")
book = (companies.loc[companies["entity_class"] == "business"]
        if business_only and "entity_class" in companies.columns else companies)
work = book
with _ftop[2]:
    search = st.text_input("Company search", placeholder="Company name or domain…",
                           label_visibility="collapsed")
    if search:
        hit = (work["domain"].str.contains(search, case=False, na=False)
               | work["org_name"].fillna("").str.contains(search, case=False))
        work = work.loc[hit]
fbar = st.columns(5)
with fbar[0]:
    with st.popover("Territory", use_container_width=True):
        n_countries = int(book["country_name"].nunique())
        if "region" in work.columns:
            st.caption(f"Region · {n_countries} countries")
            rc = book["region"].value_counts().reset_index()
            rc.columns = ["region", "count"]
            rtot = int(rc["count"].sum()) or 1
            rc["lab"] = (rc["count"].astype(str) + " ("
                         + (100 * rc["count"] / rtot).round().astype(int).astype(str) + "%)")
            pick = alt.selection_point(fields=["region"], name="region_pick", toggle="true")
            rbase = alt.Chart(rc).encode(
                y=alt.Y("region:N", title=None, sort="-x",
                        axis=alt.Axis(labelFontSize=11, labelOverlap=False)),
                x=alt.X("count:Q", title=None, axis=None,
                        scale=alt.Scale(domainMax=int(rc["count"].max()) * 1.6)))
            bars = rbase.mark_bar(cornerRadiusEnd=3, height=16).encode(
                color=alt.condition(pick, alt.value("#4c8bf5"), alt.value("#39404d")),
                tooltip=[alt.Tooltip("region:N", title="Region"),
                         alt.Tooltip("count:Q", title="Prospects")]).add_params(pick)
            rtxt = rbase.mark_text(align="left", dx=4, size=10, color="#cfcfcf").encode(text="lab:N")
            ev = cast("Any", st.altair_chart((bars + rtxt).properties(height=120),
                                             on_select="rerun", use_container_width=True, key="region_chart"))
            picked = [d["region"] for d in (ev.selection.get("region_pick", []) if ev else [])]
            if picked:
                work = work.loc[work["region"].isin(picked)]
        countries = st.multiselect("Country", sorted(work["country_name"].dropna().unique()))
        if countries:
            work = work.loc[work["country_name"].isin(countries)]
with fbar[1]:
    with st.popover("Hosting", use_container_width=True):
        if "hosting_providers" in book.columns:
            hcounts = Counter(h for hs in book["hosting_providers"] for h in _lst(hs))
            host_opts = {f"{h}  ·  {n}": h for h, n in hcounts.most_common()}
            picked_host = st.pills("Hosting provider", list(host_opts), selection_mode="multi",
                                   label_visibility="collapsed",
                                   help="Where the company is hosted (from the network owner — org/ISP).")
            for p in picked_host:
                hv = host_opts[p]
                work = work.loc[work["hosting_providers"].apply(lambda hs: hv in _lst(hs))]
with fbar[2]:
    with st.popover("Security", use_container_width=True):
        sig_opts = {f"{label}  ·  {int(cast('pd.Series', book[col]).sum())}": col
                    for label, col in SIGNALS.items()
                    if col in book.columns and int(cast("pd.Series", book[col]).sum()) > 0}
        picked_sig = st.pills("Security signals", list(sig_opts), selection_mode="multi",
                              label_visibility="collapsed")
        for p in picked_sig:
            work = work.loc[work[sig_opts[p]] == 1]
with fbar[3]:
    with st.popover("Technology", use_container_width=True):
        tech_q = st.text_input(
            "Technology / version search",
            placeholder="e.g. mongodb, openssh 7, python 2",
            help="Match a specific technology or version across the detected stack (product "
                 "names, versioned/legacy tech, exposed services & panels). Comma = OR.")
        if tech_q and {"tech_names", "versioned_tech", "legacy_tech"} <= set(work.columns):
            terms = [t.strip().lower() for t in tech_q.split(",") if t.strip()]

            def _tech_hit(r: Any) -> bool:
                blob = " ".join(_lst(r["tech_names"]) + _lst(r["versioned_tech"])
                                + _lst(r["legacy_tech"]) + _lst(r.get("exposed_services"))
                                + _lst(r.get("exposed_panels")) + _lst(r.get("server_products"))).lower()
                return any(term in blob for term in terms)

            work = work.loc[work.apply(_tech_hit, axis=1)]
        if "tech_categories" in book.columns:
            tcounts = Counter(c for cats in book["tech_categories"] for c in _lst(cats))
            tech_opts = {f"{cat}  ·  {n}": cat for cat, n in tcounts.most_common()}
            picked_tech = st.pills("Categories", list(tech_opts), selection_mode="multi", help=TECH_HELP)
            for p in picked_tech:
                cat = tech_opts[p]
                work = work.loc[work["tech_categories"].apply(lambda cats: cat in _lst(cats))]
with fbar[4]:
    with st.popover("Exposure", use_container_width=True):
        if "exposed_services" in book.columns:
            ecounts = Counter(s for svcs in book["exposed_services"] for s in _lst(svcs))
            exp_opts = {f"{svc}  ·  {n}": svc for svc, n in ecounts.most_common()}
            if exp_opts:
                st.caption("Internet-exposed services")
                picked_exp = st.pills("Internet-exposed services", list(exp_opts),
                                      selection_mode="multi", label_visibility="collapsed",
                                      help="Risky services reachable from the internet (RDP, SMB, "
                                           "Telnet, exposed databases, orchestration APIs…), from "
                                           "the port inventory.")
                for p in picked_exp:
                    svc = exp_opts[p]
                    work = work.loc[work["exposed_services"].apply(lambda ss: svc in _lst(ss))]
        if "exposed_panels" in book.columns:
            pcounts = Counter(p for ps in book["exposed_panels"] for p in _lst(ps))
            panel_opts = {f"{pn}  ·  {n}": pn for pn, n in pcounts.most_common()}
            if panel_opts:
                st.caption("Exposed admin panels")
                picked_panel = st.pills("Exposed admin panels", list(panel_opts),
                                        selection_mode="multi", label_visibility="collapsed",
                                        help="Internet-facing management/control panels (cPanel/WHM, "
                                             "Plesk, firewall & router logins, DevOps consoles…), "
                                             "named from the HTTP page title.")
                for p in picked_panel:
                    pn = panel_opts[p]
                    work = work.loc[work["exposed_panels"].apply(lambda ps: pn in _lst(ps))]

view = cast("pd.DataFrame", work)


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


def _surface_bar(df: Any, cat_col: str, height: int = 0) -> Any:
    """Horizontal bar chart with count + % (in brackets) at the bar end. Pass an explicit
    `height` to keep sibling charts (Products / Technologies) the same size."""
    total = int(df["count"].sum()) or 1
    df = df.assign(lab=df["count"].astype(str) + " ("
                   + (100 * df["count"] / total).round().astype(int).astype(str) + "%)")
    base = alt.Chart(df).encode(
        y=alt.Y(f"{cat_col}:N", title=None, sort="-x", axis=alt.Axis(labelLimit=150)),
        x=alt.X("count:Q", title=None, axis=None,
                scale=alt.Scale(domainMax=int(df["count"].max()) * 1.4)),
        tooltip=[alt.Tooltip(f"{cat_col}:N", title=cat_col.title()),
                 alt.Tooltip("count:Q", title="Services")])
    bar = base.mark_bar(cornerRadiusEnd=3, height=18, color="#4c8bf5")
    txt = base.mark_text(align="left", dx=6, size=12, color="#cfcfcf").encode(text="lab:N")
    return (bar + txt).properties(height=height or (36 * len(df) + 12))


# --- Deterministic sales narrative (the "Sales Prospect Intelligence" brief) ----------
# Transforms the cached security telemetry into a sales-ready brief with NO LLM: an
# executive summary, business-relevant themes, "why now" triggers, a grouped attack-surface
# view, ranked risk signals, and outreach talking points. Rules only — every line traces to
# a field on the row; nothing is invented (missing evidence → the section is simply omitted).
_DB_TOKENS = ("MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch", "MSSQL", "InfluxDB")
_SURFACE_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("Databases", _DB_TOKENS),
    ("Remote Access", ("RDP", "Telnet", "VNC")),
    ("File Sharing", ("SMB", "NetBIOS", "FTP")),
    ("Monitoring", ("Prometheus", "Grafana", "Kibana")),
    ("Container Platforms", ("Docker API", "Kubernetes API")),
    ("Identity Services", ("LDAP",)),
]
# theme -> (observation, business risk, conversation starter) for the talking points
_TALK: dict[str, tuple[str, str, str]] = {
    "Active Compromise": (
        "Indicators consistent with active compromise (malware / C2) were observed.",
        "Signs of an in-progress incident demand immediate investigation and response.",
        "\"Have you validated whether any of your internet-facing hosts show signs of compromise?\""),
    "Active Exploitation Risk": (
        "Internet-facing systems carry vulnerabilities that are actively exploited in the wild.",
        "Actively-exploited flaws are a leading breach vector; unpatched, they invite ransomware.",
        "\"How are you prioritising remediation for vulnerabilities already being exploited in the wild?\""),
    "Operational Technology Exposure": (
        "Industrial control / OT systems appear reachable from the internet.",
        "OT exposure carries safety and availability risk, plus heavy compliance scrutiny.",
        "\"How are you segmenting and monitoring your internet-facing OT assets?\""),
    "Internet-Exposed Data": (
        "One or more databases appear reachable from the public internet.",
        "Exposed data stores are a direct path to data theft and ransomware.",
        "\"What controls do you have around internet-reachable data stores today?\""),
    "Administrative Interface Exposure": (
        "Multiple administrative / control panels appear reachable from the internet.",
        "Admin portals are prime targets for credential-stuffing and unauthorised access.",
        "\"How are you managing exposure and monitoring of externally accessible admin portals?\""),
    "Remote Access Exposure": (
        "Internet-facing remote-access services were detected.",
        "Exposed RDP / VPN is a leading initial-access vector for intrusions.",
        "\"How are you securing and monitoring remote-access entry points?\""),
    "Legacy Infrastructure Risk": (
        "End-of-life software versions are running on public-facing systems.",
        "Unsupported software no longer gets security patches — known exploits stay open.",
        "\"What's your plan for the end-of-life systems still exposed to the internet?\""),
    "Cloud Security Risk": (
        "Public cloud-hosted assets are exposing services to the internet.",
        "Misconfigured cloud exposure is a common breach root cause.",
        "\"How are you continuously validating your cloud attack surface?\""),
}


def render_sales_narrative(row: Any) -> None:
    """Render the deterministic sales brief inside the detail card. Rules only, no LLM."""
    org, industry = _txt(row.get("org_name")), _txt(row.get("industry"))
    name = org or str(row["domain"])
    score, kev, cve = int(row.get("score") or 0), int(row.get("kev_count") or 0), int(row.get("cve_count") or 0)
    epss = float(row["max_epss"]) if pd.notna(row.get("max_epss")) else 0.0
    breach, db, ics = int(row.get("has_breach") or 0), int(row.get("has_db") or 0), int(row.get("has_ics") or 0)
    legacy_flag = int(row.get("has_legacy") or 0) or int(row.get("has_eol") or 0)
    selfsigned, rdp, telnet = int(row.get("has_selfsigned") or 0), int(row.get("has_rdp") or 0), int(row.get("has_telnet") or 0)
    smb, vpn, cloud = int(row.get("has_smb") or 0), int(row.get("has_vpn") or 0), int(row.get("has_cloud") or 0)
    panels, exposed = _lst(row.get("exposed_panels")), _lst(row.get("exposed_services"))
    legacy_tech, hosting = _lst(row.get("legacy_tech")), _lst(row.get("hosting_providers"))
    db_svcs = [s for s in exposed if s in _DB_TOKENS]
    remote_svcs = [s for s in exposed if s in ("RDP", "Telnet", "VNC")]

    # risk level + priority (deterministic; strongest signals escalate)
    if breach or (kev and (db or ics or panels)):
        level = "Critical"
    elif kev or ics or (db and legacy_flag) or score >= 110:
        level = "High"
    elif score >= 55 or db or legacy_flag or cve:
        level = "Medium"
    else:
        level = "Low"
    priority = {"Critical": "P1 — Immediate", "High": "P2 — High priority",
                "Medium": "P3 — Standard", "Low": "P4 — Nurture"}[level]
    color = {"Critical": "#e5484d", "High": "#f2994a", "Medium": "#4c8bf5", "Low": "#8a94a6"}[level]

    # business-relevant themes (name, why it matters, supporting evidence)
    themes: list[tuple[str, str, str]] = []
    if breach:
        themes.append(("Active Compromise", "Malware / C2 indicators suggest an in-progress incident.",
                       "Compromise indicators on exposed hosts"))
    if kev:
        themes.append(("Active Exploitation Risk",
                       "Vulnerabilities on CISA's Known-Exploited list are being used by attackers now.",
                       f"{kev} actively-exploited (KEV) CVE(s)" + (f"; peak EPSS {epss:.0%}" if epss else "")))
    if ics:
        themes.append(("Operational Technology Exposure",
                       "Internet-facing industrial control systems put safety-critical processes at risk.",
                       "ICS/OT protocols reachable from the internet"))
    if db or db_svcs:
        themes.append(("Internet-Exposed Data", "Databases reachable from the internet risk data theft and ransomware.",
                       "Exposed: " + ", ".join(db_svcs) if db_svcs else "A database service is internet-facing"))
    if panels:
        themes.append(("Administrative Interface Exposure", "Public admin / control panels are prime targets for credential attacks.",
                       "Panels: " + ", ".join(panels[:4])))
    if rdp or vpn or telnet or remote_svcs:
        ev = list(dict.fromkeys(remote_svcs + (["VPN"] if vpn else [])))
        themes.append(("Remote Access Exposure", "Internet-facing remote access is a leading initial-access vector.",
                       "Exposed: " + ", ".join(ev) if ev else "Remote access is internet-facing"))
    if legacy_flag:
        themes.append(("Legacy Infrastructure Risk", "End-of-life software no longer receives security patches.",
                       "Legacy: " + ", ".join(legacy_tech[:3]) if legacy_tech else "End-of-life software detected"))
    if cloud and exposed:
        themes.append(("Cloud Security Risk", "Public cloud assets exposing services is a common breach root cause.",
                       "Hosted on " + ", ".join(hosting[:3]) if hosting else "Cloud-hosted exposure"))
    themes = themes[:6]

    # Executive summary
    st.markdown(
        f"<span style='background:{color};color:#fff;padding:2px 10px;border-radius:10px;"
        f"font-weight:700;font-size:13px'>Risk: {level}</span>"
        f"&nbsp;&nbsp;&nbsp;**Priority Score:** {min(score, 100)}/100"
        f"&nbsp;&nbsp;&nbsp;**Outreach:** {priority}", unsafe_allow_html=True)
    summ = f"**{name}**" + (f" ({industry})" if industry else "")
    summ += f" presents **{level.lower()}** internet-exposure risk"
    if themes:
        summ += " driven by " + " and ".join(t[0].lower() for t in themes[:2])
    summ += f". Lead score {score}."
    if kev:
        summ += f" {kev} exposure(s) are actively exploited in the wild."
    st.markdown(summ)

    # Why They're a Fit — themes
    if themes:
        st.markdown("#### Why They're a Fit")
        for tname, why, ev in themes:
            st.markdown(f"- **{tname}** — {why}  \n  _Evidence: {ev}_")

    # Why Now — timing triggers
    triggers = []
    if breach:
        triggers.append("Indicators of active compromise (malware / C2) — warrants immediate investigation.")
    if kev:
        triggers.append(f"{kev} actively-exploited (CISA KEV) vulnerabilit{'y' if kev == 1 else 'ies'} — attackers are using these now.")
    if legacy_flag:
        triggers.append("End-of-life software still in production — no longer receiving security updates.")
    if ics:
        triggers.append("Industrial control systems exposed to the internet.")
    if panels:
        triggers.append("Administrative interfaces publicly accessible.")
    if db or db_svcs:
        triggers.append("Database services reachable from the internet.")
    if triggers:
        st.markdown("#### Why Now")
        for t in triggers[:5]:
            st.markdown(f"- {t}")

    # Attack Surface Overview — grouped, not itemised
    surface = [(cat, [s for s in exposed if s in toks]) for cat, toks in _SURFACE_CATEGORIES]
    surface = [(c, hits) for c, hits in surface if hits]
    if panels:
        surface.append(("Administrative Interfaces", panels))
    if surface:
        st.markdown("#### Attack Surface Overview")
        for cat, items in surface:
            st.markdown(f"- **{cat}** — {', '.join(items[:8])}")

    # Top Risk Signals — top 5 by business impact
    cand: list[tuple[int, str, str, str, str]] = []
    if breach:
        cand.append((100, "Active compromise", "Critical", "Malware / C2 indicators", "Possible active breach — data loss, ransomware, downtime"))
    if ics:
        cand.append((95, "OT / ICS exposed", "Critical", "Industrial control protocols internet-facing", "Safety & availability risk; regulatory exposure"))
    if kev:
        cand.append((90, f"{kev} actively-exploited (KEV) CVE(s)", "Critical", (f"CISA KEV; peak EPSS {epss:.0%}" if epss else "CISA KEV catalog"), "Exploited in the wild — high breach likelihood"))
    if db or db_svcs:
        cand.append((80, "Internet-exposed database", "High", "Exposed: " + (", ".join(db_svcs) or "database service"), "Direct path to data theft / ransomware"))
    if panels:
        cand.append((75, "Exposed admin panel", "High", "Panels: " + ", ".join(panels[:3]), "Credential attacks / unauthorised admin access"))
    if rdp:
        cand.append((70, "RDP exposed", "High", "Remote Desktop on the public internet", "Top ransomware initial-access vector"))
    if telnet:
        cand.append((65, "Telnet exposed", "High", "Unencrypted admin protocol internet-facing", "Cleartext credentials — trivial to intercept"))
    if legacy_flag:
        cand.append((60, "End-of-life software", "High" if legacy_tech else "Medium", "Legacy: " + (", ".join(legacy_tech[:3]) or "EOL-flagged"), "Unpatched, known-vulnerable stack"))
    if cve:
        cand.append((50, f"{cve} known CVE(s)", "Medium", f"{cve} distinct public vulnerabilities", "Expands the exploitable attack surface"))
    if smb:
        cand.append((45, "SMB / file-sharing exposed", "Medium", "SMB / NetBIOS internet-facing", "Lateral movement / ransomware spread"))
    if selfsigned:
        cand.append((30, "Weak / self-signed certificate", "Low", "Self-signed TLS certificate", "MITM risk; weak security hygiene"))
    cand.sort(key=lambda c: -c[0])
    if cand:
        st.markdown("#### Top Risk Signals")
        for _, risk, sev, ev, impact in cand[:5]:
            st.markdown(f"- **{risk}**  ·  _{sev}_  \n  Evidence: {ev}  \n  Business impact: {impact}")

    # Vulnerable software — the low-level, version-specific displacement hook
    # ("you run MySQL 8.0.12 which carries CVE-…"). Product@version + real CVEs, ranked.
    vuln_prod = _lst(row.get("vulnerable_products"))
    if vuln_prod:
        st.markdown("#### Vulnerable Software (version-specific)")
        for vp in vuln_prod[:6]:
            st.markdown(f"- {vp}")

    # Sales Talking Points — 3 outreach angles from the top themes
    talk = [_TALK[t[0]] for t in themes if t[0] in _TALK][:3]
    if talk:
        st.markdown("#### Sales Talking Points")
        for obs, risk, starter in talk:
            st.markdown(f"- **Observation:** {obs}  \n  **Business risk:** {risk}  \n  **Conversation starter:** {starter}")


def render_detail(domain: str) -> None:
    """Inline company detail, shown when a domain is clicked."""
    row = companies[companies["domain"] == domain].iloc[0]
    org_name, industry = _txt(row["org_name"]), _txt(row["industry"])
    tech, emails = _lst(row["tech_stack"]), _lst(row["contact_emails"])
    with st.container(border=True):
        top, close = st.columns([9, 1])
        top.subheader(domain)
        if org_name:
            top.caption(org_name)
        # push the Close button flush to the card's top-right corner
        st.markdown("<style>.st-key-close_btn{display:flex;justify-content:flex-end;}</style>",
                    unsafe_allow_html=True)
        if close.button("Close", key="close_btn"):
            st.session_state["grid_nonce"] = st.session_state.get("grid_nonce", 0) + 1  # remount grid → clear selection
            st.rerun()

        # tech profile (drives the surface bars + the sales brief). row.get() tolerates a
        # stale serving DB without the tech columns.
        tech_detected = _lst(row.get("tech_names")) or tech  # fall back to LLM tech_stack
        svc = load_services(domain)
        n_svc = len(svc)
        prod = cast("Any", svc["product"]).dropna().value_counts().reset_index()
        prod.columns = ["product", "count"]
        prod_fill = int(round(100 * cast("Any", svc["product"]).notna().mean())) if n_svc else 0
        max_epss = float(row["max_epss"]) if pd.notna(row["max_epss"]) else 0.0

        # 5 + 5 uniform tiles, ordered most-important -> least: rank + threat signals
        # first, then targeting context, then data-quality meta. Titles in Title Case.
        r1 = st.columns(5)
        r1[0].metric("Lead Score", int(row["score"]), help=SCORE_HELP, border=True)
        r1[1].metric("Actively-Exploited (KEV)", int(row["kev_count"]), help=KEV_HELP, border=True)
        r1[2].metric("Known CVEs", int(row["cve_count"]), help=CVE_HELP, border=True)
        r1[3].metric("Peak Exploit Prob.", f"{max_epss:.0%}", help=EPSS_HELP, border=True)
        r1[4].metric("Total Services", int(row["services"]), border=True)
        r2 = st.columns(5)
        r2[0].metric("Exposed IPs", int(row["hosts"]), border=True)
        r2[1].metric("Segment", str(row["segment"]), help=SEGMENT_HELP, border=True)
        r2[2].metric("Country", str(row["country_name"]), help=COUNTRY_HELP, border=True)
        r2[3].metric("Distinct Technologies", len(tech_detected), border=True)
        r2[4].metric("Confidence", f'{row["classification_confidence"]:.0%}', help=CONF_HELP, border=True)

        # score breakdown as a bar chart (in a card) — what actually drives the score
        bd = cast("Any", pd.DataFrame(score_breakdown(row), columns=["signal", "points"]))
        if len(bd):
            with st.container(border=True):
                st.markdown(f"**Score Breakdown** — {int(row['score'])} points")
                sb = alt.Chart(bd).encode(
                    y=alt.Y("signal:N", title=None, sort="-x",
                            axis=alt.Axis(labelFontSize=12, labelLimit=280)),
                    x=alt.X("points:Q", title=None, axis=None,
                            scale=alt.Scale(domainMax=int(bd["points"].max()) * 1.25)))
                sb_bar = sb.mark_bar(cornerRadiusEnd=3, height=17, color="#4c8bf5").encode(
                    tooltip=[alt.Tooltip("signal:N", title="Signal"),
                             alt.Tooltip("points:Q", title="Points")])
                sb_txt = sb.mark_text(align="left", dx=6, size=12, color="#cfcfcf").encode(text="points:Q")
                st.altair_chart((sb_bar + sb_txt).properties(height=len(bd) * 30 + 10),
                                use_container_width=True)

        # exposed surface as bars: Products + Technologies side by side. ALL entries are
        # shown (uniform bar width) inside equal fixed-height scrollable containers — so a
        # 50-tech company scrolls rather than truncating, and both panels stay the same size.
        # (Technologies from cpe fingerprints — fuller than product: jquery/php/etc.)
        top_tech = (Counter(t for names in svc["technologies"] for t in _lst(names)).most_common()
                    if "technologies" in svc.columns else [])
        tech_fill = (int(round(100 * svc["technologies"].apply(lambda t: len(_lst(t)) > 0).mean()))
                     if n_svc and "technologies" in svc.columns else 0)
        PANEL_H = 300  # equal display height for both; content taller than this scrolls
        g1, g2 = st.columns(2)
        with g1:
            st.markdown(f"**Products**  ({prod_fill}% of services)")
            with st.container(height=PANEL_H, border=True):
                if len(prod):
                    st.altair_chart(_surface_bar(prod, "product", 34 * len(prod) + 12),
                                    use_container_width=True)
                else:
                    st.caption("No product fingerprints on this surface.")
        with g2:
            st.markdown(f"**Technologies**  ({tech_fill}% of services)")
            with st.container(height=PANEL_H, border=True):
                if top_tech:
                    tdf = cast("Any", pd.DataFrame(top_tech, columns=["technology", "count"]))
                    st.altair_chart(_surface_bar(tdf, "technology", 34 * len(tdf) + 12),
                                    use_container_width=True)
                else:
                    st.caption("No technology fingerprints on this surface.")

        # deterministic sales brief (executive summary, themes, why-now, attack surface,
        # top risks, talking points) — the transformed "Company Profile & Signals".
        with st.expander("Sales Prospect Intelligence", expanded=True):
            render_sales_narrative(row)
            if emails:
                st.caption("Contact emails (regex): " + ", ".join(emails))

        pitch = _txt(row["pitch"])
        if pitch:
            with st.expander("Suggested Outreach Pitch", expanded=True):
                # the pitch is structured markdown (What we found / Why it matters /
                # Across their stack / Suggested opening) — render each part on its own line
                pitch_md = "\n\n".join(seg.strip() for seg in pitch.splitlines() if seg.strip())
                st.markdown("<style>.st-key-pitch_box{border-left:3px solid #5a9670;}</style>",
                            unsafe_allow_html=True)
                with st.container(border=True, key="pitch_box"):
                    st.markdown(pitch_md)

        # raw per-service table, always shown. Each row maps a service (ip:port) -> its
        # technologies, product, version, CVEs, tags, geo and scan date.
        st.markdown(f"**Exposed Surface**  ({n_svc} services)")
        disp = svc.copy()
        for col in ("technologies", "tags", "vulns"):
            if col in disp.columns:
                disp[col] = disp[col].apply(lambda t: ", ".join(_lst(t)))
        if "scanned_at" in disp.columns:
            disp["scanned_at"] = pd.to_datetime(disp["scanned_at"]).dt.strftime("%Y-%m-%d")
        disp = disp.rename(columns={
            "ip_str": "IP", "port": "Port", "transport": "Transport", "product": "Product",
            "version": "Version", "technologies": "Technologies", "http_server": "Server",
            "isp": "Network owner", "tags": "Tags", "vulns": "CVEs",
            "country_code": "Country", "scanned_at": "Scanned"})
        st.dataframe(disp, hide_index=True, width="stretch", height=320)

        st.info("**Contacts** — join this company (by domain) to Firmable's people "
                "data to surface the right decision-maker (CISO / IT head).")


# --- Detail slot: filled (above the table, same tab) when a company is opened -
detail_slot = st.container()

# --- Prospect list: click any row to open its detail (appears above) ---------
hd_l, hd_r = st.columns([3, 1])
hd_l.subheader(f"Prospects ({len(view)})")
hd_l.caption("Click a row to open a company. Filter with the facet bar above — then export "
             "the filtered set as a ready target list.")
# Displacement / target-list export: whatever the rep has filtered to (e.g. a specific
# competitor tech + version) downloads as a campaign-ready CSV — the sourcing deliverable.
_exp = cast("pd.DataFrame", view).copy()
for _c in ("vulnerable_products", "exposed_services", "exposed_panels", "server_products",
           "tech_categories", "hosting_providers", "reasons"):
    if _c in _exp.columns:
        _exp[_c] = _exp[_c].apply(lambda v: "; ".join(_lst(v)))
_exp_cols = [c for c in ["domain", "org_name", "segment", "country_name", "region", "score",
             "kev_count", "cve_count", "vulnerable_products", "exposed_services",
             "exposed_panels", "server_products", "tech_categories", "hosting_providers",
             "reasons"] if c in _exp.columns]
hd_r.download_button(
    "Download target list (CSV)",
    cast("pd.DataFrame", _exp[_exp_cols]).to_csv(index=False).encode("utf-8"),
    "osprey_target_list.csv", "text/csv", use_container_width=True,
    help="Export the currently-filtered prospects — company, product@version + CVEs, "
         "exposure and reasons — as a campaign-ready list for sales / CRM.")

cols = ["domain", "org_name", "segment", "country_name", "score", "services", "hosts",
        "kev_count", "cve_count",
        "has_breach", "has_db", "has_eol", "has_selfsigned", "has_vpn", "has_iot"]
table = cast("pd.DataFrame", view[cols]).reset_index(drop=True)
table["company"] = table["org_name"].where(table["org_name"].notna(), table["domain"])
# compact KEV / CVEs counts (full detail lives inside the company view)
table["kev_cves"] = (table["kev_count"].astype(int).astype(str) + " / "
                     + table["cve_count"].astype(int).astype(str))
# compact Security Signals list (short labels; KEV/CVEs shown separately as counts)
_CHIPS = [("has_breach", "Compromise"), ("has_db", "DB exposed"), ("has_eol", "EOL"),
          ("has_selfsigned", "Weak cert"), ("has_vpn", "VPN"), ("has_iot", "IoT")]
table["signals"] = table.apply(
    lambda r: "  ·  ".join(lbl for col, lbl in _CHIPS if r[col] == 1) or "—", axis=1)
# Technologies (deterministic categories) as a scannable list column
if "tech_categories" in view.columns:
    table["technologies"] = view["tech_categories"].reset_index(drop=True).apply(
        lambda c: "  ·  ".join(_lst(c)) if _lst(c) else "—")
else:
    table["technologies"] = "—"
# Hosting / infrastructure (technographic infra signal): show the normalised cloud/CDN
# when known, else the dominant network owner (ISP/AS) — so it's rarely blank.
if "hosting_providers" in view.columns:
    _prov = view["hosting_providers"].reset_index(drop=True)
    _net = (view["hosting_network"].reset_index(drop=True)
            if "hosting_network" in view.columns else pd.Series(["—"] * len(view)))
    table["hosting"] = [("  ·  ".join(_lst(p)) if _lst(p) else (_txt(n) or "—"))
                        for p, n in zip(_prov, _net)]
else:
    table["hosting"] = "—"
table = cast("pd.DataFrame", table[["company", "domain", "segment", "country_name", "score",
             "services", "hosts", "kev_cves", "signals", "technologies", "hosting", "org_name"]])

gb = GridOptionsBuilder.from_dataframe(table)
gb.configure_selection("single")  # click a row to select it (no checkbox)
gb.configure_column("company", headerName="Company", flex=1)
gb.configure_column("domain", hide=True)  # Company already falls back to the domain
gb.configure_column("segment", headerName="Segment")
gb.configure_column("country_name", headerName="Country")
gb.configure_column("score", headerName="Score")
gb.configure_column("services", headerName="Total Services")
gb.configure_column("hosts", headerName="Exposed IPs")
gb.configure_column("kev_cves", headerName="KEV / CVEs")
gb.configure_column("signals", headerName="Security Signals", flex=2, wrapText=True, autoHeight=True)
gb.configure_column("technologies", headerName="Technologies", flex=1, wrapText=True, autoHeight=True)
gb.configure_column("hosting", headerName="Hosting", flex=1, wrapText=True, autoHeight=True)
gb.configure_column("org_name", hide=True)
gb.configure_grid_options(headerHeight=44)

# header leads: a distinct band + bold, brighter text; content sits a notch dimmer
GRID_CSS = {
    ".ag-root-wrapper": {"border": "none"},
    ".ag-header": {"background-color": "rgba(76,139,245,0.16)",
                   "border-bottom": "2px solid rgba(76,139,245,0.55)"},
    ".ag-header-cell": {"border-right": "1px solid rgba(255,255,255,0.08)"},
    ".ag-header-cell-text": {"font-size": "15px", "font-weight": "700",
                             "color": "#eef2f8", "letter-spacing": "0.3px"},
    ".ag-header-cell-label": {"justify-content": "center"},  # center header labels
    ".ag-cell": {"font-size": "13.5px", "white-space": "normal !important",
                 "line-height": "1.4", "padding-top": "8px", "padding-bottom": "8px",
                 "text-align": "center", "color": "rgba(228,230,236,0.80)",
                 "border-right": "1px solid rgba(255,255,255,0.06)"},
    ".ag-row": {"background-color": "rgba(255,255,255,0.015)"},
    ".ag-row-hover": {"background-color": "rgba(76,139,245,0.28) !important"},
}
# rows auto-grow to fit wrapped Signals/Technologies lists, so budget more per row;
# show more rows before scrolling to fill the vertical space
grid_height = 44 + 78 * min(max(len(table), 1), 15)
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
