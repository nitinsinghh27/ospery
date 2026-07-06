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
        f"SELECT ip_str, port, transport, product, version{tech_sel}, tags, vulns "
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
# (keywords, label, one-line sales angle) — turns raw tech into what a rep can act on.
NOTABLE_TECH: list[tuple[tuple[str, ...], str, str]] = [
    (("hikvision", "dahua", "axis", "ip camera", "webcam", "nvr", "surveillance"),
     "Exposed IP cameras / IoT", "consumer-grade IoT, weak perimeter — likely SMB"),
    (("draytek", "mikrotik", "ubiquiti", "zyxel", "tp-link", "netgear", "router"),
     "SMB network gear", "consumer/SMB edge hardware — under-managed network"),
    (("sonicwall", "fortigate", "fortinet", "palo alto", "pfsense", "sophos", "watchguard"),
     "Firewall / security appliance", "already has a security appliance — displacement play"),
    (("winrm", "rdp", "remote desktop", "vnc", "teamviewer", "anydesk", "ssh"),
     "Exposed remote access", "internet-facing admin access — lateral-movement risk"),
    (("synology", "qnap", "truenas", "nas", "freenas"),
     "Internet-exposed NAS / storage", "data-at-rest exposed to the internet"),
    (("mysql", "postgres", "mongodb", "redis", "elasticsearch", "mssql", "couchdb", "mariadb"),
     "Exposed database", "customer/business data reachable from the internet"),
    (("openvpn", "pptp", "ipsec", "wireguard", "fortivpn", "globalprotect", "anyconnect"),
     "VPN endpoint", "remote-workforce entry point — high-value target"),
    (("exim", "postfix", "dovecot", "zimbra", "exchange", "smtp", "roundcube"),
     "Mail server exposed", "self-hosted email — phishing / BEC surface"),
    (("wordpress", "joomla", "drupal", "magento", "php"),
     "Legacy web CMS/stack", "plugin-heavy CMS — frequent, easily-exploited CVEs"),
    (("scada", "modbus", "niagara", "bacnet", "plc", "hmi"),
     "Exposed OT / industrial control", "critical infrastructure exposure — high stakes"),
]


def interpret_tech(tech: list[str]) -> list[tuple[str, str]]:
    """Map a raw tech stack to (category, sales angle) pairs (deduped, ordered)."""
    low = " ".join(tech).lower()
    return [(label, angle) for keywords, label, angle in NOTABLE_TECH
            if any(k in low for k in keywords)]


# Deterministic tech CATEGORIES -> the sales angle they imply (why the company is a
# fit). High-signal categories only; the "stack context" ones (web server, CDN, cloud,
# app framework) are common and carry no urgency — shown as footprint, not as an angle.
CATEGORY_ANGLES: dict[str, str] = {
    "AI/ML tooling": "exposed AI attack surface — net-new, few vendors target it yet",
    "ICS / OT": "critical-infrastructure exposure — high-stakes, compliance-driven buyer",
    "Database": "business / customer data reachable from the internet",
    "Remote access": "internet-facing admin access — lateral-movement risk",
    "VPN": "remote-workforce entry point — high-value target",
    "Mail server": "self-hosted email — phishing / BEC surface",
    "DevOps / observability": "exposed internal tooling — secrets / ops-maturity risk",
    "CMS": "plugin-heavy CMS — frequent, easily-exploited CVEs",
}
_CAT_ORDER = list(CATEGORY_ANGLES.keys())
# security-vendor product tokens (from cpe fingerprints) -> a competitive-displacement
# play, the single highest-value technographic signal (most B2B security buys are
# replacements — so "already runs a competitor" is a direct reason to call).
SECURITY_APPLIANCE_TOKENS = (
    "fortiweb", "fortios", "fortigate", "fortinet", "fortiproxy", "sonicwall", "pan-os",
    "paloalto", "sophos", "watchguard", "checkpoint", "check_point", "barracuda",
    "pfsense", "netscaler", "citrix", "cisco_asa",
)


# device-level labels from NOTABLE_TECH that the tech CATEGORIES don't already cover
# (the rest — remote access, database, VPN, mail, firewall, OT, CMS — are categories
# or the displacement play, so we skip them here to avoid duplicate angles).
_DEVICE_ONLY = {"Exposed IP cameras / IoT", "SMB network gear",
                "Internet-exposed NAS / storage"}


def fit_angles(tech_cats: list[str], tech_detected: list[str]) -> list[tuple[str, str]]:
    """Build a single ranked list of 'why they're a fit' sales angles from the
    deterministic tech profile: competitive displacement first, then high-signal
    category angles, then a few device-level specifics (IP cameras / NAS)."""
    out: list[tuple[str, str]] = []
    low = [t.lower() for t in tech_detected]
    hits = sorted({t for t in low if any(k in t for k in SECURITY_APPLIANCE_TOKENS)})
    if hits:
        out.append(("Runs a security appliance",
                    f"already uses {', '.join(hits[:3])} — competitive-displacement play "
                    "(most security purchases are replacements)"))
    for cat in _CAT_ORDER:
        if cat in tech_cats:
            out.append((cat, CATEGORY_ANGLES[cat]))
    for label, angle in interpret_tech(tech_detected):
        if label in _DEVICE_ONLY:
            out.append((label, angle))
    return out


companies = load_companies()

st.title("Osprey — Sales Intelligence")
st.caption("Prospect cybersecurity buyers by their internet-facing exposure — who to target, and why.")
st.markdown(  # center the KPI metrics
    "<style>[data-testid='stMetric']{text-align:center;}"
    "[data-testid='stMetricValue']>div,[data-testid='stMetricLabel']>div"
    "{justify-content:center;}</style>",
    unsafe_allow_html=True,
)

# --- Filters: region distribution (left) + dropdowns side by side (right) ----------
st.markdown("##### Filter Prospects")
work = companies
n_countries = int(companies["country_name"].nunique())

fc = st.columns([1.9, 1.2, 1.2, 1.4])
with fc[0]:
    st.markdown(f"**Countries ({n_countries})**")
    # Region: a clickable distribution (sales territory) — the top of the cascade
    if "region" in work.columns:
        rc = companies["region"].value_counts().reset_index()
        rc.columns = ["region", "count"]
        rtot = int(rc["count"].sum()) or 1
        rc["lab"] = (rc["count"].astype(str) + " ("
                     + (100 * rc["count"] / rtot).round().astype(int).astype(str) + "%)")
        pick = alt.selection_point(fields=["region"], name="region_pick", toggle="true")
        rbase = alt.Chart(rc).encode(
            y=alt.Y("region:N", title=None, sort="-x",
                    axis=alt.Axis(labelFontSize=12, labelOverlap=False)),
            x=alt.X("count:Q", title=None, axis=None,
                    scale=alt.Scale(domainMax=int(rc["count"].max()) * 1.45)))
        bars = rbase.mark_bar(cornerRadiusEnd=4, height=18).encode(
            color=alt.condition(pick, alt.value("#4c8bf5"), alt.value("#39404d")),
            tooltip=[alt.Tooltip("region:N", title="Region"),
                     alt.Tooltip("count:Q", title="Prospects")]).add_params(pick)
        rtxt = rbase.mark_text(align="left", dx=6, size=11, color="#cfcfcf").encode(text="lab:N")
        ev = cast("Any", st.altair_chart((bars + rtxt).properties(height=96),
                                         on_select="rerun", use_container_width=True, key="region_chart"))
        picked = [d["region"] for d in (ev.selection.get("region_pick", []) if ev else [])]
        if picked:
            work = work.loc[work["region"].isin(picked)]
with fc[1]:
    segments = st.multiselect("Segment", sorted(work["segment"].unique()))
    if segments:
        work = work.loc[work["segment"].isin(segments)]
with fc[2]:
    countries = st.multiselect("Country", sorted(work["country_name"].dropna().unique()))
    if countries:
        work = work.loc[work["country_name"].isin(countries)]
with fc[3]:
    search = st.text_input("Company")
    if search:
        hit = (work["domain"].str.contains(search, case=False, na=False)
               | work["org_name"].fillna("").str.contains(search, case=False))
        work = work.loc[hit]

# Security SIGNALS as clickable chips (count over the whole book so labels stay stable
# across reruns). Click to filter — the chip landscape *is* the filter.
sig_opts = {f"{label}  ·  {int(cast('pd.Series', companies[col]).sum())}": col
            for label, col in SIGNALS.items()
            if col in companies.columns and int(cast("pd.Series", companies[col]).sum()) > 0}
picked_sig = st.pills("Security signals — click to filter", list(sig_opts),
                      selection_mode="multi")
for p in picked_sig:
    work = work.loc[work[sig_opts[p]] == 1]

# TECHNOGRAPHIC categories as clickable chips (deterministic tech profile).
if "tech_categories" in companies.columns:
    tcounts = Counter(c for cats in companies["tech_categories"] for c in _lst(cats))
    tech_opts = {f"{cat}  ·  {n}": cat for cat, n in tcounts.most_common()}
    picked_tech = st.pills("Technology — click to filter", list(tech_opts),
                           selection_mode="multi", help=TECH_HELP)
    for p in picked_tech:
        cat = tech_opts[p]
        work = work.loc[work["tech_categories"].apply(lambda cats: cat in _lst(cats))]

if st.toggle("Well-enriched only (has extracted company profile)", value=False):
    work = work.loc[work["org_name"].notna()]

view = cast("pd.DataFrame", work)

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


def _surface_donut(df: Any, cat_col: str) -> Any:
    """Donut with % labels on the slices + colour legend below (clean for a few slices)."""
    total = int(df["count"].sum()) or 1
    df = df.assign(pct=(100 * df["count"] / total).round().astype(int).astype(str) + "%")
    base = alt.Chart(df).encode(
        theta=alt.Theta("count:Q", stack=True),
        color=alt.Color(f"{cat_col}:N", title=None, legend=alt.Legend(orient="bottom")),
        tooltip=[alt.Tooltip(f"{cat_col}:N", title=cat_col.title()),
                 alt.Tooltip("count:Q", title="Services")])
    arc = base.mark_arc(innerRadius=48, stroke="#0e1117", strokeWidth=1)
    txt = base.mark_text(radius=92, size=13, color="#e8e8e8").encode(text="pct:N")
    return (arc + txt).properties(height=240)


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

        # tech profile (drives the surface tiles + fit angles). row.get() tolerates a
        # stale serving DB without the v3 tech columns.
        tech_cats = _lst(row.get("tech_categories"))
        tech_detected = _lst(row.get("tech_names")) or tech  # fall back to LLM tech_stack
        angles = fit_angles(tech_cats, tech_detected)
        svc = load_services(domain)
        n_svc = len(svc)
        prod = cast("Any", svc["product"]).dropna().value_counts().head(6).reset_index()
        prod.columns = ["product", "count"]
        prod_fill = int(round(100 * cast("Any", svc["product"]).notna().mean())) if n_svc else 0
        tr = svc["transport"].value_counts().reset_index()
        tr.columns = ["transport", "count"]
        tr_fill = int(round(100 * cast("Any", svc["transport"]).notna().mean())) if n_svc else 0
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

        # exposed surface as donuts: Products + Technologies side by side, Transport below.
        # (Technologies from cpe fingerprints — fuller than product: jquery/php/etc.)
        top_tech = (Counter(t for names in svc["technologies"] for t in _lst(names)).most_common(7)
                    if "technologies" in svc.columns else [])
        tech_fill = (int(round(100 * svc["technologies"].apply(lambda t: len(_lst(t)) > 0).mean()))
                     if n_svc and "technologies" in svc.columns else 0)
        # Products + Technologies as bars (side by side, SAME height); Transport as a
        # donut below, kept to the same (half) width as Products.
        bar_h = 36 * max(len(prod), len(top_tech), 1) + 12
        g1, g2 = st.columns(2)
        with g1.container(border=True):
            st.markdown(f"**Products**  ({prod_fill}% of services)")
            if len(prod):
                st.altair_chart(_surface_bar(prod, "product", bar_h), use_container_width=True)
            else:
                st.caption("No product fingerprints on this surface.")
        with g2.container(border=True):
            st.markdown(f"**Technologies**  ({tech_fill}% of services)")
            if top_tech:
                tdf = cast("Any", pd.DataFrame(top_tech, columns=["technology", "count"]))
                st.altair_chart(_surface_bar(tdf, "technology", bar_h), use_container_width=True)
            else:
                st.caption("No technology fingerprints on this surface.")
        t1, _t2 = st.columns(2)
        with t1.container(border=True):
            st.markdown(f"**Transport**  ({tr_fill}% of services)")
            if len(tr):
                st.altair_chart(_surface_donut(tr, "transport"), use_container_width=True)

        with st.expander("Company Profile & Signals", expanded=True):
            bits = [f"**{org_name}**" if org_name else None,
                    f"industry: {industry}" if industry else None]
            head = "  ·  ".join(b for b in bits if b)
            if head:
                st.markdown(head)

            if angles:
                st.markdown("**Why They're a Fit**")
                for label, angle in angles:
                    st.markdown(f"- **{label}** — {angle}")

            st.markdown("**Targeting Signals**")
            for reason in row["reasons"]:
                st.markdown(f"- {reason}")

            if tech_detected:
                st.caption("Technology footprint: " + ", ".join(tech_detected[:25]))
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

        # raw per-service table on demand (the summary donuts are shown up top).
        # Each row maps a service (ip:port) -> its technologies, product and CVEs.
        if st.button("View Exposed Surface", key=f"svc_{domain}"):
            st.session_state[f"show_svc_{domain}"] = True
        if st.session_state.get(f"show_svc_{domain}"):
            disp = svc.copy()
            if "technologies" in disp.columns:
                disp["technologies"] = disp["technologies"].apply(lambda t: ", ".join(_lst(t)))
            st.dataframe(disp, hide_index=True, width="stretch", height=260)

        st.info("**Contacts** — join this company (by domain) to Firmable's people "
                "data to surface the right decision-maker (CISO / IT head).")


# --- Detail slot: filled (above the table, same tab) when a company is opened -
detail_slot = st.container()

# --- Prospect list: click any row to open its detail (appears above) ---------
st.subheader(f"Prospects ({len(view)})")
st.caption("Click a row to open a company. Filter with the region bars / Security "
           "signals / Technology chips above.")

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
table = cast("pd.DataFrame", table[["company", "domain", "segment", "country_name", "score",
             "services", "hosts", "kev_cves", "signals", "technologies", "org_name"]])

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
# rows auto-grow to fit wrapped Signals/Technologies lists, so budget more per row
grid_height = 44 + 60 * min(max(len(table), 1), 10)
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
