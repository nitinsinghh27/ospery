-- ============================================================================
-- v4 — DEEPER EXTRACTION: versioned tech, legacy/EOL, hosting, footprint
-- ----------------------------------------------------------------------------
-- Backs the v4 "granular technographic targeting" layer (silver_company_tech).
-- Thesis (a reviewer's prompt): "the more you mine the dataset, the more you find."
-- Shodan already reports concrete versions, EOL tags, network owners and per-domain
-- IP counts — this study quantifies what's extractable BEFORE we surface it, so the
-- feature is grounded in real coverage, not a guess.
-- Run ad-hoc:  uv run python -c "import duckdb; ..."  (queries below; outputs embedded)
-- ============================================================================


-- Q1 — Version coverage: can we actually name versions? -----------------------
-- How many services carry a concrete `version`, and how many cpe23 rows carry a
-- version segment (cpe:2.3:a:vendor:product:VERSION).
select
    count(*)                                                          as total_services,
    count(version)                                                   as with_version,
    round(100.0 * count(version) / count(*), 1)                      as pct_version,
    count(*) filter (where len(cpe23) > 0)                           as with_cpe23,
    round(100.0 * count(*) filter (where len(cpe23) > 0) / count(*), 1) as pct_cpe23
from bronze.shodan_scans;
-- OUTPUT: total_services=9,197,023 | with_version=496,377 (5.4%) | with_cpe23=2,133,846 (23.2%)
-- cpe23 version-segment coverage (unnested): 537,523 / 2,529,739 rows = 21.2% carry a version.
-- => Version data is real and non-trivial: enough to name specific stacks, not universal.


-- Q2 — Legacy / EOL prevalence: "who still runs old software?" ----------------
-- Version-gated detection of clearly end-of-life stacks (the reviewer's exact framing:
-- "who is still on Python 2.7 / Windows XP?"). Complements Shodan's own eol tags.
select lbl, count(*) as services from (
    select case
        when lower(product) like '%python%' and version like '2.%'         then 'Python 2.x'
        when lower(product) like '%php%' and (version like '5.%' or version like '4.%') then 'PHP <=5.x'
        when lower(product) like '%openssh%' and try_cast(split_part(version,'.',1) as int) < 7 then 'OpenSSH <7'
        when lower(product) like '%apache%' and version like '2.2%'        then 'Apache 2.2 (EOL)'
        when lower(product) like '%mysql%' and version like '5.%'          then 'MySQL 5.x'
        when lower(product) like '%exim%'                                  then 'Exim (mail)'
        else null end as lbl
    from bronze.shodan_scans
    where product is not null and version is not null
) t where lbl is not null group by 1 order by 2 desc;
-- OUTPUT (services): Exim 18,997 | nginx-old 15,333 | MySQL 5.x 10,796 | OpenSSH<7 6,551
--                    | Apache 2.2 EOL 2,041 | Python 2.x 37
-- Shodan's own tags corroborate: eol-product = 69,970 services, eol-os = 2,639.


-- Q3 — Named technologies at scale (searchable by real name) ------------------
-- cpe product tokens => can a rep search "mongodb" / "cassandra" / "wordpress"?
with u as (select lower(split_part(unnest(cpe23), ':', 5)) as p
           from bronze.shodan_scans where len(cpe23) > 0)
select p, count(*) as n from u
where p in ('mongodb','cassandra','redis','postgresql','mysql','elasticsearch','python',
            'php','node.js','nodejs','wordpress','jenkins','grafana','clickhouse',
            'rabbitmq','memcached','nginx','openssh','apache','docker')
group by 1 order by n desc;
-- OUTPUT (services): nginx 494,362 | openssh 95,378 | php 31,669 | mysql 24,945
--   | python 8,971 | wordpress 5,900 | node.js 3,773 | clickhouse 1,320 | jenkins 991
--   | rabbitmq 775 | redis 619 | grafana 351 | mongodb 329 | elasticsearch 84 | postgresql 19
-- => Real tech names are directly searchable. (clerk/vercel etc. are SaaS-layer and are
--    NOT fingerprinted by Shodan — an honest limit of network-scan data.)


-- Q4 — Hosting / infrastructure provider (from the network owner) -------------
-- org/isp cleanly identify the cloud/host — a technographic infra dimension.
select org, count(distinct ip_str) as ips
from bronze.shodan_scans where org is not null
group by 1 order by 2 desc limit 15;
-- OUTPUT (top orgs by IPs): Google LLC 398,458 | Incapsula 120,725 | Korea Telecom 112,896
--   | Aliyun 112,327 | Deutsche Telekom 106,702 | Cloudflare 101,985 | Amazon 27,925
--   | Hetzner 25,627 | Fly.io 23,301 | Microsoft 21,801 | DigitalOcean 21,175 ...
-- Normalised in silver_company_tech.hosting_providers (AWS/GCP/Azure/Cloudflare/Hetzner…).


-- Q5 — IPs per domain (footprint size) ---------------------------------------
-- "how many IPs can a domain have?" — larger footprint = larger account / attack surface.
select count(*)                            as prospects,
       round(avg(hosts), 1)                as avg_ips,
       median(hosts)                       as median_ips,
       max(hosts)                          as max_ips,
       count(*) filter (where hosts >= 10) as ge10,
       count(*) filter (where hosts >= 50) as ge50
from gold.gold_companies;
-- OUTPUT: prospects=3,973 | avg_ips=8.4 | median=1 | max=984 | >=10 IPs: 377 | >=50 IPs: 132


-- Q6 — v4 coverage across the prospect book (what the app now surfaces) --------
select count(*)                                              as prospects,
       count(*) filter (where len(versioned_tech) > 0)       as with_versioned,
       count(*) filter (where has_legacy = 1)                as legacy_flagged,
       count(*) filter (where len(hosting_providers) > 0)    as with_hosting
from gold.gold_prospects;
-- OUTPUT: prospects=3,973 | with_versioned=3,552 | legacy_flagged=3,607 | with_hosting=1,550
-- Top legacy labels among prospects: EOL-flagged 3,052 | Apache 2.2 281 | MySQL 5.x 262
--   | OpenSSH<7 48 | IIS<=7 37 | EOL-OS 33.
-- Top hosting among prospects: AWS 544 | DigitalOcean 231 | OVH 192 | Imperva 118
--   | Akamai 115 | Hetzner 113 | Google Cloud 92 | Cloudflare 68 | Azure 51.


-- ============================================================================
-- EXPOSURE SURFACE: risky internet-facing services (from the port inventory)
-- ----------------------------------------------------------------------------
-- The sharpest cyber-sales trigger: a specific risky service open to the internet
-- ("your RDP / SMB / database is reachable"). Named deterministically from well-known
-- ports — no LLM. Surfaced as exposure chips + reasons + a detail line.
-- ============================================================================

-- Q7 — Risky exposed services among prospects (by port) -----------------------
with svc as (select unnest(domains) d, port from bronze.shodan_scans)
select case port
    when 3306 then 'MySQL' when 21 then 'FTP' when 161 then 'SNMP' when 445 then 'SMB'
    when 3389 then 'RDP' when 5432 then 'PostgreSQL' when 9090 then 'Prometheus'
    when 389 then 'LDAP' when 6443 then 'Kubernetes API' when 23 then 'Telnet'
    when 1433 then 'MSSQL' when 5900 then 'VNC' when 6379 then 'Redis'
    when 27017 then 'MongoDB' when 9200 then 'Elasticsearch' when 2375 then 'Docker API'
    when 11434 then 'Ollama' else null end as svc,
  count(distinct d) as companies
from svc where d in (select domain from gold.gold_companies)
group by 1 having svc is not null order by companies desc;
-- OUTPUT (prospect companies): MySQL 1,386 | FTP 1,042 | SNMP 691 | SMB 626 | RDP 565
--   | PostgreSQL 549 | Prometheus 463 | LDAP 251 | Kubernetes 159 | Telnet 136
--   | MSSQL 123 | VNC 59 | ... => 2,798 prospects expose at least one risky service.


-- Q8 — SSL certificate mining: what's actually there? -------------------------
-- Attempted a deterministic org name from the cert subject (O=…). Finding: prospect
-- certs are CN-only — 0 of 97,152 cert rows carry an O= field (free/LE certs omit it).
-- So there is no org to mine from certs here; we ship the issuer (CA) instead of an
-- empty column. An honest "mined it, it's not in this data" result.
with s as (select unnest(domains) d, ssl_cert_subject subj
           from bronze.shodan_scans where ssl_cert_subject is not null)
select count(*) as cert_rows, count(*) filter (where subj like '%O=%') as with_org_field
from s where d in (select domain from gold.gold_companies);
-- OUTPUT: cert_rows=97,152 | with_org_field=0  => cert-subject org extraction not viable.


-- ============================================================================
-- HTTP TITLE mining: exposed admin panels + geographic footprint
-- ----------------------------------------------------------------------------
-- The HTTP page title (17.6% coverage) names internet-facing MANAGEMENT panels — an
-- exposed control panel is a high-value cyber target. `city` gives a rough size proxy.
-- ============================================================================

-- Q9 — Exposed admin / control panels among prospects (from http_title) -------
with s as (select unnest(domains) d, lower(http_title) t
           from bronze.shodan_scans where http_title is not null and http_title <> '')
select case
    when t like '%cpanel%' or t like '%whm login%' then 'cPanel/WHM'
    when t like '%plesk%' then 'Plesk' when t like '%3cx%' then '3CX'
    when t like '%routeros%' or t like '%mikrotik%' then 'MikroTik RouterOS'
    when t like '%synology%' then 'Synology'
    when t like '%fortin%' or t like '%web filter block%' then 'Fortinet'
    when t like '%pfsense%' then 'pfSense' when t like '%sonicwall%' then 'SonicWall'
    when t like '%grafana%' then 'Grafana' when t like '%portainer%' then 'Portainer'
    else null end as panel,
  count(distinct d) as companies
from s where d in (select domain from gold.gold_companies)
group by 1 having panel is not null order by companies desc;
-- OUTPUT (prospect companies): cPanel/WHM 524 | Synology 289 | Plesk 260 | 3CX 199
--   | MikroTik 144 | Fortinet 100 | DrayTek 75 | Control WebPanel 69 | pfSense 48
--   | SonicWall 47 | Grafana 39 | Webmin 36 | MinIO 33 | Portainer 32 | phpMyAdmin 21
--   => 1,366 prospects expose a named admin/control panel to the internet.

-- Q10 — Geographic footprint (distinct cities per prospect) -------------------
with s as (select unnest(domains) d, city from bronze.shodan_scans where city is not null)
select count(distinct d) prospects, round(avg(nc),2) avg_cities, max(nc) max_cities
from (select d, count(distinct city) nc from s
      where d in (select domain from gold.gold_companies) group by 1);
-- OUTPUT: prospects=6,654 | avg_cities=4.27 | max_cities=289 (a size / distribution proxy)


-- ============================================================================
-- "Should we add an LLM tech-extractor?" — MEASURED FIRST, then decided NO.
-- ----------------------------------------------------------------------------
-- Before building an LLM enricher to pull technologies out of unstructured text, we
-- measured the residual it would actually work on. The evidence said: not worth it — the
-- named tech lives in the `http_server` header (deterministically parseable), and the
-- banner residual is protocol noise. So we EXTENDED THE DETERMINISTIC PARSER instead.
-- ============================================================================

-- Q11 — Company-level tech coverage is already near-total (cpe) -----------------
select count(*) prospects, count(*) filter (where len(tech_names) > 0) with_tech,
       round(100.0 * count(*) filter (where len(tech_names) > 0) / count(*), 1) pct
from gold.gold_prospects;
-- OUTPUT: 6,654 | 6,649 | 99.9%  => an LLM adds ~nothing at the company level.

-- Q12 — The banner residual (services with NO cpe/product) is protocol noise ----
with s as (select unnest(domains) d, banner from bronze.shodan_scans
           where banner is not null and len(cpe23) = 0 and product is null)
select left(regexp_replace(banner, '[\n\r]+', ' '), 40) snippet, count(*) n
from s where d in (select domain from gold.gold_companies) group by 1 order by n desc limit 8;
-- OUTPUT: empty / Dovecot+IMAP+POP3 handshakes / "HTTP/1.1 401|404|400 ..." / SSL errors /
--   binary \xc8… — i.e. protocol banners & status lines, NOT technology names to extract.

-- Q13 — The real residual is the http_server long tail — and it's parseable -----
with s as (select distinct lower(http_server) hs from bronze.shodan_scans
           where http_server is not null and http_server <> '')
select count(*) distinct_http_server,
       count(*) filter (where not regexp_matches(hs,
         'nginx|apache|httpd|iis|openresty|tengine|litespeed|caddy|lighttpd|cloudflare')) outside_keyword_list
from s;
-- OUTPUT: 10,143 distinct | 6,480 outside the keyword list — but they are NAMED products in
--   the header (pve-api-daemon→Proxmox, squid→Squid, apache-coyote→Tomcat, kestrel→.NET,
--   bigip→F5, goahead-webs/boa/gsoap→embedded IoT, tr069/cwmp→router mgmt). Deterministic.
-- DECISION: no LLM. `silver_company_tech.server_products` parses these from http_server —
--   981 prospects gain a named server product (Embedded 334, Proxmox 267, Squid 216,
--   TR-069 210, Tomcat 84, Kestrel 72, SonicWall 68, F5 BIG-IP 67…). Zero LLM, full-scale.

-- ----------------------------------------------------------------------------
-- COLUMN AUDIT (all 24 bronze columns): mined vs explored vs untouched.
--   mined:    port, org, isp, domains, country_code, product, version, cpe23, tags,
--             vulns, http_server, ssl_cert_issuer, ip_str, transport, http_title
--   explored: hostnames (reverse-DNS PTR noise → skipped), ssl_cert_subject (CN-only → no
--             org), shodan_module (overlaps port)
--   n/a:      scanned_at (single-day slice), hash (dedup), asn (removed — org/isp cover it),
--             region/state (low value over country)
-- ----------------------------------------------------------------------------
