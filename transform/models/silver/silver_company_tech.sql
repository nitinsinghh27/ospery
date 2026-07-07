-- Per-company (domain) TECHNOLOGY PROFILE — deterministic, NO LLM.
-- Shodan already fingerprints technologies (cpe23, product, http_server) and tags
-- services (cloud/cdn/database/ai/ics/devops…); this model parses and categorises
-- those into a per-company tech profile. Powers technographic ICP targeting,
-- competitive-displacement plays, and the "exposed AI/ML tooling" trigger.
-- Numbers verified in data/analysis/tech_signals.sql.
{{ config(materialized='table') }}

with domain_scans as (
    select
        unnest(domains) as domain,
        tags,
        cpe23,
        -- one lowercased evidence blob per service (fingerprints + tags), plus the
        -- raw banner (kept separate: only AI/ML tooling reliably shows up there)
        lower(
            coalesce(product, '') || ' ' || coalesce(http_server, '') || ' '
            || coalesce(http_title, '') || ' ' || coalesce(array_to_string(tags, ' '), '')
            || ' ' || coalesce(array_to_string(cpe23, ' '), '')
        ) as ev,
        lower(coalesce(banner, '')) as banner
    from {{ ref('silver_services') }}
),

-- per-service category detection (deterministic keyword + tag rules)
flagged as (
    select
        domain,
        (regexp_matches(ev, 'nginx|apache|httpd|iis|openresty|tengine|litespeed|caddy|lighttpd'))::int as is_webserver,
        (list_contains(tags, 'cdn') or regexp_matches(ev, 'cloudflare|akamai|cloudfront|fastly|incapsula|imperva|sucuri|edgekey|edgesuite'))::int as is_cdn,
        (list_contains(tags, 'cloud'))::int as is_cloud,
        (regexp_matches(ev, 'wordpress|drupal|joomla|magento|typo3|prestashop|ghost cms'))::int as is_cms,
        (regexp_matches(ev, 'php|python|asp\.net|java|ruby|laravel|django|express|spring|rails|node'))::int as is_appstack,
        (list_contains(tags, 'database') or regexp_matches(ev, 'mysql|mariadb|postgres|mongodb|redis|elasticsearch|mssql|couchdb|cassandra'))::int as is_database,
        (regexp_matches(ev, 'postfix|exim|dovecot|zimbra|sendmail|smtp|exchange'))::int as is_mail,
        (regexp_matches(ev, 'openssh|teamviewer|anydesk|\bvnc\b|\brdp\b'))::int as is_remote,
        (list_contains(tags, 'vpn') or regexp_matches(ev, 'openvpn|fortinet|forticlient|globalprotect|wireguard|ipsec|pptp|anyconnect'))::int as is_vpn,
        (list_contains(tags, 'devops') or regexp_matches(ev, 'grafana|prometheus|kibana|jenkins|gitlab|kubernetes|portainer|consul'))::int as is_devops,
        (list_contains(tags, 'ai')
            or regexp_matches(banner, 'ollama|jupyter|comfyui|mlflow|vllm|triton|kubeflow|weaviate|qdrant|milvus|chromadb|gradio|tensorflow|huggingface')
            or regexp_matches(ev, 'ollama|jupyter|comfyui|mlflow|vllm|kubeflow|weaviate|qdrant'))::int as is_ai_ml,
        (list_contains(tags, 'ics'))::int as is_ics
    from domain_scans
),

per_domain as (
    select
        domain,
        max(is_webserver)     as has_webserver,
        max(is_cdn)           as has_cdn,
        max(is_cloud)         as has_cloud,
        max(is_cms)           as has_cms,
        max(is_appstack)      as has_appstack,
        max(is_database)      as has_database_tech,
        max(is_mail)          as has_mail,
        max(is_remote)        as has_remote,
        max(is_vpn)           as has_vpn_tech,
        max(is_devops)        as has_devops,
        max(is_ai_ml)         as has_ai_ml,
        max(is_ics)           as has_ics
    from flagged
    group by domain
),

-- named technologies from cpe23 (cpe:2.3:a:vendor:product:version -> product token) —
-- Shodan's own fingerprint, so these are real, not guessed
cpe_names as (
    select domain, split_part(unnest(cpe23), ':', 5) as tname
    from (select unnest(domains) as domain, cpe23
          from {{ ref('silver_services') }} where cpe23 is not null)
),
tech_by_domain as (
    select domain,
        list_distinct(list_filter(array_agg(tname),
            v -> v is not null and v <> '' and v <> '*')) as tech_names
    from cpe_names group by domain
),

-- VERSIONED technologies + legacy/EOL detection (Suresh's ask: "who runs Python 2.7 /
-- Windows XP?"). Shodan reports a concrete `product`+`version` for ~5% of services and a
-- version segment in ~21% of cpe23 rows — enough to name specific stacks and flag
-- clearly end-of-life ones. Version-specific targeting is the highest-value technographic
-- trigger (a known-vulnerable, unsupported stack is a direct reason to call).
version_scans as (
    select unnest(domains) as domain, product, version, tags
    from {{ ref('silver_services') }}
),
versioned_by_domain as (
    select
        domain,
        -- concrete "Product Version" strings (e.g. "OpenSSH 7.4", "nginx 1.18.0")
        list_distinct(list_filter(array_agg(
            case when product is not null and version is not null and version <> ''
                 then product || ' ' || version end),
            x -> x is not null)) as versioned_tech,
        -- named legacy / EOL stacks — version-gated, plus Shodan's own eol tags
        list_distinct(list_filter(array_agg(
            case
                when lower(product) like '%python%' and version like '2.%'         then 'Python 2.x (EOL)'
                when lower(product) like '%php%' and (version like '5.%' or version like '4.%') then 'PHP 5.x / 4.x (EOL)'
                when lower(product) like '%openssh%' and try_cast(split_part(version,'.',1) as int) < 7 then 'OpenSSH < 7'
                when lower(product) like '%apache%' and version like '2.2%'        then 'Apache httpd 2.2 (EOL)'
                when lower(product) like '%mysql%' and version like '5.%'          then 'MySQL 5.x (EOL)'
                when lower(product) like '%microsoft iis%' and try_cast(split_part(version,'.',1) as int) <= 7 then 'IIS <= 7 (EOL)'
                when list_contains(tags, 'eol-os')      then 'End-of-life OS'
                when list_contains(tags, 'eol-product') then 'End-of-life software (Shodan-flagged)'
                else null end),
            x -> x is not null)) as legacy_tech
    from version_scans group by domain
),

-- HOSTING / INFRASTRUCTURE provider from the network owner (org/isp). Answers "where are
-- they hosted?" — a technographic dimension for ICP fit (cloud-native vs on-prem) and for
-- reading the footprint (a company sitting behind a CDN/host vs. self-hosting).
hosting_scans as (
    select unnest(domains) as domain,
           isp,
           lower(coalesce(org, '') || ' ' || coalesce(isp, '')) as netname
    from {{ ref('silver_services') }}
),
hosting_by_domain as (
    select
        domain,
        -- Tier 1: normalised major cloud / CDN / host (clean, discrete — used for the
        -- provider filter). Empty for companies on their own network / a regional ISP.
        list_distinct(list_filter(array_agg(
            case
                when regexp_matches(netname, 'amazon|aws')         then 'AWS'
                when regexp_matches(netname, 'google')             then 'Google Cloud'
                when regexp_matches(netname, 'microsoft|azure')    then 'Microsoft Azure'
                when regexp_matches(netname, 'cloudflare')         then 'Cloudflare'
                when regexp_matches(netname, 'akamai')             then 'Akamai'
                when regexp_matches(netname, 'fastly')             then 'Fastly'
                when regexp_matches(netname, 'incapsula|imperva')  then 'Imperva'
                when regexp_matches(netname, 'digitalocean')       then 'DigitalOcean'
                when regexp_matches(netname, 'hetzner')            then 'Hetzner'
                when regexp_matches(netname, 'linode')             then 'Linode'
                when regexp_matches(netname, 'aliyun|alibaba')     then 'Alibaba Cloud'
                when regexp_matches(netname, 'fly\.io')            then 'Fly.io'
                when regexp_matches(netname, 'oracle')             then 'Oracle Cloud'
                when regexp_matches(netname, 'vultr')              then 'Vultr'
                when regexp_matches(netname, 'gcore|g-core')       then 'Gcore'
                when regexp_matches(netname, 'scaleway')           then 'Scaleway'
                when regexp_matches(netname, 'ovh')                then 'OVH'
                else null end),
            x -> x is not null)) as hosting_providers,
        -- Tier 2: the dominant network owner (ISP/AS operator) — the actual infra the
        -- company sits on, nearly always present (a regional ISP or their own network
        -- when self-hosted). This is what we DISPLAY so "hosting" is never blank.
        mode(isp) as hosting_network
    from hosting_scans group by domain
),

-- EXPOSURE SURFACE + SSL profile: the port inventory names risky internet-facing
-- services (RDP/Telnet/SMB/DB/orchestration APIs) — the sharpest cyber-sales trigger
-- ("your RDP is open to the internet"). The SSL cert subject yields a DETERMINISTIC org
-- name (O=…) and the issuer a CA/hygiene signal — no LLM.
surface_scans as (
    select unnest(domains) as domain, port, ssl_cert_subject, ssl_cert_issuer,
           lower(coalesce(http_title, '')) as title, city
    from {{ ref('silver_services') }}
),
surface_by_domain as (
    select
        domain,
        -- named risky/notable exposed services, from well-known ports
        list_distinct(list_filter(array_agg(
            case port
                when 3389  then 'RDP'            when 23    then 'Telnet'
                when 21    then 'FTP'            when 445   then 'SMB'
                when 139   then 'NetBIOS'        when 5900  then 'VNC'
                when 3306  then 'MySQL'          when 5432  then 'PostgreSQL'
                when 27017 then 'MongoDB'        when 6379  then 'Redis'
                when 9200  then 'Elasticsearch'  when 1433  then 'MSSQL'
                when 161   then 'SNMP'           when 389   then 'LDAP'
                when 2375  then 'Docker API'     when 6443  then 'Kubernetes API'
                when 11434 then 'Ollama'         when 5601  then 'Kibana'
                when 9090  then 'Prometheus'     when 8086  then 'InfluxDB'
                else null end),
            x -> x is not null)) as exposed_services,
        max((port = 3389)::int)        as has_rdp,
        max((port = 23)::int)          as has_telnet,
        max((port = 21)::int)          as has_ftp,
        max((port in (445, 139))::int) as has_smb,
        -- exposed admin / management panels, named from the HTTP page title. An
        -- internet-facing control panel — cPanel/WHM/Plesk, a firewall/router login,
        -- a DevOps console — is a high-value cyber target ("your cPanel login is public").
        list_distinct(list_filter(array_agg(
            case
                when title like '%cpanel%' or title like '%whm login%'      then 'cPanel/WHM'
                when title like '%plesk%'                                   then 'Plesk'
                when title like '%control webpanel%' or title like '%cwp%'  then 'Control WebPanel'
                when title like '%webmin%'                                  then 'Webmin'
                when title like '%directadmin%'                             then 'DirectAdmin'
                when title like '%phpmyadmin%'                              then 'phpMyAdmin'
                when title like '%pgadmin%'                                 then 'pgAdmin'
                when title like '%grafana%'                                 then 'Grafana'
                when title like '%kibana%'                                  then 'Kibana'
                when title like '%portainer%'                               then 'Portainer'
                when title like '%minio%'                                   then 'MinIO console'
                when title like '%jenkins%'                                 then 'Jenkins'
                when title like '%gitlab%'                                  then 'GitLab'
                when title like '%proxmox%'                                 then 'Proxmox'
                when title like '%routeros%' or title like '%mikrotik%'     then 'MikroTik RouterOS'
                when title like '%vigor%' or title like '%draytek%'         then 'DrayTek'
                when title like '%pfsense%'                                 then 'pfSense'
                when title like '%opnsense%'                                then 'OPNsense'
                when title like '%sonicwall%'                               then 'SonicWall'
                when title like '%fortin%' or title like '%web filter block%' then 'Fortinet'
                when title like '%sophos%'                                  then 'Sophos'
                when title like '%citrix%'                                  then 'Citrix'
                when title like '%checkpoint%' or title like '%quantum spark%' then 'Check Point'
                when title like '%3cx%'                                     then '3CX'
                when title like '%synology%'                                then 'Synology'
                else null end),
            x -> x is not null)) as exposed_panels,
        -- geographic footprint: distinct cities the company's hosts sit in — a rough size /
        -- distribution proxy (a single-city SMB vs a multi-region enterprise).
        count(distinct city) as city_count,
        -- certificate authorities in use (hygiene signal: self-signed vs Let's Encrypt vs
        -- DigiCert). NOTE: a deterministic org name from the cert subject was attempted but
        -- prospect certs are CN-only (0/97k carry an O= field — free/LE certs omit it), so
        -- there is no org to mine here; dropped rather than shipped empty.
        list_distinct(list_filter(array_agg(ssl_cert_issuer), x -> x is not null)) as ssl_issuers
    from surface_scans group by domain
),

-- HTTP `Server:` header -> named products/categories the cpe fingerprint misses. Measured
-- as the *real* residual (extraction_v4.sql): ~6.5k distinct http_server values sit outside
-- the cpe/keyword vocabulary, and they are deterministically parseable — an LLM was measured
-- and NOT justified here (the banner residual is protocol noise; the tech is in this header).
server_scans as (
    select unnest(domains) as domain,
           lower(split_part(split_part(http_server, '/', 1), ' ', 1)) as srv
    from {{ ref('silver_services') }}
    where http_server is not null and http_server <> ''
),
server_by_domain as (
    select
        domain,
        list_distinct(list_filter(array_agg(
            case
                when srv like '%pve-api%' or srv like '%proxmox%'    then 'Proxmox'
                when srv like '%squid%'                              then 'Squid'
                when srv = 'apache-coyote' or srv like '%tomcat%'    then 'Apache Tomcat'
                when srv like '%jetty%'                              then 'Jetty'
                when srv like '%kestrel%'                            then 'Kestrel (.NET)'
                when srv like '%uvicorn%'                            then 'Uvicorn (Python)'
                when srv like '%gunicorn%'                           then 'Gunicorn (Python)'
                when srv like '%werkzeug%'                           then 'Werkzeug (Python)'
                when srv like '%bigip%' or srv like '%big-ip%'       then 'F5 BIG-IP'
                when srv like '%sonicwall%'                          then 'SonicWall'
                when srv like '%miniserv%'                           then 'Webmin'
                when srv like '%haproxy%'                            then 'HAProxy'
                when srv like '%varnish%'                            then 'Varnish'
                when srv like '%traefik%'                            then 'Traefik'
                when srv like '%proxygen%'                           then 'Proxygen'
                when srv in ('goahead-webs','boa','mini_httpd','thttpd','webs','alphapd',
                             'app-webs','gsoap','dnvrs-webs')        then 'Embedded webserver'
                when srv like '%tr069%' or srv like '%cwmp%' or srv like '%ccspcwmp%'
                     or srv like '%cpe-server%'                      then 'TR-069 / CWMP router mgmt'
                else null end),
            x -> x is not null)) as server_products,
        list_distinct(list_filter(array_agg(
            case
                when srv like '%pve-api%' or srv like '%proxmox%'    then 'Virtualization'
                when srv like '%squid%' or srv like '%haproxy%' or srv like '%varnish%'
                     or srv like '%traefik%' or srv like '%proxygen%' then 'Proxy / gateway'
                when srv = 'apache-coyote' or srv like '%tomcat%' or srv like '%jetty%'
                     or srv like '%kestrel%' or srv like '%uvicorn%' or srv like '%gunicorn%'
                     or srv like '%werkzeug%'                        then 'App server'
                when srv in ('goahead-webs','boa','mini_httpd','thttpd','webs','alphapd',
                             'app-webs','gsoap','dnvrs-webs')        then 'Embedded / IoT device'
                when srv like '%tr069%' or srv like '%cwmp%' or srv like '%ccspcwmp%'
                     or srv like '%cpe-server%'                      then 'Router / CPE mgmt'
                else null end),
            x -> x is not null)) as server_categories
    from server_scans group by domain
),

-- product@version paired with its REAL CVEs — the low-level "you run X vN → CVE-Y" signal:
-- the sharpest displacement hook ("we noticed you run MySQL 8.0.12, which carries CVE-…").
-- One string per vulnerable versioned product, ranked by CVE count. CVEs are the service's
-- own `vulns` — never invented.
pv_vulns as (
    select unnest(domains) as domain,
           product || ' ' || version as pv,
           len(vulns) as ncve,
           vulns[1] as lead_cve
    from {{ ref('silver_services') }}
    where product is not null and version is not null and version <> '' and len(vulns) > 0
),
pv_by_domain as (
    select domain, pv, max(ncve) as ncve, arg_max(lead_cve, ncve) as lead_cve
    from pv_vulns group by domain, pv
),
vuln_products_by_domain as (
    select domain,
        array_agg(
            pv || ' — ' || lead_cve || case when ncve > 1 then ' (+' || (ncve - 1) || ')' else '' end
            order by ncve desc
        ) as vulnerable_products
    from pv_by_domain group by domain
)

select
    p.domain,
    p.has_webserver, p.has_cdn, p.has_cloud, p.has_cms, p.has_appstack,
    p.has_database_tech, p.has_mail, p.has_remote, p.has_vpn_tech,
    p.has_devops, p.has_ai_ml, p.has_ics,
    (len(coalesce(v.legacy_tech, [])) > 0)::int               as has_legacy,
    coalesce(t.tech_names, [])                                as tech_names,
    coalesce(v.versioned_tech, [])                            as versioned_tech,
    coalesce(v.legacy_tech, [])                               as legacy_tech,
    coalesce(h.hosting_providers, [])                         as hosting_providers,
    h.hosting_network                                         as hosting_network,
    coalesce(s.exposed_services, [])                          as exposed_services,
    coalesce(s.has_rdp, 0)    as has_rdp,
    coalesce(s.has_telnet, 0) as has_telnet,
    coalesce(s.has_ftp, 0)    as has_ftp,
    coalesce(s.has_smb, 0)    as has_smb,
    coalesce(s.exposed_panels, [])                            as exposed_panels,
    (len(coalesce(s.exposed_panels, [])) > 0)::int            as has_admin_panel,
    coalesce(s.city_count, 0)                                 as city_count,
    coalesce(s.ssl_issuers, [])                               as ssl_issuers,
    coalesce(sv.server_products, [])                          as server_products,
    coalesce(vp.vulnerable_products[1:8], [])                 as vulnerable_products,
    -- human-readable category list (for filtering + the detail view); the server-header
    -- categories (Virtualization / Proxy / App server / Embedded / Router mgmt) are merged in.
    list_distinct(list_concat(
        list_filter([
            case when p.has_ai_ml = 1        then 'AI/ML tooling' end,
            case when p.has_devops = 1       then 'DevOps / observability' end,
            case when p.has_ics = 1          then 'ICS / OT' end,
            case when len(coalesce(v.legacy_tech, [])) > 0 then 'Legacy / EOL software' end,
            case when p.has_database_tech = 1 then 'Database' end,
            case when p.has_cms = 1          then 'CMS' end,
            case when p.has_appstack = 1     then 'App framework / language' end,
            case when p.has_mail = 1         then 'Mail server' end,
            case when p.has_remote = 1       then 'Remote access' end,
            case when p.has_vpn_tech = 1     then 'VPN' end,
            case when p.has_webserver = 1    then 'Web server' end,
            case when p.has_cdn = 1          then 'CDN / edge' end,
            case when p.has_cloud = 1        then 'Cloud-hosted' end
        ], x -> x is not null),
        coalesce(sv.server_categories, [])
    ))                                                        as tech_categories
from per_domain p
left join tech_by_domain t     on t.domain = p.domain
left join versioned_by_domain v on v.domain = p.domain
left join hosting_by_domain h   on h.domain = p.domain
left join surface_by_domain s   on s.domain = p.domain
left join server_by_domain sv   on sv.domain = p.domain
left join vuln_products_by_domain vp on vp.domain = p.domain
