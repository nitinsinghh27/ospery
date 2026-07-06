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
)

select
    p.domain,
    p.has_webserver, p.has_cdn, p.has_cloud, p.has_cms, p.has_appstack,
    p.has_database_tech, p.has_mail, p.has_remote, p.has_vpn_tech,
    p.has_devops, p.has_ai_ml, p.has_ics,
    coalesce(t.tech_names, [])                                as tech_names,
    -- human-readable category list (for filtering + the detail view)
    list_filter([
        case when p.has_ai_ml = 1        then 'AI/ML tooling' end,
        case when p.has_devops = 1       then 'DevOps / observability' end,
        case when p.has_ics = 1          then 'ICS / OT' end,
        case when p.has_database_tech = 1 then 'Database' end,
        case when p.has_cms = 1          then 'CMS' end,
        case when p.has_appstack = 1     then 'App framework / language' end,
        case when p.has_mail = 1         then 'Mail server' end,
        case when p.has_remote = 1       then 'Remote access' end,
        case when p.has_vpn_tech = 1     then 'VPN' end,
        case when p.has_webserver = 1    then 'Web server' end,
        case when p.has_cdn = 1          then 'CDN / edge' end,
        case when p.has_cloud = 1        then 'Cloud-hosted' end
    ], x -> x is not null)                                    as tech_categories
from per_domain p
left join tech_by_domain t on t.domain = p.domain
