-- Per-company (domain) candidate prospects: aggregate each domain's exposed
-- services into signals, apply the deterministic business/infra classifier, and
-- compute the lead score. Business domains only (infra excluded here; the LLM
-- refines the residual downstream). Validated logic — see
-- data/analysis/company_resolution.sql and signal_scoring.sql.
{{ config(materialized='table') }}

with domain_scans as (
    select unnest(domains) as domain, ip_str, country_code, vulns, tags
    from {{ ref('silver_services') }}
),

per_domain as (
    select
        domain,
        count(*)                                             as services,
        count(distinct ip_str)                               as hosts,
        mode(country_code)                                   as country,
        len(list_distinct(flatten(array_agg(vulns))))        as cve_count,
        max((len(vulns) > 0)::int)                                                          as has_cve,
        max((list_contains(tags, 'eol-product') or list_contains(tags, 'eol-os'))::int)     as has_eol,
        max(list_contains(tags, 'database')::int)                                           as has_db,
        max(list_contains(tags, 'self-signed')::int)                                        as has_selfsigned,
        max(list_contains(tags, 'vpn')::int)                                                as has_vpn,
        max(list_contains(tags, 'iot')::int)                                                as has_iot,
        max((list_contains(tags, 'compromised') or list_contains(tags, 'c2')
             or list_contains(tags, 'doublepulsar'))::int)                                  as has_breach
    from domain_scans
    group by domain
),

classified as (
    select *,
        -- deterministic infra rule: huge IP footprint OR an infra keyword
        (hosts >= 1000 or regexp_matches(lower(domain),
          'usercontent|amazonaws|cloudfront|awsglobalaccelerator|awsdns|cloudapp|1e100|googleusercontent|cloudflar|incapdns|incapsula|imperva|akamai|edgekey|edgesuite|fastly|sucuri|hetzner|your-server|digitalocean|linode|vultr|scaleway|scw\.cloud|contabo|ovh\.|hostgator|bluehost|hostmonster|secureserver|hostinger|websitewelcome|webhostbox|kasserver|unifiedlayer|dreamhost|siteground|liquidweb|rackspace|inmotionhosting|myvps|xrea|stackcp|upcloud|kagoya|mwprem|sakura|xserver|lolipop|bizmw|znlc|etius|wixsite|wix\.com|squarespace|weebly|shopify|webflow|multiscreensite|herokuapp|netlify|vercel|wordpress|plesk|cpanel|hwclouds|\.cloud$|\.host$|localhost|notexist|traefik|invalid\.|example\.(com|net|org)|imap\.example')
        ) as is_infra
    from per_domain
)

select
    domain,
    country,
    services,
    hosts,
    cve_count,
    has_cve, has_eol, has_db, has_selfsigned, has_vpn, has_iot, has_breach,
    -- lead score (weights: breach >> cve >= db > eol > self-signed >= vpn/iot,
    -- plus a small attack-surface bonus). Capped components; ~0-113 raw.
    has_breach * 40
      + case when cve_count > 0 then 15 + least(cve_count * 2, 20) else 0 end
      + has_db * 20 + has_eol * 15 + has_selfsigned * 10 + has_vpn * 8 + has_iot * 8
      + least(cast(round(log2(services + 1) * 3) as int), 10)                       as score
from classified
where not is_infra
