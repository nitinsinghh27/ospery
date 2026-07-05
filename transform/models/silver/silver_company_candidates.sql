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
),

-- count each domain's distinct CVEs that CISA lists as actively exploited (KEV) —
-- the strongest CVE signal: exploited in the wild, not merely "a CVE exists".
kev_by_domain as (
    select domain, count(distinct cve) as kev_count
    from (select domain, unnest(vulns) as cve from domain_scans)
    where cve in (select cve_id from {{ source('reference', 'kev') }})
    group by domain
),

-- peak EPSS: the highest exploitation probability among the domain's CVEs. Great for
-- the pitch ("a CVE with 97% exploit probability") and display; carried, not scored
-- (in this exposure-heavy data almost every prospect has a high-EPSS CVE).
epss_by_domain as (
    select d.domain, max(e.epss) as max_epss
    from (select domain, unnest(vulns) as cve from domain_scans) d
    join {{ source('reference', 'epss') }} e on e.cve_id = d.cve
    group by d.domain
)

select
    c.domain,
    c.country,
    c.services,
    c.hosts,
    c.cve_count,
    coalesce(k.kev_count, 0)                              as kev_count,
    (coalesce(k.kev_count, 0) > 0)::int                  as has_kev,
    round(coalesce(ep.max_epss, 0), 4)                   as max_epss,
    c.has_cve, c.has_eol, c.has_db, c.has_selfsigned, c.has_vpn, c.has_iot, c.has_breach,
    -- lead score (weights: breach >> actively-exploited(KEV) >= cve >= db > eol >
    -- self-signed >= vpn/iot, plus a small attack-surface bonus).
    c.has_breach * 40
      + case when coalesce(k.kev_count, 0) > 0 then 30 else 0 end
      + case when c.cve_count > 0 then 15 + least(c.cve_count * 2, 20) else 0 end
      + c.has_db * 20 + c.has_eol * 15 + c.has_selfsigned * 10 + c.has_vpn * 8 + c.has_iot * 8
      + least(cast(round(log2(c.services + 1) * 3) as int), 10)                     as score
from classified c
left join kev_by_domain k on k.domain = c.domain
left join epss_by_domain ep on ep.domain = c.domain
where not c.is_infra
