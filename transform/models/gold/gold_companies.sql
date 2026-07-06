-- The prospect mart the app reads: LLM-verified BUSINESS companies with at least
-- one buying signal, scored, segmented, and with technical signals translated to
-- sales-friendly reasons. Infra and guardrail-flagged domains are excluded.
{{ config(materialized='table') }}

select
    c.domain,
    coalesce(l.segment, 'other')            as segment,
    c.country,
    coalesce(cc.country_name, c.country)     as country_name,
    coalesce(cc.region, 'Other')            as region,
    c.score,
    c.services,
    c.hosts,
    c.cve_count,
    c.kev_count,
    c.max_epss,
    c.has_cve, c.has_eol, c.has_db, c.has_selfsigned, c.has_vpn, c.has_iot, c.has_breach, c.has_kev,
    round(l.confidence, 2)                   as classification_confidence,

    -- technology profile (deterministic, from silver_company_tech) — technographic
    -- targeting: ICP fit, competitive displacement, and the "exposed AI/ML" trigger.
    coalesce(t.has_ai_ml, 0)                 as has_ai_ml,
    coalesce(t.has_ics, 0)                   as has_ics,
    coalesce(t.has_devops, 0)                as has_devops,
    coalesce(t.has_cdn, 0)                   as has_cdn,
    coalesce(t.has_cloud, 0)                 as has_cloud,
    coalesce(t.has_database_tech, 0)         as has_database_tech,
    coalesce(t.has_webserver, 0)             as has_webserver,
    coalesce(t.has_cms, 0)                   as has_cms,
    coalesce(t.has_appstack, 0)              as has_appstack,
    coalesce(t.has_mail, 0)                  as has_mail,
    coalesce(t.has_remote, 0)                as has_remote,
    coalesce(t.has_vpn_tech, 0)              as has_vpn_tech,
    coalesce(t.tech_names, []::varchar[])          as tech_names,
    coalesce(t.tech_categories, []::varchar[])     as tech_categories,

    -- reason translation: technical signals -> plain sales language (for the rep).
    -- KEV (actively-exploited) ranks just under active compromise — it's the most
    -- urgent CVE signal, so it leads the vulnerability reasons. Tech-derived triggers
    -- (ICS/OT, exposed AI/ML) are woven in where they apply.
    list_filter([
        case when c.has_breach = 1 then 'Signs of active compromise (malware / C2)' end,
        case when coalesce(t.has_ics, 0) = 1 then 'Industrial control systems (ICS/OT) exposed to the internet' end,
        case when c.kev_count > 0 then c.kev_count::varchar || ' actively-exploited (CISA KEV) vulnerabilit'
             || case when c.kev_count = 1 then 'y' else 'ies' end end,
        case when c.cve_count > 0 then c.cve_count::varchar || ' known software vulnerabilit'
             || case when c.cve_count = 1 then 'y' else 'ies' end end,
        case when coalesce(t.has_ai_ml, 0) = 1 then 'Exposed AI/ML tooling (e.g. Jupyter / Ollama / MLflow)' end,
        case when c.has_db = 1 then 'Database exposed to the internet' end,
        case when c.has_eol = 1 then 'Running unsupported / end-of-life software' end,
        case when c.has_selfsigned = 1 then 'Weak or self-signed SSL certificate' end,
        case when c.has_vpn = 1 then 'VPN / remote access exposed' end,
        case when c.has_iot = 1 then 'Exposed IoT / embedded devices' end
    ], x -> x is not null)                    as reasons

from {{ ref('silver_company_candidates') }} c
join {{ source('enrichment', 'entity_labels') }} l on l.domain = c.domain
left join {{ ref('country_codes') }} cc on cc.code = c.country
left join {{ ref('silver_company_tech') }} t on t.domain = c.domain
where l.entity_class = 'business'
  and not l.flagged
  and (c.has_cve + c.has_eol + c.has_db + c.has_selfsigned
       + c.has_vpn + c.has_iot + c.has_breach) > 0
