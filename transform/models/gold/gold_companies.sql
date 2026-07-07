-- The prospect mart the app reads: LLM-verified BUSINESS companies with at least
-- one buying signal, scored, segmented, and with technical signals translated to
-- sales-friendly reasons. Infra and guardrail-flagged domains are excluded.
{{ config(materialized='table') }}

select
    c.domain,
    l.entity_class,
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
    coalesce(t.has_legacy, 0)                as has_legacy,
    coalesce(t.tech_names, []::varchar[])          as tech_names,
    coalesce(t.versioned_tech, []::varchar[])      as versioned_tech,
    coalesce(t.legacy_tech, []::varchar[])         as legacy_tech,
    coalesce(t.hosting_providers, []::varchar[])   as hosting_providers,
    t.hosting_network                              as hosting_network,
    coalesce(t.exposed_services, []::varchar[])    as exposed_services,
    coalesce(t.has_rdp, 0)                   as has_rdp,
    coalesce(t.has_telnet, 0)                as has_telnet,
    coalesce(t.has_ftp, 0)                   as has_ftp,
    coalesce(t.has_smb, 0)                   as has_smb,
    coalesce(t.exposed_panels, []::varchar[])      as exposed_panels,
    coalesce(t.has_admin_panel, 0)           as has_admin_panel,
    coalesce(t.city_count, 0)                as city_count,
    coalesce(t.ssl_issuers, []::varchar[])         as ssl_issuers,
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
        -- name the legacy stack when we detected specific versions; otherwise the generic EOL flag
        case when len(coalesce(t.legacy_tech, [])) > 0
             then 'Legacy / end-of-life software: ' || array_to_string(t.legacy_tech[1:3], ', ')
             when c.has_eol = 1 then 'Running unsupported / end-of-life software' end,
        case when c.has_selfsigned = 1 then 'Weak or self-signed SSL certificate' end,
        case when c.has_vpn = 1 then 'VPN / remote access exposed' end,
        case when coalesce(t.has_rdp, 0) = 1 then 'Remote Desktop (RDP) exposed to the internet' end,
        case when coalesce(t.has_telnet, 0) = 1 then 'Telnet (unencrypted admin) exposed to the internet' end,
        case when coalesce(t.has_smb, 0) = 1 then 'SMB / file-sharing exposed to the internet' end,
        case when coalesce(t.has_ftp, 0) = 1 then 'FTP exposed to the internet' end,
        case when len(coalesce(t.exposed_panels, [])) > 0
             then 'Admin / control panel exposed: ' || array_to_string(t.exposed_panels[1:2], ', ') end,
        case when c.has_iot = 1 then 'Exposed IoT / embedded devices' end
    ], x -> x is not null)                    as reasons

from {{ ref('silver_company_candidates') }} c
join {{ source('enrichment', 'entity_labels') }} l on l.domain = c.domain
left join {{ ref('country_codes') }} cc on cc.code = c.country
left join {{ ref('silver_company_tech') }} t on t.domain = c.domain
-- Keep both LLM-verified BUSINESS companies and INFRASTRUCTURE / hosting providers:
-- infra is not noise but a distinct ICP segment (hosts/ISPs/datacenters are themselves
-- high-surface cybersecurity buyers). The app defaults to businesses-only and exposes
-- infra behind a toggle, so the "see past the hosting layer" default is preserved while
-- the fuller universe is one click away. `flagged` (low-confidence / footprint contradiction)
-- stays excluded — that is a label-quality gate, not a business-vs-infra decision.
where l.entity_class in ('business', 'infra')
  and not l.flagged
  and (c.has_cve + c.has_eol + c.has_db + c.has_selfsigned
       + c.has_vpn + c.has_iot + c.has_breach) > 0
