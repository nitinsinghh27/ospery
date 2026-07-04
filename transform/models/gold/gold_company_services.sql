-- Drill-down for the company detail page: every exposed service belonging to a
-- gold prospect company. A view — queried one company at a time by the app.
{{ config(materialized='view') }}

select
    t.domain,
    s.ip_str,
    s.port,
    s.transport,
    s.product,
    s.version,
    s.tags,
    s.vulns,
    s.country_code,
    s.scanned_at
from {{ ref('silver_services') }} s, unnest(s.domains) as t(domain)
where t.domain in (select domain from {{ ref('gold_companies') }})
