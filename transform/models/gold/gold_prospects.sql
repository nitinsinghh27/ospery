-- The single serving model the app reads: the ranked prospect list (gold_companies)
-- enriched with the cached LLM outputs — firmographics and the sales pitch. Kept
-- separate from gold_companies to avoid a cycle: the pitch/profile steps READ
-- gold_companies, so gold_companies cannot depend on them; this downstream model
-- joins their results back in. Only the newest prompt_version of each is used.
{{ config(materialized='table') }}

with latest_profile as (
    select * from {{ source('enrichment', 'company_profile') }}
    where prompt_version = (select max(prompt_version) from {{ source('enrichment', 'company_profile') }})
),

latest_pitch as (
    select * from {{ source('enrichment', 'company_pitch') }}
    where prompt_version = (select max(prompt_version) from {{ source('enrichment', 'company_pitch') }})
)

select
    c.*,
    prof.org_name,
    prof.industry,
    prof.tech_stack,
    prof.contact_emails,
    pit.pitch
from {{ ref('gold_companies') }} c
left join latest_profile prof on prof.domain = c.domain
left join latest_pitch   pit  on pit.domain  = c.domain
