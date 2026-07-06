-- Cleaned service-grain view over Bronze: drop honeypot decoys (fake systems that
-- would become false leads) and keep only the columns Silver needs downstream.
-- A view, so it costs no storage — it's just a filtered projection of Bronze.
{{ config(materialized='view') }}

select
    ip_str,
    port,
    transport,
    scanned_at,
    org,
    domains,
    hostnames,
    country_code,
    city,
    product,
    version,
    cpe23,
    tags,
    vulns,
    ssl_cert_subject,
    http_server,
    http_title,
    banner
from {{ source('bronze', 'shodan_scans') }}
where not list_contains(tags, 'honeypot')
