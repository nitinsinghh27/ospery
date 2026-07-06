-- ============================================================================
-- TECH-SIGNAL EXTRACTION — what technographic signals can we pull DETERMINISTICALLY?
--
-- The v1/v2 build leaned on CVE/exposure signals. This study backs the v3 direction:
-- Shodan already FINGERPRINTS technologies (product, http_server, cpe23) and TAGS
-- services (cloud/cdn/database/ai/ics/devops/c2…), so a rich tech profile is
-- extractable with pure SQL — NO LLM needed. Feeds silver_company_tech.sql.
--
-- Runs against bronze.shodan_scans + gold.gold_prospects. To run, see
-- docs/helper_commands.md. OUTPUT comments captured from the full 9.2M-row load.
-- ============================================================================


-- ----------------------------------------------------------------------------
-- A. WHICH FIELDS CARRY TECH SIGNAL (coverage of 9,197,023 rows)
-- ----------------------------------------------------------------------------

-- Q1. Field coverage — how much of the data each fingerprint field carries (non-empty;
--     `is not null` would over-count empty arrays/strings).
select
    round(100.0 * count(*) filter (where len(coalesce(http_server, '')) > 0) / count(*), 0) as pct_http_server,
    round(100.0 * count(*) filter (where len(coalesce(product, ''))     > 0) / count(*), 0) as pct_product,
    round(100.0 * count(*) filter (where len(cpe23) > 0)                     / count(*), 0) as pct_cpe23,
    round(100.0 * count(*) filter (where len(coalesce(banner, ''))      > 0) / count(*), 0) as pct_banner,
    round(100.0 * count(*) filter (where len(tags)  > 0)                     / count(*), 0) as pct_tags
from bronze.shodan_scans;
-- OUTPUT: http_server=19 | product=15 | cpe23=23 | banner=49 | tags=60


-- ----------------------------------------------------------------------------
-- B. SHODAN'S OWN TAGS — ready-made deterministic categories
-- ----------------------------------------------------------------------------

-- Q2. Tag distribution (services). Shodan pre-classifies infra + risk categories.
select t, count(*) n
from (select unnest(tags) t from bronze.shodan_scans where tags is not null)
group by 1 order by n desc limit 20;
-- OUTPUT: cdn=2,688,345 | cloud=2,377,122 | starttls=193,243 | self-signed=101,757
--         honeypot=94,240 | eol-product=69,970 | proxy=50,814 | database=50,563
--         iot=11,737 | vpn=11,533 | devops=3,161 | eol-os=2,639 | open-dir=1,139
--         videogame=1,103 | ai=1,101 | ics=784 | tor=766 | doublepulsar=304
--         c2=301 | cryptocurrency=161
--   Note the security-relevant ones: ai, ics (industrial control), c2 (command &
--   control), doublepulsar (exploit), tor, cryptocurrency — all free, deterministic.


-- ----------------------------------------------------------------------------
-- C. CPE23 — standardised vendor:product fingerprints (the richest tech source)
-- ----------------------------------------------------------------------------

-- Q3. Top technologies by cpe23 (cpe:2.3:a:vendor:product:version -> vendor:product).
select split_part(c, ':', 4) || ':' || split_part(c, ':', 5) as vendor_product, count(*) n
from (select unnest(cpe23) c from bronze.shodan_scans where cpe23 is not null)
where c like 'cpe:2.3:%'
group by 1 order by n desc limit 15;
-- OUTPUT: cloudflare:cloudflare=585,117 | f5:nginx=494,362 | imperva:incapsula=319,092
--         ntp:ntp=123,676 | apache:http_server=111,370 | openbsd:openssh=95,378
--         canonical:ubuntu_linux=56,796 | microsoft:windows=47,034
--         microsoft:iis=42,991 | fortinet:fortiweb=40,462 | openresty=38,216
--         amazon:elastic_load_balancing=34,632 | php:php=31,669 | oracle:mysql=20,691


-- ----------------------------------------------------------------------------
-- D. EXPOSED AI/ML TOOLING — an emerging, high-value targeting trigger
-- ----------------------------------------------------------------------------

-- Q4. Distinct companies (domains) exposing AI/ML + observability tooling.
--     Detected from product / http_title / banner (deterministic string match).
with ds as (
    select unnest(domains) d, lower(coalesce(product,'') || ' ' || coalesce(http_title,'')
           || ' ' || coalesce(banner,'')) txt
    from bronze.shodan_scans where domains is not null
)
select
    count(distinct d) filter (where txt like '%ollama%')     as ollama,
    count(distinct d) filter (where txt like '%jupyter%')    as jupyter,
    count(distinct d) filter (where txt like '%vllm%')       as vllm,
    count(distinct d) filter (where txt like '%comfyui%')    as comfyui,
    count(distinct d) filter (where txt like '%mlflow%')     as mlflow,
    count(distinct d) filter (where txt like '%grafana%')    as grafana,
    count(distinct d) filter (where txt like '%prometheus%') as prometheus
from ds;
-- OUTPUT: ollama=21 | jupyter=19 | vllm=33 | comfyui=9 | mlflow=3 | grafana=233 | prometheus=476
--   Small but real and differentiated — a fresh "exposed AI attack surface" trigger.
--   Examples that survive into prospects: ust.hk / kth.se (Jupyter), uni-lj.si
--   (llama.cpp), itsweb.com.br (Ollama + Grafana).


-- ----------------------------------------------------------------------------
-- E. RESULT — tech-category coverage among the 3,973 prospects (post silver+gold)
-- ----------------------------------------------------------------------------

-- Q5. How the deterministic tech profile lands on real prospects.
select
    count(*)                                        as prospects,
    round(100.0 * sum(has_webserver)     / count(*), 0) as pct_webserver,
    round(100.0 * sum(has_appstack)      / count(*), 0) as pct_appstack,
    round(100.0 * sum(has_cloud)         / count(*), 0) as pct_cloud,
    round(100.0 * sum(has_database_tech) / count(*), 0) as pct_database,
    round(100.0 * sum(has_remote)        / count(*), 0) as pct_remote,
    sum(has_devops)                                 as devops,
    sum(has_ics)                                    as ics,
    sum(has_ai_ml)                                  as ai_ml
from gold.gold_prospects;
-- OUTPUT: prospects=3,973 | webserver=91 | appstack=58 | cloud=26 | database=21
--         remote=13 | devops=75 | ics=13 | ai_ml=10
--   Broad coverage from the same data, zero LLM cost — the tech profile powers
--   technographic ICP filters, competitive-displacement plays, and niche
--   high-value triggers (exposed AI/ML, ICS/OT).
