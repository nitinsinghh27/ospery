-- ============================================================================
-- signal_scoring.sql
-- Buying-signal prevalence & co-occurrence among PROSPECT (business) companies,
-- to inform the lead-score weights. A prospect = a business domain per the
-- classifier in company_resolution.sql (infra if ips>=1000 OR infra keyword).
-- Runs against `bronze.shodan_scans`. To run, see docs/helper_commands.md.
-- OUTPUT comments captured from the full 9,197,023-row load.
--
-- Draft scoring intent (weights to be confirmed from the numbers below):
--   breach (compromised/c2/doublepulsar) >> cve >= db_exposed > eol
--     > self-signed >= vpn/iot ; plus a small multiplier for attack-surface size.
--
-- Final scoring runs on LLM-classified BUSINESS companies (see
-- docs/Stage5_EntityClassification.md) and applies an org_type modifier
-- (education / government / nonprofit scored slightly lower than commercial).
-- ============================================================================


-- Q1. Signal PREVALENCE — how many prospect companies carry each signal.
WITH domain_ips AS (
  SELECT d AS domain, count(DISTINCT ip_str) AS ips
  FROM (SELECT unnest(domains) AS d, ip_str FROM bronze.shodan_scans
        WHERE NOT list_contains(tags,'honeypot')) GROUP BY d
),
business AS (
  SELECT domain FROM domain_ips
  WHERE NOT (ips >= 1000 OR regexp_matches(lower(domain),
    'usercontent|amazonaws|cloudfront|awsglobalaccelerator|awsdns|cloudapp|1e100|googleusercontent|cloudflar|incapdns|incapsula|imperva|akamai|edgekey|edgesuite|fastly|sucuri|hetzner|your-server|digitalocean|linode|vultr|scaleway|scw\.cloud|contabo|ovh\.|hostgator|bluehost|hostmonster|secureserver|hostinger|websitewelcome|webhostbox|kasserver|unifiedlayer|dreamhost|siteground|liquidweb|rackspace|inmotionhosting|myvps|xrea|stackcp|upcloud|kagoya|mwprem|sakura|xserver|lolipop|bizmw|znlc|etius|wixsite|wix\.com|squarespace|weebly|shopify|webflow|multiscreensite|herokuapp|netlify|vercel|wordpress|plesk|cpanel|hwclouds|\.cloud$|\.host$|localhost|notexist|traefik|invalid\.|example\.(com|net|org)|imap\.example'))
),
company AS (
  SELECT t.d AS company,
    max((len(s.vulns) > 0)::INT)                                                        AS cve,
    max((list_contains(s.tags,'eol-product') OR list_contains(s.tags,'eol-os'))::INT)   AS eol,
    max(list_contains(s.tags,'database')::INT)                                          AS db,
    max(list_contains(s.tags,'self-signed')::INT)                                       AS selfsigned,
    max(list_contains(s.tags,'vpn')::INT)                                               AS vpn,
    max(list_contains(s.tags,'iot')::INT)                                               AS iot,
    max((list_contains(s.tags,'compromised') OR list_contains(s.tags,'c2')
         OR list_contains(s.tags,'doublepulsar'))::INT)                                 AS breach
  FROM bronze.shodan_scans s, unnest(s.domains) AS t(d)
  JOIN business b ON b.domain = t.d
  WHERE NOT list_contains(s.tags,'honeypot')
  GROUP BY t.d
)
SELECT
  count(*)         AS companies,
  sum(cve)         AS with_cve,
  sum(eol)         AS with_eol,
  sum(db)          AS with_db,
  sum(selfsigned)  AS with_selfsigned,
  sum(vpn)         AS with_vpn,
  sum(iot)         AS with_iot,
  sum(breach)      AS with_breach
FROM company;
-- OUTPUT: companies=503,856 | with_cve=53,832 | with_eol=28,225 | with_db=8,184
--         with_selfsigned=19,117 | with_vpn=1,737 | with_iot=273 | with_breach=119
--   → CVE is the most common signal; breach is rare (119) but premium.


-- Q2. Signal CO-OCCURRENCE — how many distinct signal types each company has.
--     Companies with several signals are the hottest leads.
WITH domain_ips AS (
  SELECT d AS domain, count(DISTINCT ip_str) AS ips
  FROM (SELECT unnest(domains) AS d, ip_str FROM bronze.shodan_scans
        WHERE NOT list_contains(tags,'honeypot')) GROUP BY d
),
business AS (
  SELECT domain FROM domain_ips
  WHERE NOT (ips >= 1000 OR regexp_matches(lower(domain),
    'usercontent|amazonaws|cloudfront|awsglobalaccelerator|awsdns|cloudapp|1e100|googleusercontent|cloudflar|incapdns|incapsula|imperva|akamai|edgekey|edgesuite|fastly|sucuri|hetzner|your-server|digitalocean|linode|vultr|scaleway|scw\.cloud|contabo|ovh\.|hostgator|bluehost|hostmonster|secureserver|hostinger|websitewelcome|webhostbox|kasserver|unifiedlayer|dreamhost|siteground|liquidweb|rackspace|inmotionhosting|myvps|xrea|stackcp|upcloud|kagoya|mwprem|sakura|xserver|lolipop|bizmw|znlc|etius|wixsite|wix\.com|squarespace|weebly|shopify|webflow|multiscreensite|herokuapp|netlify|vercel|wordpress|plesk|cpanel|hwclouds|\.cloud$|\.host$|localhost|notexist|traefik|invalid\.|example\.(com|net|org)|imap\.example'))
),
company AS (
  SELECT t.d AS company,
    max((len(s.vulns) > 0)::INT)
    + max((list_contains(s.tags,'eol-product') OR list_contains(s.tags,'eol-os'))::INT)
    + max(list_contains(s.tags,'database')::INT)
    + max(list_contains(s.tags,'self-signed')::INT)
    + max(list_contains(s.tags,'vpn')::INT)
    + max(list_contains(s.tags,'iot')::INT)
    + max((list_contains(s.tags,'compromised') OR list_contains(s.tags,'c2')
           OR list_contains(s.tags,'doublepulsar'))::INT)  AS n_signals
  FROM bronze.shodan_scans s, unnest(s.domains) AS t(d)
  JOIN business b ON b.domain = t.d
  WHERE NOT list_contains(s.tags,'honeypot')
  GROUP BY t.d
)
SELECT n_signals, count(*) AS companies
FROM company GROUP BY n_signals ORDER BY n_signals;
-- OUTPUT: 0=428,544 | 1=44,078 | 2=27,703 | 3=2,443 | 4=821 | 5=213 | 6=53 | 7=1
--   → prospects (>=1 signal)=75,312 ; multi-signal (>=2)=31,234 (hotter leads) ;
--     hottest (>=3)=3,531. The score must rank breach + multi-signal to the top.


-- Q3. DRAFT LEAD SCORE + top 20 companies (validate the ranking looks sensible).
--   score = breach*40 + (cve? 15 + min(2/CVE,20)) + db*20 + eol*15
--           + self-signed*10 + vpn*8 + iot*8 + attack-surface(<=10)
WITH domain_ips AS (
  SELECT d AS domain, count(DISTINCT ip_str) AS ips
  FROM (SELECT unnest(domains) AS d, ip_str FROM bronze.shodan_scans
        WHERE NOT list_contains(tags,'honeypot')) GROUP BY d
),
business AS (
  SELECT domain FROM domain_ips
  WHERE NOT (ips >= 1000 OR regexp_matches(lower(domain),
    'usercontent|amazonaws|cloudfront|awsglobalaccelerator|awsdns|cloudapp|1e100|googleusercontent|cloudflar|incapdns|incapsula|imperva|akamai|edgekey|edgesuite|fastly|sucuri|hetzner|your-server|digitalocean|linode|vultr|scaleway|scw\.cloud|contabo|ovh\.|hostgator|bluehost|hostmonster|secureserver|hostinger|websitewelcome|webhostbox|kasserver|unifiedlayer|dreamhost|siteground|liquidweb|rackspace|inmotionhosting|myvps|xrea|stackcp|upcloud|kagoya|mwprem|sakura|xserver|lolipop|bizmw|znlc|etius|wixsite|wix\.com|squarespace|weebly|shopify|webflow|multiscreensite|herokuapp|netlify|vercel|wordpress|plesk|cpanel|hwclouds|\.cloud$|\.host$|localhost|notexist|traefik|invalid\.|example\.(com|net|org)|imap\.example'))
),
company AS (
  SELECT t.d AS company,
    count(*)                                     AS services,
    count(DISTINCT s.ip_str)                     AS hosts,
    len(list_distinct(flatten(array_agg(s.vulns)))) AS cve_count,
    max((list_contains(s.tags,'compromised') OR list_contains(s.tags,'c2')
         OR list_contains(s.tags,'doublepulsar'))::INT)                             AS breach,
    max(list_contains(s.tags,'database')::INT)                                      AS db,
    max((list_contains(s.tags,'eol-product') OR list_contains(s.tags,'eol-os'))::INT) AS eol,
    max(list_contains(s.tags,'self-signed')::INT)                                   AS selfsigned,
    max(list_contains(s.tags,'vpn')::INT)                                           AS vpn,
    max(list_contains(s.tags,'iot')::INT)                                           AS iot
  FROM bronze.shodan_scans s, unnest(s.domains) AS t(d)
  JOIN business b ON b.domain = t.d
  WHERE NOT list_contains(s.tags,'honeypot')
  GROUP BY t.d
),
scored AS (
  SELECT *,
    breach*40
    + CASE WHEN cve_count > 0 THEN 15 + least(cve_count*2, 20) ELSE 0 END
    + db*20 + eol*15 + selfsigned*10 + vpn*8 + iot*8
    + least(cast(round(log2(services + 1) * 3) AS INT), 10) AS score
  FROM company
)
SELECT company, score, cve_count, services, hosts, breach, db, eol, selfsigned, vpn, iot
FROM scored ORDER BY score DESC, services DESC LIMIT 20;
-- OUTPUT: top-20 were ALL leaked hosting/ISP (netia.com.pl, bell.ca, poneytelecom.eu,
--   ukfast.net, constant.com, hvvc.us...). A multi-tenant host aggregates thousands
--   of customers' signals (cve_count 200-1000, every flag on, breach=1), so leakage
--   DOMINATES the top of the score — customers' problems misattributed to the host.
--   Discriminator: cve_count separates — infra >=231 vs real <=140 (stanford 140,
--   ca.gov 31, amazon 7, walmart 0). Real companies don't have 200+ distinct CVEs.
--   FIX: add a multi-tenant heuristic (very high cve_count) + LLM-classify top-N.
