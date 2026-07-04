-- ============================================================================
-- company_resolution.sql
-- Turning scan rows into real prospect COMPANIES: is `domains` a usable key,
-- how much is infra, does the certificate help, and the FINAL binary classifier
-- (business vs infra) that Silver will use.
-- Runs against `bronze.shodan_scans`. To run, see docs/helper_commands.md.
-- OUTPUT comments captured from the full 9,197,023-row load.
-- ============================================================================


-- ---------------------------------------------------------------------------
-- A. IS `domains` A USABLE COMPANY KEY?
-- ---------------------------------------------------------------------------

-- Q1. Are Shodan `domains` already registrable (like abc.com, not www.abc.com)?
SELECT len(string_split(d, '.')) AS labels, count(*) AS cnt
FROM (SELECT unnest(domains) AS d FROM bronze.shodan_scans)
GROUP BY 1 ORDER BY cnt DESC LIMIT 6;
-- OUTPUT: 2 labels=7,157,404 | 3 labels=471,704 | 4=3,711 | 5=313
--   → ~94% are 2-label (abc.com); Shodan `domains` is already ~registrable.
--     3-label are mostly ccTLDs (co.uk, com.au) — `domains` is a solid company key.


-- ---------------------------------------------------------------------------
-- B. THE INFRA POLLUTION PROBLEM
-- ---------------------------------------------------------------------------

-- Q2. Company funnel with a tiny starter blocklist: all -> non-infra -> prospects.
WITH infra AS (SELECT ['googleusercontent.com','incapdns.net','amazonaws.com','imperva.com',
    'flyio.net','scw.cloud','vultrusercontent.com','linodeusercontent.com','cloudfront.net',
    'sakura.ne.jp','t-ipconnect.de','telecomitalia.it','btcentralplus.com','ewe-ip-backbone.de',
    'telefonica.de','unifiedlayer.com'] AS blk),
exploded AS (
  SELECT unnest(domains) AS domain,
    (len(vulns) > 0 OR list_contains(tags,'eol-product') OR list_contains(tags,'eol-os')
      OR list_contains(tags,'self-signed') OR list_contains(tags,'database')
      OR list_contains(tags,'vpn') OR list_contains(tags,'iot')
      OR list_contains(tags,'compromised') OR list_contains(tags,'c2')
      OR list_contains(tags,'doublepulsar')) AS has_signal,
    list_contains(tags,'honeypot') AS is_honeypot
  FROM bronze.shodan_scans
)
SELECT
  count(DISTINCT domain)                                          AS all_domains,
  count(DISTINCT domain) FILTER (WHERE NOT list_contains((SELECT blk FROM infra), domain)) AS non_infra_domains,
  count(DISTINCT domain) FILTER (WHERE has_signal AND NOT is_honeypot
        AND NOT list_contains((SELECT blk FROM infra), domain))  AS prospect_companies_with_signal
FROM exploded;
-- OUTPUT: all_domains=506,012 | non_infra_domains=505,996 | prospect_companies_with_signal=75,931
--   → ~75,931 real companies already carry a buying signal — a rich prospect base.

-- Q3. Top domains after that tiny blocklist — shows infra still dominates the head.
WITH infra AS (SELECT ['googleusercontent.com','incapdns.net','amazonaws.com','imperva.com',
    'flyio.net','scw.cloud','vultrusercontent.com','linodeusercontent.com','cloudfront.net',
    'sakura.ne.jp','t-ipconnect.de','telecomitalia.it','btcentralplus.com','ewe-ip-backbone.de',
    'telefonica.de','unifiedlayer.com'] AS blk)
SELECT d AS domain, count(*) AS cnt
FROM (SELECT unnest(domains) AS d FROM bronze.shodan_scans)
WHERE NOT list_contains((SELECT blk FROM infra), d)
GROUP BY d ORDER BY cnt DESC LIMIT 20;
-- OUTPUT (head still infra/ISP/hosting; real ones rare):
--   your-server.de 33,036 (Hetzner) | walmart.com 31,348 (REAL) | spectrum.com 29,456 (ISP)
--   akamaitechnologies.com 26,247 | bluehost.com 22,681 | frontiernet.net 22,555 (ISP)
--   secureserver.net 22,133 (GoDaddy) | nuro.jp 20,364 (ISP) | ovh.net 12,266 | hostgator.com 11,306
--   → Frequency alone can't separate infra from real (walmart is also high-volume).


-- ---------------------------------------------------------------------------
-- C. CERTIFICATE AS AN IDENTITY SOURCE (issued to a specific real entity)
-- ---------------------------------------------------------------------------

-- Q4. Coverage + agreement between `domains` and `ssl_cert_subject`.
SELECT
  count(*)                                                          AS total,
  count(*) FILTER (WHERE len(domains) > 0)                          AS with_domain,
  count(*) FILTER (WHERE ssl_cert_subject IS NOT NULL)              AS with_cert,
  count(*) FILTER (WHERE len(domains) = 0 AND ssl_cert_subject IS NOT NULL) AS cert_but_no_domain,
  count(*) FILTER (WHERE ssl_cert_subject IS NOT NULL AND len(domains) > 0
      AND len(list_filter(domains, d -> lower(ssl_cert_subject) = lower(d)
            OR lower(ssl_cert_subject) LIKE '%.' || lower(d))) > 0)  AS cert_agrees_domain,
  count(*) FILTER (WHERE ssl_cert_subject IS NOT NULL AND len(domains) > 0
      AND len(list_filter(domains, d -> lower(ssl_cert_subject) = lower(d)
            OR lower(ssl_cert_subject) LIKE '%.' || lower(d))) = 0)  AS cert_differs_domain
FROM bronze.shodan_scans;
-- OUTPUT: total=9,197,023 | with_domain=6,243,809 | with_cert=832,885
--         cert_but_no_domain=85,340 | cert_agrees_domain=662,372 | cert_differs_domain=85,173
--   → ~80% of cert rows AGREE with a domain (cross-validation + a "real business"
--     signal); 85,340 recover identity where domains is empty; 85,173 name the real
--     company hidden behind a CDN/infra domain.

-- Q5. Distinct cert-derived identities where `domains` is empty (recovered companies).
SELECT count(DISTINCT lower(ssl_cert_subject)) AS distinct_cert_ids_when_no_domain
FROM bronze.shodan_scans
WHERE len(domains) = 0 AND ssl_cert_subject IS NOT NULL;
-- OUTPUT: distinct_cert_ids_when_no_domain = 54,054  (extra companies from certs)


-- ---------------------------------------------------------------------------
-- D. FINAL BINARY CLASSIFIER — business vs infra  (Silver will use this rule)
--   A domain is INFRA if:
--     (a) it spans a large IP footprint (>= 1000 distinct IPs) — generalises to
--         cloud / CDN / ISP providers we never named; OR
--     (b) it matches an infra keyword — catches LOW-IP infra the footprint rule
--         misses (site-builders like wix/shopify/weebly, shared hosts, junk certs).
--   Conservative on keywords so real businesses aren't wrongly killed. Residual
--   (shared hosts with generic names, niche ISPs) is left to the LLM classifier.
-- ---------------------------------------------------------------------------

-- Q6. business vs infra distribution + prospect count (business with a signal).
WITH domain_agg AS (
  SELECT d AS domain, count(DISTINCT ip_str) AS ips, count(*) AS rows_cnt,
         max(sig::INT)::BOOL AS has_signal
  FROM (SELECT unnest(domains) AS d, ip_str,
     (len(vulns) > 0 OR list_contains(tags,'eol-product') OR list_contains(tags,'eol-os')
      OR list_contains(tags,'self-signed') OR list_contains(tags,'database')
      OR list_contains(tags,'vpn') OR list_contains(tags,'iot')
      OR list_contains(tags,'compromised') OR list_contains(tags,'c2')
      OR list_contains(tags,'doublepulsar')) AS sig
   FROM bronze.shodan_scans WHERE NOT list_contains(tags,'honeypot')) GROUP BY d
),
classified AS (
  SELECT *, (ips >= 1000 OR regexp_matches(lower(domain),
    'usercontent|amazonaws|cloudfront|awsglobalaccelerator|awsdns|cloudapp|1e100|googleusercontent|cloudflar|incapdns|incapsula|imperva|akamai|edgekey|edgesuite|fastly|sucuri|hetzner|your-server|digitalocean|linode|vultr|scaleway|scw\.cloud|contabo|ovh\.|hostgator|bluehost|hostmonster|secureserver|hostinger|websitewelcome|webhostbox|kasserver|unifiedlayer|dreamhost|siteground|liquidweb|rackspace|inmotionhosting|myvps|xrea|stackcp|upcloud|kagoya|mwprem|sakura|xserver|lolipop|bizmw|znlc|etius|wixsite|wix\.com|squarespace|weebly|shopify|webflow|multiscreensite|herokuapp|netlify|vercel|wordpress|plesk|cpanel|hwclouds|\.cloud$|\.host$|localhost|notexist|traefik|invalid\.|example\.(com|net|org)|imap\.example')) AS is_infra
  FROM domain_agg
)
SELECT CASE WHEN is_infra THEN 'infra' ELSE 'business' END AS entity_class,
       count(*) AS domains, sum(rows_cnt) AS rows_cnt,
       count(*) FILTER (WHERE has_signal) AS domains_with_signal
FROM classified GROUP BY 1 ORDER BY domains DESC;
-- OUTPUT: business 503,856 domains | 2,138,571 rows | 75,312 with_signal
--         infra    2,131   domains | 5,462,898 rows |    635 with_signal
--   → ~72% of rows are infra; 503,856 business domains, 75,312 real prospects.

-- Q7. Sanity: top BUSINESS domains by footprint — should be real companies.
WITH domain_agg AS (
  SELECT d AS domain, count(DISTINCT ip_str) AS ips, count(*) AS rows_cnt
  FROM (SELECT unnest(domains) AS d, ip_str FROM bronze.shodan_scans
        WHERE NOT list_contains(tags,'honeypot')) GROUP BY d
),
classified AS (
  SELECT *, (ips >= 1000 OR regexp_matches(lower(domain),
    'usercontent|amazonaws|cloudfront|awsglobalaccelerator|awsdns|cloudapp|1e100|googleusercontent|cloudflar|incapdns|incapsula|imperva|akamai|edgekey|edgesuite|fastly|sucuri|hetzner|your-server|digitalocean|linode|vultr|scaleway|scw\.cloud|contabo|ovh\.|hostgator|bluehost|hostmonster|secureserver|hostinger|websitewelcome|webhostbox|kasserver|unifiedlayer|dreamhost|siteground|liquidweb|rackspace|inmotionhosting|myvps|xrea|stackcp|upcloud|kagoya|mwprem|sakura|xserver|lolipop|bizmw|znlc|etius|wixsite|wix\.com|squarespace|weebly|shopify|webflow|multiscreensite|herokuapp|netlify|vercel|wordpress|plesk|cpanel|hwclouds|\.cloud$|\.host$|localhost|notexist|traefik|invalid\.|example\.(com|net|org)|imap\.example')) AS is_infra
  FROM domain_agg
)
SELECT domain, ips, rows_cnt FROM classified WHERE NOT is_infra
ORDER BY rows_cnt DESC LIMIT 25;
-- OUTPUT (real companies now surface; a few shared-hosts still leak -> LLM residual):
--   walmart.com 341ip | stanford.edu 41 | intersourcing.com 20 | amazon.com 565
--   automattic.com 461 | ca.gov 613  ← REAL businesses / orgs
--   leaks: coreserver.jp, sureserver.com, justhost.com, hostdime.com, eigbox.net
--          (moderate IPs + generic names — need semantic judgment = LLM)
