-- ============================================================================
-- data_profiling.sql
-- Every number we quote about the dataset comes from a query here.
-- Runs against the Bronze table `bronze.shodan_scans` in the DuckDB warehouse.
-- OUTPUT comments below were captured from the full 9,197,023-row load.
--
-- HOW TO RUN
--   Option A — DuckDB CLI (if installed):
--     duckdb data/warehouse/osprey.duckdb
--     D .read data/analysis/data_profiling.sql
--   or a single query:
--     duckdb data/warehouse/osprey.duckdb -c "SELECT count(*) FROM bronze.shodan_scans;"
--
--   Option B — Python (always works, uses our uv env):
--     uv run python -c "import duckdb; \
--       print(duckdb.connect('data/warehouse/osprey.duckdb', read_only=True) \
--       .sql('SELECT count(*) FROM bronze.shodan_scans').fetchall())"
-- ============================================================================


-- ---------------------------------------------------------------------------
-- A. VOLUME & COVERAGE
-- ---------------------------------------------------------------------------

-- A1. Total rows (one row = one scanned service)
SELECT count(*) AS total_rows FROM bronze.shodan_scans;
-- OUTPUT: total_rows = 9,197,023

-- A2. Coverage of each signal (how many rows actually carry it)
SELECT
  count(*)                                               AS total_rows,
  count(*) FILTER (WHERE len(domains) > 0)               AS with_domain,
  count(*) FILTER (WHERE ssl_cert_subject IS NOT NULL)   AS with_cert_subject,
  count(*) FILTER (WHERE len(vulns) > 0)                 AS with_cves,
  count(*) FILTER (WHERE product IS NOT NULL)            AS with_product,
  count(*) FILTER (WHERE len(tags) > 0)                  AS with_tags
FROM bronze.shodan_scans;
-- OUTPUT: total=9,197,023 | with_domain=6,243,809 | with_cert_subject=832,885
--         with_cves=191,263 | with_product=1,365,383 | with_tags=5,481,555

-- A3. Same as % of total
SELECT
  round(100.0 * count(*) FILTER (WHERE len(domains) > 0)             / count(*), 1) AS pct_domain,
  round(100.0 * count(*) FILTER (WHERE ssl_cert_subject IS NOT NULL) / count(*), 1) AS pct_cert,
  round(100.0 * count(*) FILTER (WHERE len(vulns) > 0)               / count(*), 1) AS pct_cves,
  round(100.0 * count(*) FILTER (WHERE product IS NOT NULL)          / count(*), 1) AS pct_product
FROM bronze.shodan_scans;
-- OUTPUT: pct_domain=67.9 | pct_cert=9.1 | pct_cves=2.1 | pct_product=14.8

-- A4. Scan time window (is this a snapshot or a time series?)
SELECT min(scanned_at) AS first_scan, max(scanned_at) AS last_scan FROM bronze.shodan_scans;
-- OUTPUT: first=2026-05-12 03:20:40 | last=2026-05-12 05:00:47  (single ~1.7h snapshot)


-- ---------------------------------------------------------------------------
-- B. IDENTITY — org vs domain vs certificate
-- ---------------------------------------------------------------------------

-- B1. Distinct counts of each identity candidate
SELECT count(DISTINCT org) AS distinct_orgs FROM bronze.shodan_scans;
-- OUTPUT: distinct_orgs = 93,153

SELECT count(DISTINCT d) AS distinct_domains
FROM (SELECT unnest(domains) AS d FROM bronze.shodan_scans);
-- OUTPUT: distinct_domains = 506,012

SELECT count(DISTINCT ssl_cert_subject) AS distinct_cert_subjects
FROM bronze.shodan_scans WHERE ssl_cert_subject IS NOT NULL;
-- OUTPUT: distinct_cert_subjects = 351,920

-- B2. Top orgs — proves `org` is mostly infrastructure, not real businesses
SELECT org, count(*) AS cnt
FROM bronze.shodan_scans
GROUP BY org ORDER BY cnt DESC LIMIT 15;
-- OUTPUT (all infra/hosting, not real businesses):
--   Google LLC 2,248,452 | Incapsula Inc 1,963,114 | Cloudflare 543,603
--   Aliyun 174,266 | METEVERSE LIMITED 139,571 | Korea Telecom 114,189
--   Deutsche Telekom 107,301 | Internet Rimon 103,462 | Meteverse Limited. 97,911
--   Aliyun Computing Co.LTD 85,283 | ACEVILLE PTE.LTD. 70,944 | Incapsula Inc. 70,305
--   Fly.io 66,043 | BT Infrastructure 62,520 | Amazon.com 62,184

-- B3. Top domains — most frequent are infra too; real businesses are the long tail
SELECT d AS domain, count(*) AS cnt
FROM (SELECT unnest(domains) AS d FROM bronze.shodan_scans)
GROUP BY d ORDER BY cnt DESC LIMIT 15;
-- OUTPUT (top ones are infra; real businesses live in the 506k long tail):
--   googleusercontent.com 2,212,812 | incapdns.net 1,664,695 | amazonaws.com 124,735
--   t-ipconnect.de 106,742 | imperva.com 97,183 | telecomitalia.it 77,899
--   flyio.net 74,746 | btcentralplus.com 73,484 | scw.cloud 61,584
--   vultrusercontent.com 52,630 | linodeusercontent.com 48,596 | sakura.ne.jp 47,714
--   ewe-ip-backbone.de 42,177 | unifiedlayer.com 38,786 | telefonica.de 34,065


-- ---------------------------------------------------------------------------
-- C. TECH — what is exposed
-- ---------------------------------------------------------------------------

-- C1. Top ports
SELECT port, count(*) AS cnt
FROM bronze.shodan_scans GROUP BY port ORDER BY cnt DESC LIMIT 15;
-- OUTPUT: 2087(Plesk) 401,066 | 7547(TR-069) 385,582 | 443(https) 348,354
--   80(http) 285,969 | 8089(splunk) 259,493 | 1701(L2TP vpn) 148,936 | 123(ntp) 123,676
--   9000 98,101 | 110(pop3) 97,439 | 8443 75,272 | 22(ssh) 71,920 | 8080 67,896
--   53(dns) 63,009 | 2083 55,506 | 8081 53,629

-- C2. Top products (software detected)
SELECT product, count(*) AS cnt
FROM bronze.shodan_scans WHERE product IS NOT NULL
GROUP BY product ORDER BY cnt DESC LIMIT 15;
-- OUTPUT: nginx 450,450 | ntpd 123,676 | OpenSSH 95,378 | Apache httpd 86,970
--   CloudFlare 69,537 | AWS ELB 28,045 | Postfix smtpd 25,090 | AkamaiGHost 24,038
--   Microsoft IIS 23,770 | CloudFront 21,790 | MySQL 21,412 | OpenResty 19,827
--   Socks4A 19,567 | Exim smtpd 18,999 | Squid proxy 17,459


-- ---------------------------------------------------------------------------
-- D. BUYING SIGNALS — what security pain can we see (this dataset only)
-- ---------------------------------------------------------------------------

-- D1. Every distinct tag and how common it is (tags are Shodan's own labels)
SELECT t AS tag, count(*) AS cnt
FROM (SELECT unnest(tags) AS t FROM bronze.shodan_scans)
GROUP BY t ORDER BY cnt DESC;
-- OUTPUT (24 tags):
--   cdn 2,688,345 | cloud 2,377,122 | starttls 193,243 | self-signed 101,757
--   honeypot 94,240 | eol-product 69,970 | proxy 50,814 | database 50,563
--   iot 11,737 | vpn 11,533 | devops 3,161 | eol-os 2,639 | open-dir 1,139
--   videogame 1,103 | ai 1,101 | ics 784 | tor 766 | doublepulsar 304 | c2 301
--   cryptocurrency 161 | compromised 77 | ssh-bad-key 70 | scanner 69 | medical 12

-- D2. Rows per specific security signal we care about
SELECT
  count(*) FILTER (WHERE len(vulns) > 0)                       AS has_cve,
  count(*) FILTER (WHERE list_contains(tags, 'eol-product'))  AS eol_product,
  count(*) FILTER (WHERE list_contains(tags, 'eol-os'))       AS eol_os,
  count(*) FILTER (WHERE list_contains(tags, 'self-signed'))  AS self_signed,
  count(*) FILTER (WHERE list_contains(tags, 'database'))     AS db_exposed,
  count(*) FILTER (WHERE list_contains(tags, 'vpn'))          AS vpn_exposed,
  count(*) FILTER (WHERE list_contains(tags, 'iot'))          AS iot_exposed,
  count(*) FILTER (WHERE list_contains(tags, 'honeypot'))     AS honeypots
FROM bronze.shodan_scans;
-- OUTPUT: has_cve=191,263 | eol_product=69,970 | eol_os=2,639 | self_signed=101,757
--         db_exposed=50,563 | vpn_exposed=11,533 | iot_exposed=11,737 | honeypots=94,240

-- D3. Total distinct CVEs seen, and the most common ones
SELECT count(DISTINCT c) AS distinct_cves
FROM (SELECT unnest(vulns) AS c FROM bronze.shodan_scans);
-- OUTPUT: distinct_cves = 10,468

SELECT c AS cve, count(*) AS cnt
FROM (SELECT unnest(vulns) AS c FROM bronze.shodan_scans)
GROUP BY c ORDER BY cnt DESC LIMIT 15;
-- OUTPUT (top CVEs by #services affected):
--   CVE-2008-3844 44,679 | CVE-2007-2768 44,679 | CVE-2023-51767 44,679
--   CVE-2026-35387 43,870 | CVE-2026-35385 43,870 | CVE-2026-35414 43,870
--   CVE-2026-35386 43,870 | CVE-2026-35388 43,870 | CVE-2023-48795 41,476
--   CVE-2023-51385 41,038 | CVE-2023-38408 40,996 | CVE-2021-36368 40,708
--   CVE-2025-26465 40,707 | CVE-2016-20012 40,626 | CVE-2025-32728 40,533
