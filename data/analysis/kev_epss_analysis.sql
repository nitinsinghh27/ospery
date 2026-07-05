-- ============================================================================
-- KEV / EPSS ANALYSIS — do these third-party feeds actually discriminate prospects?
--
-- The v2 connectors add two exploitation signals on top of raw CVE counts:
--   reference.kev  — CISA Known Exploited Vulnerabilities (actively exploited in the wild)
--   reference.epss — FIRST EPSS score (modelled 30-day exploit probability, per CVE)
-- This file backs the design decision (Architecture §7): KEV boosts the lead score
-- (+30) and leads the reasons, but EPSS is used only for the pitch/display, NOT the
-- score — because among these exposure-heavy prospects EPSS>=0.5 is near-universal,
-- so it barely ranks anyone above anyone else.
--
-- Runs against silver.silver_company_candidates + reference.kev/epss + enrichment
-- .entity_labels (NOT bronze — these are post-silver signals). To run, see
-- docs/helper_commands.md. OUTPUT comments captured from the current warehouse.
-- ============================================================================


-- ----------------------------------------------------------------------------
-- A. CONNECTOR SANITY — did the feeds land?
-- ----------------------------------------------------------------------------

-- Q1. Catalog sizes (how much reference data each feed brought in).
SELECT
    (SELECT count(*) FROM reference.kev)  AS kev_cves,
    (SELECT count(*) FROM reference.epss) AS epss_rows;
-- OUTPUT: kev_cves = 1,631 | epss_rows = 345,610
--   KEV is a small curated list (actively-exploited only); EPSS scores ~every CVE.


-- ----------------------------------------------------------------------------
-- B. THE PROSPECT SET  (mirrors gold_companies.sql: business, not flagged, >=1 signal)
--    Reused by every query below.
-- ----------------------------------------------------------------------------
-- WITH prospects AS (
--   SELECT c.*
--   FROM silver.silver_company_candidates c
--   JOIN enrichment.entity_labels l ON l.domain = c.domain
--   WHERE l.entity_class = 'business' AND NOT l.flagged
--     AND (c.has_cve + c.has_eol + c.has_db + c.has_selfsigned
--          + c.has_vpn + c.has_iot + c.has_breach) > 0
-- )


-- Q2. KEV coverage — how many prospects carry an actively-exploited CVE.
WITH prospects AS (
    SELECT c.*
    FROM silver.silver_company_candidates c
    JOIN enrichment.entity_labels l ON l.domain = c.domain
    WHERE l.entity_class = 'business' AND NOT l.flagged
      AND (c.has_cve + c.has_eol + c.has_db + c.has_selfsigned
           + c.has_vpn + c.has_iot + c.has_breach) > 0
)
SELECT
    count(*)                                        AS prospects,
    count(*) FILTER (WHERE kev_count > 0)           AS with_kev,
    round(100.0 * count(*) FILTER (WHERE kev_count > 0) / count(*), 1) AS pct_kev
FROM prospects;
-- OUTPUT: prospects = 3,973 | with_kev = 3,439 | pct_kev = 86.6
--   High (exposure-heavy population), but KEV is authoritative + binary ("exploited
--   in the wild"), so it still earns the +30 boost and leads the sales reasons.


-- ----------------------------------------------------------------------------
-- C. THE DECISION — why EPSS is NOT in the lead score
-- ----------------------------------------------------------------------------

-- Q3. Peak-EPSS distribution among prospects that HAVE a CVE. If almost all of them
--     clear a high threshold, EPSS can't separate them → useless as a score input.
WITH prospects AS (
    SELECT c.*
    FROM silver.silver_company_candidates c
    JOIN enrichment.entity_labels l ON l.domain = c.domain
    WHERE l.entity_class = 'business' AND NOT l.flagged
      AND (c.has_cve + c.has_eol + c.has_db + c.has_selfsigned
           + c.has_vpn + c.has_iot + c.has_breach) > 0
)
SELECT
    count(*) FILTER (WHERE cve_count > 0)                              AS with_cve,
    count(*) FILTER (WHERE cve_count > 0 AND max_epss >= 0.5)          AS epss_ge_50,
    count(*) FILTER (WHERE cve_count > 0 AND max_epss >= 0.9)          AS epss_ge_90,
    count(*) FILTER (WHERE cve_count > 0 AND (max_epss < 0.5 OR max_epss IS NULL)) AS epss_lt_50,
    round(100.0 * count(*) FILTER (WHERE cve_count > 0 AND max_epss >= 0.5)
          / nullif(count(*) FILTER (WHERE cve_count > 0), 0), 1)       AS pct_ge_50,
    round(100.0 * count(*) FILTER (WHERE cve_count > 0 AND max_epss >= 0.9)
          / nullif(count(*) FILTER (WHERE cve_count > 0), 0), 1)       AS pct_ge_90
FROM prospects;
-- OUTPUT: with_cve = 3,971 | epss_ge_50 = 3,822 | epss_ge_90 = 3,718 | epss_lt_50 = 149
--         pct_ge_50 = 96.2 | pct_ge_90 = 93.6
--
-- FINDING: 96% of prospects with a CVE peak at EPSS >= 0.5 and 94% at >= 0.9. A signal
-- that fires for ~everyone is a weak *ranking* input — adding it to the score would
-- shift almost every prospect by the same amount and change no ordering.
--
-- DECISION: use EPSS for the *pitch and detail view* ("carries a 97% EPSS score" is a
-- concrete, credible line for a rep) and keep it OUT of the lead score. KEV (86.6%,
-- authoritative) stays in the score. This is the "third-party data where it sharpens
-- the signal, not where it just adds noise" principle — stated, and now SQL-backed.
