# Stage 4 — Company Resolution (Identity)

Turn scan rows (service grain) into **real prospect companies**. This is the
*identity* half of the Silver design; all numbers are SQL-verified in
[`data/analysis/company_resolution.sql`](../data/analysis/company_resolution.sql).

---

## 1. The problem

`org` is not the company — it is mostly infrastructure (Google, Incapsula,
Cloudflare hold the top spots). Grouping leads by `org` gives a useless list. We
must resolve the *real end-business* behind each scanned service.

---

## 2. Identity columns available

| Column | Gives | Infra risk |
|---|---|---|
| `domains` | Registered domain (`escalade-climbing.com`) | Medium (e.g. `googleusercontent.com` leaks in) |
| `hostnames` | Full hostname (often an infra PTR) | High |
| **`ssl_cert_subject`** | Certificate CN — issued to a specific real entity | **Low — strongest** |
| `org` / `isp` | Network owner | Very high |

---

## 3. Findings (SQL-verified)

- **`domains` is a solid key.** ~94% of domain values are 2-label registrable
  (`abc.com`); 3-label are mostly ccTLDs (`co.uk`). No separate eTLD extraction
  needed. → 506,012 distinct domains.
- **Prospect base is rich.** After removing infra, **75,931 companies** already
  carry at least one buying signal (honeypots excluded).
- **Infra pollution is concentrated in the head.** Even after a blocklist, the
  highest-footprint domains are still hosting/ISP/CDN (`your-server.de`,
  `secureserver.net`, ISPs). Real businesses (`walmart.com`, `stanford.edu`)
  appear but are rare in the head — **frequency alone cannot separate them**.
- **Certificates add real value:**
  - **662,372** cert rows (~80%) *agree* with a listed domain → cert
    cross-validates identity and is a strong "real business" signal.
  - **85,340** rows have a cert but no domain → identity recovered, giving
    **54,054** additional candidate companies.
  - **85,173** rows where the cert names something the domain doesn't → the real
    company hidden **behind a CDN/infra domain**.

---

## 4. Resolution strategy

**Company key — priority order:**

1. A non-infra registrable domain from `domains`.
2. Else a real domain from `ssl_cert_subject` (recovers the 54k, and unmasks the
   business behind a CDN domain).
3. Else unattributable → dropped (or `org` as a weak last-resort fallback).

---

## 5. Entity classification — binary `business` vs `infra`

We label each domain with a **binary** class (not three-way). A tri-colour scheme
was tried first, but the data showed both `domains` *and* certificates are equally
infra-polluted at the head, and the middle "uncertain" bucket was mostly ISPs —
which we exclude anyway (their IPs belong to broadband *customers*, not the ISP).
So the real question is binary: **prospect or not**.

A domain is **`infra`** if either rule fires:

1. **IP-footprint** — `distinct_ips >= 1000`. Providers (cloud / CDN / ISP) span
   thousands of IPs; real businesses span a handful (walmart 341, stanford 41,
   escalade-climbing 1). This **generalises to providers we never named**.
2. **Keyword** — matches an infra keyword. Catches **low-IP** infra the footprint
   rule misses: site-builders (`wix`, `shopify`, `weebly`), shared hosts, and
   junk/default certs (`localhost`, `traefik`, `example.com`).

Otherwise → **`business`** (a prospect). Rules are kept **conservative** so a real
company is never wrongly killed; the certificate is used as a positive identity
signal and to recover identity where `domains` is empty.

**Result (SQL-verified):** `business` = 503,856 domains (**75,312** carry a buying
signal → the prospect base); `infra` = 2,131 domains but **5,462,898 rows (~72%)**
— i.e. a few provider domains carry most of the noise.

---

## 6. Limitations & next

- The deterministic rules get us a strong base, but a **residual of shared hosts
  with generic names** (e.g. `coreserver.jp`, `justhost.com`, `hostdime.com`) has
  moderate IP counts and no obvious keyword — it leaks into `business`. Lowering
  the IP threshold to catch them would wrongly kill real companies (walmart = 341
  IPs), so pure rules cannot separate these.
- Planned enhancement: an **LLM classifier for that residual** (ambiguous
  domains), with a labelled eval set — the "rules first, LLM where it earns its
  place" pattern. Deferred; the `business` set is already usable for the prototype.
