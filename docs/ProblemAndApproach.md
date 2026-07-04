# Problem & Approach

*Why Osprey exists, how B2B sales teams actually prospect, and why turning
internet-exposure data into a ranked prospect list is a defensible approach.*

---

## 1. The problem

A cybersecurity software company's sales team needs to know **which businesses to
target, and why**. Cold-calling a random list converts poorly. What converts is
reaching the *right* account at the *right* moment with a *relevant* reason.

The raw material we're given is a Shodan internet-scan dump (~9.2M scanned
services). Osprey's job: turn that into a **ranked list of prospect companies with
plain-English reasons** a rep can act on.

## 2. How B2B sales teams actually prospect (the space)

Modern outbound prospecting rests on four ideas:

1. **ICP (Ideal Customer Profile)** — firmographics: industry, size, geography,
   tech stack. "Who looks like a good-fit account."
2. **Intent data** — behavioural signals that an account is *in-market* (e.g.
   Bombora/6sense: they're researching your category).
3. **Trigger events** — a specific, timely change that creates a reason to reach
   out *now*: funding, a new hire, a breach, a compliance deadline. Trigger-based
   outreach is one of the highest-converting outbound motions because it's timely
   and specific.
4. **Prioritization + personalization** — rank by fit/urgency, and open with a
   concrete, relevant observation rather than a generic pitch.

Tools in the space split across these: exposure/security-ratings data (Shodan,
Censys, SecurityScorecard, BitSight), contact/firmographic data (ZoomInfo, Apollo,
Cognism, **Firmable**), and intent (6sense, Bombora). No single tool does it all;
teams stitch them together.

## 3. Osprey's thesis: exposure as a trigger-event signal

For a cybersecurity vendor, an **internet-facing exposure is a trigger event**. A
company with an exposed database, active-compromise indicators, or a stack of known
CVEs has a concrete, present reason to buy security services — and the vendor has a
concrete, credible reason to call.

So Osprey is a **signal + targeting + reasoning layer**:

- **Signal** — detect exposures from scan data (CVEs, exposed DBs, EOL software,
  weak certs, VPN/IoT, malware/C2 indicators).
- **Targeting** — resolve to real companies (domain-based), classify business vs
  infrastructure, segment, and rank by a transparent lead score.
- **Reasoning** — translate technical findings into sales language, and generate a
  grounded outreach pitch that cites the *actual* CVEs/products found.

This is trigger-based prospecting, automated from exposure data.

## 4. Competitive landscape (where Osprey sits)

| Layer | Players | Osprey |
|---|---|---|
| Exposure / ratings | Shodan, Censys, SecurityScorecard, BitSight | **Osprey is here** — but neutral (any vendor) and sales-facing, not a rating for the target's own use |
| Contacts / firmographics | ZoomInfo, Apollo, Cognism, **Firmable** | **Complement** — Osprey says *which company*; Firmable says *which person* |
| Intent | 6sense, Bombora | v2 — exposure is itself a strong intent proxy |

SecurityScorecard/BitSight already commercialized "we can see your weakness" as an
outbound wedge — but locked to selling *their* product. Osprey is a **neutral
targeting layer** any cybersecurity vendor can point at their own offering.

## 5. What Osprey does — and deliberately doesn't

**Does:** identify companies with a genuine technical need, rank them, explain why,
and draft grounded outreach.

**Doesn't (honest scope):**
- No **contact data** — that's Firmable's layer (join on domain).
- No **firmographics** (size/industry/revenue) → can't yet filter by deal-size ICP.
- No **severity ranking** — CVEs are counted, not yet weighted by *actively
  exploited* (KEV/NVD is v2).
- "Need" here means *has an exposure*, not *has budget and is in-market*.

These are named, not hidden — see [Architecture.md](../Architecture.md) roadmap.

## 6. Firmable fit

Osprey is the **top-of-funnel signal** ("call this company, here's why"); Firmable
is the **people layer** ("here's the CISO / IT head and how to reach them"). Join on
domain and you have an end-to-end prospecting motion — signal → account → contact →
grounded pitch. Complementary, not competitive.
