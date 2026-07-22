# DREAD Risk Scoring

DREAD prioritises threats by scoring five factors from **1–10** each. Sum the
five for a **0–50 total**, then map to a priority. Justify every sub-score from
the specific threat and system context — a score without a rationale is not done.

## The five criteria

| Factor | Question | Scale (1 → 10) | Consider |
|--------|----------|----------------|----------|
| **Damage** | How bad would an attack be? | minimal damage → complete system compromise | financial impact, data sensitivity, regulatory consequences, business continuity |
| **Reproducibility** | How easy is it to reproduce? | very difficult → very easy | attack complexity, required tools/skills, environmental dependencies |
| **Exploitability** | How much work to launch? | very hard → very easy | technical skill required, time investment, resource requirements |
| **Affected Users** | How many users impacted? | few users → all users | user base size, impact scope, cascading effects |
| **Discoverability** | How easy to discover? | very hard → very easy | visibility of attack surface, documentation availability, common vulnerability |

## Risk levels (from the total)

| Total | Priority | Meaning |
|-------|----------|---------|
| 40–50 | **Critical** | Immediate action required |
| 30–39 | **High** | High priority for remediation |
| 20–29 | **Medium** | Medium priority |
| 5–19 | **Low** | Low priority but should be addressed |

## Calibration bands

Anchor each sub-score against these bands rather than guessing:

**Damage** — 1–3 minimal (single user, non-critical, easily recoverable) ·
4–6 moderate (multiple users, important functionality, recovery required) ·
7–9 high (most users, critical functionality, difficult recovery) ·
10 catastrophic (complete compromise, all users, irrecoverable).

**Reproducibility** — 1–3 difficult (specific timing, race conditions, rare
circumstances) · 4–6 moderate (specific configuration or user actions) ·
7–9 easy (reproducible with standard tools and documentation) ·
10 always (100% reproducible, deterministic).

**Exploitability** — 1–3 expert (deep expertise, custom tools, significant time) ·
4–6 intermediate (moderate skill, some tool customization) · 7–9 basic (standard
tools/scripts available, minimal expertise) · 10 trivial (no skill required,
fully automated tools exist).

**Affected Users** — 1–3 few (< 10% of users, isolated) · 4–6 some (10–50%,
limited scope) · 7–9 most (50–90%, widespread) · 10 all (100%, system-wide).

**Discoverability** — 1–3 hidden (source review, insider knowledge, deep
analysis) · 4–6 obscure (investigation, testing, or documentation review) ·
7–9 obvious (visible through normal usage or basic testing) · 10 public
(documented, well-known, or immediately apparent).

## Worked examples

**SQL Injection in public-facing API endpoint** (e-commerce, customer database)
— Damage 10 (full DB compromise, PII + financial theft), Reproducibility 9
(SQLMap, well-documented), Exploitability 8 (basic SQL, public exploits),
Affected Users 10 (entire database), Discoverability 9 (OWASP Top 10, scanners).
**Total 46 → Critical.**

**Insufficient audit logging for admin actions** (internal business app) —
Damage 6 (undetected malicious activity, forensics/compliance risk),
Reproducibility 10 (logging present or not), Exploitability 5 (needs legit admin
access first), Affected Users 7 (impairs incident response for all), 
Discoverability 6 (needs code/documentation review). **Total 34 → High.**

**Weak password policy** (6 chars, no complexity; consumer web app) — Damage 7,
Reproducibility 8, Exploitability 7, Affected Users 6, Discoverability 8.
**Total 36 → High.**

**Missing CSRF protection on a low-impact form** (user preference update) —
Damage 3, Reproducibility 8, Exploitability 6, Affected Users 4, Discoverability
7. **Total 28 → Medium.**

**Information disclosure via verbose error messages** (stack traces in
production) — Damage 5, Reproducibility 7, Exploitability 6, Affected Users 5,
Discoverability 8. **Total 31 → High.**
