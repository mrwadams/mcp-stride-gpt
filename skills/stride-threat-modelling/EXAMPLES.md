# Worked Example

A single system carried through the whole [`SKILL.md`](SKILL.md) workflow, in the
house style. It anchors the **format and depth** each step should reach — it is
**illustrative and partial**, not a claim of exhaustive coverage: the threat set is
trimmed to a representative spread across the six STRIDE categories and the system's
trust boundaries. A real run enumerates every element against every category.

---

## Sample system

**TaskFlow** — a small multi-tenant SaaS task manager.

- **React SPA** in the browser, served from a CDN.
- **REST API** (Node/Express), cloud-hosted (AWS ECS), internet-facing.
- **PostgreSQL**, multi-tenant with a `tenant_id` column on every row.
- **Auth0** (third-party IdP) for OAuth 2.0 / OIDC login; the API accepts JWT bearer
  tokens.
- **Stripe** for billing, via its API and an inbound webhook.
- **Sensitive data:** customer PII (names, emails), user task content, Stripe customer
  IDs, and the JWTs themselves.

---

## Step 1 — Scope

**Elements**

- *External entities:* end user (browser), Auth0, Stripe.
- *Processes:* React SPA, REST API.
- *Data stores:* PostgreSQL.
- *Data flows:* browser ↔ API (HTTPS); API ↔ PostgreSQL; API ↔ Auth0 (OAuth); API ↔
  Stripe (outbound API + inbound webhook).

**Trust boundaries**

- **TB1** browser (untrusted client) → REST API — the public internet edge.
- **TB2** REST API → PostgreSQL — application-to-data.
- **TB3** REST API ↔ Auth0 — application-to-third-party IdP.
- **TB4** REST API ↔ Stripe — application-to-third-party payments (inbound webhook).
- **TB5** tenant → tenant — logical isolation between customers sharing the database.

*Done:* every component maps to an element, and every point where trust changes is a
named boundary.

---

## Step 2 — Enumerate (STRIDE-per-element)

Each element was walked against all six categories; the threats that genuinely apply
are below, one per category to show the spread. Categories that do not apply are
recorded explicitly — e.g. for the CDN-served SPA, **Repudiation — N/A** (no
state-changing action happens client-side; every mutation goes through an
authenticated, server-logged API call).

| ID | STRIDE | Boundary | Threat |
|----|--------|----------|--------|
| TF-01 | Spoofing | TB1 / TB3 | A stolen or replayed JWT bearer token (long expiry, no token binding) lets an attacker impersonate a user at the API. |
| TF-02 | Tampering | TB1 → API | SQL injection in the task-search endpoint (`q` param concatenated into a dynamic query) allows arbitrary SQL against the tenant database. |
| TF-03 | Repudiation | TB4 | The Stripe billing webhook has no signature verification or audit trail, so a disputed plan change cannot be attributed to a genuine event. |
| TF-04 | Information Disclosure | API error handling | Verbose error responses in production leak stack traces, the DB schema, and PII. |
| TF-05 | Denial of Service | TB1 → API | No rate limiting on the token-exchange/login endpoint; credential-stuffing and request floods exhaust API and database capacity. |
| TF-06 | Elevation of Privilege | TB5 | Missing tenant scoping (broken object-level authorization): an authenticated tenant-A user reads or modifies tenant-B tasks by changing the resource ID. |

*Done:* every element considered against all six categories; each threat names a
concrete element or flow — none is boilerplate.

---

## Step 3 — DREAD

Scored per [`references/dread-scoring.md`](references/dread-scoring.md); every sub-score
is anchored to a calibration band and justified from context.

| ID | D | R | E | A | Di | Total | Priority |
|----|---|---|---|---|----|-------|----------|
| TF-02 | 9 | 9 | 8 | 9 | 9 | **44** | Critical |
| TF-06 | 8 | 9 | 7 | 8 | 7 | **39** | High |
| TF-05 | 6 | 8 | 7 | 8 | 7 | **36** | High |
| TF-03 | 4 | 10 | 5 | 6 | 6 | **31** | High |
| TF-04 | 5 | 7 | 6 | 5 | 8 | **31** | High |
| TF-01 | 7 | 6 | 5 | 5 | 6 | **29** | Medium |

Rationale (two shown; a full model justifies all five sub-scores for every threat):

- **TF-02 — Total 44, Critical.** Damage 9 (full read/write of the tenant DB incl.
  PII, cross-tenant if the query is unscoped — short of 10 only because the surrounding
  infrastructure isn't compromised). Reproducibility 9 and Exploitability 8 (SQLMap and
  public payloads; basic SQL knowledge). Affected Users 9 (everyone with data in the
  database). Discoverability 9 (OWASP Top 10; automated scanners flag it).
- **TF-03 — Total 31, High.** Damage 4 (billing disputes and a compliance gap rather
  than direct data loss). Reproducibility 10 (the control is binary — verification and
  logging are either present or absent). Exploitability 5 (needs knowledge of the
  webhook). Affected Users 6 (undermines incident response and billing integrity
  broadly). Discoverability 6 (requires code/config review).

*Done:* every threat has five justified sub-scores, a total, and a priority.

---

## Step 4 — Mitigations

Highest priority first; defence-in-depth (see
[`references/mitigations.md`](references/mitigations.md)).

- **TF-02 (Critical)** — *Preventive:* parameterise every query / use the ORM's bound
  parameters; never concatenate request input into SQL (Easy, High). Add an allowlist
  on the `q` grammar (Easy, Medium). *Detective:* WAF rule + database query-anomaly
  alerting (Medium, Medium).
- **TF-06 (High)** — *Preventive:* enforce `tenant_id` scoping in a single data-access
  layer and back it with PostgreSQL row-level security so no query can span tenants
  (Medium, High). *Detective:* alert on any query returning another tenant's rows
  (Medium, Medium).
- **TF-05 (High)** — *Preventive:* rate-limit at the API gateway with stricter
  per-account throttling on auth endpoints (Easy, High). *Detective:* traffic-spike and
  failed-login-rate alerting (Easy, Medium).

*Done:* every High/Critical threat has at least one concrete, implementable mitigation.

---

## Step 5 — Attack tree (top Critical threat, TF-02)

Text form per [`references/attack-trees.md`](references/attack-trees.md):

```
Goal: Exfiltrate the tenant task database via SQL injection
├── [OR] Inject via the task-search `q` parameter
│   ├── Discover the injectable parameter (error-based probing)   [prereq: any account]
│   └── Extract rows with UNION/blind SQLi (SQLMap)               [prereq: injectable query + network access]
└── [OR] Inject via the reporting/export filter
    ├── Manipulate a filter bound into dynamic SQL
    └── Dump adjacent tenant rows                                  [prereq: query not tenant-scoped]
```

*Done:* the Critical threat has a tree that bottoms out in concrete prerequisites.

---

## Step 7 — Coverage validation

Audited against [`references/coverage-validation.md`](references/coverage-validation.md).
Gap found: **data in transit on TB2 (API → PostgreSQL)** was not initially considered.
Resolved by adding a threat — *Information Disclosure: unencrypted API↔DB traffic on the
private subnet* — and its mitigation (enforce TLS to PostgreSQL). No other STRIDE
category/boundary pair was left unconsidered; the SPA's Repudiation N/A is recorded.

*Done:* each identified gap is filled or explicitly scoped out with a reason.

---

## Step 8 — Report excerpt

The workflow assembles the full deliverable per
[`references/report-format.md`](references/report-format.md). An excerpt showing the
house style:

```markdown
# STRIDE Threat Model Report

## Executive Summary
TaskFlow was assessed across six trust boundaries. Six representative threats were
identified spanning all STRIDE categories: **1 Critical, 4 High, 1 Medium**. The
Critical finding is SQL injection in the task-search endpoint (TF-02, DREAD 44),
which exposes the entire multi-tenant database. Immediate action: parameterise all
queries and enable PostgreSQL row-level tenant scoping. ...

## Threat Analysis
### Information Disclosure Threats
**TF-04 — Verbose production error messages.** The API returns stack traces and SQL
error detail to clients, leaking the schema and PII. *Attack scenario:* an attacker
submits malformed input and reads table and column names from the error body.
*Impact:* accelerates other attacks (e.g. TF-02) and directly discloses PII.

## Risk Assessment
### Critical Priority Threats (DREAD: 40-50)
| ID | Threat | DREAD |
|----|--------|-------|
| TF-02 | SQL injection in task-search | 44 |
```

*Done:* every fact in the report traces back to a threat, score, tree, or mitigation
from the steps above.
