---
name: stride-threat-modelling
description: >-
  Produce a consistent, house-style STRIDE threat model and report for a
  described system — enumerate threats STRIDE-per-element across trust
  boundaries and data flows, score them with DREAD, then recommend mitigations,
  attack trees, security tests, and a coverage check. Use when the user wants a
  threat model, STRIDE analysis, security risk assessment, DREAD scoring, an
  attack tree, or a threat report for an application, architecture, feature, or
  repository.
license: GPL-3.0-or-later
---

# STRIDE Threat Modelling

Turn a system description into a rigorous, house-style STRIDE threat model and
report. The methodology, rubrics, and report craft live in this skill — it runs
on your own model with **no API key and no dependency on the STRIDE-GPT MCP
server**. (The hosted MCP server remains only as an optional add-by-URL
distribution channel; this skill stands on its own.)

The discipline is **per-element**: enumerate threats systematically for every
element of the system — each process, data store, data flow, and external
entity, and especially each **trust boundary** they cross — rather than
brainstorming threats at large. Per-element coverage is what makes two runs of
this skill land in the same place.

## Inputs to gather

Ask for whatever is missing before enumerating:

- **System description** — what it does, main components, and how they connect.
- **App type** — e.g. web app, API/microservices, mobile, cloud service,
  AI/ML system, IoT/embedded, desktop.
- **Authentication methods** — how identities are established.
- **Internet-facing?** — is the attack surface public or internal-only.
- **Sensitive data** — what the system holds or processes (PII, credentials,
  financial, health, secrets).

If the user points you at a **repository** instead of a written description,
follow [`references/repo-analysis.md`](references/repo-analysis.md) to extract
these inputs efficiently before you start, then continue the workflow below.

## Workflow

Run these in order. Each step names its **done-when** condition — do not move on
until it holds.

1. **Scope the system.** Restate the architecture in your own words and list the
   elements and trust boundaries you will analyse (processes, data stores, data
   flows, external entities). *Done when* every component in the description maps
   to at least one listed element, and every boundary where trust changes is
   named.

2. **Enumerate threats — STRIDE-per-element.** For each element and boundary,
   walk all six STRIDE categories (Spoofing, Tampering, Repudiation, Information
   Disclosure, Denial of Service, Elevation of Privilege) and select the threats
   that genuinely apply to *this* system. Draw on the extended threat domains
   relevant to the app type. Give each threat a stable ID, its STRIDE category,
   and a specific description. See
   [`references/stride-framework.md`](references/stride-framework.md). *Done
   when* every element has been considered against all six categories (record
   "not applicable" explicitly rather than skipping), and no threat is generic
   boilerplate — each names a concrete element or flow.

3. **Score with DREAD.** Score each threat on Damage, Reproducibility,
   Exploitability, Affected Users, and Discoverability (1–10 each), sum to a
   0–50 total, and map to a Critical/High/Medium/Low priority. Justify every
   score from the specific threat and system context. Use the calibration
   bands and worked examples in
   [`references/dread-scoring.md`](references/dread-scoring.md). *Done when*
   every threat has five justified sub-scores, a total, and a priority.

4. **Recommend mitigations.** For each threat (highest priority first), give
   specific, actionable controls classified Preventive / Detective / Corrective,
   with an implementation difficulty and priority, following defence-in-depth.
   See [`references/mitigations.md`](references/mitigations.md). *Done when* every
   High/Critical threat has at least one concrete, implementable mitigation.

5. **(Optional) Attack trees.** When the user wants attack paths visualised, or a
   high-value threat warrants decomposition, build attack trees per
   [`references/attack-trees.md`](references/attack-trees.md). *Done when* each
   requested tree decomposes a root goal into sub-goals, methods, and
   prerequisites.

6. **(Optional) Security tests.** When the user wants validation, generate test
   cases (default Gherkin) that prove each mitigation works, per
   [`references/security-tests.md`](references/security-tests.md). *Done when*
   each targeted threat has at least one positive and one negative test.

7. **Validate coverage.** Before reporting, audit the model against
   [`references/coverage-validation.md`](references/coverage-validation.md):
   every STRIDE category considered for every trust boundary and data flow,
   threats specific and actionable, high-risk threats given due attention. *Done
   when* each identified gap is either filled or explicitly noted as
   out-of-scope with a reason.

8. **Assemble the report.** Produce the deliverable in the house style defined by
   [`references/report-format.md`](references/report-format.md) — Markdown by
   default. *Done when* the report contains every requested section and each fact
   traces back to a threat, score, or mitigation from the steps above.

## Output

Default output is **Markdown**, structured per
[`references/report-format.md`](references/report-format.md). Keep the tone
professional and the recommendations specific to the described system — no
generic advice that would read the same for any application.

When the user asks for a **report / handout / deck / printable / PDF** (or "make
it nice"), switch to the self-contained HTML report per
[`references/html-report.md`](references/html-report.md) instead — same content,
delivered as a single offline file written to the OS temp dir and opened. Stay in
Markdown otherwise.

## Reference files

Consulted on demand — load the one the current step points to:

- [`references/stride-framework.md`](references/stride-framework.md) — STRIDE
  categories, per-element method, and extended threat domains by app type.
- [`references/dread-scoring.md`](references/dread-scoring.md) — the DREAD 1–10
  scales, calibration bands, risk-level mapping, and worked examples.
- [`references/mitigations.md`](references/mitigations.md) — the mitigation
  classification and prioritisation framework.
- [`references/attack-trees.md`](references/attack-trees.md) — attack-tree
  structure, common patterns, and text / Mermaid / JSON formats.
- [`references/security-tests.md`](references/security-tests.md) — security test
  types, formats, and coverage areas.
- [`references/coverage-validation.md`](references/coverage-validation.md) — the
  completeness checklist and common coverage gaps.
- [`references/report-format.md`](references/report-format.md) — the house-style
  report structure.
- [`references/html-report.md`](references/html-report.md) — delivery mechanics
  for the self-contained HTML report (clones `assets/stride-report.html`).
- [`references/repo-analysis.md`](references/repo-analysis.md) — staged approach
  for extracting threat-modelling inputs from a code repository.
