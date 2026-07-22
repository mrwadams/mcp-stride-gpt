# Coverage Validation

Before assembling the report, audit the threat model for completeness. The goal
is to catch what was missed, not to re-list what was found.

## Per-category check

Verify each STRIDE category has been considered for every trust boundary and
data flow:

- **S — Spoofing** — all identity-related threats considered.
- **T — Tampering** — all data/code integrity threats considered.
- **R — Repudiation** — all accountability threats considered.
- **I — Information Disclosure** — all confidentiality threats considered.
- **D — Denial of Service** — all availability threats considered.
- **E — Elevation of Privilege** — all authorization threats considered.

## Validation criteria

- **Completeness** — all STRIDE categories addressed for each trust boundary.
- **Specificity** — threats are specific to the application context, not generic.
- **Actionability** — threats lead to implementable mitigations.
- **Risk alignment** — high-risk threats receive appropriate attention.

## Common gaps

Look specifically for these — they are where models routinely fall short:

- **Trust boundaries** — missing threats at component interfaces.
- **Data flows** — insufficient consideration of data in transit.
- **Privileged operations** — inadequate coverage of admin functions.
- **Error conditions** — missing threat consideration for edge cases.

Every gap you find must be either filled or explicitly recorded as out-of-scope
with a reason before you report.
