# Report Format (House Style)

The deliverable is a Markdown report titled **STRIDE Threat Model Report**.
Include the sections the user asked for; default to all of them. Populate every
section with specific analysis from the threat model — never leave the guidance
prose in place of real content. Each fact must trace back to a threat, DREAD
score, or mitigation produced during the workflow.

## Section structure

```markdown
# STRIDE Threat Model Report

## Executive Summary
- Total threats identified across STRIDE categories
- Critical and high-priority threats highlighted
- Key recommendations for immediate action
- Risk assessment summary

## Application Overview
Architecture, components, and security-relevant characteristics of the system.

## Threat Analysis
Threats organised by STRIDE category. For each: Threat ID, description, STRIDE
category, attack scenarios, potential impact.
### Spoofing Threats
### Tampering Threats
### Repudiation Threats
### Information Disclosure Threats
### Denial of Service Threats
### Elevation of Privilege Threats

## Risk Assessment
DREAD scores and prioritisation.
### Critical Priority Threats (DREAD: 40-50)
### High Priority Threats (DREAD: 30-39)
### Medium Priority Threats (DREAD: 20-29)
### Low Priority Threats (DREAD: 5-19)

## Recommended Mitigations
For each: control type (Preventive/Detective/Corrective), difficulty
(Easy/Medium/Hard), priority, and specific implementation guidance.
### High Priority Mitigations
### Medium Priority Mitigations
### Low Priority Mitigations

## Security Testing Plan
Test scenarios per major threat, acceptance criteria, methodology.

## Implementation Roadmap
- Phase 1 (0-30 days): Critical mitigations
- Phase 2 (30-90 days): High-priority mitigations
- Phase 3 (90+ days): Medium and low-priority mitigations

## Appendix
### Threat Model Data
Total threats identified; STRIDE coverage breakdown by category.
### References
- STRIDE Threat Modeling Methodology
- DREAD Risk Assessment Framework
- OWASP Top 10
- CWE/SANS Top 25
```

Close with a short footer noting the framework (STRIDE), the risk-scoring method
(DREAD), and the generation date.

> For a **printable / handout / PDF** deliverable, produce the self-contained
> HTML report instead — same section structure, delivered as a single offline
> file. See [`html-report.md`](html-report.md). Default to Markdown otherwise.
