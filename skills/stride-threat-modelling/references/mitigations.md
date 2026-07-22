# Mitigations

For each threat — highest priority first — give specific, actionable controls.
Apply defence-in-depth: prefer layered Preventive + Detective + Corrective
controls over a single point of failure. Prioritise by risk level and
implementation difficulty.

## Control categories

- **Preventive** — controls that stop the threat from occurring.
- **Detective** — controls that detect when the threat occurs.
- **Corrective** — controls that respond to and recover from the threat.

## Implementation difficulty

- **Easy** — implementable quickly with existing tools/processes.
- **Medium** — moderate effort, possibly new tools.
- **Hard** — significant resources, time, or architectural changes.

## Priority

- **High** — critical security controls to implement immediately.
- **Medium** — important controls to plan for the near term.
- **Low** — nice-to-have controls for comprehensive defence.

## Guidance

For every High/Critical threat, produce at least one concrete, implementable
mitigation — not a restatement of the threat. Name the control, its category, its
difficulty, its priority, and specific implementation guidance for *this* system.
Implement high-priority preventive controls first, then layer detective and
corrective controls to close residual risk.
