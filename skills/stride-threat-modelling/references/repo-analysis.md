# Repository Analysis

When the user points you at a code repository instead of a written description,
extract the threat-modelling inputs efficiently, then return to the main
workflow. The aim is **enough context to model threats**, not a complete reading
of the codebase — every extra file read is wasted context.

## Staged approach

**Stage 1 — Initial (quick scan).** Objective: understand the tech stack,
architecture, and deployment model. Read **3–5 key files** (e.g. `README`,
`package.json` / dependency manifest, `docker-compose.yml` / deployment config,
`.env.example`). Output: tech stack, deployment model, basic architecture.
*Checkpoint:* after 3–5 reads, STOP and ask — can I identify app type, tech
stack, and deployment model? If yes, go to Stage 2. If no, read 1–2 more
specific files.

**Stage 2 — Deep dive.** Objective: extract detailed security context. Perform
**8–12 targeted searches/reads** on security-critical components only (auth,
authorization, data handling, external integrations). Output: trust boundaries,
sensitive data, access controls. *Checkpoint:* after 8–12 searches/reads, STOP
and ask — can I populate the threat-modelling inputs (app type, auth methods,
internet-facing, sensitive data, trust boundaries)? If yes, start threat
modelling. If no, search only for the specific missing information.

**Stage 3 — Validation.** Verify you have sufficient context. Output: a
readiness assessment, or a short list of remaining gaps to fill.

## Context-management principles

- When in doubt, **search instead of read**.
- STOP after 3–5 file reads in Stage 1; STOP after 8–12 searches/reads in Stage 2.
- Don't re-read files — reference earlier reads by file path.
- Search returns snippets; full reads return entire files.
- Use **file-path references** in threat descriptions, not pasted code snippets.
- Don't read for completeness — read until you have enough. More files = wasted
  context.

## Read vs. search

**Read the full file when:** you need specific configuration values
(`.env.example`, config files); the file is typically small (`package.json`,
`docker-compose.yml`, `README`); or you need the complete architecture overview.

**Search when:** looking for patterns (authentication methods, authorization
checks); examining application code (controllers, services, middleware); the file
is typically large; or you need to understand *how* something works rather than a
specific value.
