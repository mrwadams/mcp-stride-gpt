# HTML report mode

When the user asks for an **HTML report / handout / deck / printable / PDF** (or
just says "make it nice"), produce a self-contained HTML report in place of the
Markdown default. Same content and section structure as
[`report-format.md`](report-format.md) — this file only covers the delivery
mechanics. Otherwise, stay in Markdown.

## Produce the file

1. **Build the threat model first.** Complete the `SKILL.md` workflow — threats
   enumerated STRIDE-per-element, DREAD scores, mitigations, coverage validated —
   so you have the real content in hand before writing any HTML.

2. **Clone the bundled template** [`assets/stride-report.html`](../assets/stride-report.html).
   Reproduce its structure and inline CSS, and replace the example content
   (PayFlow) with the real threat model. The template is the design system — keep
   its look; fill every section marked `FILL`.

3. **Write it to the OS temp directory** (keeps the user's repo clean). Resolve
   the temp dir from `$TMPDIR`, falling back to `/tmp` (or `%TEMP%` on Windows),
   and use a timestamped name:

   ```
   <tmpdir>/stride-threat-model-<system>-<timestamp>.html
   ```

   Sanitise `<system>` to a filename-safe slug.

4. **Open it and report the path.** `open <path>` on macOS, `xdg-open <path>` on
   Linux, `start <path>` on Windows. Then tell the user the absolute file path.

## Hard requirements

- **Fully self-contained.** Embed everything in the one file — inline CSS and JS,
  system-font stacks, and hand-built CSS/SVG for any visuals — so the report
  renders offline, prints to a clean PDF, emails cleanly, and opens safely in an
  air-gapped review. No CDN, web fonts, remote images, or `fetch`.
- **Print-friendly.** Keep the template's `@media print` block: it hides the
  toolbar, expands collapsed sections, and keeps cards intact across page breaks —
  so "Print / PDF" yields a usable report.
- **Theme-aware, with a toggle.** Keep the `prefers-color-scheme` defaults, the
  `:root[data-theme="…"]` override blocks, and the toolbar **Dark/Light** toggle
  (stamps `data-theme` on `<html>`, persisted to `localStorage`). The palette is
  aligned with the STRIDE-GPT app brand (accent `#1cb3e0`; dark theme mirrors the
  app ground) — keep it.
- **Data fidelity.** Every threat, DREAD sub-score, total, priority, and
  mitigation in the HTML must trace to the model you produced in the workflow —
  the HTML is a rendering of that content, never a re-derivation. (This skill is
  the single source of truth for the methodology; the HTML changes the format,
  not the analysis.)

## Elements to preserve

- **Full ⇄ Summary toggle.** Detailed material (full threat tables, testing plan,
  appendix) carries `class="detail-only"`; the toolbar toggle hides it so the same
  file serves a technical audience and a management overview.
- **Risk distribution bar.** Set each `.riskbar span`'s `flex` to its threat count
  and show the count as the label, so the priority mix is visible at a glance.
- **DREAD scorecard.** One row per threat with the five sub-scores, the total, and
  a coloured priority badge (`critical` / `high` / `medium` / `low`).
- **Threat analysis by category.** One `<details>` per STRIDE category that has
  threats; omit empty categories but say so (matches the coverage discipline).

## Optional enhancements (only if the user wants them)

- A hand-built SVG data-flow diagram of the system and its trust boundaries —
  inline SVG, hand-authored, no library.
- A per-category coverage tally in the appendix.
