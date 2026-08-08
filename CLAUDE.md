# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This is Vlad Ignatovskiy's personal GitHub Pages site (`vignatovskiy1.github.io`, served at the custom domain `vladcyber.it.com` via the `CNAME` file). It has no build system, package manager, or test suite — it's a static site deployed directly from the `main` branch.

## Structure

- `index.html` — the deployed page. Currently a single self-contained tool: the "FortiEDR Incident Summary Formatter," a client-side text parser/formatter with no external dependencies (no build step, no CDN scripts beyond system fonts). All markup, CSS, and JavaScript live inline in this one file.
- `README.md` — profile/portfolio blurb shown on the GitHub repo page.
- `how-i-set-up-my-cybersecurity-portfolio.md` — a personal how-to log (domain purchase, DNS records, Zoho email, GitHub Pages setup). Reference material, not something code changes should touch.
- `CNAME` — GitHub Pages custom domain config (`vladcyber.it.com`). Only touch this if intentionally changing the custom domain.

## Development workflow

There is no build, lint, or test tooling in this repo — edits are made directly to `index.html` (or other files) and committed. To preview changes, open `index.html` directly in a browser (or serve the directory with any static file server); there's no dev server script.

Deployment is automatic: GitHub Pages serves whatever is committed to `main`, so pushing to `main` is equivalent to shipping to production at `vladcyber.it.com`.

## `index.html` architecture: the FortiEDR formatter

The page takes raw pasted text from FortiEDR (a SOC/EDR product) event notifications and reformats it into a standardized incident-summary block for SOC handoff. All logic is in the inline `<script>`:

1. **`splitEvents`** splits the pasted blob into individual event chunks on the literal delimiter `Event Graph` or `Event GraphAutomated Analysis` (FortiEDR emits copy-pasted text with these markers between events).
2. For each chunk, **`buildEventSummary`** extracts fields by scanning chunk lines with a family of small, single-purpose extractor functions (`extractProcess`, `extractDevice`, `extractLoggedInUser`, `extractCompany`, `extractClassification`, `extractCollectorGroup`, `extractAdditionalInfo`, `extractVirusTotalLink`, `buildTechNotes`, etc.). Each extractor implements its own heuristic for finding a value in unstructured, copy-pasted text — e.g. matching a label line, then reading N lines below it, or falling back to a parsed table (`parseSelectedTable`) or a regex over the raw chunk.
3. Fields are assembled into a fixed-format text block via `padLabel` (aligns `Label:` to a consistent column) and joined into the final output, ending with a fixed SOC handoff sentence.
4. The formatted output is rendered into a `contenteditable` `<pre>` so an analyst can hand-edit before copying (`copyButton` uses the Clipboard API).

**Key thing to know when modifying extractors:** this logic was built up incrementally against real-world FortiEDR paste formats (see commit history — many small PRs each fixing one field's edge case, e.g. "Handle Company colon-only follow up", "Update classification extraction logic", "Allow Event Graph delimiter variant"). The extractors are intentionally defensive/heuristic (multiple fallback strategies per field, default to `'N/A'`) because the input is inconsistently formatted pasted text, not structured data. When fixing a field, prefer adding/adjusting a fallback branch over rewriting the whole extractor, and keep behavior for already-working paste formats intact.
