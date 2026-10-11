<!--
title: Vulnerability Library and PoC Editor
slug: /docs/web/poc-library
lang: en
summary: Browse built-in/curated/my PoCs in the vulnerability library, inspect vulnerability details, and write and validate your own PoCs with a spec-driven editor.
status: published
source: new
last_reviewed: 2026-10-10
-->

## Vulnerability library

The **Vulnerability Library** is for browsing and searching PoCs. Sources fall into:

| Source | Description |
| --- | --- |
| Built-in | Built-in PoCs shipped with afrog |
| Curated | Curated PoCs pulled by members (Curated) |
| Mine | PoCs you created/saved as copies (editable, deletable) |
| Local / Append | PoCs in a local directory or append directory |

The list supports filtering by severity, tag, author, time, starred, and more, plus keyword search. Click any entry to open the **vulnerability detail page**.

## Vulnerability details

The detail page shows the full metadata of the PoC:

- Name, severity, source, CVE / CWE / CVSS
- **Vulnerability details** (description), **references** (reference)
- **Affected versions** (affected), **solutions** (solutions)
- **PoC source** (YAML), copyable and downloadable
- At the top: copy PoC ID, edit (Mine only), save as a copy of mine, delete

## Writing a PoC

**New PoC** and editing **My PoCs** share the same full-screen editor:

- Write YAML on the left; the right side shows **validation results and a metadata preview** in real time
- **Insert template** at the top inserts a skeleton in one click — basic HTTP, multi-rule, OOB, TCP, brute, raw and more
- Saving goes through the create or update API; on success you jump to that PoC's detail page

### What the editor helps you with

The editor assists around the **afrog PoC spec** rather than making you write from memory:

- **Autocomplete**: in different positions such as `info` / `rules` / `request` / `brute` / `expression` / `set`, it suggests the corresponding fields, enums, and expression variables/functions
- **Hover docs**: hover a field name, built-in variable, or function to see its description, parameters and examples
- **Live structural validation**: validated as you type, with issues listed on the right; **clicking an issue jumps to the offending line**
- **Templates and snippets**: insert editable skeletons for common scenarios directly

The authoritative source for fields, built-in variables and functions is afrog's PoC spec and engine implementation; for syntax details see the [PoC syntax reference](../poc/02-syntax.md), and to start from scratch see [Write your first PoC](../poc/01-quickstart.md).

## Relation to scanning

The editor is for **writing**; the **PoCs and scope** section of [scanning](./02-scan.md) decides **which ones to use**. Both use the same set of PoC sources, so a finished **My PoC** immediately shows up in the scan's PoC selector.

> **← Previous:** [Findings Ledger](./05-ledger.md) ｜ **Handbook home:** [Web Console Overview](./01-overview.md) ｜ **Next →:** [Scheduled Scans](./07-scheduled-scans.md)
