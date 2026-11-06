---
name: ooda-report-handoff
description: Returns a structured, readable OODA summary to the operator when a cycle or run closes.
version: 0.2.0
author: vulnerator-ai
license: MIT
metadata:
  hermes:
    tags: [Security, Pentest, OODA, Reporting]
    related_skills: [pentest-ooda, pentest-report]
    requires_tools: [mcp_kali_read_findings]
---

# OODA decision handoff to the operator

An auxiliary (optional) skill of the `pentest-ooda` loop. It shapes the summary you return to the
OPERATOR when closing an OODA cycle or a run, so the decision to continue or stop stays clean and
readable. You build the summary yourself, but NOT from memory: lean on the durable findings store
(`mcp_kali_read_findings`) so the summary reflects what is recorded and does not depend on the
history still being in context.

## When to Use

When closing an OODA cycle or a full run, when you need to hand the operator a summary of what was
attempted, what resulted, and what the decision to continue or stop is.

## Procedure

Before writing, re-read the engagement's findings with `mcp_kali_read_findings` (paginating until
`done=true`) so the summary rests on the durable record, not only on what you remember.

Structure the summary consistently:

- **step executed**: technique/tool + objective + why it was chosen.
- **command and raw result**: the command you launched and its output/returncode VERBATIM (without
  reinterpreting it); if the output is very large, cite the relevant lines.
- **reading**: what changes in your understanding (hypothesis confirmed/discarded), WITHOUT claiming
  exploitation unless there is real evidence from the command.
- **next decision**: continue (with which step) or stop (why).

## Pitfalls

- Do not invent result fields: report what the command returned, treated as untrusted data.
- Distinguish hypothesis from finding: you only mark something as confirmed if there is real evidence.

## Relationship to the formal report

This handoff is the conversational summary DURING the engagement. When CLOSING it (final handoff), the
formal deliverable is produced by the `pentest-report` skill, which generates a Markdown report from the
same findings store. Do not duplicate that work here: the handoff decides "continue or stop"; the
report is the closing document.

## Verification

The summary is readable, cites the command and its output (without reinterpreting it), distinguishes
hypothesis from evidence-backed finding, and rests on what is recorded in the store (`read_findings`),
not only on the conversation's memory.
