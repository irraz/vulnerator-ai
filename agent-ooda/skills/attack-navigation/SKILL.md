---
name: attack-navigation
description: Use MITRE ATT&CK as the LANGUAGE of the OODA loop — orient by tactics (what comes next) and tag every finding with its technique_id.
version: 0.1.0
author: vulnerator-ai
license: MIT
metadata:
  hermes:
    tags: [Security, Pentest, MITRE, ATTACK, OODA, Orient]
    related_skills: [pentest-ooda, aws-pacu-privesc, l3-recon-pivot, ooda-report-handoff]
    # Cross-cutting: applies to any engagement with execution on the Kali. It is an ORIENTATION LENS
    # and a tagging taxonomy, not an attack procedure.
    requires_tools: [mcp_kali_kali_run]
---

# ATT&CK as the language of the OODA loop

[MITRE ATT&CK](https://attack.mitre.org/) is the standard vocabulary of adversary tactics and
techniques. It is NOT your control loop (the loop is still OODA) nor an attack procedure:
it is the **language you ORIENT with** (naming what you see and seeing which tactic comes next) and the
**taxonomy you TAG with** for each finding. Deliberately lightweight: this is the skeleton of
tactics and the techniques most relevant to what your Kali can execute, NOT the full matrix.

Methodology and IDs taken from the official source (https://attack.mitre.org/, Enterprise domain).

## When to Use

In the **Orient** phase of any engagement, to situate where you are in the kill-chain and decide
which tactic is the next logical one. And when recording a finding, to assign it its `technique_id`. If
the engagement is cloud/AWS, combine with `aws-pacu-privesc` (which brings the ATT&CK Cloud detail).

## The 14 Enterprise tactics (the axis of the kill-chain)

Typical progression order of an engagement. In Orient, ask: "which tactic am I in and which is
the next plausible one?".

| ID | Tactic | The adversary's "why" |
|---|---|---|
| TA0043 | Reconnaissance | Gather information about the target (pre-access). |
| TA0042 | Resource Development | Prepare infrastructure/credentials for the attack. |
| TA0001 | Initial Access | Get into the environment. |
| TA0002 | Execution | Run code on the target. |
| TA0003 | Persistence | Maintain access. |
| TA0004 | Privilege Escalation | Obtain higher permissions. |
| TA0005 | Defense Evasion | Avoid detection. |
| TA0006 | Credential Access | Steal credentials. |
| TA0007 | Discovery | Understand the internal environment. |
| TA0008 | Lateral Movement | Move to other systems. |
| TA0009 | Collection | Gather data of interest. |
| TA0011 | Command and Control | Communicate with compromised systems. |
| TA0010 | Exfiltration | Get the data out. |
| TA0040 | Impact | Manipulate/interrupt/destroy. |

The order is NOT rigid: a real engagement jumps and repeats tactics. The axis is for orienting, not
for forcing a sequence.

## How to integrate it into OODA (without changing the loop)

- **Observe.** What you observe is usually Reconnaissance/Discovery. Record what you discovered.
- **Orient.** Situate what you observed in a tactic and ask which is the next plausible one given your
  current access. Example: you have valid credentials (T1078) -> the next logical one may be
  Discovery (TA0007) to map permissions, or Privilege Escalation (TA0004) if you already see a path. ATT&CK
  gives you the range of "what comes next", which feeds the **Decide with alternatives** step of
  `pentest-ooda`.
- **Decide.** When choosing ONE action, name the tactic/technique it pursues. That makes the decision
  traceable and comparable.
- **Act + record.** When executing and recording the result, **tag the finding with its
  `technique_id`** (e.g. `T1552` for exposed credentials you found). This is what, later,
  enables ATT&CK-mapped reports and a Navigator layer almost for free.

## Frequent techniques by tactic (a useful subset on this Kali)

Not exhaustive. These are the ones you are most likely to tag with the pentest/collection tools of this
Kali:

- **Reconnaissance (TA0043)**: T1595 Active Scanning (nmap), T1590 Gather Victim Network Info.
- **Initial Access (TA0001)**: T1078 Valid Accounts, T1190 Exploit Public-Facing Application.
- **Execution (TA0002)**: T1059 Command and Scripting Interpreter.
- **Persistence (TA0003)**: T1098 Account Manipulation, T1136 Create Account.
- **Privilege Escalation (TA0004)**: T1548 Abuse Elevation Control Mechanism, T1078 Valid Accounts.
- **Credential Access (TA0006)**: T1552 Unsecured Credentials, T1110 Brute Force.
- **Discovery (TA0007)**: T1046 Network Service Discovery, T1526 Cloud Service Discovery, T1087
  Account Discovery.
- **Lateral Movement (TA0008)**: T1021 Remote Services.
- **Collection/Exfiltration (TA0009/TA0010)**: T1530 Data from Cloud Storage, T1537 Transfer to Cloud
  Account.

When you need a technique that is not here, use the real ID from attack.mitre.org; do not invent IDs.

## Pitfalls

- **ATT&CK classifies, it does not procedure.** Do not treat it as a checklist to complete top to
  bottom; it is a lens for orienting and tagging. You drive the loop with OODA.
- **Do not invent technique_ids.** If you are not sure of the ID, say so or look up the real one; an
  invented ID contaminates the report.
- **Tag only what the evidence supports.** Tagging a finding with a technique is asserting that it
  happened: apply the same hypothesis-vs-confirmed discipline as the rest of the OODA loop.

## Verification

Before closing a cycle with ATT&CK: (a) you oriented by naming the current tactic and the next
plausible one; (b) each recorded finding carries a REAL `technique_id` backed by evidence; (c)
you did not force a rigid sequence of tactics or invent IDs.
