"""Deterministic pentest report generator (Markdown + HTML) from the findings store.

Produces the engagement DELIVERABLE(s) at close, complementing ``ooda-report-handoff``
(which only gives the conversational summary DURING the engagement). It READS the durable
register of findings (``finding_store``) rather than rebuilding from the conversation, and
writes the report(s) as ARTIFACTS on the data plane (``/artifacts``), downloadable over the
HTTP channel (:8901) without going through MCP.

Pattern like the other baked-in scripts (Prowler/Pacu): PURE STDLIB, invoked with
``kali_run`` (``python3 report_gen.py --engagement <id> [--format md|html|both]``). The
render LOGIC is testable without the SDK (``render_markdown`` / ``render_html`` over a list
of findings); ``main`` chains read-from-store -> render -> stage.

Both formats are DETERMINISTIC: the same findings and the same ``generated_at`` produce
byte-identical artifacts. The deliverable is therefore reproducible from the store instead
of being hand-written by the model.

Report structure (distilled from public pentest templates, with attribution —
Theophilus/athena-pentest and Marmeus/pentesting-report-generator): engagement details,
executive summary (non-technical), severity table, methodology (OODA/PTES/OWASP),
findings with CVSS 3.1 + CWE and reproducible evidence, remediation. CVSS/severity only for
CONFIRMED findings (coherent with the "no finding without evidence" discipline).

OUTPUT LANGUAGE: the reports are emitted in ENGLISH (aligned with the repo's public
documentation). This module's comments/docstrings are in English, like the rest of
docker/kali/. Only strings ending up in the deliverables are user-visible.

Untrusted data: the evidence of each finding (command/output) comes from tools against a
real target. Here it is RENDERED verbatim inside code blocks; it is never interpreted.
"""

from __future__ import annotations

import argparse
import html as _html
import re
import sys
from datetime import datetime, timezone

import artifact_store
import finding_store

# Canonical name of the Markdown report inside the engagement directory (downloadable artifact).
REPORT_NAME = "pentest-report.md"

# Canonical name of the deterministic HTML report (same artifact plane as the Markdown).
REPORT_HTML_NAME = "pentest-report.html"

# Deliverable planes accepted by ``generate``/``main``. ``md`` is the legacy default, so the
# historical artefact (``pentest-report.md``) keeps being produced by a bare invocation.
_FORMATS = ("md", "html", "both")

# Presentation order of states and their human label (output in English).
_STATE_LABEL = {
    "confirmed": "Confirmed",
    "partial": "Partial",
    "hypothesis": "Hypothesis",
    "discarded": "Discarded",
}
_STATE_ORDER = ["confirmed", "partial", "hypothesis", "discarded"]

# Phase order used to present coverage deterministically.
_PHASE_ORDER = ("observe", "orient", "decide", "act")

_SEVERITIES = ("critical", "high", "medium", "low", "info")

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fence(text: str) -> str:
    """Wraps text (untrusted data) in a verbatim code block.

    Uses a 4-backtick fence so it does not break if the content itself contains ```.
    """
    body = text if isinstance(text, str) else str(text)
    return "````\n" + body.rstrip("\n") + "\n````"


def _evidence_block(evidence: dict) -> list[str]:
    """Renders the evidence of a finding (command/returncode/output or artifact ref)."""
    if not isinstance(evidence, dict) or not evidence:
        return ["_No evidence recorded._"]
    out: list[str] = []
    command = evidence.get("command")
    if command:
        out.append("**Command:**")
        out.append(_fence(str(command)))
    if "returncode" in evidence:
        out.append(f"**Return code:** `{evidence.get('returncode')}`")
    output = evidence.get("output")
    if output:
        out.append("**Output (verbatim, untrusted data):**")
        out.append(_fence(str(output)))
    ref = evidence.get("artifact_ref")
    if isinstance(ref, dict) and ref:
        exec_id = ref.get("execution_id", "")
        name = ref.get("name", "")
        out.append(f"**Artifact:** `{exec_id}/{name}` (downloadable via the data channel).")
    if not out:
        # Evidence of unknown shape: dumped verbatim to avoid losing information.
        out.append(_fence(repr(evidence)))
    return out


def _finding_section(index: int, finding: dict) -> list[str]:
    """Renders a single finding as a Markdown section."""
    title = finding.get("title", "(untitled)")
    state = finding.get("state", "")
    lines = [f"### F{index}. {title}", ""]

    meta_rows = [
        ("Status", _STATE_LABEL.get(state, state or "—")),
        ("OODA phase", finding.get("phase") or "—"),
        ("ATT&CK technique", finding.get("technique_id") or "—"),
        ("Target", finding.get("target") or "—"),
        ("Confidence", finding.get("confidence") or "—"),
    ]
    # CVSS/CWE only make sense for confirmed findings (discipline "no finding without
    # evidence"): they are shown if the agent recorded them.
    if state == "confirmed":
        meta_rows.append(("CVSS 3.1", finding.get("cvss") or "— (not scored)"))
        meta_rows.append(("CWE", finding.get("cwe") or "—"))

    lines.append("| Field | Value |")
    lines.append("|---|---|")
    for key, value in meta_rows:
        lines.append(f"| {key} | {value} |")
    lines.append("")

    lines.append("**Evidence:**")
    lines.append("")
    lines.extend(_evidence_block(finding.get("evidence", {})))
    lines.append("")

    remediation = finding.get("remediation")
    if remediation:
        lines.append("**Remediation:**")
        lines.append("")
        lines.append(str(remediation))
        lines.append("")

    change = finding.get("change")
    if isinstance(change, dict) and change:
        tag = change.get("tag", "")
        revert = change.get("revert", "")
        lines.append("**Change introduced in the account/target (traceability):**")
        lines.append("")
        if tag:
            lines.append(f"- Tag: `{tag}`")
        if revert:
            lines.append("- Revert:")
            lines.append(_fence(str(revert)))
        lines.append("")

    return lines


def render_markdown(engagement_id: str, findings: list[dict], generated_at: str | None = None) -> str:
    """Renders the full Markdown report from the list of findings.

    PURE, testable function (does not touch the store or FS): receives already-read findings
    and returns the report text. Groups by state (confirmed first), with the status table and
    the methodology/remediation sections.
    """
    generated_at = generated_at or _now_iso()

    # Groups by state, preserving insertion order within each group.
    by_state: dict[str, list[dict]] = {s: [] for s in _STATE_ORDER}
    extra: list[dict] = []
    for f in findings:
        state = f.get("state")
        if state in by_state:
            by_state[state].append(f)
        else:
            extra.append(f)

    lines: list[str] = []
    lines.append(f"# Pentest report — engagement `{engagement_id}`")
    lines.append("")
    lines.append(f"- **Generated:** {generated_at}")
    lines.append(f"- **Total recorded findings:** {len(findings)}")
    lines.append("")

    # --- Executive summary (non-technical) ---
    confirmed = by_state["confirmed"]
    lines.append("## Executive summary")
    lines.append("")
    if confirmed:
        lines.append(
            f"The engagement confirmed **{len(confirmed)}** finding(s) with reproducible "
            "evidence. The technical detail, evidence and remediation for each are below. "
            "Items marked as hypothesis or partial require further verification and do not "
            "constitute confirmed exploitation."
        )
    else:
        lines.append(
            "No exploitable finding was confirmed with reproducible evidence within the "
            "scope and window of this engagement. This is NOT a verdict of a \"secure "
            "system\": it is the absence of confirmed findings given the methods and time "
            "used. Items recorded as hypothesis or partial are documented for follow-up."
        )
    lines.append("")

    # --- Severity table (by state) ---
    lines.append("## Summary by status")
    lines.append("")
    lines.append("| Status | Count |")
    lines.append("|---|---|")
    for state in _STATE_ORDER:
        lines.append(f"| {_STATE_LABEL[state]} | {len(by_state[state])} |")
    if extra:
        lines.append(f"| Other | {len(extra)} |")
    lines.append("")

    # --- Methodology ---
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "The engagement was driven by an **OODA** loop (Observe-Orient-Decide-Act), "
        "orienting by **MITRE ATT&CK** tactics and techniques and drawing on **PTES** and "
        "**OWASP** practices according to the surface (network, cloud, web). Each finding "
        "requires reproducible evidence of the executed command; there is no confirmed "
        "finding without proof."
    )
    lines.append("")

    # --- Findings (confirmed first) ---
    lines.append("## Findings")
    lines.append("")
    counter = 1
    any_rendered = False
    for state in _STATE_ORDER:
        group = by_state[state]
        if not group:
            continue
        any_rendered = True
        lines.append(f"### {_STATE_LABEL[state]} ({len(group)})")
        lines.append("")
        for f in group:
            lines.extend(_finding_section(counter, f))
            counter += 1
    for f in extra:
        any_rendered = True
        lines.extend(_finding_section(counter, f))
        counter += 1
    if not any_rendered:
        lines.append("_No findings recorded for this engagement._")
        lines.append("")

    # --- Scope note / limitations ---
    lines.append("## Scope and limitations")
    lines.append("")
    lines.append(
        "This report reflects only the findings recorded during the engagement against "
        "operator-authorized targets. Responsibility for the scope rests with the operator. "
        "The included evidence is raw tool output, presented verbatim."
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Deterministic HTML deliverable (Vulnerator-AI visual theme)
# ---------------------------------------------------------------------------

# Palette/sections reused from labs/looney-tunables-ctf/docs/pentest-report-example.html
# and docker/web/report.py: dark red cyber theme, matrix green, terminal blocks.
_HTML_CSS = """
  :root {
    --bg:         #0d0000;
    --bg-panel:   #180000;
    --bg-card:    #1e0000;
    --border:     #cc0000;
    --border-dim: #550000;
    --red:        #cc0000;
    --red-bright: #ff4444;
    --green:      #00ff41;
    --green-dim:  #007a1f;
    --text:       #e8e8e8;
    --text-dim:   #aa7777;
    --text-muted: #664444;
    --yellow:     #ff8800;
    --code-bg:    #0a0000;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }

  /* Header */
  .site-header {
    background: var(--bg-panel);
    border-bottom: 2px solid var(--border);
    padding: 16px 32px;
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .site-header .logo {
    font-family: monospace;
    font-size: 22px;
    font-weight: bold;
    color: var(--red-bright);
    letter-spacing: 2px;
  }
  .site-header .logo span { color: var(--green); }
  .site-header .tagline {
    font-size: 11px;
    color: var(--text-dim);
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-left: auto;
  }

  /* Meta bar */
  .report-meta {
    background: var(--bg-panel);
    border-bottom: 1px solid var(--border-dim);
    padding: 12px 32px;
    display: flex;
    gap: 32px;
    flex-wrap: wrap;
  }
  .meta-item { display: flex; flex-direction: column; gap: 2px; }
  .meta-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
  .meta-value { font-size: 13px; color: var(--text); font-family: monospace; }

  .container { max-width: 1100px; margin: 0 auto; padding: 32px; }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
    text-transform: uppercase;
  }
  .badge-critical { background: #7a0000; color: #ff4444; border: 1px solid #cc0000; }
  .badge-high    { background: #7a0000; color: #ff4444; border: 1px solid #cc0000; }
  .badge-medium  { background: #5a3000; color: #ff8800; border: 1px solid #885500; }
  .badge-low     { background: #1a3a00; color: #88ff00; border: 1px solid #337700; }
  .badge-info    { background: #002244; color: #4488ff; border: 1px solid #224488; }
  .badge-ok      { background: #003300; color: #00ff41; border: 1px solid #007722; }
  .badge-cvss    { background: #7a0000; color: #ffcc00; border: 1px solid #cc0000; font-size: 13px; padding: 4px 14px; }

  /* CVSS hero */
  .cvss-hero {
    background: var(--bg-panel);
    border: 2px solid var(--red);
    border-radius: 6px;
    padding: 24px 32px;
    margin-bottom: 32px;
    display: flex;
    align-items: center;
    gap: 32px;
    flex-wrap: wrap;
  }
  .cvss-score {
    font-family: monospace;
    font-size: 56px;
    font-weight: bold;
    color: var(--red-bright);
    line-height: 1;
  }
  .cvss-score .cvss-label { display: block; font-size: 12px; color: var(--text-dim); letter-spacing: 2px; margin-bottom: 4px; }
  .cvss-details { flex: 1; min-width: 260px; }
  .cvss-cve {
    font-family: monospace;
    font-size: 20px;
    color: var(--green);
    font-weight: bold;
    margin-bottom: 8px;
    word-break: break-word;
  }
  .cvss-vector {
    font-family: monospace;
    font-size: 11px;
    color: var(--text-dim);
    background: var(--code-bg);
    padding: 4px 8px;
    border-radius: 3px;
    border-left: 2px solid var(--border-dim);
    margin-bottom: 8px;
    word-break: break-word;
  }
  .cvss-tags { display: flex; gap: 8px; flex-wrap: wrap; }
  .ooda-count { text-align: right; }
  .ooda-count .ooda-num { font-size: 28px; color: var(--green); font-family: monospace; font-weight: bold; }
  .ooda-count .ooda-sub { font-size: 11px; color: var(--text-muted); }

  /* Sections */
  .section { margin-bottom: 40px; }
  .section-title {
    font-size: 13px;
    font-weight: bold;
    color: var(--green);
    letter-spacing: 2px;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border-dim);
    padding-bottom: 8px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .section-title::before { content: '\26a1'; color: var(--red-bright); }
  .section-title .section-num { color: var(--text-muted); font-weight: normal; }

  .exec-summary {
    background: var(--bg-panel);
    border-left: 3px solid var(--red);
    padding: 20px 24px;
    border-radius: 0 6px 6px 0;
    color: var(--text);
    line-height: 1.8;
  }
  .exec-summary code, .main-table code, .remediation-list code {
    background: var(--code-bg); padding: 1px 5px; border-radius: 3px;
    font-size: 12px; color: var(--green);
  }

  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th {
    background: var(--bg-card);
    color: var(--text-dim);
    text-align: left;
    padding: 8px 12px;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
  }
  td { padding: 9px 12px; border-bottom: 1px solid var(--border-dim); vertical-align: top; }
  tr:hover td { background: rgba(204,0,0,0.04); }
  td code { background: var(--code-bg); padding: 1px 5px; border-radius: 3px; font-size: 12px; color: var(--green); }
  td strong { color: var(--text); }
  .td-key { color: var(--text-dim); font-size: 12px; white-space: nowrap; width: 200px; }
  .td-val { color: var(--text); }

  /* Terminal / code blocks */
  .terminal {
    background: var(--code-bg);
    border: 1px solid var(--border-dim);
    border-radius: 6px;
    overflow: hidden;
    margin: 16px 0;
  }
  .terminal-bar {
    background: var(--bg-card);
    border-bottom: 1px solid var(--border-dim);
    padding: 6px 12px;
    font-size: 11px;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .terminal-bar .dot { width: 8px; height: 8px; border-radius: 50%; }
  .dot-red   { background: #cc0000; }
  .dot-amber { background: #ff8800; }
  .dot-green { background: #00ff41; }
  .terminal-body {
    padding: 16px 20px;
    font-family: 'Cascadia Code', 'Fira Code', 'Courier New', monospace;
    font-size: 12px;
    color: var(--green);
    overflow-x: auto;
    white-space: pre;
    line-height: 1.7;
  }
  .terminal-body .cmd     { color: #e8e8e8; }
  .terminal-body .out-ok  { color: var(--green); }
  .terminal-body .out-err { color: var(--red-bright); }
  .terminal-body .comment { color: var(--text-muted); }

  /* Controls table */
  .controls-table td.rc-ok   { color: var(--green); font-family: monospace; }
  .controls-table td.rc-fail { color: var(--red-bright); font-family: monospace; font-weight: bold; }
  .controls-table td.result-ok   { color: var(--green); }
  .controls-table td.result-fail { color: var(--red-bright); }

  /* Discarded vectors */
  .discarded-row td { opacity: 0.65; }
  .discarded-row td:first-child { text-decoration: line-through; text-decoration-color: var(--border-dim); }

  /* Remediation steps */
  .remediation-list { list-style: none; padding: 0; counter-reset: rem; }
  .remediation-list li {
    background: var(--bg-panel);
    border-left: 3px solid var(--yellow);
    padding: 14px 18px;
    margin-bottom: 10px;
    border-radius: 0 6px 6px 0;
    line-height: 1.7;
  }
  .remediation-list li strong { color: var(--yellow); }
  .remediation-list li .priority {
    font-size: 10px; letter-spacing: 1px; text-transform: uppercase;
    color: var(--text-muted); margin-bottom: 6px; display: block;
  }
  .remediation-list li .priority.p1 { color: var(--red-bright); }
  .remediation-list li .priority.p2 { color: var(--yellow); }
  .remediation-list li .priority.p3 { color: var(--text-dim); }

  /* Scope checklist */
  .scope-list { list-style: none; padding: 0; }
  .scope-list li {
    padding: 8px 12px;
    display: flex;
    align-items: center;
    gap: 10px;
    border-bottom: 1px solid var(--border-dim);
    font-size: 13px;
  }
  .scope-list li:last-child { border-bottom: none; }
  .scope-list li .check { color: var(--green); font-size: 16px; }
  .scope-note {
    margin-top: 16px;
    background: var(--bg-panel);
    border: 1px solid var(--green-dim);
    border-radius: 6px;
    padding: 14px 18px;
    color: var(--text-dim);
    font-size: 13px;
    line-height: 1.7;
  }
  .scope-note strong { color: var(--green); }

  /* Footer */
  .site-footer {
    background: var(--bg-panel);
    border-top: 1px solid var(--border-dim);
    padding: 20px 32px;
    margin-top: 48px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
  }
  .site-footer .footer-brand { font-family: monospace; font-size: 13px; color: var(--red); }
  .site-footer .footer-brand span { color: var(--green); }
  .site-footer .footer-meta { font-size: 11px; color: var(--text-muted); text-align: right; }

  /* Condition pills */
  .condition-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
  .pill {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-radius: 12px;
    padding: 3px 10px;
    font-size: 11px;
    font-family: monospace;
    color: var(--text-dim);
  }
  .pill.active { border-color: var(--red); color: var(--red-bright); }

  code { font-family: 'Cascadia Code', 'Fira Code', monospace; }
"""

_BADGE_CLASS = {
    "critical": "badge-critical",
    "high": "badge-high",
    "medium": "badge-medium",
    "low": "badge-low",
    "info": "badge-info",
}


def _escape(value: object) -> str:
    """HTML-escapes untrusted data (evidence is verbatim data, never interpreted)."""
    return _html.escape("" if value is None else str(value), quote=True)


def _as_float(value: object) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_int(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _cvss_score(finding: dict) -> float | None:
    """CVSS of a finding from the explicit ``cvss``/``score`` field, parsed deterministically."""
    raw = finding.get("cvss")
    if raw is None:
        raw = finding.get("score")
    return _as_float(raw)


def _severity_bucket(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _severity_of(finding: dict) -> str:
    severity = finding.get("severity")
    if isinstance(severity, str) and severity.strip().lower() in _SEVERITIES:
        return severity.strip().lower()
    return _severity_bucket(_cvss_score(finding))


def _unique(values) -> list[str]:
    out: list[str] = []
    for value in values:
        text = "" if value is None else str(value).strip()
        if text and text not in out:
            out.append(text)
    return out


def _phases(findings: list[dict]) -> list[str]:
    present = {str(f.get("phase")) for f in findings if f.get("phase")}
    ordered = [phase for phase in _PHASE_ORDER if phase in present]
    return ordered + sorted(present.difference(ordered))


def _excerpt(text: object, limit: int = 160) -> str:
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _state_groups(findings: list[dict]) -> tuple[dict[str, list[dict]], list[dict]]:
    by_state: dict[str, list[dict]] = {s: [] for s in _STATE_ORDER}
    extra: list[dict] = []
    for f in findings:
        state = f.get("state")
        if state in by_state:
            by_state[state].append(f)
        else:
            extra.append(f)
    return by_state, extra


def _primary_finding(confirmed: list[dict]) -> dict | None:
    """Highest-CVSS confirmed finding (first one wins ties), else the first confirmed one."""
    best: dict | None = None
    best_score: float | None = None
    for finding in confirmed:
        score = _cvss_score(finding)
        if score is not None and (best_score is None or score > best_score):
            best, best_score = finding, score
    return best if best is not None else (confirmed[0] if confirmed else None)


def _badge(severity: str, label: str | None = None) -> str:
    css = _BADGE_CLASS.get(severity, "badge-info")
    return f'<span class="badge {css}">{_escape(label or severity.upper())}</span>'


def _terminal(label: str, command: str, output: str, returncode: object) -> str:
    body: list[str] = []
    if command:
        body.append('<span class="cmd">$ ' + _escape(command) + "</span>")
    if output:
        rc = _as_int(returncode)
        css = "out-ok" if rc in (None, 0) else "out-err"
        body.append(f'<span class="{css}">{_escape(output)}</span>')
    return (
        '<div class="terminal"><div class="terminal-bar">'
        '<span class="dot dot-red"></span><span class="dot dot-amber"></span>'
        '<span class="dot dot-green"></span><span>' + _escape(label) + "</span></div>"
        '<div class="terminal-body">' + "\n".join(body) + "</div></div>"
    )


def _section(number: str, title: str, inner: str) -> str:
    return (
        '<div class="section">'
        f'<div class="section-title"><span class="section-num">{number} /</span> {_escape(title)}</div>'
        f'{inner}</div>'
    )


def render_html(engagement_id: str, findings: list[dict], generated_at: str | None = None) -> str:
    """Renders the deterministic Vulnerator-AI HTML report from the list of findings.

    PURE, testable function (does not touch the store or FS). Reuses the palette and the
    section layout of ``labs/looney-tunables-ctf/docs/pentest-report-example.html`` and
    ``docker/web/report.py``. Every value comes from the findings store: nothing is invented,
    unavailable metadata is shown as an explicit placeholder instead of being fabricated.
    Same findings + same ``generated_at`` -> byte-identical document.
    """
    generated_at = generated_at or _now_iso()
    by_state, extra = _state_groups(findings)
    confirmed = by_state["confirmed"]
    counts = {state: len(by_state[state]) for state in _STATE_ORDER}
    targets = _unique(f.get("target") for f in findings)
    phases = _phases(findings)
    primary = _primary_finding(confirmed)
    e = _escape

    # --- CVSS hero ---
    score = _cvss_score(primary) if primary else None
    score_text = f"{score:.1f}" if score is not None else "—"
    severity = _severity_of(primary) if primary else "info"

    cve_match = None
    for finding in confirmed:
        match = _CVE_RE.search(str(finding.get("title") or ""))
        if match:
            cve_match = match.group(0).upper()
            break
    cve_line = cve_match or "No CVE recorded in the store"

    vector = ""
    if primary:
        for key in ("cvss_vector", "vector"):
            if primary.get(key):
                vector = str(primary[key])
                break
    vector_line = vector or "— (not recorded in the store)"

    hero_badges = [_badge(severity, severity.upper())]
    if primary and primary.get("technique_id"):
        hero_badges.append(f'<span class="badge badge-info">{e(primary["technique_id"])}</span>')
    hero_badges.append(f'<span class="badge badge-cvss">CVSS {e(score_text)}</span>')
    if confirmed:
        hero_badges.append(f'<span class="badge badge-ok">{len(confirmed)} confirmed</span>')
    hero_badges.append(f'<span class="badge badge-info">{len(findings)} recorded</span>')

    # --- Meta bar ---
    meta_items = [
        ("Engagement", engagement_id),
        ("Target(s)", ", ".join(targets) if targets else "—"),
        ("Mode", "pentest"),
        ("Findings", str(len(findings))),
        ("Confirmed", str(len(confirmed))),
        ("Generated", generated_at),
    ]
    meta_html = "".join(
        f'<div class="meta-item"><span class="meta-label">{e(label)}</span>'
        f'<span class="meta-value">{e(value)}</span></div>'
        for label, value in meta_items
    )

    # --- 01 / Executive summary ---
    if confirmed:
        summary = (
            f'The engagement confirmed <strong>{len(confirmed)}</strong> finding(s) with '
            "reproducible evidence recorded in the findings store. The technical detail, "
            "evidence and remediation for each are below. Items marked as hypothesis or "
            "partial require further verification and do not constitute confirmed exploitation."
        )
        if primary:
            summary += f' Primary finding: <code>{e(primary.get("title") or "(untitled)")}</code>.'
    else:
        summary = (
            "No exploitable finding was confirmed with reproducible evidence within the "
            "scope and window of this engagement. This is NOT a verdict of a \"secure "
            "system\": it is the absence of confirmed findings given the methods and time "
            "used. Items recorded as hypothesis or partial are documented for follow-up."
        )
    exec_html = f'<div class="exec-summary">{summary}</div>'

    # --- 02 / Main finding ---
    main_rows: list[tuple[str, str]] = []
    if primary:
        main_rows.append(("Title", f"<strong>{e(primary.get('title') or '(untitled)')}</strong>"))
        main_rows.append(("Status", _badge(_severity_of(primary), _STATE_LABEL.get(str(primary.get("state") or ""), ""))))
        main_rows.append(("OODA phase", e(primary.get("phase") or "—")))
        main_rows.append(("ATT&CK technique", f'<code>{e(primary.get("technique_id") or "—")}</code>'))
        main_rows.append(("Target", e(primary.get("target") or "—")))
        main_rows.append(("Confidence", e(primary.get("confidence") or "—")))
        main_rows.append(("CVSS 3.1", e(primary.get("cvss") or score_text)))
        main_rows.append(("CWE", f'<code>{e(primary.get("cwe") or "—")}</code>'))
    else:
        main_rows.append(
            ("Result", "No confirmed finding with reproducible evidence; nothing to detail.")
        )
    main_html = (
        '<table class="main-table"><tbody>'
        + "".join(
            f'<tr><td class="td-key">{e(key)}</td><td class="td-val">{value}</td></tr>'
            for key, value in main_rows
        )
        + "</tbody></table>"
    )

    # --- 03 / Exploitability evidence ---
    terminals: list[str] = []
    controls_rows: list[str] = []
    counter = 1
    for state in _STATE_ORDER:
        for finding in by_state[state]:
            terminals.extend(
                _html_evidence_terminal(counter, finding, e, _terminal)
            )
            controls_rows.append(_controls_row(counter, finding, e))
            counter += 1
    for finding in extra:
        terminals.extend(_html_evidence_terminal(counter, finding, e, _terminal))
        controls_rows.append(_controls_row(counter, finding, e))
        counter += 1
    if not terminals:
        terminals.append(
            '<div class="exec-summary">No command/output evidence recorded in the store.</div>'
        )
    pills = [
        f'<span class="pill{" active" if phase in phases else ""}">{e(phase)}</span>'
        for phase in _PHASE_ORDER
    ]
    pills.append('<span class="pill">evidence: command+output</span>')
    evidence_html = (
        "".join(terminals)
        + '<p style="color:var(--text-dim);margin:16px 0 10px;font-size:13px">'
        "Reproduction record (return codes and states from the store):</p>"
        '<table class="controls-table"><thead><tr><th>Test</th><th>rc</th><th>State</th></tr></thead>'
        "<tbody>"
        + "".join(row for row in controls_rows if row)
        + "</tbody></table>"
        + '<div class="condition-pills">' + "".join(pills) + "</div>"
    )

    # --- 04 / Evaluated & discarded vectors ---
    vector_rows: list[str] = []
    for state in ("partial", "hypothesis", "discarded"):
        for finding in by_state[state]:
            vector_rows.append(_vector_row(finding, state, e))
    for finding in extra:
        vector_rows.append(_vector_row(finding, str(finding.get("state") or "other"), e))
    if not vector_rows:
        vector_rows.append(
            '<tr><td colspan="3">No partial/hypothesis/discarded vectors recorded.</td></tr>'
        )
    vectors_html = (
        '<table><thead><tr><th>Vector</th><th>Evidence</th><th>Status</th></tr></thead>'
        "<tbody>" + "".join(vector_rows) + "</tbody></table>"
    )

    # --- 05 / Remediation ---
    priorities = {"confirmed": ("p1", "Priority 1 — Confirmed"), "partial": ("p2", "Priority 2 — Planned")}
    items: list[str] = []
    for state in _STATE_ORDER:
        css, label = priorities.get(state, ("p3", "Priority 3 — Follow-up"))
        for finding in by_state[state]:
            remediation = finding.get("remediation")
            if not remediation:
                continue
            items.append(
                f'<li><span class="priority {css}">{label}</span>'
                f'<strong>{e(finding.get("title") or "(untitled)")}</strong><br>{e(remediation)}</li>'
            )
    if not items:
        items.append(
            '<li><span class="priority p3">Priority 3 — Follow-up</span>'
            "No remediation recorded in the store.</li>"
        )
    remediation_html = '<ol class="remediation-list">' + "".join(items) + "</ol>"

    # --- 06 / Scope compliance ---
    checks = [
        f"Findings persisted in the engagement store ({len(findings)})",
        f"Reproducible evidence recorded for {len(confirmed)} confirmed finding(s)",
        "Verbatim evidence rendered as-is; never interpreted",
        "CVSS/CWE shown only for confirmed findings",
        "States: Confirmed {a} · Partial {b} · Hypothesis {c} · Discarded {d}".format(
            a=counts["confirmed"], b=counts["partial"], c=counts["hypothesis"], d=counts["discarded"]
        ),
    ]
    if phases:
        checks.append("OODA phases covered: " + " → ".join(phases))
    scope_items = "".join(f'<li><span class="check">✓</span> {e(item)}</li>' for item in checks)
    scope_note = (
        "<strong>No verdict of a \"secure system\"</strong>: this report reflects only the "
        "findings recorded against operator-authorized targets within the declared scope and "
        "window. The included evidence is raw tool output, presented verbatim. Scope "
        "responsibility rests with the operator."
    )
    scope_html = (
        '<ul class="scope-list">' + scope_items + '</ul><div class="scope-note">' + scope_note + "</div>"
    )

    body = f"""<header class="site-header">
  <div class="logo">VULNERATOR<span>-AI</span></div>
  <div class="tagline">OODA Pentest Engine · Automated Security Assessment</div>
</header>

<div class="report-meta">{meta_html}</div>

<div class="container">

  <div class="cvss-hero">
    <div class="cvss-score"><span class="cvss-label">CVSS 3.1</span>{e(score_text)}</div>
    <div class="cvss-details">
      <div class="cvss-cve">{e(cve_line)}</div>
      <div class="cvss-vector">{e(vector_line)}</div>
      <div class="cvss-tags">{"".join(hero_badges)}</div>
    </div>
    <div class="ooda-count">
      <div class="ooda-sub">OODA LOOP</div>
      <div class="ooda-num">{len(findings)} findings</div>
      <div class="ooda-sub">{e(" → ".join(phases)) if phases else "no phases recorded"}</div>
    </div>
  </div>

  {_section("01", "Executive Summary", exec_html)}
  {_section("02", "Main Finding", main_html)}
  {_section("03", "Exploitability Evidence", evidence_html)}
  {_section("04", "Evaluated & Discarded Vectors", vectors_html)}
  {_section("05", "Remediation", remediation_html)}
  {_section("06", "Scope Compliance", scope_html)}

</div>

<footer class="site-footer">
  <div class="footer-brand">VULNERATOR<span>-AI</span> · OODA Pentest Engine</div>
  <div class="footer-meta">
    {e(engagement_id)} · {e(generated_at)}<br>
    Generated deterministically by report_gen.py from the findings store
  </div>
</footer>
"""

    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>Vulnerator-AI — Pentest Report: {e(engagement_id)}</title>\n"
        "<style>" + _HTML_CSS + "</style>\n</head>\n<body>\n"
        + body
        + "\n</body>\n</html>\n"
    )


def _html_evidence_terminal(index: int, finding: dict, e, terminal_factory) -> list[str]:
    """Builds the terminal block(s) of one finding from its stored evidence."""
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        return []
    command = evidence.get("command") or ""
    output = evidence.get("output") or ""
    ref = evidence.get("artifact_ref")
    if not command and not output and not ref:
        return []
    label = f"F{index} — {_excerpt(finding.get('title') or '(untitled)', 60)}"
    blocks = [terminal_factory(label, str(command), str(output), evidence.get("returncode"))]
    if isinstance(ref, dict) and ref:
        blocks.append(
            '<pre class="txt" style="background:#0a0000;color:#aa7777;border:1px solid #550000;'
            'border-radius:4px;padding:9px 11px;font-size:11px;margin:-8px 0 16px;">'
            "# evidence artifact: "
            + e(f"{ref.get('execution_id', '')}/{ref.get('name', '')}")
            + " (downloadable via the data channel)</pre>"
        )
    return blocks


def _controls_row(index: int, finding: dict, e) -> str:
    """Row of the reproduction/controls table (test, rc, state) from the store."""
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        return ""
    command = evidence.get("command") or ""
    output = evidence.get("output") or ""
    rc = _as_int(evidence.get("returncode"))
    if not command and output is None and "returncode" not in evidence:
        return ""
    test = _excerpt(command or finding.get("title") or "", 80)
    rc_text = str(rc) if rc is not None else "—"
    rc_css = "rc-ok" if rc in (None, 0) else "rc-fail"
    state = finding.get("state") or ""
    result_css = "result-ok" if state == "confirmed" else "result-fail"
    return (
        f'<tr><td><code>{e(test)}</code></td>'
        f'<td class="{rc_css}">{e(rc_text)}</td>'
        f'<td class="{result_css}">{e(_STATE_LABEL.get(state, state or "—"))}</td></tr>'
    )


def _vector_row(finding: dict, state: str, e) -> str:
    """Row of the evaluated/discarded vectors table."""
    evidence = finding.get("evidence")
    detail = ""
    if isinstance(evidence, dict):
        detail = evidence.get("command") or evidence.get("output") or ""
        ref = evidence.get("artifact_ref")
        if not detail and isinstance(ref, dict) and ref:
            detail = f"{ref.get('execution_id', '')}/{ref.get('name', '')}"
    row_class = ' class="discarded-row"' if state == "discarded" else ""
    return (
        f'<tr{row_class}><td>{e(finding.get("title") or "(untitled)")}</td>'
        f'<td>{e(_excerpt(detail) if detail else "—")}</td>'
        f'<td>{_badge("info", _STATE_LABEL.get(state, state or "Other"))}</td></tr>'
    )


def generate(engagement_id: str, fmt: str = "md", generated_at: str | None = None) -> dict:
    """Reads the WHOLE engagement store, renders the requested format(s) and stages them.

    ``fmt`` selects the deliverable plane: ``"md"`` (DEFAULT, backward compatible with the
    legacy behaviour and the staged ``pentest-report.md``), ``"html"`` (only
    ``pentest-report.html``) or ``"both"``. ``generated_at`` fixes the generation timestamp
    for byte-deterministic output; it defaults to now.

    Returns ``{"status", "format", "findings_count", "artifacts", "artifact"}`` where
    ``artifacts`` lists every staged entry (in md-then-html order) and ``artifact`` is the
    primary entry (the Markdown report whenever it is produced). The artifacts are
    downloadable through the data channel in ``<engagement_id>/<name>``.
    """
    fmt = (fmt or "md").lower()
    if fmt not in _FORMATS:
        raise ValueError(f"invalid format {fmt!r}: expected one of {_FORMATS}")

    page = finding_store.read(engagement_id, cursor=0, limit=None)
    findings = page.get("findings", [])

    entries: list[dict] = []
    if fmt in ("md", "both"):
        markdown = render_markdown(engagement_id, findings, generated_at=generated_at)
        entries.append(
            artifact_store.put_bytes(
                engagement_id,
                REPORT_NAME,
                markdown.encode("utf-8"),
                {
                    "kind": "pentest-report",
                    "format": "md",
                    "engagement_id": engagement_id,
                    "findings": len(findings),
                },
            )
        )
    if fmt in ("html", "both"):
        document = render_html(engagement_id, findings, generated_at=generated_at)
        entries.append(
            artifact_store.put_bytes(
                engagement_id,
                REPORT_HTML_NAME,
                document.encode("utf-8"),
                {
                    "kind": "pentest-report",
                    "format": "html",
                    "engagement_id": engagement_id,
                    "findings": len(findings),
                },
            )
        )

    return {
        "status": "done",
        "format": fmt,
        "findings_count": len(findings),
        "artifacts": entries,
        "artifact": entries[0],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the deterministic pentest report from the findings store. "
            "--format md is the DEFAULT (legacy Markdown artefact); use html or both to "
            "stage the Vulnerator-AI HTML report as well."
        )
    )
    parser.add_argument("--engagement", required=True, help="engagement_id in the findings store")
    parser.add_argument(
        "--format",
        choices=list(_FORMATS),
        default="md",
        help="deliverable format: md (default), html or both",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="fixed ISO-8601 generation timestamp (byte-deterministic output; defaults to now)",
    )
    args = parser.parse_args(argv)
    try:
        result = generate(args.engagement, fmt=args.format, generated_at=args.generated_at)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for entry in result["artifacts"]:
        # Readable output line for the OODA loop (seen via kali_run).
        print(
            f"report generated: {args.engagement}/{entry['name']} "
            f"({entry['size']} bytes, {result['findings_count']} findings, "
            f"sha256={entry['sha256']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
