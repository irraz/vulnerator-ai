"""Generador del informe formal de pentest (Markdown) desde el store de hallazgos.

Produce el ENTREGABLE al cerrar un engagement, complementando a ``ooda-report-handoff``
(que solo da el resumen conversacional DURANTE el engagement). LEE el registro durable de
findings (``finding_store``) rather than rebuilding from the conversation, and writes a
informe Markdown que se deja como ARTEFACTO en el plano de datos (``/artifacts``), para
descargarlo por el canal HTTP (:8901) sin sacar nada por el MCP.

Pattern like the other baked-in scripts (Prowler/Pacu): PURE STDLIB, invoked with
``kali_run`` (``python3 report_gen.py --engagement <id>``). The render LOGIC is testable
sin el SDK (``render_markdown`` sobre una lista de hallazgos); ``main`` encadena
leer-del-store -> render -> stage.

Report structure (distilled from public pentest templates, with attribution —
Theophilus/athena-pentest y Marmeus/pentesting-report-generator): engagement details,
executive summary (non-technical), severity table, methodology (OODA/PTES/OWASP),
findings with CVSS 3.1 + CWE and reproducible evidence, remediation. CVSS/severity only for
hallazgos CONFIRMADOS (coherente con "no hay hallazgo sin evidencia").

OUTPUT LANGUAGE: the report is emitted in ENGLISH (aligned with the repo's public
documentation). This module's comments/docstrings are translated to English, like the rest of
docker/kali/. Only strings ending up in the deliverable Markdown are in English.

Dato NO confiable: la evidencia de cada hallazgo (comando/salida) viene de tools contra un
real target. Here it is RENDERED verbatim inside code blocks; it is never interpreted.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

import artifact_store
import finding_store

# Canonical name of the report inside the engagement directory (downloadable artifact).
REPORT_NAME = "pentest-report.md"

# Presentation order of states and their human label (output in English).
_STATE_LABEL = {
    "confirmed": "Confirmed",
    "partial": "Partial",
    "hypothesis": "Hypothesis",
    "discarded": "Discarded",
}
_STATE_ORDER = ["confirmed", "partial", "hypothesis", "discarded"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fence(text: str) -> str:
    """Wraps text (untrusted data) in a verbatim code block.

    Usa una valla de 4 backticks para no romperse si el contenido trae ``` dentro.
    """
    body = text if isinstance(text, str) else str(text)
    return "````\n" + body.rstrip("\n") + "\n````"


def _evidence_block(evidence: dict) -> list[str]:
    """Renderiza la evidencia de un hallazgo (comando/returncode/salida o ref a artefacto)."""
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
    # CVSS/CWE solo tienen sentido en hallazgos confirmados (disciplina "no hay hallazgo
    # without evidence"): they are shown if the agent recorded them.
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
    """Renderiza el informe Markdown completo a partir de la lista de hallazgos.

    PURE, testable function (does not touch the store or FS): receives already-read findings and
    devuelve el texto del informe. Agrupa por estado (confirmados primero), con tabla de
    severities by state and the methodology/remediation sections.
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

    # --- Tabla de severidades (por estado) ---
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

    # --- Hallazgos (confirmados primero) ---
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

    # --- Nota de alcance / limitaciones ---
    lines.append("## Scope and limitations")
    lines.append("")
    lines.append(
        "This report reflects only the findings recorded during the engagement against "
        "operator-authorized targets. Responsibility for the scope rests with the operator. "
        "The included evidence is raw tool output, presented verbatim."
    )
    lines.append("")

    return "\n".join(lines)


def generate(engagement_id: str) -> dict:
    """Lee TODO el store del engagement, renderiza el informe y lo stagea como artefacto.

    Returns the meta entry of the staged artifact (``{name, size, sha256, ...}``) plus the
    recuento de hallazgos. El Markdown queda descargable por el canal de datos en
    ``<engagement_id>/pentest-report.md``.
    """
    page = finding_store.read(engagement_id, cursor=0, limit=None)
    findings = page.get("findings", [])
    markdown = render_markdown(engagement_id, findings)
    entry = artifact_store.put_bytes(
        engagement_id,
        REPORT_NAME,
        markdown.encode("utf-8"),
        {"kind": "pentest-report", "engagement_id": engagement_id, "findings": len(findings)},
    )
    return {"status": "done", "artifact": entry, "findings_count": len(findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Markdown pentest report from the findings store."
    )
    parser.add_argument("--engagement", required=True, help="engagement_id in the findings store")
    args = parser.parse_args(argv)
    try:
        result = generate(args.engagement)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    entry = result["artifact"]
    # Readable output line for the OODA loop (seen via kali_run).
    print(
        f"report generated: {args.engagement}/{entry['name']} "
        f"({entry['size']} bytes, {result['findings_count']} findings, "
        f"sha256={entry['sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
