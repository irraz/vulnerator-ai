"""Generates the pentest report (MD / TXT / HTML) from the store's PoCs,
with the exact command, evidence output and raw VERBATIM of each finding."""
from __future__ import annotations
import html as _html
import json
import re
import datetime

import event_model as em

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_EN = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
SEV_HEX = {"critical": "#ef5350", "high": "#ffa726", "medium": "#d4b26a", "low": "#7fb3c9", "info": "#9aa0ac"}


def derive_sev(title: str):
    t = (title or "").upper()
    m = re.search(r"CVSS\s*(\d{1,2}(?:\.\d)?)", t)
    score = float(m.group(1)) if m else None
    if re.search(r"\bCRIT[IÍ]CA\b|\bCRITICAL\b", t) or (score is not None and score >= 9.0):
        return "critical", score
    if re.search(r"\bHIGH\b|\bALTA\b", t) or (score is not None and score >= 7.0):
        return "high", score
    if re.search(r"\bMEDIUM\b|\bMEDIA\b", t) or (score is not None and score >= 4.0):
        return "medium", score
    if re.search(r"\bLOW\b|\bBAJA\b", t) or (score is not None and score > 0):
        return "low", score
    return "info", score


def clean_output(raw):
    """Extracts the real stdout from the output of an MCP tool. Reuses the SINGLE unwrapper
    (``event_model.tool_output_text``); the regex is only a FALLBACK for outputs with a
    prefix like ``<untrusted_tool_result>{...}`` that the strict unwrapper (which requires JSON
    at the start) does not cover. If nothing applies, it returns the raw value as is (still verbatim)."""
    if not raw:
        return ""
    s = str(raw)
    out = em.tool_output_text(s)
    if out != s:
        return out
    try:  # fallback: isolate the JSON embedded after a prefix and run it through the same helper again
        m = re.search(r"\{.*\}", s, re.S)
        if m:
            inner = em.tool_output_text(m.group(0))
            if inner and inner != m.group(0):
                return inner
    except Exception:
        pass
    return s


def _norm_key(s):
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def ai_lookup(title, ai_sev):
    """AI severity verdict for a title. EXACT match → normalized (ignores whitespace/case).
    NO fuzzy matching: it never lends the severity of one finding to another with a similar
    title (the prompt forces the AI to use the EXACT TITLE, so fuzzy matching only caused crossovers)."""
    if not ai_sev:
        return None
    if title in ai_sev:
        return ai_sev[title]
    nk = _norm_key(title)
    return {_norm_key(k): v for k, v in ai_sev.items()}.get(nk)


def _coerce_sev(entry):
    """Accepts {title: 'high'} or {title: {severity, cvss, rationale}}."""
    if isinstance(entry, str):
        return entry.lower().strip(), None, ""
    if isinstance(entry, dict):
        sev = str(entry.get("severity") or entry.get("sev") or "").lower().strip()
        return (sev if sev in SEV_RANK else None), entry.get("cvss"), entry.get("rationale") or entry.get("justification") or ""
    return None, None, ""


def severity_for(title, ai_sev=None):
    """SINGLE source of truth for the severity of a finding (used by the console and the report).

    Base: title regex (``derive_sev``). If the AI rated it (``severities.json``), its verdict
    WINS and provides its own CVSS and justification. Returns ``(sev, sev_by, score, rationale)``,
    where ``sev_by`` is ``"ia"`` or ``"regex"`` and ``score`` is the CVSS (the AI's one if provided).
    """
    sev, score = derive_sev(title)
    sev_by, rationale = "regex", ""
    hit = ai_lookup(title, ai_sev)
    if hit is not None:
        ai_s, ai_cvss, ai_rat = _coerce_sev(hit)
        if ai_s:
            sev, sev_by, rationale = ai_s, "ia", ai_rat
            if ai_cvss is not None:
                try:
                    score = float(ai_cvss)
                except Exception:
                    pass
    return sev, sev_by, score, rationale


def normalize(pocs, ai_sev=None):
    """pocs: list of complete PoCs. ai_sev: map title→AI severity (wins over the regex)."""
    out = []
    for p in pocs:
        f = p.get("finding", {}) or {}
        rep = p.get("reproduction", {}) or {}
        ex = rep.get("execution", {}) or {}
        ev = f.get("evidence", {}) or {}
        title = f.get("title", "")
        sev, sev_by, score, rationale = severity_for(title, ai_sev)
        out.append({
            "sev_by": sev_by,
            "rationale": rationale,
            "sev": sev, "score": score,
            "title": f.get("title", "(untitled)"),
            "target": f.get("target", ""),
            "technique": f.get("technique_id", ""),
            "confidence": f.get("confidence", ""),
            "state": p.get("store_status") or f.get("state", ""),
            "confirmed": bool(p.get("confirmed")),
            "command": rep.get("command") or ex.get("command") or ev.get("command") or "",
            "evidence_output": ev.get("output") or rep.get("evidence_output") or "",
            "raw_output": clean_output(ex.get("output")),
            "tool": ex.get("tool", ""),
            "returncode": ex.get("returncode"),
            "truncated": ex.get("output_truncated"),
            "phase": p.get("phase"), "step": p.get("step"),
            "ooda_path": p.get("ooda_path") or [],
        })
    out.sort(key=lambda x: (-SEV_RANK[x["sev"]], -(x["score"] or 0)))
    return out


def _counts(findings):
    c = {k: 0 for k in SEV_RANK}
    for f in findings:
        c[f["sev"]] += 1
    return c


def _targets(findings):
    hosts = set()
    for f in findings:
        m = re.search(r"\d+\.\d+\.\d+\.\d+", f["target"] or "")
        if m:
            hosts.add(m.group(0))
    return sorted(hosts)


# ─────────────────────────────────────────── Markdown
def _byline(client, operator, now, sep):
    parts = []
    if client:
        parts.append("Client: " + client)
    if operator:
        parts.append("Operator: " + operator)
    parts.append("Generated: " + now)
    return sep.join(parts)


def render_md(findings, engagement="engagement", narrative="", operator="", client=""):
    c = _counts(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = []
    L.append(f"# Pentest report — {engagement}")
    L.append(f"_{_byline(client, operator, now, ' · ')}_\n")
    L.append("## Executive summary\n")
    L.append(f"- **Hosts in scope:** {', '.join(_targets(findings)) or '—'}")
    L.append(f"- **Findings:** {len(findings)} "
             f"(🔴 {c['critical']} critical · 🟠 {c['high']} high · 🟡 {c['medium']} medium · "
             f"🔵 {c['low']} low · ⚪ {c['info']} info)")
    L.append("- **Mode:** non-intrusive pentest (no exploitation)\n")
    L.append("| Severity | Finding | Target |")
    L.append("|---|---|---|")
    for f in findings:
        L.append(f"| {SEV_EN[f['sev']]} | {f['title'].replace('|','/')} | {(f['target'] or '').replace('|','/')} |")
    L.append("")
    if narrative.strip():
        L.append("## Analyst narrative\n")
        L.append(narrative.strip() + "\n")
    L.append("## Detailed findings — reproduction and verbatim\n")
    for i, f in enumerate(findings, 1):
        L.append(f"### {i}. [{SEV_EN[f['sev']]}] {f['title']}\n")
        meta = [f"**Target:** {f['target'] or '—'}",
                f"**Technique:** {f['technique'] or '—'}",
                f"**Confidence:** {f['confidence'] or '—'}",
                f"**State:** {f['state'] or '—'}"]
        if f["score"]:
            meta.insert(1, f"**CVSS:** {f['score']}")
        L.append("  ·  ".join(meta) + "\n")
        if f.get("rationale"):
            L.append(f"> **Severity assigned by AI:** {f['rationale']}\n")
        if f["command"]:
            L.append("**Command:**\n")
            L.append("```bash\n" + f["command"].strip() + "\n```\n")
        if f["evidence_output"]:
            L.append("**Output (evidence):**\n")
            L.append("```\n" + str(f["evidence_output"]).strip() + "\n```\n")
        if f["raw_output"] and f["raw_output"].strip() != str(f["evidence_output"]).strip():
            L.append("**Full verbatim"
                     + (" (truncated by the tool)" if f["truncated"] else "") + ":**\n")
            L.append("```\n" + f["raw_output"].strip() + "\n```\n")
        if f["ooda_path"]:
            steps = " → ".join(str(s.get("label") or s) if isinstance(s, dict) else str(s) for s in f["ooda_path"])
            L.append(f"**OODA path:** {steps}\n")
    return "\n".join(L)


# ─────────────────────────────────────────── Plain text
def render_txt(findings, engagement="engagement", narrative="", operator="", client=""):
    c = _counts(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    bar = "=" * 78
    L = [bar, f"PENTEST REPORT — {engagement.upper()}",
         _byline(client, operator, now, " | "), bar, "",
         "EXECUTIVE SUMMARY",
         f"  Hosts: {', '.join(_targets(findings)) or '-'}",
         f"  Findings: {len(findings)} (CRITICAL {c['critical']} | HIGH {c['high']} | "
         f"MEDIUM {c['medium']} | LOW {c['low']} | INFO {c['info']})",
         "  Mode: non-intrusive pentest (no exploitation)", ""]
    if narrative.strip():
        L += ["-" * 78, "ANALYST NARRATIVE", "-" * 78, "",
              re.sub(r"[#*`>]", "", narrative).strip(), ""]
    L += ["-" * 78, "DETAILED FINDINGS — REPRODUCTION AND VERBATIM", "-" * 78, ""]
    for i, f in enumerate(findings, 1):
        L.append(f"[{i}] ({SEV_EN[f['sev']]}{(' CVSS '+str(f['score'])) if f['score'] else ''}) {f['title']}")
        L.append(f"    Target: {f['target'] or '-'} | Technique: {f['technique'] or '-'} | "
                 f"Confidence: {f['confidence'] or '-'} | State: {f['state'] or '-'}")
        if f.get("rationale"):
            L.append("    Severity (AI): " + f["rationale"])
        if f["command"]:
            L += ["", "    COMMAND:", "      " + f["command"].strip().replace("\n", "\n      ")]
        if f["evidence_output"]:
            L += ["", "    OUTPUT (EVIDENCE):",
                  "      " + str(f["evidence_output"]).strip().replace("\n", "\n      ")]
        if f["raw_output"] and f["raw_output"].strip() != str(f["evidence_output"]).strip():
            L += ["", "    FULL VERBATIM" + (" (truncated)" if f["truncated"] else "") + ":",
                  "      " + f["raw_output"].strip().replace("\n", "\n      ")]
        L += ["", "-" * 78, ""]
    return "\n".join(L)


# ─────────────────────────────────────────── HTML (view)
def render_html(findings, engagement="engagement", narrative="", operator="", client=""):
    c = _counts(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    e = _html.escape
    title_who = " — ".join(x for x in (e(client), e(operator)) if x)
    sub_who = "".join(
        ([" · Client <b>%s</b>" % e(client)] if client else [])
        + ([" · Operator <b>%s</b>" % e(operator)] if operator else []))

    def block(label, text, mono=True):
        if not text:
            return ""
        body = e(str(text).strip())
        cls = "pre" if mono else "txt"
        return f'<div class="lbl">{e(label)}</div><pre class="{cls}">{body}</pre>'

    rows = ""
    for f in findings:
        rows += (f'<tr><td><span class="sev sev--{f["sev"]}">{SEV_EN[f["sev"]]}</span></td>'
                 f'<td>{e(f["title"])}</td><td class="mut">{e(f["target"] or "—")}</td></tr>')
    cards = ""
    for i, f in enumerate(findings, 1):
        cvss = f'<span class="meta">CVSS <b>{f["score"]}</b></span>' if f["score"] else ""
        narr_raw = ""
        if f["raw_output"] and f["raw_output"].strip() != str(f["evidence_output"]).strip():
            narr_raw = block("Full verbatim" + (" (truncated by the tool)" if f["truncated"] else ""),
                             f["raw_output"])
        cards += f"""
        <section class="card card--{f['sev']}">
          <h3><span class="sev sev--{f['sev']}">{SEV_EN[f['sev']]}</span> {i}. {e(f['title'])}</h3>
          <div class="metas">
            <span class="meta">Target <b>{e(f['target'] or '—')}</b></span>
            <span class="meta">Technique <b>{e(f['technique'] or '—')}</b></span>
            <span class="meta">Confidence <b>{e(f['confidence'] or '—')}</b></span>
            <span class="meta">State <b>{e(f['state'] or '—')}</b></span>
            {cvss}
            {'<span class="meta meta--ia">AI severity</span>' if f.get('sev_by') == 'ia' else ''}
          </div>
          {('<div class="airat"><b>Severity (AI):</b> ' + e(f['rationale']) + '</div>') if f.get('rationale') else ''}
          {block("Command", f['command'])}
          {block("Output (evidence)", f['evidence_output'])}
          {narr_raw}
        </section>"""
    narrative_html = ""
    if narrative.strip():
        narrative_html = f'<section class="narr"><h2>Analyst narrative</h2><pre class="txt">{e(narrative.strip())}</pre></section>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Pentest report — {e(engagement)}{(' — ' + title_who) if title_who else ''}</title>
<style>
  @page {{ size: A4; margin: 16mm 14mm; @bottom-right {{ content: "Page " counter(page) "/" counter(pages); font-size: 9px; color: #888; }} }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #15171e; background: #fff; margin: 0; font-size: 12px; line-height: 1.5; }}
  h1 {{ color: #b03a3a; margin: 0 0 2px; font-size: 24px; }}
  h2 {{ color: #b03a3a; border-bottom: 2px solid #eadada; padding-bottom: 4px; margin-top: 26px; }}
  h3 {{ margin: 0 0 8px; font-size: 14px; }}
  .sub {{ color: #777; margin: 0 0 18px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0 6px; }}
  th, td {{ text-align: left; padding: 5px 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
  th {{ background: #faf5f5; color: #b03a3a; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }}
  .mut {{ color: #777; }}
  .sev {{ display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 10px; font-weight: 700; letter-spacing: .06em; color: #fff; }}
  .sev--critical {{ background: {SEV_HEX['critical']}; }} .sev--high {{ background: {SEV_HEX['high']}; color:#2a1c00; }}
  .sev--medium {{ background: {SEV_HEX['medium']}; color:#2a2200; }} .sev--low {{ background: {SEV_HEX['low']}; color:#06252e; }}
  .sev--info {{ background: {SEV_HEX['info']}; }}
  .card {{ border: 1px solid #e7e7ea; border-left: 4px solid #ccc; border-radius: 5px; padding: 12px 14px; margin: 12px 0; page-break-inside: avoid; }}
  .card--critical {{ border-left-color: {SEV_HEX['critical']}; }} .card--high {{ border-left-color: {SEV_HEX['high']}; }}
  .card--medium {{ border-left-color: {SEV_HEX['medium']}; }} .card--low {{ border-left-color: {SEV_HEX['low']}; }}
  .card--info {{ border-left-color: {SEV_HEX['info']}; }}
  .metas {{ display: flex; flex-wrap: wrap; gap: 6px 14px; margin: 2px 0 10px; font-size: 11px; color: #555; }}
  .meta b {{ color: #15171e; }}
  .meta--ia {{ background: #eef3ff; color: #3a5bbf; border-radius: 3px; padding: 0 6px; font-size: 10px; letter-spacing: .05em; text-transform: uppercase; }}
  .airat {{ background: #f3f6ff; border-left: 3px solid #3a5bbf; border-radius: 4px; padding: 7px 10px; margin: 2px 0 10px; font-size: 11px; color: #2a3550; }}
  .airat b {{ color: #3a5bbf; }}
  .lbl {{ font-size: 10px; letter-spacing: .06em; text-transform: uppercase; color: #b03a3a; margin: 9px 0 3px; font-weight: 700; }}
  pre.pre, pre.txt {{ background: #0e1118; color: #e6e8ec; border-radius: 4px; padding: 9px 11px; overflow-wrap: anywhere; white-space: pre-wrap; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 10.5px; margin: 0; }}
  pre.txt {{ background: #f6f6f8; color: #222; }}
  .summary {{ background: #faf7f7; border: 1px solid #eadada; border-radius: 6px; padding: 10px 14px; }}
</style></head><body>
  <h1>Pentest report</h1>
  <p class="sub">Engagement <b>{e(engagement)}</b>{sub_who} · {now} · <b>non-intrusive pentest (no exploitation)</b></p>
  <div class="summary">
    <b>{len(findings)} findings</b> — 🔴 {c['critical']} critical · 🟠 {c['high']} high · 🟡 {c['medium']} medium · 🔵 {c['low']} low · ⚪ {c['info']} info
    &nbsp;|&nbsp; Hosts: {e(', '.join(_targets(findings)) or '—')}
  </div>
  <h2>Findings summary</h2>
  <table><thead><tr><th>Sev.</th><th>Finding</th><th>Target</th></tr></thead><tbody>{rows}</tbody></table>
  {narrative_html}
  <h2>Detailed findings — reproduction and verbatim</h2>
  {cards}
</body></html>"""


