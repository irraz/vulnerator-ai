"""Genera el informe de pentest (MD / TXT / HTML) a partir de los PoC del store,
con comando exacto, salida de evidencia y VERBATIM crudo de cada hallazgo."""
from __future__ import annotations
import html as _html
import json
import re
import datetime

import event_model as em

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_ES = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA", "info": "INFO"}
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
    """Extrae el stdout real de la salida de una tool MCP. Reutiliza el ÚNICO desenvolvedor
    (``event_model.tool_output_text``); el regex queda solo como RESPALDO para salidas con un
    prefijo tipo ``<untrusted_tool_result>{...}`` que el desenvolvedor estricto (pide JSON al
    inicio) no cubre. Si nada aplica, devuelve el crudo tal cual (sigue siendo verbatim)."""
    if not raw:
        return ""
    s = str(raw)
    out = em.tool_output_text(s)
    if out != s:
        return out
    try:  # respaldo: aísla el JSON embebido tras un prefijo y vuelve a pasarlo por el mismo helper
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
    """Veredicto de severidad de la IA para un título. Match EXACTO → normalizado (ignora
    espacios/mayúsculas). SIN difuso: nunca presta la severidad de un hallazgo a otro de título
    parecido (el prompt obliga a la IA a usar el TÍTULO EXACTO, así que el difuso solo metía cruces)."""
    if not ai_sev:
        return None
    if title in ai_sev:
        return ai_sev[title]
    nk = _norm_key(title)
    return {_norm_key(k): v for k, v in ai_sev.items()}.get(nk)


def _coerce_sev(entry):
    """Admite {title: 'high'} o {title: {severity, cvss, rationale}}."""
    if isinstance(entry, str):
        return entry.lower().strip(), None, ""
    if isinstance(entry, dict):
        sev = str(entry.get("severity") or entry.get("sev") or "").lower().strip()
        return (sev if sev in SEV_RANK else None), entry.get("cvss"), entry.get("rationale") or entry.get("justification") or ""
    return None, None, ""


def severity_for(title, ai_sev=None):
    """ÚNICA fuente de verdad de la severidad de un hallazgo (la usan la consola y el informe).

    Base: regex del título (``derive_sev``). Si la IA lo calificó (``severities.json``), su veredicto
    MANDA y aporta su propio CVSS y su justificación. Devuelve ``(sev, sev_by, score, rationale)``,
    donde ``sev_by`` es ``"ia"`` o ``"regex"`` y ``score`` es el CVSS (el de la IA si lo dio).
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
    """pocs: lista de PoC completos. ai_sev: mapa título→severidad de la IA (manda sobre el regex)."""
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
            "title": f.get("title", "(sin título)"),
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
        parts.append("Cliente: " + client)
    if operator:
        parts.append("Operador: " + operator)
    parts.append("Generado: " + now)
    return sep.join(parts)


def render_md(findings, engagement="engagement", narrative="", operator="", client=""):
    c = _counts(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = []
    L.append(f"# Informe de pentest — {engagement}")
    L.append(f"_{_byline(client, operator, now, ' · ')}_\n")
    L.append("## Resumen ejecutivo\n")
    L.append(f"- **Hosts en alcance:** {', '.join(_targets(findings)) or '—'}")
    L.append(f"- **Hallazgos:** {len(findings)} "
             f"(🔴 {c['critical']} críticas · 🟠 {c['high']} altas · 🟡 {c['medium']} medias · "
             f"🔵 {c['low']} bajas · ⚪ {c['info']} info)")
    L.append("- **Modo:** pentest no intrusivo (sin explotación)\n")
    L.append("| Severidad | Hallazgo | Target |")
    L.append("|---|---|---|")
    for f in findings:
        L.append(f"| {SEV_ES[f['sev']]} | {f['title'].replace('|','/')} | {(f['target'] or '').replace('|','/')} |")
    L.append("")
    if narrative.strip():
        L.append("## Narrativa del analista\n")
        L.append(narrative.strip() + "\n")
    L.append("## Hallazgos detallados — reproducción y verbatim\n")
    for i, f in enumerate(findings, 1):
        L.append(f"### {i}. [{SEV_ES[f['sev']]}] {f['title']}\n")
        meta = [f"**Target:** {f['target'] or '—'}",
                f"**Técnica:** {f['technique'] or '—'}",
                f"**Confianza:** {f['confidence'] or '—'}",
                f"**Estado:** {f['state'] or '—'}"]
        if f["score"]:
            meta.insert(1, f"**CVSS:** {f['score']}")
        L.append("  ·  ".join(meta) + "\n")
        if f.get("rationale"):
            L.append(f"> **Severidad asignada por IA:** {f['rationale']}\n")
        if f["command"]:
            L.append("**Comando:**\n")
            L.append("```bash\n" + f["command"].strip() + "\n```\n")
        if f["evidence_output"]:
            L.append("**Salida (evidencia):**\n")
            L.append("```\n" + str(f["evidence_output"]).strip() + "\n```\n")
        if f["raw_output"] and f["raw_output"].strip() != str(f["evidence_output"]).strip():
            L.append("**Verbatim completo"
                     + (" (truncado por la herramienta)" if f["truncated"] else "") + ":**\n")
            L.append("```\n" + f["raw_output"].strip() + "\n```\n")
        if f["ooda_path"]:
            steps = " → ".join(str(s.get("label") or s) if isinstance(s, dict) else str(s) for s in f["ooda_path"])
            L.append(f"**Ruta OODA:** {steps}\n")
    return "\n".join(L)


# ─────────────────────────────────────────── Texto plano
def render_txt(findings, engagement="engagement", narrative="", operator="", client=""):
    c = _counts(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    bar = "=" * 78
    L = [bar, f"INFORME DE PENTEST — {engagement.upper()}",
         _byline(client, operator, now, " | "), bar, "",
         "RESUMEN EJECUTIVO",
         f"  Hosts: {', '.join(_targets(findings)) or '-'}",
         f"  Hallazgos: {len(findings)} (CRITICAS {c['critical']} | ALTAS {c['high']} | "
         f"MEDIAS {c['medium']} | BAJAS {c['low']} | INFO {c['info']})",
         "  Modo: pentest no intrusivo (sin explotacion)", ""]
    if narrative.strip():
        L += ["-" * 78, "NARRATIVA DEL ANALISTA", "-" * 78, "",
              re.sub(r"[#*`>]", "", narrative).strip(), ""]
    L += ["-" * 78, "HALLAZGOS DETALLADOS — REPRODUCCION Y VERBATIM", "-" * 78, ""]
    for i, f in enumerate(findings, 1):
        L.append(f"[{i}] ({SEV_ES[f['sev']]}{(' CVSS '+str(f['score'])) if f['score'] else ''}) {f['title']}")
        L.append(f"    Target: {f['target'] or '-'} | Tecnica: {f['technique'] or '-'} | "
                 f"Confianza: {f['confidence'] or '-'} | Estado: {f['state'] or '-'}")
        if f.get("rationale"):
            L.append("    Severidad (IA): " + f["rationale"])
        if f["command"]:
            L += ["", "    COMANDO:", "      " + f["command"].strip().replace("\n", "\n      ")]
        if f["evidence_output"]:
            L += ["", "    SALIDA (EVIDENCIA):",
                  "      " + str(f["evidence_output"]).strip().replace("\n", "\n      ")]
        if f["raw_output"] and f["raw_output"].strip() != str(f["evidence_output"]).strip():
            L += ["", "    VERBATIM COMPLETO" + (" (truncado)" if f["truncated"] else "") + ":",
                  "      " + f["raw_output"].strip().replace("\n", "\n      ")]
        L += ["", "-" * 78, ""]
    return "\n".join(L)


# ─────────────────────────────────────────── HTML (vista)
def render_html(findings, engagement="engagement", narrative="", operator="", client=""):
    c = _counts(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    e = _html.escape
    title_who = " — ".join(x for x in (e(client), e(operator)) if x)
    sub_who = "".join(
        ([" · Cliente <b>%s</b>" % e(client)] if client else [])
        + ([" · Operador <b>%s</b>" % e(operator)] if operator else []))

    def block(label, text, mono=True):
        if not text:
            return ""
        body = e(str(text).strip())
        cls = "pre" if mono else "txt"
        return f'<div class="lbl">{e(label)}</div><pre class="{cls}">{body}</pre>'

    rows = ""
    for f in findings:
        rows += (f'<tr><td><span class="sev sev--{f["sev"]}">{SEV_ES[f["sev"]]}</span></td>'
                 f'<td>{e(f["title"])}</td><td class="mut">{e(f["target"] or "—")}</td></tr>')
    cards = ""
    for i, f in enumerate(findings, 1):
        cvss = f'<span class="meta">CVSS <b>{f["score"]}</b></span>' if f["score"] else ""
        narr_raw = ""
        if f["raw_output"] and f["raw_output"].strip() != str(f["evidence_output"]).strip():
            narr_raw = block("Verbatim completo" + (" (truncado por la herramienta)" if f["truncated"] else ""),
                             f["raw_output"])
        cards += f"""
        <section class="card card--{f['sev']}">
          <h3><span class="sev sev--{f['sev']}">{SEV_ES[f['sev']]}</span> {i}. {e(f['title'])}</h3>
          <div class="metas">
            <span class="meta">Target <b>{e(f['target'] or '—')}</b></span>
            <span class="meta">Técnica <b>{e(f['technique'] or '—')}</b></span>
            <span class="meta">Confianza <b>{e(f['confidence'] or '—')}</b></span>
            <span class="meta">Estado <b>{e(f['state'] or '—')}</b></span>
            {cvss}
            {'<span class="meta meta--ia">severidad IA</span>' if f.get('sev_by') == 'ia' else ''}
          </div>
          {('<div class="airat"><b>Severidad (IA):</b> ' + e(f['rationale']) + '</div>') if f.get('rationale') else ''}
          {block("Comando", f['command'])}
          {block("Salida (evidencia)", f['evidence_output'])}
          {narr_raw}
        </section>"""
    narrative_html = ""
    if narrative.strip():
        narrative_html = f'<section class="narr"><h2>Narrativa del analista</h2><pre class="txt">{e(narrative.strip())}</pre></section>'
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Informe de pentest — {e(engagement)}{(' — ' + title_who) if title_who else ''}</title>
<style>
  @page {{ size: A4; margin: 16mm 14mm; @bottom-right {{ content: "Pág. " counter(page) "/" counter(pages); font-size: 9px; color: #888; }} }}
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
  <h1>Informe de pentest</h1>
  <p class="sub">Engagement <b>{e(engagement)}</b>{sub_who} · {now} · <b>pentest no intrusivo (sin explotación)</b></p>
  <div class="summary">
    <b>{len(findings)} hallazgos</b> — 🔴 {c['critical']} críticas · 🟠 {c['high']} altas · 🟡 {c['medium']} medias · 🔵 {c['low']} bajas · ⚪ {c['info']} info
    &nbsp;|&nbsp; Hosts: {e(', '.join(_targets(findings)) or '—')}
  </div>
  <h2>Resumen de hallazgos</h2>
  <table><thead><tr><th>Sev.</th><th>Hallazgo</th><th>Target</th></tr></thead><tbody>{rows}</tbody></table>
  {narrative_html}
  <h2>Hallazgos detallados — reproducción y verbatim</h2>
  {cards}
</body></html>"""


