"""Fingerprinting web por CRUCE de whatweb + webanalyze + wpscan (STDLIB PURA).

It is the testable LOGIC of the ``webtech_scan`` runner that ``kali_mcp_server`` exposes as
``@mcp.tool``. Igual que ``shell_exec`` / ``dnsdumpster_client`` / ``scope_guard``, vive en
a separate module with ONLY the standard library (no ``mcp``) to be covered by tests
unitarios en el venv de dev.

What it solves: three tools see a site's technology stack with different biases.
No single one is trustworthy for a component's VERSION; cross-checking raises confidence and
exposes discrepancies. This module runs all three (each OPTIONAL: if the binary is
absent it is skipped and reported, never faked) and MERGES their outputs into a single table
``technology -> {versions by source, sources that saw it, agreement/conflict}``:

  - whatweb     : broad, fast fingerprinting; versions in ``plugins.<x>.version``.
  - webanalyze  : motor de fingerprints de Wappalyzer (port en Go; el CLI oficial de
                  Wappalyzer is discontinued). Categories + version per app.
  - wpscan      : especialista WordPress. Si el objetivo NO es WordPress lo dice
                  (``scan_aborted``) y se reporta como tal (NO es un error); si lo es,
                  provides core version, versioned plugins/themes and findings.

Version cross-check: for each technology, ALL versions observed by
fuente. Si dos fuentes dan versiones distintas para el mismo componente se marca
``version_conflict`` (a signal to the OODA loop that the version is inconclusive). The
"best" version is the most specific agreeing one.

UNTRUSTED data: the three tools' output is transported verbatim; here only the
PARSEA su forma conocida, nunca se interpreta su contenido. Las funciones ``parse_*`` y
``cross_reference`` are PURE (JSON string -> dict) and are the core covered by tests; the
orquestador ``run_webtech`` ejecuta los binarios y delega en ellas.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any

# Timeout per tool (seconds). whatweb/webanalyze are fast; wpscan can be slow.
DEFAULT_TOOL_TIMEOUT_S = int(os.environ.get("WEBTECH_TOOL_TIMEOUT", "300"))

# Binary names (overridable via environment for containers with non-standard paths).
WHATWEB_BIN = os.environ.get("WHATWEB_BIN", "whatweb")
WEBANALYZE_BIN = os.environ.get("WEBANALYZE_BIN", "webanalyze")
WPSCAN_BIN = os.environ.get("WPSCAN_BIN", "wpscan")

# webanalyze lee sus fingerprints de ``technologies.json`` en el CWD por defecto. En el
# container the file is downloaded to a fixed path (see Dockerfile) and exposed here to
# pass with ``-apps``; if empty, webanalyze uses its default search.
WEBANALYZE_APPS = os.environ.get("WEBANALYZE_APPS", "")


class WebTechError(ValueError):
    """Invalid input for the runner (fail-closed; nothing is executed)."""


def _validate_url(url: Any) -> str:
    """Validates that ``url`` is a non-empty http(s) URL, or raises ``WebTechError``."""
    if not isinstance(url, str) or not url.strip():
        raise WebTechError("invalid url: expected a non-empty http(s) URL.")
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


# --------------------------------------------------------------- parsers (PUROS)


def parse_whatweb(raw: str) -> list[dict[str, Any]]:
    """Parsea el ``--log-json`` de whatweb en ``[{name, version, source='whatweb'}]``.

    whatweb emite un ARRAY (una entrada por salto de URL); cada una lleva ``plugins`` como
    dict ``name -> {version:[...], string:[...]}``. Name+version is extracted from each
    plugin. Robust to empty/bad JSON (returns an empty list): untrusted data.
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        docs = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return out
    if isinstance(docs, dict):
        docs = [docs]
    if not isinstance(docs, list):
        return out
    for doc in docs:
        plugins = doc.get("plugins") if isinstance(doc, dict) else None
        if not isinstance(plugins, dict):
            continue
        for name, info in plugins.items():
            versions = info.get("version", []) if isinstance(info, dict) else []
            if not isinstance(versions, list):
                versions = [versions]
            versions = [str(v) for v in versions if v not in (None, "", [])]
            if versions:
                for v in versions:
                    key = (name, v)
                    if key not in seen:
                        seen.add(key)
                        out.append({"name": name, "version": v, "source": "whatweb"})
            else:
                key = (name, "")
                if key not in seen:
                    seen.add(key)
                    out.append({"name": name, "version": "", "source": "whatweb"})
    return out


def parse_webanalyze(raw: str) -> list[dict[str, Any]]:
    """Parsea el ``-output json`` de webanalyze en ``[{name, version, categories, source}]``.

    webanalyze emite un objeto ``{hostname, matches:[{app_name, version, app:{category_names}}]}``
    (o un array de ellos si se le pasan varios hosts). Robusto a formas inesperadas.
    """
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return out
    docs = data if isinstance(data, list) else [data]
    for doc in docs:
        matches = doc.get("matches") if isinstance(doc, dict) else None
        if not isinstance(matches, list):
            continue
        for m in matches:
            if not isinstance(m, dict):
                continue
            name = m.get("app_name") or m.get("app") or ""
            if not isinstance(name, str) or not name:
                continue
            version = str(m.get("version") or "")
            cats = []
            app = m.get("app")
            if isinstance(app, dict) and isinstance(app.get("category_names"), list):
                cats = [str(c) for c in app["category_names"]]
            key = (name, version)
            if key not in seen:
                seen.add(key)
                out.append(
                    {
                        "name": name,
                        "version": version,
                        "categories": cats,
                        "source": "webanalyze",
                    }
                )
    return out


def parse_wpscan(raw: str) -> dict[str, Any]:
    """Parsea el ``--format json`` de wpscan en un resumen WordPress estructurado.

    Devuelve ``{is_wordpress, aborted_reason, wp_version, theme, plugins:[...],
    interesting_count, techs:[...]}`` donde ``techs`` normaliza core + plugins + tema a
    ``[{name, version, source='wpscan'}]`` for cross-checking. If wpscan aborted because the site
    no es WordPress, ``is_wordpress=False`` y ``aborted_reason`` lleva el motivo (NO es un
    error). Robust to empty/bad JSON.
    """
    result: dict[str, Any] = {
        "is_wordpress": False,
        "aborted_reason": "",
        "wp_version": "",
        "theme": "",
        "plugins": [],
        "interesting_count": 0,
        "techs": [],
    }
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        result["aborted_reason"] = "salida de wpscan no parseable"
        return result
    if not isinstance(data, dict):
        return result

    aborted = data.get("scan_aborted")
    if aborted:
        result["aborted_reason"] = str(aborted)
        return result

    techs: list[dict[str, Any]] = []
    version = data.get("version")
    if isinstance(version, dict) and version.get("number"):
        result["is_wordpress"] = True
        result["wp_version"] = str(version["number"])
        techs.append(
            {"name": "WordPress", "version": result["wp_version"], "source": "wpscan"}
        )

    main_theme = data.get("main_theme")
    if isinstance(main_theme, dict):
        tname = main_theme.get("slug") or main_theme.get("style_name") or ""
        tver = (
            str(main_theme.get("version", {}).get("number", ""))
            if isinstance(main_theme.get("version"), dict)
            else ""
        )
        if tname:
            result["is_wordpress"] = True
            result["theme"] = f"{tname} {tver}".strip()
            techs.append(
                {"name": f"theme:{tname}", "version": tver, "source": "wpscan"}
            )

    plugins = data.get("plugins")
    if isinstance(plugins, dict):
        for slug, pinfo in plugins.items():
            if not isinstance(pinfo, dict):
                continue
            result["is_wordpress"] = True
            pver = ""
            if isinstance(pinfo.get("version"), dict):
                pver = str(pinfo["version"].get("number", ""))
            result["plugins"].append({"slug": slug, "version": pver})
            techs.append(
                {"name": f"plugin:{slug}", "version": pver, "source": "wpscan"}
            )

    interesting = data.get("interesting_findings")
    if isinstance(interesting, list):
        result["interesting_count"] = len(interesting)
        # Un target vivo con findings pero sin version/plugins detectados sigue siendo WP
        # if wpscan did not abort: we mark it so as not to report a false "not WordPress".
        if interesting and not result["is_wordpress"] and not result["aborted_reason"]:
            result["is_wordpress"] = True

    result["techs"] = techs
    return result


def _norm(name: str) -> str:
    """Case-insensitive merge key without leading/trailing spaces for a tech name."""
    return name.strip().lower()


def cross_reference(*tech_lists: list[dict[str, Any]]) -> dict[str, Any]:
    """Fusiona varias listas ``[{name, version, source}]`` cruzando versiones por fuente.

    Devuelve ``{technologies:[...], conflicts:[...], sources:[...]}`` donde cada entrada de
    ``technologies`` es::

        {name, sources:[...], versions:{source: [v,...]}, best_version, version_conflict}

    ``version_conflict`` is True if two sources report different NON-empty versions for
    the same component (inconclusive-version signal). ``best_version`` is the version
    most specific agreeing one (the longest among those observed; empty if no source
    gave a version). Cross-checking is by normalized name (case-insensitive).
    """
    merged: dict[str, dict[str, Any]] = {}
    all_sources: list[str] = []

    for tech_list in tech_lists:
        for tech in tech_list:
            name = tech.get("name", "")
            if not name:
                continue
            source = tech.get("source", "?")
            version = str(tech.get("version", "") or "")
            if source not in all_sources:
                all_sources.append(source)
            key = _norm(name)
            entry = merged.setdefault(
                key,
                {"name": name, "sources": [], "versions": {}, "categories": []},
            )
            if source not in entry["sources"]:
                entry["sources"].append(source)
            entry["versions"].setdefault(source, [])
            if version and version not in entry["versions"][source]:
                entry["versions"][source].append(version)
            cats = tech.get("categories")
            if isinstance(cats, list):
                for c in cats:
                    if c and c not in entry["categories"]:
                        entry["categories"].append(c)

    technologies: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for entry in merged.values():
        distinct_versions = sorted(
            {v for versions in entry["versions"].values() for v in versions}
        )
        conflict = len(distinct_versions) > 1
        best = max(distinct_versions, key=len) if distinct_versions else ""
        tech_out = {
            "name": entry["name"],
            "sources": entry["sources"],
            "versions": entry["versions"],
            "best_version": best,
            "version_conflict": conflict,
        }
        if entry["categories"]:
            tech_out["categories"] = entry["categories"]
        technologies.append(tech_out)
        if conflict:
            conflicts.append(
                {
                    "name": entry["name"],
                    "versions": distinct_versions,
                    "by_source": entry["versions"],
                }
            )

    # Stable order: first those seen by more sources, then alphabetical.
    technologies.sort(key=lambda t: (-len(t["sources"]), t["name"].lower()))
    return {
        "technologies": technologies,
        "conflicts": conflicts,
        "sources": all_sources,
    }


# --------------------------------------------------------------- orquestador (ejecuta)


def _which(bin_name: str) -> str | None:
    return shutil.which(bin_name)


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Ejecuta ``cmd`` sin shell con timeout; devuelve ``(rc, stdout, stderr)``.

    It does not raise on returncode or timeout: a tool failure is information, not
    an exception. UNTRUSTED data: stdout/stderr verbatim.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - fixed binaries, args built here
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout tras {timeout}s"
    except FileNotFoundError:
        return -1, "", "binario no encontrado"


def run_webtech(
    url: str,
    run_wpscan: bool = True,
    aggression: int = 3,
    timeout: int = DEFAULT_TOOL_TIMEOUT_S,
) -> dict[str, Any]:
    """Ejecuta whatweb + webanalyze + (opcional) wpscan y CRUZA sus versiones.

    Each tool is optional: if its binary is absent, it is skipped and noted in ``skipped``
    (disciplina "no se finge"). Flujo por herramienta: ejecutar -> capturar JSON (fichero o
    stdout) -> parse with the corresponding pure function. Finally ``cross_reference``
    fusiona las tres fuentes.

    Returns ``{'status':'done', url, cross_reference:{...}, wpscan:{...}, ran:[...],
    skipped:[...], errors:[...]}``. ``status`` es ``'done'`` aunque alguna herramienta
    fails (what the others collected is still useful); it is ``'failed'`` only if the URL
    is invalid or NO tool could run.
    """
    try:
        u = _validate_url(url)
    except WebTechError as exc:
        return {"status": "failed", "url": url, "error": str(exc)}
    ran: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []
    whatweb_techs: list[dict[str, Any]] = []
    webanalyze_techs: list[dict[str, Any]] = []
    wpscan_summary: dict[str, Any] = {}

    workdir = tempfile.mkdtemp(prefix="webtech-")
    try:
        # --- whatweb (--log-json a fichero) ---
        if _which(WHATWEB_BIN):
            out_f = os.path.join(workdir, "whatweb.json")
            rc, _so, se = _run(
                [
                    WHATWEB_BIN,
                    "--quiet",
                    f"--log-json={out_f}",
                    "-a",
                    str(aggression),
                    u,
                ],
                timeout,
            )
            try:
                with open(out_f, encoding="utf-8", errors="replace") as fh:
                    whatweb_techs = parse_whatweb(fh.read())
                ran.append("whatweb")
            except OSError:
                errors.append(f"whatweb: sin salida (rc={rc}) {se[:120]}")
        else:
            skipped.append("whatweb")

        # --- webanalyze (-output json a stdout) ---
        if _which(WEBANALYZE_BIN):
            wa_cmd = [WEBANALYZE_BIN, "-host", u, "-output", "json", "-crawl", "0"]
            if WEBANALYZE_APPS:
                wa_cmd += ["-apps", WEBANALYZE_APPS]
            rc, so, se = _run(wa_cmd, timeout)
            webanalyze_techs = parse_webanalyze(so)
            if webanalyze_techs or rc == 0:
                ran.append("webanalyze")
            else:
                errors.append(f"webanalyze: sin matches (rc={rc}) {se[:120]}")
        else:
            skipped.append("webanalyze")

        # --- wpscan (--format json a fichero) ---
        if run_wpscan:
            if _which(WPSCAN_BIN):
                out_f = os.path.join(workdir, "wpscan.json")
                cmd = [
                    WPSCAN_BIN,
                    "--url",
                    u,
                    "--format",
                    "json",
                    "--no-banner",
                    "--random-user-agent",
                    "-o",
                    out_f,
                ]
                token = os.environ.get("WPSCAN_API_TOKEN", "").strip()
                if token:
                    cmd += ["--api-token", token]
                rc, _so, se = _run(cmd, timeout)
                try:
                    with open(out_f, encoding="utf-8", errors="replace") as fh:
                        wpscan_summary = parse_wpscan(fh.read())
                    ran.append("wpscan")
                except OSError:
                    errors.append(f"wpscan: sin salida (rc={rc}) {se[:120]}")
            else:
                skipped.append("wpscan")

        if not ran:
            return {
                "status": "failed",
                "url": u,
                "error": "ninguna herramienta de fingerprint disponible",
                "skipped": skipped,
                "errors": errors,
            }

        wpscan_techs = wpscan_summary.get("techs", []) if wpscan_summary else []
        crossref = cross_reference(whatweb_techs, webanalyze_techs, wpscan_techs)

        out: dict[str, Any] = {
            "status": "done",
            "url": u,
            "ran": ran,
            "cross_reference": crossref,
        }
        if wpscan_summary:
            # WP summary without the ``techs`` list (already merged in cross_reference)
            out["wpscan"] = {k: v for k, v in wpscan_summary.items() if k != "techs"}
        if skipped:
            out["skipped"] = skipped
        if errors:
            out["errors"] = errors
        return out
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
