"""Generic multi-tool runner for `kali-mcp` (PURE STDLIB).

It generalizes the LIVE collection pattern (until now Prowler-specific) to several
tools (Prowler/ScoutSuite/Cloudsplaining) under ONE single contract: a **registry** per
fuente aporta (a) el binario a comprobar con ``shutil.which``, (b) el/los comando(s) a
to run and where they write their output, (c) how to locate the raw file (NOT the HTML) and its
canonical artifact name, and (d) finalization (stage the raw as an artifact and
construir el ``done`` con la REFERENCIA, nunca la carga). NO es una ruta nueva por
tool: it is a generic worker/finalize + registry.

Why a separate module (like ``tool_streaming``/``artifact_store``/``prowler_artifact``):
``kali_mcp_server.py`` imports ``mcp``/``anyio`` (not in the dev venv). All the
runner mechanics live here with ONLY the standard library, so it is covered by tests without the
SDK. It reuses ``tool_streaming`` (streaming + group kill + cancellation) and
``artifact_store`` (staging del crudo) ya existentes; Prowler delega en ``prowler_artifact``
(same finalize + compat SSE bridge) — zero duplication.

Plane separation: the raw output of ANY tool travels on the DATA plane (artifacts);
the CONTROL ``done`` only carries the reference. For non-Prowler sources the
``set_findings`` SSE bridge is NOT populated: its output is a single JSON document downloaded via the
data plane. arm64 discipline: if the binary is absent, it is reported (not faked).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import artifact_store
import prowler_artifact
import tool_streaming

# Timeout por defecto de una collection (segundos); el server puede pasar el suyo.
DEFAULT_TIMEOUT = int(os.environ.get("COLLECTION_TIMEOUT", os.environ.get("PROWLER_TIMEOUT", "900")))

# Canonical names of the raw artifact per source.
PROWLER_ARTIFACT_NAME = prowler_artifact.PROWLER_ARTIFACT_NAME  # "prowler.ocsf.json"
SCOUTSUITE_ARTIFACT_NAME = "scoutsuite.results.json"
CLOUDSPLAINING_ARTIFACT_NAME = "cloudsplaining.results.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _ring_tail(execution_id: str, max_lines: int = 20) -> str:
    """Last lines of a run's output (UNTRUSTED data, verbatim)."""
    page = tool_streaming.read(execution_id, 0)
    lines = page.get("lines", [])
    tail = lines[-max_lines:]
    return "\n".join(f"[{line['stream']}] {line['text']}" for line in tail)


# --------------------------------------------------------------- comandos por fuente


def _prowler_binary() -> str | None:
    return shutil.which("prowler")


def _build_prowler_cmd(outdir: str) -> list[str]:
    """Args del comando Prowler (sin shell) escribiendo en ``outdir`` (igual que antes).

    Gathers the MVP's environment configuration (status/regions/services/verbose). It assumes
    Prowler is available (the runner validates it with ``shutil.which``).
    """
    cmd = [
        _prowler_binary() or "prowler",
        "aws",
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        outdir,
        "--status",
        *os.environ.get("PROWLER_STATUS", "FAIL").split(),
    ]
    _regions = os.environ.get("PROWLER_REGIONS", os.environ.get("AWS_REGION", "")).strip()
    if _regions:
        cmd += ["--region", *_regions.split()]
    _services = os.environ.get("PROWLER_SERVICES", "").strip()
    if _services:
        cmd += ["--service", *_services.split()]
    cmd += ["--verbose", "--log-level", "INFO"]
    return cmd


def _prowler_commands(account_id: str, workdir: str, outdir: str, params: dict) -> list[list[str]]:
    return [_build_prowler_cmd(outdir)]


def _scoutsuite_commands(account_id: str, workdir: str, outdir: str, params: dict) -> list[list[str]]:
    """ScoutSuite AWS, read-only, salida JSON en ``outdir/scoutsuite-results/*.js``.

    ``--no-browser`` evita abrir el navegador; las credenciales AWS read-only se toman del
    entorno del contenedor (igual que Prowler).
    """
    return [
        [
            "scout",
            "aws",
            "--no-browser",
            "--result-format",
            "json",
            "--report-dir",
            outdir,
            "--report-name",
            "hermes",
        ]
    ]


def _cloudsplaining_commands(account_id: str, workdir: str, outdir: str, params: dict) -> list[list[str]]:
    """Cloudsplaining en dos pasos: descargar los detalles IAM y escanearlos.

    1. ``cloudsplaining download --output <dir>`` baja el account-authorization-details. OJO:
       su ``--output`` es un DIRECTORIO EXISTENTE (``click.Path(exists=True)``, default el cwd),
       NO un fichero; escribe ``<profile>.json`` dentro (sin ``--profile`` -> ``default.json``).
       AWS credentials come from the environment (no ``--profile``), so the downloaded raw
       es ``<workdir>/default.json``.
    2. ``cloudsplaining scan --input-file <workdir>/default.json`` lo analiza y escribe el JSON
       de resultados (``iam-results-*.json`` / ``iam-findings-*.json``) en ``outdir``
       (``--skip-open-report`` evita abrir el navegador). El JSON es lo que se stagea; el HTML
       (presentation) is ignored. ``download`` writes to ``workdir`` (OUTSIDE ``outdir``), so
       que el localizador ``*.json`` de ``outdir`` solo ve la salida del scan, no el crudo IAM.
    """
    authfile = str(Path(workdir) / "default.json")
    return [
        ["cloudsplaining", "download", "--output", workdir],
        [
            "cloudsplaining",
            "scan",
            "--input-file",
            authfile,
            "--output",
            outdir,
            "--skip-open-report",
        ],
    ]


# --------------------------------------------------------------- localizadores de crudo


def _locate_newest(outdir: Path, patterns: tuple[str, ...]) -> Path | None:
    """Most recent readable file matching any of the ``patterns`` (rglob)."""
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(p for p in outdir.rglob(pattern) if p.is_file())
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    return candidates[0]


def _scoutsuite_locate(outdir: Path) -> Path | None:
    # ScoutSuite escribe el crudo en ``scoutsuite-results/scoutsuite_results_*.js`` (o .json
    # con --result-format json). El envoltorio ``.js`` lo tolera el normalizador del consumidor.
    return _locate_newest(
        outdir, ("scoutsuite_results_*.js", "scoutsuite_results_*.json")
    )


def _cloudsplaining_locate(outdir: Path) -> Path | None:
    # El scan de Cloudsplaining escribe DOS JSON en ``outdir`` (ambos serializados desde
    # ``authorization_details.results`` in pinned version 0.9.1): ``iam-results-<name>.json``
    # and ``iam-findings-<name>.json``. Both carry the shape of policy sections
    # (``customer_managed_policies``/``inline_policies``/``aws_managed_policies``) que el
    # normalizador (``CloudsplainingImportCollector``) sabe parsear. Se fija el prefijo de
    # forma DETERMINISTA —primero ``iam-results-*``, con ``iam-findings-*`` como respaldo— en
    # instead of "the most recent ``*.json``" (which, with two files, picks by mtime blindly and
    # may keep the wrong raw -> 0 findings). NEVER the ``*.html`` (presentation)
    # ni el ``default.json`` de descarga (input del scan, FUERA de ``outdir``).
    return _locate_newest(outdir, ("iam-results-*.json",)) or _locate_newest(
        outdir, ("iam-findings-*.json",)
    )


# --------------------------------------------------------------- per-source finalization


def _finalize_artifact(
    execution_id: str,
    outdir: Path,
    returncode: int,
    params: dict,
    *,
    source: str,
    artifact_name: str,
    locate: Callable[[Path], Path | None],
) -> dict[str, Any] | None:
    """Finaliza una collection NO-Prowler: stagea el crudo y construye el ``done``.

Does NOT populate the ``set_findings`` SSE bridge (the output is a single JSON document that is
    baja por el plano de datos). Si no hay salida legible, devuelve ``None`` (el caller
published; on failure it reports ``failed`` with a diagnostic).
    """
    path = locate(outdir)
    if path is None:
        return None
    meta = {
        "tool": source,
        "phase": "collection",
        "params": dict(params),
        "ts": _now_iso(),
        "returncode": returncode,
        "status": "done",
    }
    entry = artifact_store.put_file(execution_id, artifact_name, path, meta)
    return {
        "status": "done",
        "returncode": returncode,
        "timed_out": False,
        "artifact": {
            "execution_id": execution_id,
            "name": artifact_name,
            "size": entry["size"],
            "sha256": entry["sha256"],
        },
    }


def _prowler_finalize(
    execution_id: str, outdir: Path, returncode: int, params: dict
) -> dict[str, Any] | None:
    """Finaliza Prowler reutilizando ``prowler_artifact`` (stage + puente SSE + ``done``)."""
    return prowler_artifact.finalize_scan(execution_id, outdir, returncode, dict(params))


# --------------------------------------------------------------- registro de fuentes


@dataclass(frozen=True)
class CollectorSpec:
    """Contrato de un collector EN VIVO (una entrada del registro)."""

    source: str
    binary: str
    artifact_name: str
    build_commands: Callable[[str, str, str, dict], list[list[str]]]
    finalize: Callable[[str, Path, int, dict], "dict[str, Any] | None"]


def _non_bridged_finalize(
    source: str, artifact_name: str, locate: Callable[[Path], Path | None]
) -> Callable[[str, Path, int, dict], "dict[str, Any] | None"]:
    def _f(execution_id: str, outdir: Path, returncode: int, params: dict) -> "dict[str, Any] | None":
        return _finalize_artifact(
            execution_id,
            outdir,
            returncode,
            params,
            source=source,
            artifact_name=artifact_name,
            locate=locate,
        )

    return _f


REGISTRY: dict[str, CollectorSpec] = {
    "prowler": CollectorSpec(
        source="prowler",
        binary="prowler",
        artifact_name=PROWLER_ARTIFACT_NAME,
        build_commands=_prowler_commands,
        finalize=_prowler_finalize,
    ),
    "scoutsuite": CollectorSpec(
        source="scoutsuite",
        binary="scout",
        artifact_name=SCOUTSUITE_ARTIFACT_NAME,
        build_commands=_scoutsuite_commands,
        finalize=_non_bridged_finalize(
            "scoutsuite", SCOUTSUITE_ARTIFACT_NAME, _scoutsuite_locate
        ),
    ),
    "cloudsplaining": CollectorSpec(
        source="cloudsplaining",
        binary="cloudsplaining",
        artifact_name=CLOUDSPLAINING_ARTIFACT_NAME,
        build_commands=_cloudsplaining_commands,
        finalize=_non_bridged_finalize(
            "cloudsplaining", CLOUDSPLAINING_ARTIFACT_NAME, _cloudsplaining_locate
        ),
    ),
}


def available_collectors() -> dict[str, bool]:
    """Disponibilidad REAL de cada collector (``shutil.which`` del binario), sin fingir."""
    return {src: shutil.which(spec.binary) is not None for src, spec in REGISTRY.items()}


def finalize(
    source: str, execution_id: str, outdir: str | os.PathLike[str], returncode: int, params: dict | None = None
) -> dict[str, Any] | None:
    """Finaliza una collection ya ejecutada: stagea el crudo y construye el ``done``.

    Single reusable point (used by ``run_collection`` and the tests, which stage a raw
    de fixture por fuente). Despacha al ``finalize`` de la fuente.
    """
    spec = REGISTRY.get(source)
    if spec is None:
        raise ValueError(f"fuente de collection desconocida: {source!r}")
    return spec.finalize(execution_id, Path(outdir), returncode, dict(params or {}))


def run_collection(
    source: str,
    account_id: str,
    execution_id: str,
    params: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Generic worker: launches the tool for ``source`` and returns ``done``/``failed``.

    Corre en el hilo de ``tool_streaming.start_background`` (indexado por ``execution_id``).
    Flujo: valida binario -> ejecuta el/los comando(s) con streaming de logs en vivo y kill
    group on timeout/cancellation -> locates the raw -> stages it as
    artefacto -> construye el ``done`` con la REFERENCIA (no la carga). Reporta ``failed`` con
    diagnostic if there is no binary or readable output; ``cancelled`` if the user cancels.
    """
    spec = REGISTRY.get(source)
    if spec is None:
        raise RuntimeError(f"fuente de collection desconocida: {source!r}")
    if shutil.which(spec.binary) is None:
        # arm64 u otra arquitectura sin la tool: se reporta, no se finge.
        raise RuntimeError(
            f"tool {spec.binary!r} (source {source!r}) is not available in this "
            f"runtime ({os.uname().machine}); no se finge la collection."
        )

    workdir = tempfile.mkdtemp(prefix=f"{source}-")
    try:
        outdir = Path(workdir) / "out"
        outdir.mkdir(parents=True, exist_ok=True)
        commands = spec.build_commands(account_id, workdir, str(outdir), _parse_params(params))

        returncode = 0
        for cmd in commands:
            returncode, timed_out, cancelled = tool_streaming.run_tool_streaming(
                cmd, execution_id, timeout=timeout, cwd=workdir
            )
            if cancelled:
                return {"status": "cancelled", "cancelled": True, "returncode": returncode}
            if timed_out:
                return {
                    "status": "failed",
                    "timed_out": True,
                    "returncode": returncode,
                    "error": (
                        f"{source} exceeded the timeout ({timeout}s). "
                        f"Last lines: {_ring_tail(execution_id)}"
                    ),
                }

        done = spec.finalize(
            execution_id,
            outdir,
            returncode,
            {"account_id": account_id, "source": source},
        )
        if done is None:
            return {
                "status": "failed",
                "returncode": returncode,
                "error": (
                    f"{source} no produjo salida legible (exit={returncode}): "
                    f"{_ring_tail(execution_id)}"
                ),
            }
        return done
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _parse_params(params: Any) -> dict:
    """Parse tolerante de los params del start_collection (string JSON opcional)."""
    if isinstance(params, dict):
        return params
    if isinstance(params, str) and params.strip():
        try:
            import json

            parsed = json.loads(params)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:  # noqa: BLE001 - params libre, no fatal
            return {}
    return {}
