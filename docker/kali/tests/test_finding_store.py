"""Tests stdlib-only del store de hallazgos por engagement (`docker/kali/finding_store.py`).

No importan `mcp`/`anyio`: sólo librería estándar + pytest. Verifican:
  - ``append`` normaliza y persiste un hallazgo (id/recorded_at autoritativos del servidor);
  - validación fail-closed (title vacío, state inválido, phase inválida -> no se escribe);
  - append atómico de varias líneas y lectura paginada por cursor;
  - confinamiento de rutas (engagement_id con traversal -> no escapa / lectura vacía);
  - tolerancia a líneas corruptas (se saltan) y a engagements inexistentes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# El módulo bajo prueba vive en docker/kali/ (junto al servidor MCP, que NO se importa
# aquí porque arrastra `mcp`/`anyio`). Lo añadimos al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import finding_store  # noqa: E402


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    """Apunta la raíz del staging a un tmp dir por test (env leído en caliente)."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def _minimal(**over):
    base = {"title": "SSH abierto en 10.0.0.5", "state": "hypothesis"}
    base.update(over)
    return base


# ------------------------------------------------------------------ append / normalize


def test_append_persists_and_fills_server_fields(staging):
    rec = finding_store.append("eng-1", _minimal(phase="observe", technique_id="T1046"))

    # El servidor rellena id y recorded_at (autoritativos).
    assert rec["id"] and isinstance(rec["id"], str)
    assert rec["recorded_at"].endswith("Z")
    assert rec["title"] == "SSH abierto en 10.0.0.5"
    assert rec["state"] == "hypothesis"
    assert rec["phase"] == "observe"
    assert rec["technique_id"] == "T1046"

    # Quedó una línea JSON en el fichero del engagement.
    path = staging / "eng-1" / finding_store.FINDINGS_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["id"] == rec["id"]


def test_append_generates_id_when_absent_and_respects_given_id(staging):
    auto = finding_store.append("eng-id", _minimal())
    assert auto["id"]
    given = finding_store.append("eng-id", _minimal(id="my-fixed-id"))
    assert given["id"] == "my-fixed-id"


def test_append_server_timestamp_overrides_agent_supplied(staging):
    rec = finding_store.append("eng-ts", _minimal(recorded_at="1999-01-01T00:00:00Z"))
    assert rec["recorded_at"] != "1999-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "bad",
    [
        {"state": "hypothesis"},                       # falta title
        {"title": "   ", "state": "hypothesis"},       # title vacío
        {"title": "x"},                                # falta state
        {"title": "x", "state": "exploited"},          # state fuera del enum
        {"title": "x", "state": "confirmed", "phase": "pwn"},  # phase inválida
        "not-a-dict",                                  # no es objeto
    ],
)
def test_append_rejects_invalid_without_writing(staging, bad):
    with pytest.raises(finding_store.FindingStoreError):
        finding_store.append("eng-bad", bad)
    # Fail-closed: no se creó el fichero.
    assert not (staging / "eng-bad" / finding_store.FINDINGS_NAME).exists()


@pytest.mark.parametrize("sev", ["critical", "high", "medium", "low", "info"])
def test_append_accepts_canonical_severity(staging, sev):
    rec = finding_store.append("eng-sev", _minimal(title=f"f-{sev}", severity=sev))
    assert rec["severity"] == sev


def test_append_without_severity_is_valid_and_omits_field(staging):
    # Opcional y retrocompatible: ausente sigue siendo válido y no se inventa el campo.
    rec = finding_store.append("eng-sev", _minimal())
    assert "severity" not in rec


@pytest.mark.parametrize("bad_sev", ["informational", "warning", "HIGH", "7.5", "none", ""])
def test_append_rejects_non_canonical_severity(staging, bad_sev):
    # Fuera de los cinco buckets canónicos -> fail-closed, no se escribe nada.
    with pytest.raises(finding_store.FindingStoreError):
        finding_store.append("eng-sev-bad", _minimal(severity=bad_sev))
    assert not (staging / "eng-sev-bad" / finding_store.FINDINGS_NAME).exists()


def test_append_keeps_category_verbatim(staging):
    # category es string libre de primer nivel: se guarda tal cual (sin validar).
    rec = finding_store.append("eng-cat", _minimal(severity="high", category="auth/idp"))
    assert rec["category"] == "auth/idp"


def test_append_keeps_evidence_and_change_verbatim(staging):
    evidence = {"command": "nmap -sV 10.0.0.5", "returncode": 0, "output": "22/tcp open ssh OpenSSH 8.9p1"}
    change = {"tag": "vulnerator-ai", "revert": "aws iam delete-user --user-name x"}
    rec = finding_store.append(
        "eng-ev",
        _minimal(state="confirmed", evidence=evidence, change=change, confidence="high"),
    )
    assert rec["evidence"] == evidence
    assert rec["change"] == change
    assert rec["confidence"] == "high"


# ------------------------------------------------------------------ evidencia de 'confirmed'


def test_confirmed_requires_evidence(staging):
    # Un confirmado SIN evidencia se rechaza fail-closed (trazabilidad).
    with pytest.raises(finding_store.FindingStoreError):
        finding_store.append("eng-c", _minimal(state="confirmed"))
    assert not (staging / "eng-c" / finding_store.FINDINGS_NAME).exists()


def test_confirmed_rejects_empty_command(staging):
    with pytest.raises(finding_store.FindingStoreError):
        finding_store.append("eng-c", _minimal(
            state="confirmed",
            evidence={"command": "   ", "output": "HTTP 200 cuerpo con prueba suficiente"},
        ))


def test_confirmed_rejects_trivial_output(staging):
    # Salida demasiado corta (marcador vacío) no sirve como evidencia verbatim.
    with pytest.raises(finding_store.FindingStoreError):
        finding_store.append("eng-c", _minimal(
            state="confirmed",
            evidence={"command": "curl -sS http://t/x", "output": "200"},
        ))


def test_confirmed_accepts_command_plus_output(staging):
    rec = finding_store.append("eng-c", _minimal(
        state="confirmed",
        evidence={"command": "curl -sS 'http://t/search?q=%27))--'", "output": "HTTP 500 SQLITE_ERROR near ')' ...", "returncode": 0},
    ))
    assert rec["state"] == "confirmed"


def test_confirmed_accepts_artifact_ref(staging):
    # Para salidas grandes, el crudo va como artefacto y basta la referencia.
    rec = finding_store.append("eng-c", _minimal(
        state="confirmed",
        evidence={"artifact_ref": {"execution_id": "exec-9", "name": "users_dump.txt"}},
    ))
    assert rec["state"] == "confirmed"


def test_non_confirmed_states_do_not_require_evidence(staging):
    # hypothesis / partial / discarded NO exigen evidencia reproducible.
    for st in ("hypothesis", "partial", "discarded"):
        rec = finding_store.append("eng-c", _minimal(title=f"f-{st}", state=st))
        assert rec["state"] == st


# ------------------------------------------------------------------ read / paging


def test_read_empty_engagement_returns_done_zero(staging):
    page = finding_store.read("nope")
    assert page == {"findings": [], "next_cursor": 0, "done": True, "total": 0}


def test_read_paginates_by_cursor(staging):
    for i in range(5):
        finding_store.append("eng-page", _minimal(title=f"f{i}"))

    first = finding_store.read("eng-page", cursor=0, limit=2)
    assert [f["title"] for f in first["findings"]] == ["f0", "f1"]
    assert first["next_cursor"] == 2
    assert first["done"] is False
    assert first["total"] == 5

    second = finding_store.read("eng-page", cursor=first["next_cursor"], limit=2)
    assert [f["title"] for f in second["findings"]] == ["f2", "f3"]
    assert second["done"] is False

    third = finding_store.read("eng-page", cursor=second["next_cursor"], limit=2)
    assert [f["title"] for f in third["findings"]] == ["f4"]
    assert third["done"] is True


def test_read_skips_corrupt_lines(staging):
    finding_store.append("eng-corrupt", _minimal(title="good"))
    path = staging / "eng-corrupt" / finding_store.FINDINGS_NAME
    # Inyecta una línea corrupta (no JSON) y otra válida.
    with path.open("a", encoding="utf-8") as handle:
        handle.write("}{ not json\n")
        handle.write(json.dumps({"id": "x", "title": "also good", "state": "partial"}) + "\n")

    page = finding_store.read("eng-corrupt")
    titles = [f["title"] for f in page["findings"]]
    assert titles == ["good", "also good"]  # la línea corrupta se saltó
    assert page["total"] == 2


# ------------------------------------------------------------------ confinamiento


@pytest.mark.parametrize("evil", ["../escape", "a/b", "..", "with\x00nul"])
def test_append_rejects_unsafe_engagement_id(staging, evil):
    with pytest.raises(ValueError):
        finding_store.append(evil, _minimal())


def test_read_unsafe_engagement_id_returns_empty(staging):
    # En lectura el confinamiento NO revienta: devuelve página vacía (fail-closed).
    page = finding_store.read("../escape")
    assert page["total"] == 0
    assert page["done"] is True
