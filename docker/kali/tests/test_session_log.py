"""Tests stdlib-only del log de auditoría por engagement (`docker/kali/session_log.py`).

No importan `mcp`/`anyio`: sólo librería estándar + pytest. Verifican:
  - ``record`` persiste un registro como una ÚNICA línea JSON (aunque el output tenga
    miles de líneas: los saltos se escapan dentro del string JSON);
  - ``read`` pagina por cursor y salta líneas corruptas;
  - ``safe_engagement`` cae a ``_unscoped`` con id vacío/no-string/con traversal, y el
    fichero NO escapa de la raíz del staging;
  - appends CONCURRENTES (O_APPEND) no se entrelazan: N líneas, todas JSON válido.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

# El módulo bajo prueba vive en docker/kali/ (junto al servidor MCP, que NO se importa
# aquí porque arrastra `mcp`/`anyio`). Lo añadimos al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import session_log  # noqa: E402


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    """Apunta la raíz del staging a un tmp dir por test (env leído en caliente)."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def _entry(**over):
    base = {
        "execution_id": "exec-1",
        "engagement_id": "eng-1",
        "tool": "kali_run",
        "command": "id",
        "status": "done",
        "returncode": 0,
        "output": "[stdout] uid=0(root)\n",
    }
    base.update(over)
    return base


# ------------------------------------------------------------------ record / read


def test_record_writes_single_json_line_under_engagement(staging):
    session_log.record("eng-1", _entry())

    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["execution_id"] == "exec-1"
    assert doc["command"] == "id"


def test_record_multiline_output_stays_one_physical_line(staging):
    # Output con 5000 saltos: json.dumps los escapa -> UNA sola línea física en el fichero.
    big = "\n".join(f"[stdout] line-{i}" for i in range(5000)) + "\n"
    session_log.record("eng-1", _entry(output=big, total_lines=5000))

    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    raw = path.read_text(encoding="utf-8")
    assert raw.count("\n") == 1  # una única línea JSON terminada en \n
    doc = json.loads(raw)
    # El output completo se recupera íntegro tras el parseo.
    assert doc["output"].count("\n") == 5000
    assert "[stdout] line-4999" in doc["output"]


def test_read_paginates_in_order_and_reports_total(staging):
    for i in range(5):
        session_log.record("eng-1", _entry(execution_id=f"exec-{i}"))

    page = session_log.read("eng-1", cursor=0, limit=2)
    assert [e["execution_id"] for e in page["executions"]] == ["exec-0", "exec-1"]
    assert page["next_cursor"] == 2
    assert page["done"] is False
    assert page["total"] == 5

    tail = session_log.read("eng-1", cursor=4)
    assert [e["execution_id"] for e in tail["executions"]] == ["exec-4"]
    assert tail["done"] is True


def test_read_unknown_engagement_is_empty_done(staging):
    page = session_log.read("never-written")
    assert page["executions"] == []
    assert page["done"] is True
    assert page["total"] == 0


def test_read_skips_corrupt_lines(staging):
    session_log.record("eng-1", _entry(execution_id="good-1"))
    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    with path.open("a", encoding="utf-8") as handle:
        handle.write("this is not json\n")
    session_log.record("eng-1", _entry(execution_id="good-2"))

    page = session_log.read("eng-1")
    ids = [e["execution_id"] for e in page["executions"]]
    assert ids == ["good-1", "good-2"]  # la línea corrupta se salta
    assert page["total"] == 2


# ------------------------------------------------------------------ safe_engagement


@pytest.mark.parametrize("bad", ["", None, 123, "..", "a/b", "a\\b", "x\x00y"])
def test_unsafe_engagement_falls_back_to_unscoped(staging, bad):
    assert session_log.safe_engagement(bad) == session_log.DEFAULT_ENGAGEMENT


def test_record_with_traversal_id_stays_inside_root(staging):
    # Un engagement_id con traversal NO escapa: cae a _unscoped dentro de la raíz.
    session_log.record("../escape", _entry(engagement_id="../escape"))

    escaped = staging.parent / "escape" / session_log.SESSION_LOG_NAME
    assert not escaped.exists()
    fallback = staging / session_log.DEFAULT_ENGAGEMENT / session_log.SESSION_LOG_NAME
    assert fallback.is_file()


def test_valid_engagement_is_preserved(staging):
    assert session_log.safe_engagement("engagement-10.0.0.5") == "engagement-10.0.0.5"


# ------------------------------------------------------------------ concurrencia


def test_concurrent_appends_do_not_interleave(staging):
    # 20 hilos x 25 registros: O_APPEND garantiza líneas enteras sin entrelazado.
    def worker(wid: int) -> None:
        for i in range(25):
            session_log.record("eng-1", _entry(execution_id=f"w{wid}-{i}"))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 500
    # Cada línea es JSON válido y completo (ninguna partida por el entrelazado).
    for line in lines:
        json.loads(line)
