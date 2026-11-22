"""PURE logic of the MCP wrapper (no `mcp`/`httpx`): scope-folding, validation and `done`.

It deliberately lives apart from ``vulnerator_mcp_server.py`` (like ``scope_guard``/
``tool_streaming`` live apart from ``kali_mcp_server``): that module imports `mcp` (FastMCP),
which is not in the dev venv. These functions are string composition and shape
validation, so they are covered by unit tests WITHOUT the SDK.

Discipline: ``scope`` is REQUIRED but ADVISORY. The wrapper does NOT enforce scope or add
seguridad; solo DOBLA el scope dentro del prompt como metadato de claridad del operador.
``input``/``scope``/``run_id`` are UNTRUSTED DATA: here they are only shape-validated
(presence/non-empty) and, for ``scope``, concatenated to the prompt verbatim.
"""

from __future__ import annotations

from typing import Any, Optional

# Prefijo con el que se dobla el scope dentro del input (metadato ADVISORY, no un guard).
SCOPE_PREFIX = "AUTHORIZED SCOPE (operator-declared, advisory):"


def invalid_request(message: str) -> dict[str, Any]:
    """OpenAI-style error envelope for LOCAL validation failures (no upstream call)."""
    return {
        "error": {
            "message": message,
            "type": "invalid_request_error",
            "param": None,
            "code": "invalid_request",
        }
    }


def fold_scope_into_input(input: str, scope: str) -> str:
    """Folds ``scope`` into ``input`` as a delimited line (design §5).

    NO impone nada: es un afordance de claridad para el operador que conduce el cliente MCP.
    Format: a line ``AUTHORIZED SCOPE ...: <scope>``, a blank line, then the input
    original verbatim.
    """
    return "%s %s\n\n%s" % (SCOPE_PREFIX, scope, input)


def validate_start_pentest(input: Any, scope: Any) -> Optional[dict[str, Any]]:
    """Valida ``input``/``scope`` de ``start_pentest``. Devuelve un sobre de error o None.

    Both required, non-empty string (after strip). Empty/non-string -> ``invalid_request``
    with NO upstream call (fail-closed). Length is NOT capped (Hermes owns the
    prompt limits).
    """
    if not isinstance(input, str) or not input.strip():
        return invalid_request("'input' is required and cannot be empty")
    if not isinstance(scope, str) or not scope.strip():
        return invalid_request("'scope' is required and cannot be empty (advisory)")
    return None


def validate_run_id(run_id: Any) -> Optional[dict[str, Any]]:
    """Validates that ``run_id`` is a non-empty string. Returns an error envelope or None.

    It does NOT validate the ``run_`` format (Hermes owns the id space): it is forwarded and left
    que upstream responda ``run_not_found`` si no existe.
    """
    if not isinstance(run_id, str) or not run_id.strip():
        return invalid_request("'run_id' is required and cannot be empty")
    return None


def validate_steer(run_id: Any, input: Any) -> Optional[dict[str, Any]]:
    """Valida ``run_id`` + ``input`` de ``steer_run``. Devuelve un sobre de error o None."""
    err = validate_run_id(run_id)
    if err is not None:
        return err
    if not isinstance(input, str) or not input.strip():
        return invalid_request("'input' is required and cannot be empty")
    return None


def clamp_cursor(cursor: Any) -> int:
    """Normaliza el cursor a un int >= 0 (negativo/no-int -> 0)."""
    if not isinstance(cursor, int) or isinstance(cursor, bool) or cursor < 0:
        return 0
    return cursor


def normalize_optional_positive(value: Any) -> Optional[Any]:
    """Normalizes max_events/wait_seconds: non-positive or non-numeric -> None (uses the internal default)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value > 0:
        return value
    return None


# ------------------------------------------------------------------ terminalidad / done


def is_terminal_run(run_obj: Any) -> bool:
    """True SOLO si el objeto run indica terminalidad por BOOLEANOS LITERALES ``True``.

    Version-tolerancia (§1.1) + dato NO CONFIABLE (fija review Finding "truthy terminal"):
    se mira ``completed``/``interrupted`` y se exige que sean EXACTAMENTE ``True`` (``is
    True``), nunca ``bool(...)``. Un payload malformado o cambiado (``{"completed": "false"}``
    or ``1`` or ``"true"``) does NOT count as terminal: missing, numeric, string or
    contenedor se tratan como NO terminales (seguir paginando), manteniendo el resto de
    campos opacos. El string ``status`` NUNCA se usa para decidir terminalidad.
    """
    if not isinstance(run_obj, dict):
        return False
    return run_obj.get("completed") is True or run_obj.get("interrupted") is True


def decide_stream_done(
    *,
    saw_terminal_event: bool,
    stream_drained: bool,
    confirm_run: Any,
    confirm_is_error: bool,
) -> tuple[bool, bool]:
    """Decides ``done`` for a ``stream_run_events`` batch (PURE logic; design §4.1).

    Separada del servidor (que importa ``mcp``) para poder TESTEAR el contrato de ``done``
    sin el SDK (fija review Finding "done untested"). Reglas (design §4.1):

      - Si se vio un evento ``run.completed`` en el batch -> ``done=True`` (caso 1).
      - If the stream was DRAINED without a terminal event, ONE ``get_run`` confirmation is made:
          * if it failed (error envelope) -> ``done=False`` and the server attaches the envelope
            COMPLETO ``confirm_run`` (``{"error": {...}}``) bajo ``terminality_error`` (el
            client keeps paging; the error is NOT swallowed). (case 2 / review-3 F5)
          * si no, ``done = is_terminal_run(confirm_run)``.
      - If the batch closed due to a CAP (cap/deadline) and did NOT drain -> ``done=False`` WITHOUT confirming
        (fija el blocking Finding de opus: nunca declarar done con eventos pendientes tras el
        cursor). ``get_run`` confirmation only runs on a real stream drain.

    Args:
        saw_terminal_event: True si el batch contuvo un ``run.completed``.
        stream_drained: True only if the stream was closed by upstream (STOP_DRAINED), NOT by
            un tope (STOP_CAP/STOP_DEADLINE).
        confirm_run: resultado de ``get_run`` (solo relevante en drenado sin evento terminal).
        confirm_is_error: True si ``confirm_run`` es un sobre de error.

    Returns:
        ``(done, needs_terminality_error)``: ``done`` es el booleano final; si
        ``needs_terminality_error`` es True el servidor debe adjuntar el sobre COMPLETO
        ``confirm_run`` (``{"error": {...}}``, no solo su interior) bajo ``terminality_error``,
        para que tenga la MISMA forma que ``stream_error`` y el resto de errores de la API.
    """
    if saw_terminal_event:
        return True, False
    if not stream_drained:
        # Tope (cap/deadline): hay datos pendientes -> no terminal, no se confirma.
        return False, False
    # Real drain without a terminal event: a get_run confirmation decides.
    if confirm_is_error:
        return False, True  # confirmation error: not terminal + attach terminality_error
    return is_terminal_run(confirm_run), False
