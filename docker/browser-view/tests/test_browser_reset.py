"""Tests de las funciones puras de browser_reset.py (sin red, sin Chrome real)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import browser_reset as br  # noqa: E402


def test_pick_live_root_ignores_children_and_picks_most_recent():
    sessions = [
        {"id": "root-old", "parent_session_id": None, "last_active": 100},
        {"id": "child-1", "parent_session_id": "root-old", "last_active": 999},  # no cuenta
        {"id": "root-new", "parent_session_id": None, "last_active": 200},
    ]
    assert br.pick_live_root(sessions) == "root-new"


def test_pick_live_root_falls_back_to_started_at_without_last_active():
    sessions = [
        {"id": "a", "parent_session_id": "", "started_at": 10},
        {"id": "b", "parent_session_id": None, "started_at": 50},
    ]
    assert br.pick_live_root(sessions) == "b"


def test_pick_live_root_empty_or_only_children_returns_none():
    assert br.pick_live_root([]) is None
    assert br.pick_live_root([{"id": "c", "parent_session_id": "root", "last_active": 1}]) is None


def test_should_reset_only_on_genuine_change_after_first_sighting():
    # primer avistamiento: no resetea aunque "cambie" de None a algo (es el arranque del watcher)
    assert br.should_reset(None, "s1", seen_any=False) is False
    # ya habíamos visto una sesión antes: un id distinto SÍ dispara el reset
    assert br.should_reset("s1", "s2", seen_any=True) is True
    # la misma sesión (incluidos sus subagentes) no dispara nada
    assert br.should_reset("s1", "s1", seen_any=True) is False
    # sin sesión activa ahora mismo: nada que resetear
    assert br.should_reset("s1", None, seen_any=True) is False


def test_ws_frame_short_payload_uses_single_length_byte():
    frame = br._ws_frame(b"hola")
    assert frame[0] == 0x81  # FIN + opcode texto
    assert frame[1] & 0x80  # bit de máscara puesto
    assert (frame[1] & 0x7F) == 4  # longitud literal para payloads < 126


def test_ws_frame_medium_payload_uses_16bit_length():
    payload = b"x" * 200
    frame = br._ws_frame(payload)
    assert (frame[1] & 0x7F) == 126
    assert int.from_bytes(frame[2:4], "big") == len(payload)


def test_ws_handshake_has_required_upgrade_headers():
    head = br._ws_handshake("/devtools/page/abc", "127.0.0.1:9223").decode()
    assert head.startswith("GET /devtools/page/abc HTTP/1.1\r\n")
    assert "Host: 127.0.0.1:9223\r\n" in head
    assert "Upgrade: websocket\r\n" in head
    assert "Sec-WebSocket-Key: " in head
