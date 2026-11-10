"""Tests de las funciones puras del proxy de Caido (inyección del token)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import caido_proxy as cp  # noqa: E402

TOK = '{"__typename":"AuthenticationToken","accessToken":"abc==.def.guest","refreshToken":null,"scopes":["PROFILE_READ"]}'


def test_bootstrap_script_is_safe_js_string():
    sc = cp._bootstrap_script(TOK)
    assert sc.startswith("<script>") and sc.endswith("</script>")
    assert "localStorage.setItem('CAIDO_AUTHENTICATION'," in sc
    # el token va como literal JS entre comillas dobles (json.dumps), no crudo
    assert '"{\\"__typename' in sc


def test_inject_after_head():
    html = "<!doctype html><html><head><title>Caido</title></head><body>x</body></html>"
    out = cp.inject(html, TOK)
    assert out.index("CAIDO_AUTHENTICATION") < out.index("<title>")
    assert out.count("<head>") == 1


def test_inject_without_head_falls_back_to_html_tag():
    out = cp.inject("<html><body>x</body></html>", TOK)
    assert "CAIDO_AUTHENTICATION" in out and out.index("<script>") < out.index("<body>")


def test_inject_no_markup_prepends():
    out = cp.inject("plain", TOK)
    assert out.startswith("<script>") and out.endswith("plain")
