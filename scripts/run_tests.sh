#!/usr/bin/env bash
# Runner de las 6 suites de tests del repo (una por componente).
#
#   bash scripts/run_tests.sh
#
# Corre cada suite en su propio subproceso con `env -u PYTHONPATH` (un PYTHONPATH
# global contamina con mcp 2.3.0) y desde la raiz del worktree. Agrega los exit
# codes e imprime totales. NUNCA usa --import-mode=importlib.
#
# Dependencias por suite: se resuelven con uv en un entorno efimero (--no-project),
# porque el python del sistema no trae pytest ni los SDK de los componentes.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- localizar uv -----------------------------------------------------------
UV_BIN="${UV_BIN:-}"
if [ -z "$UV_BIN" ]; then
  if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
  elif [ -x /home/irraz/.hermes/tools/uv-0.13.5-linux-x64/uv ]; then
    UV_BIN=/home/irraz/.hermes/tools/uv-0.13.5-linux-x64/uv
  else
    echo "❌ no se encuentra el binario de uv (define UV_BIN)" >&2
    exit 127
  fi
fi

# --- suites y dependencias --------------------------------------------------
# pares "suite|dep1;dep2;..." (el separador de suite/deps es '|'; las deps van
# separadas por ';' porque los version specifiers contienen comas: mcp>=1.28,<2).
SUITES=(
  "agent-ooda/tests|pytest;pyyaml"
  "docker/kali/tests|pytest"
  "docker/mcp/tests|pytest;anyio;httpx;mcp>=1.28,<2"
  "docker/web/tests|pytest;anyio;httpx;starlette>=0.52.1,<1;uvicorn>=0.54.0,<1;websockets>=13.0,<16"
  "docker/browser-view/tests|pytest"
  "scripts/tests|pytest"
)

echo "== run_tests: uv=$UV_BIN root=$ROOT =="
echo

total_rc=0
failed_suites=0
ran_suites=0
absent_suites=0

for entry in "${SUITES[@]}"; do
  suite="${entry%%|*}"
  deps="${entry#*|}"

  # `scripts/tests` la anade feat/base-linters: si aun no existe, se omite con ⚠️
  # (una suite ausente no es una suite en rojo).
  if [ ! -d "$suite" ]; then
    echo "=== $suite ==="
    echo "⚠️  $suite: no existe en esta rama (la anade feat/base-linters); se omite"
    absent_suites=$((absent_suites + 1))
    echo
    continue
  fi

  # reconstruye la lista de --with a partir de las deps separadas por ';'
  args=(run --no-project --quiet)
  IFS=';' read -r -a dep_arr <<< "$deps"
  for dep in "${dep_arr[@]}"; do
    args+=(--with "$dep")
  done

  echo "=== $suite ==="
  # env -u PYTHONPATH: el PYTHONPATH global contamina con mcp 2.3.0
  env -u PYTHONPATH "$UV_BIN" "${args[@]}" python3 -m pytest "$suite" -p no:cacheprovider -q
  rc=$?
  ran_suites=$((ran_suites + 1))
  total_rc=$((total_rc + rc))
  if [ "$rc" -ne 0 ]; then
    failed_suites=$((failed_suites + 1))
    echo "--- $suite: EXIT $rc ---"
  else
    echo "--- $suite: EXIT 0 ---"
  fi
  echo
done

echo "== TOTALES =="
echo "suites corridas : $ran_suites"
echo "suites ausentes : $absent_suites"
echo "suites en rojo  : $failed_suites"
echo "exit code agregado: $total_rc"

if [ "$failed_suites" -ne 0 ]; then
  echo "⚠️  hay suites en rojo (revisa el detalle de cada suite arriba)"
  exit 1
fi

echo "✅ las $ran_suites suites pasan"
exit 0
