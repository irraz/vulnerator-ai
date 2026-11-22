#!/usr/bin/env bash
# Runner for the repo's 6 test suites (one per component).
#
#   bash scripts/run_tests.sh
#
# Runs each suite in its own subprocess with `env -u PYTHONPATH` (a global PYTHONPATH
# contaminates with mcp 2.3.0) and from the worktree root. Aggregates the exit
# codes and prints totals. NEVER uses --import-mode=importlib.
#
# Per-suite dependencies: resolved with uv in an ephemeral environment (--no-project),
# because the system python has neither pytest nor the component SDKs.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- locate uv -----------------------------------------------------------
UV_BIN="${UV_BIN:-}"
if [ -z "$UV_BIN" ]; then
  if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
  elif [ -x /home/irraz/.hermes/tools/uv-0.13.5-linux-x64/uv ]; then
    UV_BIN=/home/irraz/.hermes/tools/uv-0.13.5-linux-x64/uv
  else
    echo "❌ uv binary not found (set UV_BIN)" >&2
    exit 127
  fi
fi

# --- suites and dependencies --------------------------------------------------
# "suite|dep1;dep2;..." pairs (the suite/deps separator is '|'; the deps are
# separated by ';' because version specifiers contain commas: mcp>=1.28,<2).
SUITES=(
  "agent-ooda/tests|pytest;pyyaml"
  "docker/kali/tests|pytest"
  "docker/mcp/tests|pytest;anyio;httpx;mcp>=1.28,<2"
  "docker/web/tests|pytest;anyio;httpx;starlette>=0.52.1,<1;uvicorn>=0.54.0,<1;websockets>=13.0,<16"
  "docker/browser-view/tests|pytest"
  "scripts/tests|pytest;pyyaml"
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

  # `scripts/tests` is added by feat/base-linters: if it does not exist yet, it is
  # skipped with ⚠️ (a missing suite is not a red suite).
  if [ ! -d "$suite" ]; then
    echo "=== $suite ==="
    echo "⚠️  $suite: does not exist in this branch (added by feat/base-linters); skipped"
    absent_suites=$((absent_suites + 1))
    echo
    continue
  fi

  # rebuild the --with list from the ';'-separated deps
  args=(run --no-project --quiet)
  IFS=';' read -r -a dep_arr <<< "$deps"
  for dep in "${dep_arr[@]}"; do
    args+=(--with "$dep")
  done

  echo "=== $suite ==="
  # env -u PYTHONPATH: the global PYTHONPATH contaminates with mcp 2.3.0
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

echo "== TOTALS =="
echo "suites run     : $ran_suites"
echo "suites absent  : $absent_suites"
echo "suites failing : $failed_suites"
echo "aggregated exit code: $total_rc"

if [ "$failed_suites" -ne 0 ]; then
  echo "⚠️  there are failing suites; dump each suite's summary"
  exit 1
fi

echo "✅ all $ran_suites suites pass"
exit 0
