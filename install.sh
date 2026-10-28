#!/usr/bin/env bash
# =============================================================================
# install.sh — the "easy" installer for vulnerator-ai.
# =============================================================================
# The fast path: the ONLY thing the user must provide is OPENROUTER_API_KEY.
# The script:
#   1. Checks prerequisites (docker, docker compose v2, openssl).
#   2. Reads OPENROUTER_API_KEY (from a prompt, the environment, or a flag).
#   3. Auto-generates HERMES_API_SERVER_KEY and VULNERATOR_MCP_INBOUND_TOKEN
#      (SEPARATE secrets).
#   4. Builds the .env from .env.example, filling in only those three keys
#      (everything else keeps the template defaults, comments included).
#   5. Brings the default stack up (WITHOUT the Juice Shop lab) with
#      docker compose up -d --build.
#
# Usage:
#   ./install.sh                             # interactive: prompts for the OpenRouter key
#   OPENROUTER_API_KEY=sk-... ./install.sh   # non-interactive (takes the key from the env)
#   ./install.sh --with-juice-shop           # also brings up the OWASP Juice Shop lab (opt-in)
#   ./install.sh --no-up                     # writes the .env but does NOT run docker
#   ./install.sh --force                     # overwrites an existing .env
# =============================================================================
set -euo pipefail

# --- Locate the repo directory (where this script lives) ---------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

# --- Flags -------------------------------------------------------------------
FORCE=0
NO_UP=0
WITH_JUICE_SHOP=0

usage() {
  cat <<'EOF'
install.sh — easy installer for vulnerator-ai

Usage:
  ./install.sh [options]

Options:
  --force             Overwrite an existing .env (default: abort if .env exists).
  --no-up             Generate the .env but do NOT run docker compose up.
  --with-juice-shop   Also bring up the OWASP Juice Shop lab target (opt-in).
  -h, --help          Show this help.

The only value you must provide is OPENROUTER_API_KEY. It is read interactively,
or taken from the OPENROUTER_API_KEY environment variable if already exported.
HERMES_API_SERVER_KEY and VULNERATOR_MCP_INBOUND_TOKEN are generated automatically.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --no-up) NO_UP=1 ;;
    --with-juice-shop) WITH_JUICE_SHOP=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown option '$1' (use --help)" >&2; exit 2 ;;
  esac
  shift
done

# --- Output helpers ----------------------------------------------------------
info()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m OK\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m  !\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Prerequisites --------------------------------------------------------
check_prereqs() {
  info "Checking prerequisites..."

  command -v docker >/dev/null 2>&1 \
    || die "docker is not installed or not in PATH. Install Docker: https://docs.docker.com/get-docker/"

  # docker compose v2 (plugin). The legacy 'docker-compose' (v1) is not supported.
  if ! docker compose version >/dev/null 2>&1; then
    die "the 'docker compose' v2 plugin is not available. Install/update Docker Desktop or the compose plugin: https://docs.docker.com/compose/install/"
  fi

  command -v openssl >/dev/null 2>&1 \
    || die "openssl is not installed or not in PATH (needed to generate the secret keys)."

  [ -f "$ENV_EXAMPLE" ] \
    || die ".env.example not found at $ENV_EXAMPLE. Run this script from the repo root."

  ok "docker, docker compose v2 and openssl are available."
}

# --- 2. OPENROUTER_API_KEY ---------------------------------------------------
# Resolution order: exported environment variable > interactive prompt.
read_openrouter_key() {
  if [ -n "${OPENROUTER_API_KEY:-}" ]; then
    info "Using OPENROUTER_API_KEY from the environment."
    return
  fi

  if [ ! -t 0 ]; then
    die "OPENROUTER_API_KEY is not set and no interactive terminal is available. Export OPENROUTER_API_KEY and re-run, e.g.: OPENROUTER_API_KEY=sk-... ./install.sh"
  fi

  echo
  info "Enter your OpenRouter API key (the LLM provider that reasons the OODA loop)."
  info "Create one at https://openrouter.ai/keys"
  # -s suppresses the on-screen echo; -r keeps backslashes literal.
  printf 'OPENROUTER_API_KEY: '
  read -rs OPENROUTER_API_KEY
  echo
  export OPENROUTER_API_KEY
}

# --- 2b. Recon / fingerprint API keys (OPTIONAL) -----------------------------
# These are NOT required to bring the stack up. They enable two recon tools:
#   - DNSDUMPSTER_API_KEY -> the `dns_recon` tool (DNS + attack-surface recon).
#   - WPSCAN_API_TOKEN    -> CVE data in the `webtech_scan` tool (wpscan works without it).
# Resolution order per key: exported environment variable > interactive prompt (Enter to
# skip) > empty. A non-interactive run just leaves whatever the environment provided.
read_recon_keys() {
  # DNSDumpster
  if [ -z "${DNSDUMPSTER_API_KEY:-}" ] && [ -t 0 ]; then
    echo
    info "OPTIONAL: DNSDumpster API key for the 'dns_recon' tool (DNS + attack surface)."
    info "Free key at https://dnsdumpster.com/ — press Enter to skip."
    printf 'DNSDUMPSTER_API_KEY (optional): '
    read -rs DNSDUMPSTER_API_KEY
    echo
  fi
  export DNSDUMPSTER_API_KEY="${DNSDUMPSTER_API_KEY:-}"

  # WPScan
  if [ -z "${WPSCAN_API_TOKEN:-}" ] && [ -t 0 ]; then
    echo
    info "OPTIONAL: WPScan API token for 'webtech_scan' (adds CVE data; wpscan runs without it)."
    info "Free token at https://wpscan.com/profile — press Enter to skip."
    printf 'WPSCAN_API_TOKEN (optional): '
    read -rs WPSCAN_API_TOKEN
    echo
  fi
  export WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"
}

# --- 3. Secret generation ----------------------------------------------------
gen_secret() { openssl rand -hex 32; }

# --- 4. Build the .env -------------------------------------------------------
# Copy .env.example (preserving comments and order) and substitute ONLY the lines
# for the three managed keys. Every other variable stays as-is (defaults/empty).
# awk receives the values via -v so they are never interpolated into the program,
# avoiding any injection coming from the user-supplied API key.
build_env() {
  local openrouter_key="$1" hermes_key="$2" mcp_token="$3"
  # Optional recon keys (may be empty); passed through to .env as-is.
  local dnsdumpster_key="${4:-}" wpscan_token="${5:-}"

  info "Building .env from .env.example (required keys filled in; optional recon keys if provided)..."

  awk -v ork="$openrouter_key" -v hk="$hermes_key" -v mt="$mcp_token" \
      -v ddk="$dnsdumpster_key" -v wpt="$wpscan_token" '
    /^OPENROUTER_API_KEY=/        { print "OPENROUTER_API_KEY=" ork;        next }
    /^HERMES_API_SERVER_KEY=/     { print "HERMES_API_SERVER_KEY=" hk;      next }
    /^VULNERATOR_MCP_INBOUND_TOKEN=/ { print "VULNERATOR_MCP_INBOUND_TOKEN=" mt; next }
    /^DNSDUMPSTER_API_KEY=/       { print "DNSDUMPSTER_API_KEY=" ddk;       next }
    /^WPSCAN_API_TOKEN=/          { print "WPSCAN_API_TOKEN=" wpt;          next }
    { print }
  ' "$ENV_EXAMPLE" > "$ENV_FILE.tmp"

  # Sanity check: the three keys must have ended up with a non-empty value.
  grep -q "^OPENROUTER_API_KEY=.\+"        "$ENV_FILE.tmp" || { rm -f "$ENV_FILE.tmp"; die "failed to write OPENROUTER_API_KEY into .env (is the key in .env.example?)."; }
  grep -q "^HERMES_API_SERVER_KEY=.\+"     "$ENV_FILE.tmp" || { rm -f "$ENV_FILE.tmp"; die "failed to write HERMES_API_SERVER_KEY into .env."; }
  grep -q "^VULNERATOR_MCP_INBOUND_TOKEN=.\+" "$ENV_FILE.tmp" || { rm -f "$ENV_FILE.tmp"; die "failed to write VULNERATOR_MCP_INBOUND_TOKEN into .env."; }

  mv "$ENV_FILE.tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  ok ".env written (OpenRouter key set; Hermes API key and MCP inbound token auto-generated)."
}

# --- 5. Bring the stack up ---------------------------------------------------
compose_up() {
  local -a compose_args=(compose)
  if [ "$WITH_JUICE_SHOP" -eq 1 ]; then
    compose_args+=(-f docker-compose.yml -f docker-compose.target.yml)
    info "Bringing the stack up WITH the Juice Shop lab target..."
  else
    info "Bringing the default stack up (no Juice Shop lab)..."
  fi
  compose_args+=(up -d --build)

  docker "${compose_args[@]}"
}

# --- Orchestration -----------------------------------------------------------
main() {
  check_prereqs

  if [ -f "$ENV_FILE" ] && [ "$FORCE" -ne 1 ]; then
    die ".env already exists at $ENV_FILE. Refusing to overwrite it. Re-run with --force to replace it, or delete it first."
  fi

  read_openrouter_key
  [ -n "${OPENROUTER_API_KEY:-}" ] || die "OPENROUTER_API_KEY is empty. It is required in OpenRouter mode (the default)."

  # Optional recon/fingerprint API keys (Enter to skip; empty is fine).
  read_recon_keys

  local hermes_key mcp_token
  hermes_key="$(gen_secret)"
  mcp_token="$(gen_secret)"

  build_env "$OPENROUTER_API_KEY" "$hermes_key" "$mcp_token" \
    "${DNSDUMPSTER_API_KEY:-}" "${WPSCAN_API_TOKEN:-}"

  if [ "$NO_UP" -eq 1 ]; then
    echo
    ok "Done (--no-up): .env is ready. Bring the stack up yourself with: docker compose up -d --build"
    return
  fi

  compose_up

  # --- Final summary -------------------------------------------------------
  echo
  ok "vulnerator-ai is coming up."
  echo
  info "Secrets written to .env:"
  echo "    - OPENROUTER_API_KEY           (the key you provided)"
  echo "    - HERMES_API_SERVER_KEY        (auto-generated, 32-byte hex)"
  echo "    - VULNERATOR_MCP_INBOUND_TOKEN (auto-generated, 32-byte hex)"
  [ -n "${DNSDUMPSTER_API_KEY:-}" ] && echo "    - DNSDUMPSTER_API_KEY          (optional; enables dns_recon)"
  [ -n "${WPSCAN_API_TOKEN:-}" ]    && echo "    - WPSCAN_API_TOKEN             (optional; CVE data in webtech_scan)"
  echo
  info "Open the interactive TUI once the containers are healthy:"
  echo "    docker compose exec -it ooda-agent hermes chat"
  echo
  warn "This engine has NO scope-guard, consent or audit by default. Use it ONLY against"
  warn "explicitly authorized targets and in a controlled environment. See docs/security.md."
}

main "$@"
