#!/bin/bash
# Script to run the security checks LOCALLY before pushing
# Simulates what the GitHub Actions pipeline will run
#
# Usage: .github/scripts/local-security-check.sh [--fix]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
FIX_MODE=false
if [[ "$1" == "--fix" ]]; then
    FIX_MODE=true
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       🔐 LOCAL SECURITY CHECK - Vulnerator AI                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

FAILED_CHECKS=0
TOTAL_CHECKS=0

# Function to report a result
report_check() {
    local check_name=$1
    local status=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [[ $status -eq 0 ]]; then
        echo -e "${GREEN}✓${NC} $check_name"
    else
        echo -e "${RED}✗${NC} $check_name"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# ==============================================================================
# 1. CHECK DEPENDENCIES
# ==============================================================================
echo -e "\n${YELLOW}[1/7]${NC} Checking dependencies..."

if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker is not installed${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python3 is not installed${NC}"
    exit 1
fi

# Check/install Python tools
pip3 install --quiet --upgrade pip 2>/dev/null || true
pip3 install --quiet flake8 black bandit safety 2>/dev/null || true

echo -e "${GREEN}✓${NC} Dependencies checked"

# ==============================================================================
# 2. SECRET DETECTION (TruffleHog simulated with grep)
# ==============================================================================
echo -e "\n${YELLOW}[2/7]${NC} 🔐 Scanning for secrets..."

# Common secret patterns
SECRET_PATTERNS=(
    "AKIA[0-9A-Z]{16}"  # AWS Access Key
    "(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{32,45}['\"]"
    "(?i)password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    "(?i)secret['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{32,}['\"]"
    "-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
)

SECRETS_FOUND=false
for pattern in "${SECRET_PATTERNS[@]}"; do
    if grep -rE "$pattern" . \
        --exclude-dir={.git,.venv,venv,node_modules,.pytest_cache,__pycache__} \
        --exclude={"*.log","*.pyc",".secrets.baseline"} \
        --exclude-dir=".github" \
        2>/dev/null | grep -v ".env.example" | grep -v "QUICKSTART.md" | grep -v "local-security-check.sh"; then
        SECRETS_FOUND=true
    fi
done

if [[ "$SECRETS_FOUND" == true ]]; then
    report_check "Secret detection" 1
else
    report_check "Secret detection" 0
fi

# ==============================================================================
# 3. PYTHON LINTING (flake8)
# ==============================================================================
echo -e "\n${YELLOW}[3/7]${NC} 🐍 Python linting (flake8)..."

if flake8 . \
    --count \
    --select=E9,F63,F7,F82 \
    --exclude=.venv,venv,.git,__pycache__,.pytest_cache \
    --show-source \
    --statistics \
    &> /tmp/flake8-critical.log; then
    report_check "Flake8 (critical errors)" 0
else
    cat /tmp/flake8-critical.log
    report_check "Flake8 (critical errors)" 1
fi

# Warnings do not block
flake8 . \
    --count \
    --max-complexity=10 \
    --max-line-length=127 \
    --exclude=.venv,venv,.git,__pycache__,.pytest_cache \
    --exit-zero \
    --statistics \
    > /tmp/flake8-warnings.log 2>&1

WARNING_COUNT=$(grep -c "^" /tmp/flake8-warnings.log || echo 0)
if [[ $WARNING_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}⚠${NC}  $WARNING_COUNT style warnings (non-blocking)"
fi

# ==============================================================================
# 4. CODE FORMATTING (black)
# ==============================================================================
echo -e "\n${YELLOW}[4/7]${NC} 🎨 Checking formatting (black)..."

if [[ "$FIX_MODE" == true ]]; then
    black . --exclude='/(\.venv|venv|\.git|__pycache__|\.pytest_cache)/' &> /dev/null
    report_check "Black (auto-formatted)" 0
else
    if black --check --diff . --exclude='/(\.venv|venv|\.git|__pycache__|\.pytest_cache)/' &> /tmp/black.log; then
        report_check "Black (format)" 0
    else
        echo -e "${YELLOW}💡 Run with --fix to auto-format${NC}"
        report_check "Black (format)" 1
    fi
fi

# ==============================================================================
# 5. SECURITY CHECK (bandit)
# ==============================================================================
echo -e "\n${YELLOW}[5/7]${NC} 🛡️  Security analysis (bandit)..."

if bandit -r docker/ agent-ooda/ -ll -f text 2>/dev/null > /tmp/bandit.log; then
    report_check "Bandit (Python security)" 0
else
    ISSUES=$(grep -c "Issue:" /tmp/bandit.log || echo 0)
    if [[ $ISSUES -gt 0 ]]; then
        echo -e "${YELLOW}⚠${NC}  $ISSUES security issues found:"
        cat /tmp/bandit.log
        report_check "Bandit (Python security)" 1
    else
        report_check "Bandit (Python security)" 0
    fi
fi

# ==============================================================================
# 6. DEPENDENCY SCANNING (safety)
# ==============================================================================
echo -e "\n${YELLOW}[6/7]${NC} 📦 Scanning vulnerable dependencies..."

VULN_FOUND=false

# Kali deps
if [[ -f "docker/kali/requirements.txt" ]]; then
    if safety check -r docker/kali/requirements.txt --json > /tmp/safety-kali.json 2>/dev/null; then
        echo -e "${GREEN}  ✓${NC} Kali dependencies OK"
    else
        VULNS=$(jq '. | length' /tmp/safety-kali.json 2>/dev/null || echo 0)
        if [[ $VULNS -gt 0 ]]; then
            echo -e "${RED}  ✗${NC} $VULNS vulnerabilities in Kali dependencies"
            VULN_FOUND=true
        fi
    fi
fi

# MCP deps
if [[ -f "docker/mcp/requirements.txt" ]]; then
    if safety check -r docker/mcp/requirements.txt --json > /tmp/safety-mcp.json 2>/dev/null; then
        echo -e "${GREEN}  ✓${NC} MCP dependencies OK"
    else
        VULNS=$(jq '. | length' /tmp/safety-mcp.json 2>/dev/null || echo 0)
        if [[ $VULNS -gt 0 ]]; then
            echo -e "${RED}  ✗${NC} $VULNS vulnerabilities in MCP dependencies"
            VULN_FOUND=true
        fi
    fi
fi

if [[ "$VULN_FOUND" == true ]]; then
    report_check "Dependency scan" 1
else
    report_check "Dependency scan" 0
fi

# ==============================================================================
# 7. DOCKER LINTING (hadolint if available)
# ==============================================================================
echo -e "\n${YELLOW}[7/7]${NC} 🐳 Checking Dockerfiles..."

if command -v hadolint &> /dev/null; then
    DOCKER_ERRORS=0
    
    if hadolint docker/kali/Dockerfile 2>/dev/null; then
        echo -e "${GREEN}  ✓${NC} Kali Dockerfile OK"
    else
        echo -e "${RED}  ✗${NC} Issues in Kali Dockerfile"
        DOCKER_ERRORS=1
    fi
    
    if hadolint docker/mcp/Dockerfile 2>/dev/null; then
        echo -e "${GREEN}  ✓${NC} MCP Dockerfile OK"
    else
        echo -e "${RED}  ✗${NC} Issues in MCP Dockerfile"
        DOCKER_ERRORS=1
    fi
    
    report_check "Dockerfile linting" $DOCKER_ERRORS
else
    echo -e "${YELLOW}⚠${NC}  hadolint not installed (optional)"
    echo "   Install: brew install hadolint (macOS) or docker run --rm -i hadolint/hadolint"
fi

# ==============================================================================
# FINAL SUMMARY
# ==============================================================================
echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        FINAL SUMMARY                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

PASSED=$((TOTAL_CHECKS - FAILED_CHECKS))
echo -e "Total checks: ${BLUE}$TOTAL_CHECKS${NC}"
echo -e "Passed:       ${GREEN}$PASSED${NC}"
echo -e "Failed:       ${RED}$FAILED_CHECKS${NC}"
echo ""

if [[ $FAILED_CHECKS -eq 0 ]]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ALL CHECKS PASSED - Ready to push                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ SOME CHECKS FAILED - Fix before pushing                    ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}💡 Suggestions:${NC}"
    echo "   - Run with --fix to auto-format code"
    echo "   - Review the logs above for specific details"
    echo "   - If you need to skip checks: git commit --no-verify"
    echo ""
    exit 1
fi
