# 🔐 Security Pipeline - Vulnerator AI

## Overview

This project implements a **complete, free security pipeline** using GitHub Actions, designed to run automatically on every PR before approval.

## 🛡️ Security Components

### 1. **TruffleHog** - Secret Detection
- **What it does**: Scans the entire Git history for exposed secrets (API keys, tokens, passwords)
- **When it runs**: On every PR and push to the main branches
- **Configuration**: `.github/workflows/security.yml` (job: `secrets-scan`)
- **Severity**: ❌ **BLOCKS the PR** if it finds verified secrets

### 2. **CodeQL** - Static Code Analysis (SAST)
- **What it does**: Deep security analysis of the Python code
- **Detects**: 
  - SQL injection
  - XSS (Cross-Site Scripting)
  - Insecure deserialization
  - Path traversal
  - Command injection
  - Common CWE vulnerabilities
- **When it runs**: On every PR, push, and weekly
- **Configuration**: `.github/workflows/security.yml` (job: `codeql-analysis`)
- **Results**: Visible in the "Security" tab → "Code scanning alerts"

### 3. **Python Linting** - Code Quality and Security
- **Tools**:
  - **flake8**: Syntax and style error detection
  - **black**: Consistent formatting verification
  - **bandit**: Python-specific security analysis
- **When it runs**: On every PR
- **Configuration**: `.github/workflows/security.yml` (job: `python-lint`)
- **Severity**: ⚠️ **Does not block** but generates reports

### 4. **Safety** - Vulnerable Dependency Scan
- **What it does**: Checks known vulnerabilities in Python dependencies
- **Scans**: 
  - `docker/kali/requirements.txt`
  - `docker/mcp/requirements.txt`
- **Database**: CVEs and security advisories
- **When it runs**: On every PR
- **Configuration**: `.github/workflows/security.yml` (job: `dependency-scan`)

### 5. **Trivy** - Docker Image Scan
- **What it does**: Scans Docker images for vulnerabilities
- **Detects**:
  - CVEs in operating system packages
  - Vulnerabilities in dependencies
  - Misconfigurations
- **Scanned images**:
  - `vulnerator-kali`
  - `vulnerator-mcp`
- **When it runs**: On every PR
- **Configuration**: `.github/workflows/security.yml` (job: `docker-scan`)
- **Severity**: Reports CRITICAL and HIGH only

### 6. **Hadolint** - Dockerfile Linting
- **What it does**: Validates best practices in Dockerfiles
- **Detects**:
  - Use of the `latest` tag
  - Unnecessary layers
  - Hardcoded secrets
  - Cache problems
- **When it runs**: On every PR
- **Configuration**: `.github/workflows/pr-checks.yml` (job: `dockerfile-lint`)

### 7. **Dependabot** - Automatic Updates
- **What it does**: Opens automatic PRs to update dependencies
- **Monitors**:
  - Python dependencies (pip)
  - Docker base images
  - GitHub Actions
- **Frequency**: Weekly
- **Configuration**: `.github/dependabot.yml`
- **Security alerts**: Automatic in the "Security" tab → "Dependabot alerts"

## 🚀 Workflow

### When you open a PR:

```
1. PR opened
   ↓
2. The following run automatically:
   ├─ TruffleHog (secrets)
   ├─ CodeQL (vulnerabilities)
   ├─ Python Lint (quality)
   ├─ Safety (vulnerable deps)
   ├─ Trivy (Docker)
   ├─ Hadolint (Dockerfiles)
   └─ PR validations
   ↓
3. Results visible in:
   - PR checks
   - "Security" tab
   - Automatic comments
   ↓
4. ✅ If all pass → PR ready for review
   ❌ If any fail → fix before merging
```

## 📊 Where to See the Results

### In the PR:
- **Checks tab**: status of all workflows
- **Files changed**: CodeQL and linter inline annotations
- **Comments**: automatic summary of the quality checks

### In the Repository:
- **Security tab**:
  - `Code scanning alerts`: CodeQL and Trivy vulnerabilities
  - `Dependabot alerts`: vulnerable dependencies
  - `Secret scanning`: detected secrets (if enabled in the repo)

### Artifacts:
- bandit JSON reports: `bandit-security-report`
- safety JSON reports: `safety-reports`

## ⚙️ Initial Setup

### 1. Enable Security Features on GitHub

In your repository, go to **Settings** → **Security**:

```
☑️ Dependabot alerts (FREE)
☑️ Dependabot security updates (FREE)
☑️ Code scanning (FREE for public repos)
☑️ Secret scanning (FREE for public repos)
```

### 2. Push the Files

```bash
git add .github/
git commit -m "feat: add the complete security pipeline"
git push origin main
```

### 3. Verify It Works

1. Open a test PR
2. Go to the repository's "Actions" tab
3. You should see the workflows running

## 🔧 Customization

### Adjust TruffleHog Severity

In `.github/workflows/security.yml`, in the `secrets-scan` job line:

```yaml
extra_args: --debug --only-verified  # Verified secrets only
# Or to detect everything:
extra_args: --debug  # Detects all potential secrets
```

### Change Dependabot Reviewers

In `.github/dependabot.yml`:

```yaml
reviewers:
  - "your-github-username"
  - "another-collaborator"
```

### Disable a Check

Comment out or delete the corresponding job in the YAML files.

### Adjust Scan Frequency

In `.github/workflows/security.yml`:

```yaml
schedule:
  - cron: '0 2 * * 1'  # Mondays at 2 AM
  # Change to daily: '0 2 * * *'
  # Change to monthly: '0 2 1 * *'
```

## 🐛 Troubleshooting

### TruffleHog finds false positives

Create a `.trufflehogignore` file at the root:

```
# Example patterns to ignore
docker/kali/tests/*.py
labs/**/*.py
```

### Safety reports a non-critical vulnerability

If you need to ignore it temporarily:

```bash
# In the dependency-scan job, add:
safety check --ignore=51457  # Replace with the CVE ID
```

### CodeQL takes a long time

Normal on the first run. Subsequent scans are incremental and faster.

## 📈 Metrics and Reports

### View Security Trends

1. Go to **Insights** → **Security**
2. Charts of:
   - Open vs closed alerts
   - Resolution time
   - Vulnerability types

### Export Reports

The JSON artifacts are available for 90 days and can be downloaded from the "Actions" tab.

## 🎯 Best Practices

1. **Do not ignore warnings**: review every alert even if it does not block the PR
2. **Update dependencies regularly**: approve the Dependabot PRs
3. **Review the weekly scans**: even without a PR, the weekly scan can detect new vulnerabilities
4. **Keep `.env.example` up to date**: never commit a real `.env`
5. **Use GitHub Secrets**: for sensitive CI/CD variables

## 🆓 Costs

**EVERYTHING IS FREE** for public and private repositories (with generous limits):

- ✅ GitHub Actions: 2,000 free minutes/month
- ✅ Dependabot: unlimited
- ✅ CodeQL: free for public repos
- ✅ TruffleHog: open source, free
- ✅ Trivy: open source, free

For private repos the minutes are consumed, but the free quota is usually enough.

## 📚 References

- [TruffleHog Docs](https://github.com/trufflesecurity/trufflehog)
- [CodeQL Docs](https://codeql.github.com/docs/)
- [Trivy Docs](https://aquasecurity.github.io/trivy/)
- [Dependabot Docs](https://docs.github.com/en/code-security/dependabot)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)

---

**Maintained by**: [@irraz](https://github.com/irraz)  
**Last updated**: 2026-10-23
