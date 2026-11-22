# 🚀 Quick Start - Security Pipeline

## ⚡ Setup in 5 Minutes

### Step 1: Enable GitHub Features (30 seconds)

Go to your repository on GitHub → **Settings** → **Security**:

```
☑️ Dependabot alerts
☑️ Dependabot security updates  
☑️ Code scanning
☑️ Secret scanning (public repos only)
```

### Step 2: Push the Pipeline (1 minute)

```bash
# You already have the files, just push them:
git add .github/
git add .pre-commit-config.yaml
git commit -m "feat: add the complete security pipeline with TruffleHog, CodeQL, Trivy"
git push origin main
```

### Step 3: Configure Branch Protection (2 minutes)

**Option A - Web UI:**
1. Settings → Branches → Add rule
2. Branch name: `main`
3. Enable: ☑️ Require status checks (select all the pipeline checks)
4. Enable: ☑️ Require pull request reviews (minimum 1)
5. Save changes

**Option B - GitHub CLI (faster):**
```bash
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["🔐 TruffleHog - Secret Detection", "🔍 CodeQL - Code Analysis (python)", "🐍 Python Linting", "📦 Dependency Scan", "✅ PR Validation", "🔒 Sensitive Change Review", "🐳 Dockerfile Linting", "🐳 Trivy - Docker Image Scan (kali)", "🐳 Trivy - Docker Image Scan (mcp)", "🧱 Base scaffolding"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

### Step 4: (Optional) Local Pre-commit Hooks (1 minute)

```bash
# Install pre-commit
pip install pre-commit

# Activate the hooks
pre-commit install

# Run once to verify
pre-commit run --all-files
```

---

## ✅ Done!

Your repository now has:

- ✅ **TruffleHog** detecting secrets on every PR
- ✅ **CodeQL** analyzing security vulnerabilities
- ✅ **Trivy** scanning Docker images
- ✅ **Bandit** reviewing Python code
- ✅ **Safety** checking vulnerable dependencies
- ✅ **Dependabot** opening automatic update PRs
- ✅ **Hadolint** validating Dockerfiles
- ✅ **Branch Protection** blocking unsafe merges

---

## 🧪 Verify It Works

### Test 1: Create a Test PR

```bash
git checkout -b test/security-pipeline
echo "# Test" >> TEST.md
git add TEST.md
git commit -m "test: verify the security pipeline"
git push origin test/security-pipeline

# Open the PR
gh pr create --title "Test: Security Pipeline" --body "Verify that all checks run"
```

### Test 2: Check the Checks

1. Go to the PR on GitHub
2. In the "Checks" tab you should see:
   - 🔐 TruffleHog - Secret Detection
   - 🔍 CodeQL - Code Analysis
   - 🐍 Python Linting
   - 📦 Dependency Scan
   - 🐳 Trivy - Docker Image Scan
   - ✅ PR Validation
   - 🐳 Dockerfile Linting

3. ⚠️ The "Merge" button should stay **disabled** until:
   - ✅ All checks pass
   - ✅ Someone approves the PR

### Test 3: Test Secret Detection (DO NOT DO THIS ON MAIN!)

```bash
# ON A TEST BRANCH ONLY
git checkout -b test/secret-detection
echo "AWS_SECRET_KEY=«redacted:AKIA…»" > fake-secret.txt  # pragma: allowlist secret
git add fake-secret.txt
git commit -m "test: trigger secret detection"
git push origin test/secret-detection

# TruffleHog SHOULD detect it and FAIL the check
```

---

## 📊 Where to See Results

### During Development (Local)
```bash
# Run the checks locally before pushing
pre-commit run --all-files

# A single check only
pre-commit run bandit --all-files
```

### On GitHub

**"Actions" tab**: status of all workflows
- https://github.com/OWNER/REPO/actions

**"Security" tab**: consolidated alerts
- Code scanning: https://github.com/OWNER/REPO/security/code-scanning
- Dependabot: https://github.com/OWNER/REPO/security/dependabot

**In each PR**: 
- "Checks" tab: detailed status
- "Files changed" tab: CodeQL inline annotations

---

## 🔧 Quick Customization

### Change your user in Dependabot

```bash
# Edit .github/dependabot.yml
sed -i '' 's/irraz/YOUR-USERNAME/g' .github/dependabot.yml
```

### Temporarily disable a check

```bash
# Comment out the job in the workflow
sed -i '' 's/docker-scan:/# docker-scan:/g' .github/workflows/security.yml
```

### Adjust TruffleHog severity

```yaml
# In .github/workflows/security.yml
# Change:
extra_args: --only-verified
# To:
extra_args: --debug  # Detects EVERYTHING
```

---

## 🆘 Common Troubleshooting

### "The check does not appear in Branch Protection"

**Cause**: It must run at least once.

**Solution**: Open any PR, wait for it to run, go back to Settings.

### "Pre-commit fails with 'command not found'"

```bash
# Reinstall
pip install --upgrade pre-commit
pre-commit clean
pre-commit install
```

### "CodeQL takes a long time"

Normal on the first run. It caches results and is faster afterwards.

### "Dependabot opens too many PRs"

```yaml
# In .github/dependabot.yml
open-pull-requests-limit: 2  # Reduce from 5 to 2
```

### "False positive in TruffleHog"

```bash
# Create .trufflehogignore at the root
echo "labs/**" >> .trufflehogignore
echo "tests/**" >> .trufflehogignore
```

---

## 📚 Next Level

### 1. **Slack/Discord Notifications**

Add at the end of `.github/workflows/security.yml`:

```yaml
- name: Notify on Slack
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### 2. **Badges in the README**

```markdown
![Security Pipeline](https://github.com/OWNER/REPO/workflows/Security%20Pipeline/badge.svg)
![CodeQL](https://github.com/OWNER/REPO/workflows/CodeQL/badge.svg)
```

### 3. **Additional SAST with Semgrep**

```yaml
- name: Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: auto
```

### 4. **Test Coverage**

```yaml
- name: Coverage
  run: |
    pytest --cov=. --cov-report=xml
- name: Upload to Codecov
  uses: codecov/codecov-action@v3
```

---

## 🎯 Final Checklist

- [ ] Pipeline pushed to GitHub
- [ ] Branch protection configured on `main`
- [ ] Dependabot enabled
- [ ] Code scanning enabled
- [ ] Pre-commit hooks installed locally
- [ ] Test PR succeeded
- [ ] Team notified of the new process
- [ ] SECURITY-PIPELINE.md documentation reviewed

---

## 💡 Pro Tips

1. **Run the checks locally** with pre-commit before pushing to iterate faster
2. **Review Dependabot weekly** instead of ignoring its PRs
3. **Do not ignore Bandit warnings**, even if they do not block the PR
4. **Keep `.env.example` up to date** so new devs know which variables they need
5. **Review the Security tab** at least once a month

---

**Problems?** Open an issue or check [SECURITY-PIPELINE.md](./SECURITY-PIPELINE.md) for more details.

**Total setup time**: ~5 minutes  
**Benefit**: enterprise-grade security **for free** 🎉
