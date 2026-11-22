# 🛡️ Branch Protection Setup

## Steps to Set Up Branch Protection on GitHub

To make sure the security pipeline runs **mandatorily** before merging into `main`, follow these steps:

### 1. Open Branch Protection Rules

1. Go to your repository on GitHub
2. Click **Settings** (⚙️)
3. In the side menu, click **Branches**
4. Under "Branch protection rules", click **Add branch protection rule**

### 2. Recommended Configuration

#### Branch name pattern:
```
main
```

#### ✅ Required Checks You MUST Enable:

**Require a pull request before merging**
- ☑️ Require approvals: `1` (at least 1 approval)
- ☑️ Dismiss stale pull request approvals when new commits are pushed
- ☑️ Require review from Code Owners (optional)

**Require status checks to pass before merging**
- ☑️ Require branches to be up to date before merging
- **Status checks that must pass** (search for them and select them):
  ```
  ☑️ 🧱 Base scaffolding   <-- BLOCKING gate for the scaffolding (ci.yml)
  ☑️ TruffleHog - Secret Detection
  ☑️ CodeQL - Code Analysis  
  ☑️ Python Linting
  ☑️ Dependency Scan
  ☑️ Trivy - Docker Image Scan
  ☑️ PR Validation
  ☑️ Dockerfile Linting
  ```

  > `🧱 Base scaffolding` (`.github/workflows/ci.yml`) is the blocking gate: static
  > smoke + `docker compose config` + quick-fix comment rule + ruff + mypy + the 6
  > suites. The rest of the legacy pipeline is
  > informative (it does not block the merge).

**Require conversation resolution before merging**
- ☑️ All comments must be resolved before merging

**Require signed commits** (optional but recommended)
- ☑️ Require signed commits

**Require linear history** (optional)
- ☑️ Prevents merge commits; only allows rebase and squash

**Do not allow bypassing the above settings**
- ☑️ Apply to administrators too
- ⚠️ Turn this off only if you need to ship emergency hotfixes

#### 🔒 Additional Recommended Protections:

**Restrict who can push to matching branches**
- Limit direct pushes to:
  - Administrators
  - CI/CD service accounts

**Allow force pushes**
- ❌ **Disabled** (NEVER allow a force push to main)

**Allow deletions**
- ❌ **Disabled** (prevent accidental deletion of main)

### 3. Save

Click **Create** or **Save changes**

---

## 📋 Complete Configuration (Copy/Paste Template)

If you prefer the GitHub API or Terraform, here is the configuration in JSON format:

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "🧱 Base scaffolding",
      "secrets-scan",
      "codeql-analysis",
      "python-lint",
      "dependency-scan",
      "docker-scan",
      "pr-validation",
      "dockerfile-lint"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismissal_restrictions": {},
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true
}
```

### Apply with the GitHub CLI:

```bash
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --input branch-protection.json
```

---

## 🔐 CODEOWNERS Configuration (Optional)

Create the `.github/CODEOWNERS` file to assign automatic reviewers:

```
# Default owners for the whole repo
* @irraz

# Security-sensitive files
/.github/workflows/ @irraz @security-team
/docker/ @irraz @devops-team
.env.example @irraz @security-team
docker-compose*.yml @irraz @devops-team

# Python security
*.py @irraz @dev-team
requirements.txt @irraz @security-team
```

---

## 🚨 Exception Policy

### When to bypass the protections?

**NEVER** in normal situations. Only in:

1. **Critical production hotfix**: 
   - Document the reason in the commit
   - Create a post-mortem issue
   - Open a retrospective PR with the checks

2. **Security emergency**:
   - Patch the critical vulnerability
   - Notify the team immediately
   - Run the pipeline manually afterwards

### Exception Process:

```bash
# 1. Document
git commit -m "HOTFIX: [TICKET-123] Description of the critical problem"

# 2. Push with bypass (if you have permissions)
git push origin main

# 3. Immediately afterwards, create a verification PR
git checkout -b hotfix/verify-TICKET-123
git push origin hotfix/verify-TICKET-123
gh pr create --title "Post-hotfix verification TICKET-123" --body "Run the full pipeline over the hotfix"
```

---

## ✅ Verification

After configuring, verify that it works:

1. Create a test branch:
   ```bash
   git checkout -b test/branch-protection
   echo "test" >> README.md
   git add README.md
   git commit -m "test: verify branch protection"
   git push origin test/branch-protection
   ```

2. Open a PR into `main`

3. Try to merge **without waiting for the checks to pass**:
   - ❌ It should be **disabled**
   - ✅ Message: "Required status checks must pass"

4. Wait for all checks to pass

5. Try to merge **without approval**:
   - ❌ It should be **disabled**
   - ✅ Message: "At least 1 approving review is required"

6. Approve the PR and merge
   - ✅ Now it **should allow** the merge

---

## 📊 Monitoring

### View Bypass Attempts

Settings → Branches → View "Protection rule activity"

### Audit

Settings → Security → Audit log → Filter by "protected branch"

---

## 🆘 Troubleshooting

### "The status check does not appear in the list"

**Cause**: The check must run at least once before it appears.

**Solution**:
1. Open any PR
2. Wait for the pipeline to run
3. Go back to the protection configuration
4. It should now appear in the list

### "I cannot merge even though the checks pass"

**Check**:
- Does it have at least 1 approval?
- Are all comments resolved?
- Is the branch up to date with main?

### "Administrators can bypass the rules"

**Solution**: Enable "Do not allow bypassing the above settings" and apply it to administrators.

---

**Recommended configuration applied to**: `main`, `master`, `develop`, `production`
