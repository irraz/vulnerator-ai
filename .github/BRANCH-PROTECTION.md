# 🛡️ Configuración de Protección de Ramas

## Pasos para Configurar Branch Protection en GitHub

Para asegurar que la pipeline de seguridad se ejecute **obligatoriamente** antes de hacer merge a `main`, sigue estos pasos:

### 1. Acceder a Branch Protection Rules

1. Ve a tu repositorio en GitHub
2. Click en **Settings** (⚙️)
3. En el menú lateral, click en **Branches**
4. En "Branch protection rules", click en **Add branch protection rule**

### 2. Configuración Recomendada

#### Branch name pattern:
```
main
```

#### ✅ Checks Obligatorios que DEBES Habilitar:

**Require a pull request before merging**
- ☑️ Require approvals: `1` (al menos 1 aprobación)
- ☑️ Dismiss stale pull request approvals when new commits are pushed
- ☑️ Require review from Code Owners (opcional)

**Require status checks to pass before merging**
- ☑️ Require branches to be up to date before merging
- **Status checks que deben pasar** (búscalos y selecciónalos):
  ```
  ☑️ 🧱 Base scaffolding   <-- GATE BLOQUEANTE del andamiaje (ci.yml)
  ☑️ TruffleHog - Detección de Secretos
  ☑️ CodeQL - Análisis de Código  
  ☑️ Python Linting
  ☑️ Escaneo de Dependencias
  ☑️ Trivy - Escaneo de Imágenes Docker
  ☑️ Validación de PR
  ☑️ Dockerfile Linting
  ```

  > `🧱 Base scaffolding` (`.github/workflows/ci.yml`) es el gate bloqueante: smoke
  > estático + `docker compose config` + regla anti-comentarios + ruff + mypy + las 6
  > suites. El resto del pipeline legacy es
  > informativo (no bloquea el merge).

**Require conversation resolution before merging**
- ☑️ Todos los comentarios deben resolverse antes del merge

**Require signed commits** (opcional pero recomendado)
- ☑️ Require signed commits

**Require linear history** (opcional)
- ☑️ Previene merge commits, solo permite rebase y squash

**Do not allow bypassing the above settings**
- ☑️ Aplicar a administradores también
- ⚠️ Desactiva esto solo si necesitas hacer hotfixes de emergencia

#### 🔒 Protecciones Adicionales Recomendadas:

**Restrict who can push to matching branches**
- Limitar push directo solo a:
  - Administradores
  - Service accounts para CI/CD

**Allow force pushes**
- ❌ **Deshabilitado** (NUNCA permitir force push a main)

**Allow deletions**
- ❌ **Deshabilitado** (Prevenir borrado accidental de main)

### 3. Guardar

Click en **Create** o **Save changes**

---

## 📋 Configuración Completa (Copiar/Pegar Template)

Si prefieres usar la API de GitHub o Terraform, aquí está la configuración en formato JSON:

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

### Aplicar con GitHub CLI:

```bash
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --input branch-protection.json
```

---

## 🔐 Configuración de CODEOWNERS (Opcional)

Crea el archivo `.github/CODEOWNERS` para asignar revisores automáticos:

```
# Default owners para todo el repo
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

## 🚨 Política de Excepciones

### ¿Cuándo saltarse las protecciones?

**NUNCA** en situaciones normales. Solo en:

1. **Hotfix crítico de producción**: 
   - Documentar en el commit el motivo
   - Crear issue post-mortem
   - Abrir PR retrospectivo con los checks

2. **Emergencia de seguridad**:
   - Parchear vulnerabilidad crítica
   - Notificar al equipo inmediatamente
   - Ejecutar pipeline manualmente después

### Proceso de Excepción:

```bash
# 1. Documentar
git commit -m "HOTFIX: [TICKET-123] Descripción del problema crítico"

# 2. Push con bypass (si tienes permisos)
git push origin main

# 3. Inmediatamente después, crear PR de verificación
git checkout -b hotfix/verify-TICKET-123
git push origin hotfix/verify-TICKET-123
gh pr create --title "Verificación post-hotfix TICKET-123" --body "Ejecutar pipeline completa sobre el hotfix"
```

---

## ✅ Verificación

Después de configurar, verifica que funciona:

1. Crea una rama de prueba:
   ```bash
   git checkout -b test/branch-protection
   echo "test" >> README.md
   git add README.md
   git commit -m "test: Verificar branch protection"
   git push origin test/branch-protection
   ```

2. Abre un PR hacia `main`

3. Intenta hacer merge **sin esperar a que pasen los checks**:
   - ❌ Debería estar **deshabilitado**
   - ✅ Mensaje: "Required status checks must pass"

4. Espera a que pasen todos los checks

5. Intenta hacer merge **sin aprobación**:
   - ❌ Debería estar **deshabilitado**
   - ✅ Mensaje: "At least 1 approving review is required"

6. Aprueba el PR y haz merge
   - ✅ Ahora **sí debería permitir** el merge

---

## 📊 Monitoring

### Ver Intentos de Bypass

Settings → Branches → Ver "Protection rule activity"

### Auditoría

Settings → Security → Audit log → Filtrar por "protected branch"

---

## 🆘 Troubleshooting

### "Status check no aparece en la lista"

**Causa**: El check debe ejecutarse al menos una vez para aparecer.

**Solución**:
1. Abre cualquier PR
2. Espera a que se ejecute la pipeline
3. Vuelve a la configuración de protección
4. Ahora debería aparecer en la lista

### "No puedo hacer merge aunque los checks pasen"

**Verifica**:
- ¿Tiene al menos 1 aprobación?
- ¿Todos los comentarios están resueltos?
- ¿La rama está actualizada con main?

### "Los administradores pueden saltarse las reglas"

**Solución**: Marca "Do not allow bypassing the above settings" y aplica a administradores.

---

**Configuración recomendada aplicada a**: `main`, `master`, `develop`, `production`
