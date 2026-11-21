# 🚀 Inicio Rápido - Pipeline de Seguridad

## ⚡ Setup en 5 Minutos

### Paso 1: Habilitar Funciones de GitHub (30 segundos)

Ve a tu repositorio en GitHub → **Settings** → **Security**:

```
☑️ Dependabot alerts
☑️ Dependabot security updates  
☑️ Code scanning
☑️ Secret scanning (solo repos públicos)
```

### Paso 2: Subir la Pipeline (1 minuto)

```bash
# Ya tienes los archivos, solo súbelos:
git add .github/
git add .pre-commit-config.yaml
git commit -m "feat: Agregar pipeline de seguridad completa con TruffleHog, CodeQL, Trivy"
git push origin main
```

### Paso 3: Configurar Branch Protection (2 minutos)

**Opción A - Interfaz Web:**
1. Settings → Branches → Add rule
2. Branch name: `main`
3. Habilita: ☑️ Require status checks (selecciona todos los checks de la pipeline)
4. Habilita: ☑️ Require pull request reviews (mínimo 1)
5. Save changes

**Opción B - GitHub CLI (más rápido):**
```bash
gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --input - <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["secrets-scan", "codeql-analysis", "python-lint", "dependency-scan", "docker-scan"]
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

### Paso 4: (Opcional) Pre-commit Hooks Locales (1 minuto)

```bash
# Instalar pre-commit
pip install pre-commit

# Activar hooks
pre-commit install

# Ejecutar una vez para verificar
pre-commit run --all-files
```

---

## ✅ ¡Listo!

Ahora tu repositorio tiene:

- ✅ **TruffleHog** detectando secretos en cada PR
- ✅ **CodeQL** analizando vulnerabilidades de seguridad
- ✅ **Trivy** escaneando imágenes Docker
- ✅ **Bandit** revisando código Python
- ✅ **Safety** verificando dependencias vulnerables
- ✅ **Dependabot** creando PRs automáticos de actualizaciones
- ✅ **Hadolint** validando Dockerfiles
- ✅ **Branch Protection** bloqueando merges inseguros

---

## 🧪 Verificar que Funciona

### Test 1: Crear un PR de Prueba

```bash
git checkout -b test/security-pipeline
echo "# Test" >> TEST.md
git add TEST.md
git commit -m "test: Verificar pipeline de seguridad"
git push origin test/security-pipeline

# Abrir PR
gh pr create --title "Test: Security Pipeline" --body "Verificar que todos los checks se ejecuten"
```

### Test 2: Verificar los Checks

1. Ve al PR en GitHub
2. En la pestaña "Checks" deberías ver:
   - 🔐 TruffleHog - Detección de Secretos
   - 🔍 CodeQL - Análisis de Código
   - 🐍 Python Linting
   - 📦 Escaneo de Dependencias
   - 🐳 Trivy - Escaneo Docker
   - ✅ Validación de PR
   - 🐳 Dockerfile Linting

3. ⚠️ El botón "Merge" debería estar **deshabilitado** hasta que:
   - ✅ Todos los checks pasen
   - ✅ Alguien apruebe el PR

### Test 3: Probar Detección de Secretos (¡NO HAGAS ESTO EN MAIN!)

```bash
# EN UNA RAMA DE PRUEBA SOLAMENTE
git checkout -b test/secret-detection
echo "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE" > fake-secret.txt  # pragma: allowlist secret
git add fake-secret.txt
git commit -m "test: Trigger secret detection"
git push origin test/secret-detection

# TruffleHog DEBERÍA detectarlo y FALLAR el check
```

---

## 📊 Dónde Ver Resultados

### Durante el Desarrollo (Local)
```bash
# Ejecutar checks localmente antes de push
pre-commit run --all-files

# Solo un check específico
pre-commit run bandit --all-files
```

### En GitHub

**Pestaña "Actions"**: Estado de todos los workflows
- https://github.com/OWNER/REPO/actions

**Pestaña "Security"**: Alertas consolidadas
- Code scanning: https://github.com/OWNER/REPO/security/code-scanning
- Dependabot: https://github.com/OWNER/REPO/security/dependabot

**En cada PR**: 
- Tab "Checks": Estado detallado
- Tab "Files changed": Anotaciones inline de CodeQL

---

## 🔧 Personalización Rápida

### Cambiar tu usuario en Dependabot

```bash
# Editar .github/dependabot.yml
sed -i '' 's/irraz/TU-USUARIO/g' .github/dependabot.yml
```

### Deshabilitar un check temporalmente

```bash
# Comentar el job en el workflow
sed -i '' 's/docker-scan:/# docker-scan:/g' .github/workflows/security.yml
```

### Ajustar severidad de TruffleHog

```yaml
# En .github/workflows/security.yml
# Cambiar:
extra_args: --only-verified
# A:
extra_args: --debug  # Detecta TODO
```

---

## 🆘 Solución de Problemas Comunes

### "El check no aparece en Branch Protection"

**Causa**: Debe ejecutarse al menos una vez.

**Solución**: Abre un PR cualquiera, espera que se ejecute, vuelve a Settings.

### "Pre-commit falla con 'command not found'"

```bash
# Reinstalar
pip install --upgrade pre-commit
pre-commit clean
pre-commit install
```

### "CodeQL tarda mucho"

Normal en la primera vez. Cachea resultados y es más rápido después.

### "Dependabot crea demasiados PRs"

```yaml
# En .github/dependabot.yml
open-pull-requests-limit: 2  # Reducir de 5 a 2
```

### "False positivo en TruffleHog"

```bash
# Crear .trufflehogignore en la raíz
echo "labs/**" >> .trufflehogignore
echo "tests/**" >> .trufflehogignore
```

---

## 📚 Siguiente Nivel

### 1. **Notificaciones Slack/Discord**

Agrega al final de `.github/workflows/security.yml`:

```yaml
- name: Notify on Slack
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

### 2. **Badges en README**

```markdown
![Security Pipeline](https://github.com/OWNER/REPO/workflows/Security%20Pipeline/badge.svg)
![CodeQL](https://github.com/OWNER/REPO/workflows/CodeQL/badge.svg)
```

### 3. **SAST Adicional con Semgrep**

```yaml
- name: Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: auto
```

### 4. **Cobertura de Tests**

```yaml
- name: Coverage
  run: |
    pytest --cov=. --cov-report=xml
- name: Upload to Codecov
  uses: codecov/codecov-action@v3
```

---

## 🎯 Checklist Final

- [ ] Pipeline subida a GitHub
- [ ] Branch protection configurada en `main`
- [ ] Dependabot habilitado
- [ ] Code scanning habilitado
- [ ] Pre-commit hooks instalados localmente
- [ ] PR de prueba exitoso
- [ ] Equipo notificado del nuevo proceso
- [ ] Documentación SECURITY-PIPELINE.md revisada

---

## 💡 Pro Tips

1. **Ejecuta los checks localmente** con pre-commit antes de push para iterar más rápido
2. **Revisa Dependabot semanalmente** en lugar de ignorar sus PRs
3. **No ignores warnings** de Bandit, aunque no bloqueen el PR
4. **Mantén actualizado `.env.example`** para que nuevos devs sepan qué variables necesitan
5. **Revisa la pestaña Security** al menos una vez al mes

---

**¿Problemas?** Abre un issue o revisa [SECURITY-PIPELINE.md](./SECURITY-PIPELINE.md) para más detalles.

**Tiempo total de setup**: ~5 minutos  
**Beneficio**: Seguridad enterprise-grade **gratis** 🎉
