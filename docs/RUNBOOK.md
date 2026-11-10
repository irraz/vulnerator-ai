# RUNBOOK — Vulnerator-AI con consola web, pantallas en vivo y director de Caido

Guía para levantar **todo desde cero** (clon limpio del repo) y que funcione. Incluye lo nuevo:
la **consola web** (`vulnerator-web`), el **navegador visible** (`browser-view`), el **director de
Caido** (`caido-director`) y Hermes **v0.23.0**. Pensada para operador; en español.

> Esto documenta el estado de la rama de trabajo. Nada está subido a GitHub todavía.

---

## 1. Qué levanta la stack (9 servicios)

| Servicio | Imagen | Puerto host | Qué es |
|---|---|---|---|
| `kali` | `vulnerator-ai-kali:dev` (build) | 8900 | Runtime de tools (nmap, whatweb, sqlmap, Caido client…) vía kali-mcp. |
| `ooda-agent` | `nousresearch/hermes-agent:v0.23.0` | 8642 (API), 9119 (dashboard), 9120 (webapp) | El cerebro OODA (Hermes). |
| `playwright-mcp` | `mcr.microsoft.com/playwright/mcp` | — (interno) | Navegador del agente. **Conduce el navegador de `browser-view` por CDP.** |
| `vulnerator-mcp` | `vulnerator-ai-mcp:dev` (build) | — (interno) | Front door MCP sobre la API de runs. |
| `vulnerator-web` | `vulnerator-ai-web:dev` (build) | **9100** (GUI), 7000 (Caido pre-auth) | **La consola web.** También sirve la UI de Caido pre-autenticada como invitado. |
| `browser-view` | `vulnerator-ai-browser-view:dev` (build) | 6080 (noVNC) | Chromium **visible** que conduce el agente; se ve por noVNC en la consola. |
| `caido-director` | `vulnerator-ai-caido-director:dev` (build) | 6090 (noVNC) | Re-escenifica en la UI de Caido lo que el agente hace con ella. |
| `caido` + `caido-init` | `caido/caido:0.59.0` | — (interno) | Toolkit web (proxy/Replay/Automate/Intercept). |
| `juice-shop` (opcional, lab) | `bkimminich/juice-shop` | — (interno) | Objetivo de prácticas; solo con `docker-compose.target.yml`. |

**Imágenes propias a construir:** `kali`, `vulnerator-mcp`, `vulnerator-web`, `browser-view`,
`caido-director`. Las demás se descargan.

---

## 2. Requisitos

- **Docker** + **docker compose v2** (`docker compose version`).
- Acceso a internet (para descargar imágenes y para que Hermes llame a OpenRouter).
- Disco: ~5-6 GB de imágenes (Hermes v0.23.0 pesa ~3,2 GB).
- Una clave de **OpenRouter** con saldo (el cerebro de Hermes). Alternativa: Ollama (ver §9).

---

## 3. Preparar el `.env` (una sola vez)

Copia la plantilla y rellena lo imprescindible:

```sh
cd ~/vulnerator-ai-work          # tu clon del repo
cp .env.example .env
chmod 600 .env
```

**Variables OBLIGATORIAS** (sin ellas la stack no arranca, son fail-closed):

```ini
# Clave del proveedor LLM de Hermes (OpenRouter). Requerida en modo OpenRouter.
OPENROUTER_API_KEY=sk-or-v1-....................................................

# Bearer de la API de Hermes (:8642). Genera uno:  openssl rand -hex 32
HERMES_API_SERVER_KEY=<64 hex>

# Token de entrada del MCP front door. Genera otro distinto:  openssl rand -hex 32
VULNERATOR_MCP_INBOUND_TOKEN=<64 hex>
```

> Genera las dos claves con `openssl rand -hex 32` (una distinta para cada una).
> `install.sh` también las genera por ti si prefieres ese camino (§5, opción B).

**Recomendadas para las pantallas en vivo de Caido** (si no, Caido no verá el tráfico del
agente):

```ini
# El navegador visible enruta su tráfico por el proxy de Caido -> se ve en Caido.
BROWSER_VIEW_PROXY=http://caido:8080
# Las tools HTTP de kali (curl/nuclei/ffuf…) también pasan por el proxy de Caido.
CAIDO_PROXY_CAPTURE=1
```

**Opcionales** (tienen default sensato; ver `.env.example` para todas):
`VULNERATOR_WEB_PASSWORD` (login de la consola; por defecto `vulnerator`),
`HERMES_IMAGE` (por defecto `nousresearch/hermes-agent:v0.23.0`),
`CAIDO_DIRECTOR_STEP` (ritmo del director), puertos `*_HOST_PORT`.

El `.env` está en `.gitignore` — **nunca se sube**.

---

## 4. Construir las imágenes propias

El `docker-compose.yml` declara `platforms:` multi-arch (para publicar), y un Docker **sin
buildx/containerd** falla con *"Multi-platform build is not supported for the docker driver"*.
Por eso, el camino fiable es construir cada imagen para tu arquitectura con el script incluido:

```sh
./build-local-images.sh
```

(Equivale a `docker build -f docker/<x>/Dockerfile -t vulnerator-ai-<x>:dev .` de las 5 imágenes.)

> Si tu Docker **sí** tiene buildx/containerd, puedes saltarte esto y usar `docker compose up -d
> --build` directamente (o `./install.sh`).

---

## 5. Levantar la stack

**Opción A — manual (recomendada tras `build-local-images.sh`):**

```sh
# Sin lab:
docker compose up -d --no-build
# Con el lab de prácticas OWASP Juice Shop:
docker compose -f docker-compose.yml -f docker-compose.target.yml up -d --no-build
```

**Opción B — instalador oficial** (genera el `.env` y hace `up -d --build`; requiere que tu
Docker construya multi-plataforma, o adáptalo):

```sh
./install.sh                     # te pide la OpenRouter key y genera claves
./install.sh --with-juice-shop   # además levanta el lab
```

---

## 6. Verificar que está sano

```sh
docker compose ps        # todos "healthy" / "Up" (ooda-agent no tiene healthcheck: es normal)
curl -s http://localhost:8642/health            # {"status":"ok",...,"version":"0.23.0"}
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:9100/healthz   # 200
```

`caido` tarda ~30-60 s en estar listo tras un arranque en frío. El **director de Caido** necesita
ese margen para dejar la UI pre-autenticada y sin onboarding (lo hace solo, ver §10/§11).

---

## 7. Entrar en la consola web

La consola está en **http://localhost:9100**.

- **Login propio** (usuario `admin` / contraseña `vulnerator`, o lo que pongas en
  `VULNERATOR_WEB_USER`/`PASSWORD`). Para acceso sin credenciales en una máquina controlada,
  `VULNERATOR_WEB_AUTH=0`.

Pestañas:
- **Terminal** — el bucle OODA en vivo: fases, razonamiento, cada comando con su salida.
- **Copilot** — "ahora mismo": tool en curso, navegador, tráfico de Caido, hallazgos.
- **Trazas** — cascada de tool-calls (duración, estado, fase) tipo Langfuse.
- **PoC** — por cada hallazgo confirmado: ruta OODA + reproducción grabada (`.cast`/`.md`).
- **Pantallas** — para demos: **acciones de Hermes en vivo** + **navegador del agente** (noVNC)
  + **Caido operándose solo** (director) + enlaces al Dashboard/Webapp de Hermes.
- **Hermes** — accesos al Dashboard (`:9119`, Kanban) y Webapp (`:9120`).

---

## 8. Lanzar un engagement (como usuario)

Es independiente de la consola (la consola solo observa). Formas:

```sh
# a) TUI interactiva:
docker compose exec -it ooda-agent hermes chat

# b) API de runs (lo que se ve en vivo en la consola):
KEY=$(grep '^HERMES_API_SERVER_KEY=' .env | cut -d= -f2-)
curl -s http://localhost:8642/v1/runs -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"input":"Authorized pentest against http://juice-shop:3000 (scope: that host only). ..."}'
```

El lab interno se alcanza como `http://juice-shop:3000`. Para un objetivo externo autorizado,
pon su URL y acota el scope a ese host.

Seguirlo **desde la terminal** (CLI, stdlib pura):
```sh
docker compose exec vulnerator-web python3 vulnerator_watch.py            # todas las sesiones
# o desde el host:  python3 docker/web/vulnerator_watch.py --record-dir ./pocs
```

---

## 9. Modo Ollama (sin OpenRouter)

Pon en `.env` `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1` y `OLLAMA_MODEL=<modelo>`;
entonces `OPENROUTER_API_KEY` no es obligatoria. (Ver `.env.example`.)

---

## 10. Las pantallas en vivo (cómo ver lo que hace)

- **Navegador del agente** (`browser-view`, noVNC en `:6080`): el agente controla ese Chromium
  pixel a pixel; lo ves navegar/clicar. Para objetivos **HTTPS por el proxy de Caido** el
  navegador usa `--ignore-certificate-errors` (el proxy hace MITM con su propia CA).
- **Caido (director)** (`caido-director`, noVNC en `:6090`): la UI de Caido **se mueve sola**
  reproduciendo cada `caido_request`/`caido_automate`/`caido_history`/scope del agente: abre la
  sesión de Replay, teclea el filtro HTTPQL, abre el paquete, etc. Los **datos son reales** (los
  del agente); el "paseo" por la UI lo coreografía el director. Va al **ritmo del agente**
  (cada acción es una inferencia del LLM, ~30-60 s): es el "directo lento pero se ve todo".
- Para que Caido tenga tráfico que mostrar: `BROWSER_VIEW_PROXY=http://caido:8080` y
  `CAIDO_PROXY_CAPTURE=1` en `.env` (§3).

**Caido entra siempre como invitado, sin onboarding** — está resuelto en código: `vulnerator-web`
hace de proxy de Caido e inyecta un token de invitado y marca el onboarding/analytics como hecho
(ver `docker/web/caido_proxy.py`). Sobrevive a borrar el volumen de Caido. Quien quiera su cuenta
Caido la configura al instalar (token de entorno `CAIDO_PAT`).

---

## 11. Troubleshooting (cosas que ya resolvimos)

- **Caido muestra "Learn the Essentials"/analytics al abrir** → solo pasa en los primeros ~30 s
  tras un volumen de Caido recién creado (el proxy aún está fijando el estado). Refresca; se
  auto-corrige en cada carga. Está resuelto en código, no hay que tocar nada a mano.
- **Caido no captura nada** → faltan `BROWSER_VIEW_PROXY=http://caido:8080` y/o
  `CAIDO_PROXY_CAPTURE=1` en `.env`, o estás mirando tráfico de antes de arrancar el engagement.
- **El navegador visible da error de certificado en HTTPS** → ya está el flag
  `--ignore-certificate-errors` en `browser-view` (necesario al pasar por el proxy de Caido).
- **Caido entra en pánico "Permission denied" tras borrar su volumen** → lo arregla el servicio
  one-shot `caido-init` (hace `chown` del volumen). Si recreas Caido a mano con `--no-deps`,
  ejecuta antes `docker compose run --rm caido-init`.
- **`docker compose build` falla "Multi-platform build is not supported"** → usa
  `./build-local-images.sh` (§4).
- **Hermes rechaza el LLM con `HTTP 401 User not found`** → la `OPENROUTER_API_KEY` es inválida
  o sin saldo; pon una válida y recrea: `docker compose up -d ooda-agent`.
- **Rollback de Hermes** → `HERMES_IMAGE=nousresearch/hermes-agent:v0.22.7` en `.env` y
  `docker compose up -d ooda-agent`.
- **El director de Caido está quieto** → el agente no está usando tools de Caido en ese momento
  (hace recon/navegador). Solo se mueve cuando el agente ejecuta `caido_*`.

---

## 12. Empezar un ejercicio DESDE 0 (pizarra limpia)

Para una demo desde cero sin rastro de pruebas anteriores:

```sh
# 1) parar runs activos (si los hay): por la API /v1/runs/<id>/stop, o reinicia ooda-agent.
# 2) borrar estado (sesiones de Hermes, base de la consola, tráfico de Caido):
docker compose down                         # para la stack (conserva volúmenes)
docker volume rm vulnerator-ai-work_hermes-data \
                 vulnerator-ai-work_vulnerator-web-data \
                 vulnerator-ai-work_caido-data
docker compose run --rm caido-init          # permisos del volumen nuevo de Caido
docker compose up -d --no-build             # (+ -f docker-compose.target.yml para el lab)
```

Esto deja Hermes sin sesiones, la consola vacía y Caido sin tráfico. El onboarding de Caido se
vuelve a poner solo (código). Espera ~30-60 s a que todo esté sano antes de lanzar el engagement.

> Borrar `hermes-data` resetea también el perfil/Kanban de Hermes (se reconstruye al arrancar
> desde `./agent-ooda`). Si solo quieres limpiar la consola y el tráfico, borra únicamente
> `vulnerator-web-data` y `caido-data`.

---

## 13. Reset total (borrar TODO, incl. imágenes)

```sh
docker compose down -v                      # para y borra TODOS los volúmenes
# (opcional) borrar las imágenes propias:
docker image rm vulnerator-ai-kali:dev vulnerator-ai-mcp:dev vulnerator-ai-web:dev \
                vulnerator-ai-browser-view:dev vulnerator-ai-caido-director:dev
# luego: ./build-local-images.sh && docker compose up -d --no-build
```

---

## 14. Estado del repo / qué falta

- Rama de trabajo local sobre `master`. **Sin commits todavía; nada subido a GitHub.**
- Añadidos nuevos: `docker/web/`, `docker/browser-view/`, `docker/caido-director/`,
  `build-local-images.sh`, `docs/web-gui.md`, `docs/RUNBOOK.md`.
- Modificados: `docker-compose.yml`, `.env.example`, `README.md`.
- Documentación de la consola y las pantallas: **[`docs/web-gui.md`](web-gui.md)**.
