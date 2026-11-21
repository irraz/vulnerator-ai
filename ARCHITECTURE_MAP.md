# ARCHITECTURE_MAP.md — mapa verificable de vulnerator-ai

> **Cómo leer este mapa.**
>
> - Cada afirmación lleva su referencia `fichero:línea` **real**, relativa a la raíz del
>   worktree. No hay rutas inventadas: el smoke las comprueba con `test -e`.
> - El mapa no contiene secretos (no se copian tokens, claves ni el hash de la contraseña)
>   ni comentarios de parche; solo describe el cableado y dónde vive.
> - La fuente de verdad es el código, no este documento. El mapa se verifica con:
>
>   ```sh
>   env -u PYTHONPATH python3 scripts/smoke.py --check
>   ```
>
>   que valida contratos YAML, las tools por AST y la coincidencia de los anexos con el
>   `docker-compose.yml` y los servidores MCP. Las 6 suites se corren aparte con
>   `env -u PYTHONPATH python3 scripts/smoke.py --tests` (o `bash scripts/run_tests.sh`).
> - Convención de nombres: el servidor MCP `kali` registra sus tools como `mcp_kali_<tool>`
>   y el `playwright` como `mcp_playwright_<tool>` (`agent-ooda/profile/config.yaml:88`).
> - Puertos y URLs se escriben como texto plano (no como `ruta:línea`) a propósito: solo
>   las referencias `fichero:línea` van entre backticks.

---

## 1. Diagrama ASCII

Vista de caja negra del stack (componentes, transportes y puertos). Las líneas son las
citas del README y del design; los detalles están en las secciones siguientes.

```
  operador                         MCP clients externos
  (TUI / Webapp)                   (Claude Code, Kiro, BugTraceAI)
      │                                   │
      │ docker compose exec               │ MCP (stdio o streamable-HTTP)
      ▼                                   ▼
┌─────────────────────────────┐   ┌──────────────────────────┐
│          ooda-agent         │   │     vulnerator-mcp       │
│  Hermes = cerebro OODA      │◄──┤  front door :8700        │
│  model.default              │   │  6 tools (sección 6)     │
│  mistral-large-4-0          │   └───────────┬──────────────┘
│  API server :8642           │               │ HTTP Bearer
│  (platforms.api_server)     │               ▼
└───────┬──────────────┬──────┘        ooda-agent :8642
        │ MCP          │ MCP           (sección 3)
        ▼              ▼
┌───────────────────┐ ┌───────────────────┐
│  kali (kali-mcp)  │ │  playwright-mcp   │
│  :8900            │ │  :8931 (/mcp)     │
│  21 tools (sec.4) │ │  real browser     │
│  artifacts :8901  │ │  (sección 5)      │
└─────────┬─────────┘ └───────────────────┘
          │ GraphQL (red interna, NO publicada)
          ▼
   ┌──────────────┐        ┌──────────────────────────────┐
   │ caido :8080  │        │ observables (profile `web`)  │
   │ proxy/Replay │        │ vulnerator-web :9100         │
   │ HTTPQL       │        │ browser-view :6080           │
   └──────────────┘        │ caido-director :6090         │
                           └──────────────────────────────┘
```

- Resumen de la arquitectura: `README.md:96` y su diagrama `README.md:98`.
- El design completo y la comparación con otros OODA: `docs/design.md:7`.
- El frente de interceptación (Caido) y el frente web: `docs/design.md:112` y `docs/design.md:100`.

## 2. Bucle OODA

El OODA **no es un motor**: no hay código que itere ni un scheduler. Es un comportamiento
inducido por el prompt, repartido en tres piezas del perfil (`docs/design.md:9`):

| Pieza | Rol | Referencia |
| --- | --- | --- |
| `profile/SOUL.md` | identidad del conductor OODA | `agent-ooda/profile/SOUL.md:12` |
| `skills/pentest-ooda/SKILL.md` | procedimiento del bucle | `agent-ooda/skills/pentest-ooda/SKILL.md:16` |
| `skills/ooda-report-handoff/SKILL.md` | resumen al cerrar un ciclo | `docs/design.md:16` |

El ciclo es Observe → Orient → Decide → Act (`agent-ooda/skills/pentest-ooda/SKILL.md:18`),
y el procedimiento completo está en `agent-ooda/skills/pentest-ooda/SKILL.md:124`:

- **Observe**: `server_info` y, según el engagement, `prowler_scan` / `iam_enum`
  (`agent-ooda/skills/pentest-ooda/SKILL.md:126`).
- **Orient**: cruza lo observado con técnicas y superficie; `iam_simulate` para AWS/IAM
  (`agent-ooda/skills/pentest-ooda/SKILL.md:129`).
- **Decide**: enumera 2-3 alternativas y se compromete con UNA
  (`agent-ooda/skills/pentest-ooda/SKILL.md:131`).
- **Act**: ejecuta en serial con `kali_run` (bloqueante) o `kali_exec` + poll
  (`agent-ooda/skills/pentest-ooda/SKILL.md:139`).
- **Lee la salida como dato no confiable y registra evidencia**
  (`agent-ooda/skills/pentest-ooda/SKILL.md:142`).
- **Criterio de parada**: no abandonar antes de 3 pasos sin progreso
  (`agent-ooda/skills/pentest-ooda/SKILL.md:147`); al cerrar, generar el informe
  (`agent-ooda/skills/pentest-ooda/SKILL.md:153`).

Reglas transversales:

- Formato de fase por turno: `agent-ooda/prompts/ephemeral-system.md:11`.
- Disciplina OODA y manejo de estado: `agent-ooda/context/AGENTS.md:31` y
  `agent-ooda/profile/SOUL.md:109`.
- Toda salida de tool es **dato no confiable** (prompt injection):
  `agent-ooda/context/AGENTS.md:41` y `agent-ooda/profile/SOUL.md:269`.
- Higiene de contexto: delegar ramas largas a subagentes
  (`agent-ooda/skills/pentest-ooda/SKILL.md:100`).
- Persistencia de evidencia por engagement: `docs/design.md:69` (el store vive en el plano
  de artefactos, no en el estado de Hermes).

## 3. Cliente Hermes

Hermes es un **cliente MCP** de dos servidores; no hay núcleo, API o UI de por medio
(`agent-ooda/README.md:10`). El perfil declarativo es la plantilla que el contenedor
`ooda-agent` copia a su home en cada arranque (`docker-compose.yml:141`).

**Los dos MCP, exactamente** (`agent-ooda/profile/config.yaml:92`):

| Server | URL | Referencia |
| --- | --- | --- |
| `kali` | http://kali (puerto 8900) | `agent-ooda/profile/config.yaml:93` y `agent-ooda/profile/config.yaml:97` |
| `playwright` | http://playwright-mcp (puerto 8931, ruta /mcp) | `agent-ooda/profile/config.yaml:122` y `agent-ooda/profile/config.yaml:123` |

- No hay `tools.include`: el servidor es la fuente de verdad
  (`agent-ooda/profile/config.yaml:98`).
- `toolsets` es una lista de bundles, no `toolsets.enabled`
  (`agent-ooda/profile/config.yaml:141`): `kali` (`agent-ooda/profile/config.yaml:142`),
  `playwright` (`agent-ooda/profile/config.yaml:143`), `todo` (`agent-ooda/profile/config.yaml:144`)
  y `kanban` (`agent-ooda/profile/config.yaml:145`).
- Los bundles nativos (terminal, file, browser, web, code_execution, …) están
  desactivados explícitamente (`agent-ooda/profile/config.yaml:159`).
- Modelo por defecto: `mistralai/mistral-large-4-0` (`agent-ooda/profile/config.yaml:51`),
  con fallback automático a `z-ai/glm-5.3-flash` (`agent-ooda/profile/config.yaml:79`).
- El progreso de tool_search se desactiva para ver las tools MCP directamente
  (`agent-ooda/profile/config.yaml:175`).
- La plataforma API server se declara en `platforms.api_server`
  (`agent-ooda/profile/config.yaml:203`), puerto 8642 (`agent-ooda/profile/config.yaml:207`).

**El servicio `ooda-agent`** (`docker-compose.yml:120`):

- Imagen oficial `nousresearch/hermes-agent:v0.23.0` (`docker-compose.yml:126`).
- `command` arranca el gateway en primer plano (`docker-compose.yml:132` y `docker-compose.yml:206`),
  inyecta la clave del API server (`docker-compose.yml:154`) y copia la plantilla de
  perfil (`docker-compose.yml:141`).
- `environment` (`docker-compose.yml:207`): la key del LLM va por `OPENROUTER_API_KEY`
  (`docker-compose.yml:227`), con modo Ollama opcional (`docker-compose.yml:237`).
- `volumes` (`docker-compose.yml:240`): `hermes-data:/opt/data` (`docker-compose.yml:243`) y la
  plantilla de perfil en `/opt/profile-src:ro` (`docker-compose.yml:245`).
- TTY interactivo para `hermes chat`: `stdin_open` (`docker-compose.yml:252`) y `tty`
  (`docker-compose.yml:253`).
- Publica 8642, 9119 y 9120 (`docker-compose.yml:264`).
- Espera a kali y playwright-mcp con `service_healthy`
  (`docker-compose.yml:275`, `docker-compose.yml:277`, `docker-compose.yml:280`).

La API HTTP de runs que envuelve `vulnerator-mcp` está documentada en `docs/http-api.md:1`;
el Bearer es `HERMES_API_SERVER_KEY` (`docs/http-api.md:19`) y el endpoint de runs es
`POST /v1/runs` (`docs/http-api.md:55`).

## 4. MCP Kali (21 tools)

Servidor `kali-mcp` en el contenedor `kali` (`docker/kali/kali_mcp_server.py:1`): expone
las tools de pentest sobre FastMCP (`docker/kali/kali_mcp_server.py:119` y `docker/kali/kali_mcp_server.py:225`), en
streamable-HTTP en el puerto 8900 (`docker/kali/kali_mcp_server.py:123`) y con el plano
de artefactos en 8901 (`docker/kali/kali_mcp_server.py:132`).

- `server_info` deriva la lista de tools por **introspección del registro de FastMCP**,
  no de una lista estática (`docker/kali/kali_mcp_server.py:303`); el bloque de plugins
  cerrado está en `docker/kali/kali_mcp_server.py:317`.
- Store de hallazgos por engagement: `finding_store.append`
  (`docker/kali/finding_store.py:189`) y `finding_store.read`
  (`docker/kali/finding_store.py:214`); vive en `/artifacts` (`docs/design.md:73`).
- Scope-guard opt-in: `scope_guard.is_enforcing` (`docker/kali/scope_guard.py:96`) y
  `scope_guard.extract_targets_from_command` (`docker/kali/scope_guard.py:294`); sin
  `scope.json` con `enabled: true` no hay gate (`docs/security.md:10`).
- Streaming de ejecuciones: `tool_streaming._Execution`
  (`docker/kali/tool_streaming.py:43`) y `tool_streaming.read`
  (`docker/kali/tool_streaming.py:173`).
- Runner de shell cruda: `shell_exec.run_shell` (`docker/kali/shell_exec.py:177`),
  importado en `docker/kali/kali_mcp_server.py:57`.
- Las 21 tools, con su línea exacta, están en el **Anexo A** (sección 11).
- Imagen: `kalilinux/kali-rolling:latest` (`docker/kali/Dockerfile:29`), WORKDIR
  `/opt/kali-mcp` (`docker/kali/Dockerfile:111`), venv dedicado (`docker/kali/Dockerfile:117`)
  y dependencias fijadas (`docker/kali/Dockerfile:122`): `prowler==5.44.0`
  (`docker/kali/requirements.txt:8`) y `mcp>=1.28,<2` (`docker/kali/requirements.txt:17`).

## 5. MCP Playwright

Segundo MCP del stack: un Chromium headless real para la parte web, sin reactivar ningún
toolset nativo (`docker-compose.yml:291`).

- Imagen oficial `mcr.microsoft.com/playwright/mcp` (`docker-compose.yml:298`), entrada
  `node` (`docker-compose.yml:306`) y comando con `--headless --browser chromium
  --no-sandbox --isolated` (`docker-compose.yml:307`).
- Salud: `healthcheck` contra `/mcp` (`docker-compose.yml:325`).
- **Sin `ports`**: no se publica al host (`docker-compose.yml:331`).
- En el perfil: `agent-ooda/profile/config.yaml:122` con `tools:` que solo desactiva los
  wrappers de utilidad (`agent-ooda/profile/config.yaml:127`).
- El overlay `docker-compose.web.yml` cambia el modo headless por el Chromium visible de
  `browser-view` sobre CDP (`docker-compose.web.yml:1`).
- El frente web y su skill: `docs/design.md:100` y `docs/design.md:104`.

## 6. MCP vulnerator-mcp (6 tools)

Front door MCP fino sobre la API de runs de Hermes (`docker/mcp/vulnerator_mcp_server.py:1`).
Envuelve —no reemplaza— el API HTTP: expone **solo** el ciclo de vida de un run.

- FastMCP en `docker/mcp/vulnerator_mcp_server.py:94`; puerto 8700
  (`docker/mcp/vulnerator_mcp_server.py:77`) y upstream http://ooda-agent (puerto 8642)
  (`docker/mcp/vulnerator_mcp_server.py:79`).
- Transporte `stdio` (default) o `streamable-http`
  (`docker/mcp/vulnerator_mcp_server.py:83`); fail-closed en el token de entrada
  (`docker/mcp/vulnerator_mcp_server.py:86`); ruta de salud dedicada `/healthz`
  (`docker/mcp/vulnerator_mcp_server.py:90`).
- Todas las tools son `async` y offloadean la llamada HTTP bloqueante a un hilo
  (`docker/mcp/vulnerator_mcp_server.py:105`).
- Cliente fino SDK-free de :8642: `HermesApiClient`
  (`docker/mcp/hermes_api_client.py:377`), con `create_run`
  (`docker/mcp/hermes_api_client.py:492`), `get_run`, `steer_run`, `stop_run` y
  `iter_events` (`docker/mcp/hermes_api_client.py:543`).
- Lógica pura: `fold_scope_into_input` (`docker/mcp/mcp_tool_logic.py:34`),
  `validate_start_pentest` (`docker/mcp/mcp_tool_logic.py:44`) y `decide_stream_done`
  (`docker/mcp/mcp_tool_logic.py:113`).
- Las 6 tools, con su línea exacta, están en el **Anexo A** (sección 11); el mapeo
  uno a uno con la API está en `docs/usage.md:25`.
- Servicio compose `vulnerator-mcp` (`docker-compose.yml:334`): build
  (`docker-compose.yml:351`), upstream (`docker-compose.yml:360`), token de entrada
  (`docker-compose.yml:367`), transporte (`docker-compose.yml:368`), puerto interno
  (`docker-compose.yml:371`), `depends_on: ooda-agent` (`docker-compose.yml:380`) y
  healthcheck (`docker-compose.yml:390`). No publica puerto al host por defecto
  (`docker-compose.yml:372`).
- Imagen python 3.13-slim (`docker/mcp/Dockerfile:17`), dependencias
  (`docker/mcp/Dockerfile:26`), módulos (`docker/mcp/Dockerfile:31`,
  `docker/mcp/Dockerfile:32`, `docker/mcp/Dockerfile:33`),
  `EXPOSE 8700` (`docker/mcp/Dockerfile:45`) y entrypoint (`docker/mcp/Dockerfile:60`).
- El entrypoint por defecto es stdio (`docker/mcp/entrypoint.sh:25`) y exec
  `vulnerator_mcp_server.py` (`docker/mcp/entrypoint.sh:34`).
- Token de entrada documentado en `docs/security.md:67`; el wrapper no es un guard
  (`docs/security.md:76`).

## 7. ATT&CK

ATT&CK es el **lenguaje de Orient** y la taxonomía de los hallazgos; no sustituye al OODA
(`docs/design.md:35`).

- Skill transversal `attack-navigation`: `agent-ooda/skills/attack-navigation/SKILL.md:3`,
  con los 14 tácticas Enterprise (`agent-ooda/skills/attack-navigation/SKILL.md:32`),
  la integración en el bucle (`agent-ooda/skills/attack-navigation/SKILL.md:57`) y la
  regla de no inventar IDs (`agent-ooda/skills/attack-navigation/SKILL.md:88`). ATT&CK
  clasifica, no procedimenta (`agent-ooda/skills/attack-navigation/SKILL.md:92`).
- En SOUL: `agent-ooda/profile/SOUL.md:272` y `agent-ooda/profile/SOUL.md:274`.
- Cada hallazgo puede llevar `technique_id` (`docker/kali/kali_mcp_server.py:873`).
- El informe lo muestra en la tabla (`docker/kali/report_gen.py:98`) y en la metodología
  (`docker/kali/report_gen.py:204`).
- Variante Cloud: `agent-ooda/skills/aws-pacu-privesc/SKILL.md:90`.
- El registro de hallazgos y el informe lo consumen: `agent-ooda/skills/pentest-report/SKILL.md:19`.

## 8. Docker Compose (9 servicios)

El fichero base es `docker-compose.yml:24`. Los 9 servicios, con su línea de declaración,
están en el **Anexo B** (sección 12). Perfiles y volúmenes:

| Concepto | Valor | Referencia |
| --- | --- | --- |
| Servicios | 9 | `docker-compose.yml:24` |
| Volúmenes con nombre | 4 | `docker-compose.yml:665` |
| Perfil `web` | `vulnerator-web`, `browser-view`, `caido-director` | `docker-compose.yml:427`, `docker-compose.yml:509`, `docker-compose.yml:549` |
| Red | una sola red interna de compose (DNS por nombre de servicio) | `docker-compose.yml:289` |
| `kali` publica | 8900 (MCP) | `docker-compose.yml:108` |
| `ooda-agent` publica | 8642, 9119, 9120 | `docker-compose.yml:264` |
| `vulnerator-web` publica | 9100 y 7010 | `docker-compose.yml:470` |
| `browser-view` publica | 6080 | `docker-compose.yml:523` |
| `caido-director` publica | 6090 | `docker-compose.yml:559` |
| `playwright-mcp` | NO publica | `docker-compose.yml:331` |
| `vulnerator-mcp` | NO publica por defecto | `docker-compose.yml:372` |
| `caido` | NO publica (la UI la sirve vulnerator-web) | `docker-compose.yml:651` |

- `kali` healthcheck TCP a 8900 (`docker-compose.yml:112`) y `ooda-agent` espera
  `service_healthy` (`docker-compose.yml:277`).
- `caido-init` es un one-shot que ajusta ownership del volumen
  (`docker-compose.yml:571`) y `caido` espera `service_completed_successfully`
  (`docker-compose.yml:642`).
- Overlays opcionales: consola y pantallas vivas (`docker-compose.web.yml:1`) y laboratorio
  Juice Shop (`docker-compose.target.yml:1`).

## 9. Sistema de tests

Seis suites, una por componente. Se corren con `bash scripts/run_tests.sh`
(`scripts/run_tests.sh:1`) o `env -u PYTHONPATH python3 scripts/smoke.py --tests`
(`scripts/smoke.py:1`). El gate de CI las invoca en modo estático
(`.github/workflows/ci.yml:1`).

| Suite | Cubre | Referencia |
| --- | --- | --- |
| `agent-ooda/tests` | contratos declarativos de `config.yaml` + compose | `agent-ooda/tests/test_profile_kali_direct.py:1` |
| `docker/kali/tests` | runtime kali-mcp (streaming, scope, store, tools) | `docker/kali/tests/test_tool_streaming.py:1` |
| `docker/mcp/tests` | front door (cliente :8642 + tools, con `importorskip("mcp.server.fastmcp")`) | `docker/mcp/tests/test_server_tools.py:30` |
| `docker/web/tests` | consola web (ingest, event model, PoC, watch) | `docker/web/tests/test_ingest_app.py:1` |
| `docker/browser-view/tests` | proxy CDP y reset del browser visible | `docker/browser-view/tests/test_cdp_proxy.py:1` |
| `scripts/tests` | andamiaje (regla anti-parche y tests del humo) | `scripts/tests/` |

- Los tests de agent-ooda resuelven las rutas desde la raíz con fixtures
  (`agent-ooda/tests/conftest.py:1`) y configuran pytest en
  `agent-ooda/tests/pyproject.toml:1`.
- Los tests unitarios de lógica pura corren **sin** el SDK `mcp`
  (`docker/mcp/tests/test_server_tools.py:30` lo omite si falta).
- El gate bloqueante del andamiaje es `🧱 Base scaffolding`
  (`.github/workflows/ci.yml:1`): smoke estático + `docker compose config` +
  anti-comentarios de parche + type-check (mypy) + las 6 suites.
- En el árbol integrado las 6 suites están en verde; el recuento exacto depende del
  entorno de test y lo reporta `scripts/smoke.py --quick`. Los 4 tests declarativos que
  antes fallaban quedaron actualizados al contrato v2.0.0 en `feat/base-declared-contracts`.
- El detalle de las 6 suites y el comando del smoke está en el **Anexo C** (sección 13).

## 10. Entorno dev

- Anfitrión: Python 3.14; contenedores propios: Python 3.13
  (`docker/kali/Dockerfile:29`, `docker/mcp/Dockerfile:17`, `docker/web/Dockerfile:16`).
- Los tests y el smoke corren con `env -u PYTHONPATH` (un PYTHONPATH global contamina con
  `mcp` 2.3.0) y nunca con `--import-mode=importlib`.
- `uv` resuelve las dependencias de cada suite en un entorno efímero
  (`scripts/run_tests.sh:1`); las dependencias de producto están fijadas en
  `docker/kali/requirements.txt:1`, `docker/mcp/requirements.txt:1` y
  `docker/web/requirements.txt:1`.
- El pin de test es `mcp>=1.28,<2`. Con `mcp` 2.x, `FastMCP` desaparece y
  `pytest.importorskip("mcp.server.fastmcp")` omite en silencio 13 tests:
  `docker/kali/tests/test_plugin_introspection.py` (5) y
  `docker/mcp/tests/test_server_tools.py` (8).
- Imágenes propias: `docker/kali/Dockerfile:1`, `docker/mcp/Dockerfile:1`,
  `docker/web/Dockerfile:1`, `docker/browser-view/Dockerfile:1`,
  `docker/caido-director/Dockerfile:1`.
- Arranque del stack: `install.sh:1` y `docs/RUNBOOK.md:1`; build local de las imágenes:
  `build-local-images.sh:1`.
- Variables de entorno documentadas: `docs/configuration.md:1` (requeridas en
  `docs/configuration.md:20`, puertos en `docs/configuration.md:44`).

## 11. Anexo A — herramientas

Formato: `| herramienta | fichero:línea |`. La línea es la del `def` (el decorador
`@mcp.tool` está en la línea anterior). Fuente: AST de cada servidor, sin importarlos.

### 11.1 kali-mcp (21 tools)

| Herramienta | Fichero:línea |
| --- | --- |
| `server_info` | `docker/kali/kali_mcp_server.py:237` |
| `read_tool_logs` | `docker/kali/kali_mcp_server.py:369` |
| `read_scan_findings` | `docker/kali/kali_mcp_server.py:389` |
| `start_collection` | `docker/kali/kali_mcp_server.py:442` |
| `prowler_scan` | `docker/kali/kali_mcp_server.py:471` |
| `get_scan_status` | `docker/kali/kali_mcp_server.py:488` |
| `cancel_scan` | `docker/kali/kali_mcp_server.py:509` |
| `iam_enum` | `docker/kali/kali_mcp_server.py:530` |
| `iam_simulate` | `docker/kali/kali_mcp_server.py:571` |
| `kali_exec` | `docker/kali/kali_mcp_server.py:679` |
| `kali_run` | `docker/kali/kali_mcp_server.py:757` |
| `record_finding` | `docker/kali/kali_mcp_server.py:830` |
| `read_findings` | `docker/kali/kali_mcp_server.py:931` |
| `dns_recon` | `docker/kali/kali_mcp_server.py:955` |
| `webtech_scan` | `docker/kali/kali_mcp_server.py:1000` |
| `caido_graphql` | `docker/kali/kali_mcp_server.py:1048` |
| `caido_request` | `docker/kali/kali_mcp_server.py:1123` |
| `caido_history` | `docker/kali/kali_mcp_server.py:1203` |
| `caido_automate` | `docker/kali/kali_mcp_server.py:1233` |
| `caido_intercept` | `docker/kali/kali_mcp_server.py:1302` |
| `caido_proxy` | `docker/kali/kali_mcp_server.py:1416` |

### 11.2 vulnerator-mcp (6 tools)

| Herramienta | Fichero:línea |
| --- | --- |
| `start_pentest` | `docker/mcp/vulnerator_mcp_server.py:122` |
| `get_run_status` | `docker/mcp/vulnerator_mcp_server.py:175` |
| `stream_run_events` | `docker/mcp/vulnerator_mcp_server.py:198` |
| `steer_run` | `docker/mcp/vulnerator_mcp_server.py:350` |
| `stop_run` | `docker/mcp/vulnerator_mcp_server.py:373` |
| `health` | `docker/mcp/vulnerator_mcp_server.py:393` |

Las tools de `playwright-mcp` no viven en este repo: las expone la imagen externa
`mcr.microsoft.com/playwright/mcp` (`docker-compose.yml:298`), registrada como el server
`playwright` (`agent-ooda/profile/config.yaml:122`).

## 12. Anexo B — servicios y volúmenes

Formato: `| clave | docker-compose.yml:línea |`. Fuente: `docker-compose.yml` parseado.

### 12.1 Servicios (9)

| Servicio | Fichero:línea |
| --- | --- |
| `kali` | `docker-compose.yml:25` |
| `ooda-agent` | `docker-compose.yml:120` |
| `playwright-mcp` | `docker-compose.yml:291` |
| `vulnerator-mcp` | `docker-compose.yml:334` |
| `vulnerator-web` | `docker-compose.yml:397` |
| `browser-view` | `docker-compose.yml:492` |
| `caido-director` | `docker-compose.yml:535` |
| `caido-init` | `docker-compose.yml:571` |
| `caido` | `docker-compose.yml:585` |

### 12.2 Volúmenes (4)

| Volumen | Fichero:línea |
| --- | --- |
| `hermes-data` | `docker-compose.yml:668` |
| `kali-artifacts` | `docker-compose.yml:671` |
| `caido-data` | `docker-compose.yml:673` |
| `vulnerator-web-data` | `docker-compose.yml:675` |

## 13. Anexo C — Tests y verificación

Seis suites: las 5 originales más `scripts/tests`.

| # | Suite | Tipo | Referencia |
| --- | --- | --- | --- |
| 1 | `agent-ooda/tests` | declarativos (config.yaml + compose) | `agent-ooda/tests/test_profile_kali_direct.py:1` |
| 2 | `docker/kali/tests` | runtime kali-mcp | `docker/kali/tests/test_tool_streaming.py:1` |
| 3 | `docker/mcp/tests` | front door sobre :8642 | `docker/mcp/tests/test_server_tools.py:1` |
| 4 | `docker/web/tests` | consola web | `docker/web/tests/test_ingest_app.py:1` |
| 5 | `docker/browser-view/tests` | proxy CDP / reset | `docker/browser-view/tests/test_cdp_proxy.py:1` |
| 6 | `scripts/tests` | andamiaje (regla anti-parche y tests del humo) | `scripts/tests/` |

Comando del smoke (`scripts/smoke.py:1`):

```sh
env -u PYTHONPATH python3 scripts/smoke.py --static   # contratos + tools AST + anexos + imports
env -u PYTHONPATH python3 scripts/smoke.py --tests    # las 6 suites en subproceso
env -u PYTHONPATH python3 scripts/smoke.py --quick    # estatico + tests
env -u PYTHONPATH python3 scripts/smoke.py --check     # alias de --static
bash scripts/run_tests.sh                             # runner shell de las 6 suites
```

- El gate bloqueante es `🧱 Base scaffolding` (`.github/workflows/ci.yml:1`): corre
  `--static`, `docker compose config --quiet`, `scripts/check_quick_fix_comments.py --all`,
  type-check (mypy) y `--quick` (las 6 suites).
- El exit code del smoke es no-cero si **cualquier** suite falla.

## 14. Deuda conocida

- Reformateo pendiente: `black` (55 ficheros), `isort` (13) y `prettier` (46) para el
  `chore(style)`; no cambian comportamiento.
- `ruff` con `B/UP/SIM/RUF` queda como asesora no bloqueante (`pyproject.toml:10`);
  el gate bloqueante solo selecciona correctitud (`E9/F63/F7/F82/F401/F811/F821`).
- `hadolint` exige Docker y no corre en el gate estático.
- `pytest` desde la raíz sin `--import-mode=importlib` rompe (9 errores de colección
  por colisión de los paquetes `tests` de los cuatro módulos); el gate ejecuta las 6
  suites por separado, que es la vía soportada. Es deuda pre-existente de `master`, no
  de este andamiaje.
- `detect-secrets` no escanea `.env.example` (y el hook lo excluye): si se volcara un
  secreto real ahí, pasaría.
