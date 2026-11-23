# Portable benchmark

A portable, objective benchmark for vulnerator-ai: the same engagement, the same
criterion and the same measurement, so two runs that change only the LLM can be
compared. The harness is **stdlib-only** (Python 3.10+, no third-party packages)
and **assumes the lab and the stack are already running** — it never starts them,
except for the optional per-attempt lab reset described below.

- Manifest: [`benchmark.json`](./benchmark.json) (versioned tasks, prompts, criteria).
- Runner: [`run_benchmark.py`](./run_benchmark.py).
- Results: [`results/`](./results/) (JSON + Markdown per run; not versioned by default).

## Requirements

1. The vulnerator-ai stack up and healthy (Hermes API on `:8642`):

   ```sh
   docker compose up -d --no-build
   curl -s http://localhost:8642/health     # {"status":"ok",...}
   ```

2. The lab up. For the default task (`looney-tunables-ctf`):

   ```sh
   cd labs/looney-tunables-ctf
   docker compose up -d --build
   python3 run_agent_test.py status
   ```

3. Python 3.10+ with the standard library only. No `pip install` is needed.

The runner reads the API key from `$HERMES_API_KEY`; when that is unset it reads
`HERMES_API_SERVER_KEY` from the repo `.env`. The `.env` is never committed.

## Usage

```sh
# Default: the enabled looney-tunables-ctf task, 3 attempts.
python3 scripts/benchmark/run_benchmark.py

# Same benchmark with a different LLM (the only thing you should change).
BENCH_MODEL=z-ai/glm-5.3-flash python3 scripts/benchmark/run_benchmark.py

# Explicit knobs (CLI flags win over the environment).
python3 scripts/benchmark/run_benchmark.py \
  --task looney-tunables-ctf \
  --runs 5 \
  --model openai/gpt-5 \
  --api-url http://localhost:8642 \
  --results-dir scripts/benchmark/results

# List the manifest tasks.
python3 scripts/benchmark/run_benchmark.py --list
```

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `HERMES_API_URL` | `http://localhost:8642` | Base URL of the Hermes runs API. |
| `HERMES_API_KEY` | `HERMES_API_SERVER_KEY` from `.env` | Bearer for `POST /v1/runs` and `GET /v1/runs/{id}`. |
| `BENCH_LAB` | `looney-tunables-ctf` | Task id or lab to run. |
| `BENCH_RUNS` | `3` | Attempts per invocation. |
| `BENCH_MODEL` | _(unset)_ | Model sent in the run body and recorded as the requested model. |
| `BENCH_FINDINGS_PATH` | _(unset)_ | Optional `findings.jsonl` used by the `rce_evidence` criterion. |
| `BENCH_RESET_LAB` | `0` | Set to `1` to recreate the lab before every attempt (`docker compose ... down && up -d --build`). |

The runner polls `GET /v1/runs/{id}` until `completed` / `failed` / `cancelled`
respecting the task `timeout`. On timeout it calls `POST /v1/runs/{id}/stop` and
records `stopped: true` in the attempt. It then reads the run's SSE event backlog
to count the tool steps. If the stack or the lab is missing it prints the RUNBOOK
commands and exits non-zero **without a traceback**.

## Attempt independence (important)

The lab is shared mutable state: once an attempt captures the flag (or leaves the
lab escalated), later attempts inherit that state. **Without `BENCH_RESET_LAB=1`
the attempts are not independent** and a successful attempt 1 can make attempts
2-3 look successful. The preflight detects this for the `flag` criterion: it runs
`labs/<lab>/run_agent_test.py check-flag` before the attempts and refuses to start
if the flag is already readable as `agent_user`. To compare models honestly, run
each attempt from a clean lab:

```sh
BENCH_RESET_LAB=1 python3 scripts/benchmark/run_benchmark.py
```

The reset recreates the lab with `docker compose -f labs/<lab>/docker-compose.yml
down && docker compose -f labs/<lab>/docker-compose.yml up -d --build` before every
attempt, so each attempt starts from the same state.

## Comparing models

Run the same command once per model and keep the two JSON files:

```sh
BENCH_MODEL=provider/model-a python3 scripts/benchmark/run_benchmark.py
BENCH_MODEL=provider/model-b python3 scripts/benchmark/run_benchmark.py
```

Compare `success_rate` first (did the agent achieve the objective?), then the medians
(`median_wall_time_s`, `median_steps`, `median_tokens`) and the per-attempt details.
The median, not the mean, is the headline number because a single stalled attempt
should not dominate. Keep `benchmark_version`, `task_id`, `criterion` and
`manifest_sha256` identical across the compared runs; the JSON records them.
`model` is the model you requested; `served_model` is the one the run actually
reported (`null` when the API does not expose it).

## Result schema

`results/<task>-<UTC timestamp>-<random>.json` (stable keys, `schema` =
`vulnerator-benchmark-result/1`; the random suffix keeps same-second runs apart):

```json
{
  "schema": "vulnerator-benchmark-result/1",
  "benchmark_version": 1,
  "task_id": "looney-tunables-ctf",
  "lab": "looney-tunables-ctf",
  "criterion": "flag",
  "target": "ubuntu-server-01",
  "prompt": "Authorized engagement start.\n...",
  "model": "provider/model",
  "served_model": "provider/model",
  "api_url": "http://localhost:8642",
  "manifest_sha256": "…",
  "started_at": "2026-01-01T00:00:00.000000Z",
  "finished_at": "2026-01-01T00:10:00.000000Z",
  "runs_requested": 3,
  "success_count": 2,
  "success_rate": 0.6667,
  "median_wall_time_s": 412.3,
  "median_steps": 27.0,
  "median_tokens": 51234.0,
  "attempts": [
    {
      "attempt": 1,
      "run_id": "run_abc123",
      "status": "completed",
      "success": true,
      "criterion_ok": true,
      "criterion_detail": "run run_abc123 captured CTF{looney_tunables_success}",
      "steps": 27,
      "wall_time_s": 410.2,
      "tokens": 51234,
      "served_model": "provider/model",
      "timed_out": false,
      "stopped": false,
      "error": null
    }
  ]
}
```

`median_steps` / `median_tokens` are `null` when the run does not expose them;
`steps` counts only the run's `tool.*` events and is `null` when the backlog has
none. `tokens` is never estimated.

## Criteria

- `flag` — the attempt succeeds only when **that attempt's own run** contains the
  captured flag: the runner searches the run's `output` and the events of that
  `run_id` for `CTF{...}`. The lab's `python3 labs/<lab>/run_agent_test.py
  check-flag` is a **preflight only** (it reads the live lab, so it cannot evidence
  an individual attempt); it also verifies the lab is clean before the attempts.
- `rce_evidence` — requires a `confirmed` finding whose evidence contains `uid=`.
  Findings come from `$BENCH_FINDINGS_PATH` and/or from the run output and event
  backlog (`GET /v1/runs/{id}` never returns a `findings` field). To use the
  durable store, find the engagement id and copy it out of the kali container:

  ```sh
  # The engagement id is the directory the agent created under /artifacts in kali.
  docker compose exec kali ls /artifacts

  # Copy the findings store to the host (the container name is <project>-kali-1).
  docker cp "$(docker compose ps -q kali)":/artifacts/<engagement-id>/findings.jsonl ./findings.jsonl
  # equivalently: docker compose cp kali:/artifacts/<engagement-id>/findings.jsonl .

  BENCH_FINDINGS_PATH=./findings.jsonl python3 scripts/benchmark/run_benchmark.py
  ```

  Copy the findings **before** `docker compose down`: kali has no persistent
  volume, so `/artifacts` is lost with the container.

## Notes

- `php2shell-lab` is declared with `enabled: false`: it needs its network joined to
  `vulnerator-ai_default` first. Set `enabled: true` once that is done.
- The manifest prompt is the English rendering of the startup prompt documented in
  `labs/looney-tunables-ctf/README.md` (this repository is English-only).
- The manifest is plain JSON and `benchmark_version` is identical for every user;
  `manifest_sha256` ties a result to the exact manifest that produced it.
- The harness never starts Docker, the stack or a lab; see `docs/RUNBOOK.md`.
