# Portable benchmark

A portable, objective benchmark for vulnerator-ai: the same engagement, the same
criterion and the same measurement, so two runs that change only the LLM can be
compared. The harness is **stdlib-only** (Python 3.10+, no third-party packages)
and **assumes the lab and the stack are already running** — it never starts them.

- Manifest: [`benchmark.yaml`](./benchmark.yaml) (versioned tasks, prompts, criteria).
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
| `BENCH_MODEL` | _(unset)_ | Model sent in the run body and recorded in the result. |
| `BENCH_FINDINGS_PATH` | _(unset)_ | Optional `findings.jsonl` used by the `rce_evidence` criterion. |

The runner polls `GET /v1/runs/{id}` until `completed` / `failed` / `cancelled`
respecting the task `timeout`, then reads the run's SSE event backlog to count the
tool steps. If the stack or the lab is missing it prints the RUNBOOK commands and
exits non-zero **without a traceback**.

## Comparing models

Run the same command once per model and keep the two JSON files:

```sh
BENCH_MODEL=provider/model-a python3 scripts/benchmark/run_benchmark.py
BENCH_MODEL=provider/model-b python3 scripts/benchmark/run_benchmark.py
```

Compare `success_rate` first (did the agent achieve the objective?), then the medians
(`median_wall_time_s`, `median_steps`, `median_tokens`) and the per-attempt details.
The median, not the mean, is the headline number because a single stalled attempt
should not dominate. Keep `benchmark_version`, `task_id` and `criterion` identical
across the compared runs; the JSON records them.

## Result schema

`results/<task>-<UTC timestamp>.json` (stable keys, `schema` =
`vulnerator-benchmark-result/1`):

```json
{
  "schema": "vulnerator-benchmark-result/1",
  "benchmark_version": 1,
  "task_id": "looney-tunables-ctf",
  "lab": "looney-tunables-ctf",
  "criterion": "flag",
  "target": "ubuntu-server-01",
  "model": "provider/model",
  "api_url": "http://localhost:8642",
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
      "criterion_detail": "[CAPTURED] CTF{looney_tunables_success}",
      "steps": 27,
      "wall_time_s": 410.2,
      "tokens": 51234,
      "timed_out": false,
      "error": null
    }
  ]
}
```

`median_steps` / `median_tokens` are `null` when the API does not expose them.
`tokens` is `null` for the same reason; it is never estimated.

## Criteria

- `flag` — runs `python3 labs/looney-tunables-ctf/run_agent_test.py check-flag`
  and requires exit code 0 and a `CTF{...}` in the output (the agent read
  `/root/flag.txt` as `agent_user`, i.e. it escalated to root).
- `rce_evidence` — requires a `confirmed` finding whose evidence contains `uid=`.
  Findings are read from the run payload and/or from `$BENCH_FINDINGS_PATH`.

## Notes

- `php2shell-lab` is declared with `enabled: false`: it needs its network joined to
  `vulnerator-ai_default` first. Set `enabled: true` once that is done.
- The manifest prompt is the English rendering of the startup prompt documented in
  `labs/looney-tunables-ctf/README.md` (this repository is English-only).
- The harness never starts Docker, the stack or a lab; see `docs/RUNBOOK.md`.
