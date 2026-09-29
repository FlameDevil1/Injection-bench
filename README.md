# Prompt Injection Test Bench

A small, reproducible tool that measures how vulnerable a simple LLM app is to prompt
injection, and how much cheap defenses help without breaking normal use.

**Research question:** Which prompt injection techniques succeed against a simple LLM app,
and which cheap defenses reduce success without breaking normal use?

The only target is **MailMate**, a toy summarizer/email assistant in this repo whose system
prompt holds a **fake** secret (`CANARY-7f3a91`). Everything runs locally against Ollama by
default. There is no telemetry, and no code points at any other app or service.

**New here?** [docs/guide.md](docs/guide.md) is a hands-on walkthrough: the sandbox, attacking a
model by hand with `play.py`, running experiments, reading results, and changing things.

## How it works

1. **36 attacks** (`attacks/*.yaml`) in 5 categories try to make MailMate leak the canary or print
   the marker `PWNED-4471`, through the user message or hidden inside the document.
2. **17 benign tasks** (`data/benign_tasks.yaml`) measure whether the app still does its job.
3. Each input runs under **5 defense settings**: D0 none, D1 regex input filter, D2 delimiters plus a
   hardened system prompt, D3 output filter, D4 all combined. Each (input, defense) pair runs
   several **trials** (default 5, temperature 0.7, seeds `base_seed + trial`).
4. **Scoring** is deterministic keyword matching (no LLM judge). Rates come with 95% Wilson intervals.
5. The **report** (`results/<run>/report.md`) has tables, heatmaps, findings and limitations.

## Install (Windows)

1. **Python 3.11 or newer.** Install from https://www.python.org/downloads/ (tick *Add python.exe to
   PATH*) or run `winget install Python.Python.3.12`. Check it in a new terminal:

   ```bash
   py --version
   ```

2. **Ollama.** Download the Windows installer from https://ollama.com/download and run it. Ollama
   then runs in the background (tray icon) and serves `http://localhost:11434`. Get the model:

   ```bash
   ollama pull llama3.2
   ```

   Optional, for the second model in `config.yaml` (about 5 GB; fine with 16 GB RAM, but slow on CPU):

   ```bash
   ollama pull llama3.1:8b
   ```

3. **Project environment**, from the project folder:

   ```bash
   py -m venv .venv
   ```

   ```bash
   .venv\Scripts\python -m pip install -r requirements.txt
   ```

   The commands below call `.venv\Scripts\python` directly, so you don't need to activate
   the venv (activation in PowerShell can be blocked by the script execution policy).

## Run the tests

No model or network needed; tests use the scripted `MockProvider`.

```bash
.venv\Scripts\python -m pytest
```

## Mock run (seconds)

Runs the whole pipeline with two simulated models and writes a report to `results/mock/`.
The numbers are **simulated** and say nothing about real models.

```bash
.venv\Scripts\python -m bench.run --config config.mock.yaml
```

## Small real run (30 to 60 minutes)

One trial per case on `llama3.2`. Check the plan first. `--dry-run` calls nothing:

```bash
.venv\Scripts\python -m bench.run --config config.small.yaml --dry-run
```

A 5-minute smoke test (stops after 10 model calls; the same command without the flag continues from there):

```bash
.venv\Scripts\python -m bench.run --config config.small.yaml --max-calls 10
```

The full small run:

```bash
.venv\Scripts\python -m bench.run --config config.small.yaml
```

## Long overnight run (about 9 hours)

`config.yaml` runs the full grid on `llama3.2` (5 trials) and a reduced grid on `llama3.1:8b`
(3 trials, shorter answers). A model that isn't pulled is skipped with a message.

```bash
.venv\Scripts\python -m bench.run --config config.yaml --dry-run
```

```bash
.venv\Scripts\python -m bench.run --config config.yaml
```

Tips for a long run on a laptop:

- Plug it in and set Windows *Sleep* to *Never* while plugged in. Sleep pauses the run.
- **Ctrl+C is safe.** Every finished trial is already on disk. Run the same command again to resume;
  finished trials are skipped and cached responses are reused.
- Failed calls (timeouts, Ollama restarts) are recorded and retried on the next run. After
  `max_consecutive_errors` failures in a row the bench moves on to the next model.
- `--max-calls N` or `run.max_calls` in the config caps real model calls for a session.
- Rebuild the report at any time, even mid-run from another terminal:

  ```bash
  .venv\Scripts\python -m bench.report --config config.yaml
  ```

## Outputs

Each config writes to its own `results_dir` (for example `results/full/`):

| File | Contents |
|---|---|
| `<model>.jsonl` | One row per trial: case id, category, channel, goal, defense, trial, seed, model, response, success, blocked_by, error, cached, elapsed seconds. |
| `report.md` | Scope, method, models, per-model tables and findings, model comparison, limitations. |
| `heatmap_<model>.png` | Attack success by category and defense. |
| `summary.csv` | Successes, trials, rate and interval for every model/category/defense. |
| `run.log` | Warnings and errors from the run. |

Responses are cached in `.cache/responses.jsonl`, keyed by a hash of (provider, model, system,
user, temperature, seed, max_tokens). Because D1 and D3 send the same prompt as D0, and D4 the
same as D2, they reuse those responses. That makes them nearly free and makes the comparisons paired.
`results/` and `.cache/` are git-ignored.

## Configuration

All numbers, paths and model names live in the YAML config: trials, temperature, seeds,
`max_tokens` (Ollama `num_predict`), `timeout_seconds`, which defenses to run, and per-model
overrides. See the comments in `config.yaml`.

The optional **Anthropic** entry is `enabled: false`. It never runs unless you set it to `true`,
and then it reads the key from the `ANTHROPIC_API_KEY` environment variable. It costs money, and the
API ignores seeds.

## Project layout

| File | Job |
|---|---|
| `bench/config.py` | Loads and validates the YAML config. |
| `bench/provider.py` | Model interface: Ollama, Mock, optional Anthropic, and the disk cache. |
| `bench/app.py` | The toy target app (MailMate): system prompt, prompt assembly, benign task loader. |
| `bench/corpus.py` | Loads and validates `attacks/*.yaml`. |
| `bench/scoring.py` | Deterministic success detection and Wilson intervals. |
| `bench/defenses.py` | D0 to D4 as small input/prompt/output functions and a registry. |
| `bench/run.py` | CLI runner: grid, resume, limits, progress/ETA, error handling. |
| `bench/report.py` | Tables, heatmaps, findings, `report.md`. |
| `play.py` | Playground: send one attack or your own text through each defense and see every step. |
| `docs/guide.md` | Hands-on guide to using and extending the bench. |
| `docs/threat_model.md` | Assets, attacker, goals, scope, metrics. |
| `docs/roadmap.md` | Future extensions and where they plug in. |

To add an attack, add an entry to any `attacks/*.yaml`. To add a defense, write one function in
`bench/defenses.py` and register it in `DEFENSES`.

## Assumptions and limitations

- **Small local models** (3B and 8B). Results may not transfer to larger or differently trained models.
- **Small, hand-written, static corpus.** Attacks don't adapt to defenses, so real attackers would do better.
- **Keyword scoring.** It misses partial or paraphrased leaks, and it counts a marker quoted while refusing
  as a success. Benign success only needs one keyword.
- **D3 uses the scorer's own detector**, so its near-zero attack success is an upper bound.
- **D1 was written with this corpus in view**, so its catch rate is optimistic.
- **Seeds** make runs repeatable on one machine and Ollama version, not across them.
- **Mock results are simulated** and only demonstrate the pipeline.
