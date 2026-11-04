# Prompt Injection Test Bench

A small, reproducible tool that measures how vulnerable a simple LLM app is to prompt
injection, and how much cheap defenses help without breaking normal use. It is the shared
test harness for two class proposals:

- **CYB 240:** Which attack categories succeed, how does the delivery channel change the
  outcome, and how much do low-cost defenses help and cost? (Defenses D0 to D4.)
- **CYB 220:** Can ideas from cryptography protect an LLM app, and how do they compare with
  those simple defenses? (Adds defenses D5 to D7.)

The only target is **MailMate**, a toy summarizer/email assistant in this repo whose system
prompt holds a **fake** secret (`CANARY-7f3a91`). Everything runs locally against Ollama.
There is no telemetry, and no code points at any other app or service.

**New here?** [docs/guide.md](docs/guide.md) is a hands-on walkthrough: the sandbox, attacking a
model by hand with `play.py`, running experiments, reading results, and changing things.

**Want the results?** [docs/results_explained.md](docs/results_explained.md) explains what the full run
found, for a cybersecurity student.

## How it works

1. **36 fixed attacks** (`attacks/*.yaml`) in 5 categories try to make MailMate leak the canary or
   print the marker `PWNED-4471`, through the user message or hidden inside the document.
2. **17 benign tasks** (`data/benign_tasks.yaml`) measure whether the app still does its job. The
   config locks both sets by fingerprint, so a run refuses to start if they change.
3. Each input runs under **8 defense settings** (below), each for several **trials** (default 5,
   temperature 0.7, seeds `base_seed + trial`).
4. **Scoring** is deterministic keyword matching (no LLM judge). Rates come with 95% Wilson
   intervals, and two rates only count as different if their intervals don't overlap.
5. One **report per proposal** (`results/full/report_cyb240.md`, `report_cyb220.md`) has tables,
   heatmaps, findings and limitations.

| Defense | What it does | Proposal |
|---|---|---|
| D0 | Nothing | CYB 240 baseline |
| D1 | Regex input filter | CYB 240 baseline |
| D2 | Delimiters plus a hardened system prompt | CYB 240 baseline |
| D3 | Output filter for the canary and marker | CYB 240 baseline |
| D4 | D1 + D2 + D3 | CYB 240 baseline |
| D5 | Nonce-authenticated delimiters: D2's rules, a new unpredictable tag per request, and forged tags or chat-template markers in the document are escaped | CYB 220 |
| D6 | Secret indirection: the model only sees a useless placeholder. A reply containing it is recorded as a would-be leak | CYB 220 |
| D7 | Keyed-hash output check: decodes base64, rot13, reversed and spaced text, then compares by HMAC, so the check doesn't need the plain secret | CYB 220 |

## Install (Windows)

1. **Python 3.11 or newer** from https://www.python.org/downloads/ (tick *Add python.exe to PATH*).
2. **Git** from https://git-scm.com/download/win, and sign in to GitHub so you can reach the
   private repo. GitHub CLI's `gh auth login` is the easiest way.
3. **Ollama** from https://ollama.com/download. It runs in the background and serves
   `http://localhost:11434`. Then get the model:

   ```bash
   ollama pull llama3.2
   ```

   Optional, for the larger comparison model:

   ```bash
   ollama pull llama3.1:8b
   ```

4. **The project:**

   ```bash
   git clone https://github.com/FlameDevil1/Injection-bench
   ```

   ```bash
   cd Injection-bench
   ```

   ```bash
   py -m venv .venv
   ```

   ```bash
   .venv\Scripts\python -m pip install -r requirements.txt
   ```

   The commands below call `.venv\Scripts\python` directly, so you don't need to activate the venv.

## Check a computer

Before running anything real, check the computer. This reports its hardware, the code version, the
corpus fingerprint and the exact model build, then times a real model call and shows how much of the
model is on the GPU.

```bash
.venv\Scripts\python -m bench.doctor --config config.yaml
```

## Run the tests

No model or network needed; tests use the scripted `MockProvider`.

```bash
.venv\Scripts\python -m pytest
```

## Mock run (seconds)

Runs the whole pipeline with two simulated models and writes reports to `results/mock/`. The numbers
are **simulated** and say nothing about real models.

```bash
.venv\Scripts\python -m bench.run --config config.mock.yaml
```

## Small real run

One trial per case on `llama3.2`, 212 model calls. On a laptop with a working GPU that took under
5 minutes. `--dry-run` shows the plan without calling anything, and `--max-calls 10` makes it
a quick smoke test.

```bash
.venv\Scripts\python -m bench.run --config config.small.yaml --dry-run
```

```bash
.venv\Scripts\python -m bench.run --config config.small.yaml
```

## The real run

`config.yaml` runs all 8 defenses for 5 trials on `llama3.2` and on the larger `llama3.1:8b`, with the
same settings so they're compared fairly. A model that isn't pulled is skipped with a message. `llama3.2` needs about 1,060 model calls,
about 20 minutes at the 1.1 seconds per call we measured on a laptop GPU. A CPU would be far slower, and
`bench.doctor` shows which one you have.

```bash
.venv\Scripts\python -m bench.run --config config.yaml
```

- **Ctrl+C is safe.** Every finished trial is already on disk. Run the same command again to resume.
- Failed calls (timeouts, Ollama restarts) are recorded and retried on the next run. After
  `max_consecutive_errors` failures in a row the bench moves on to the next model.
- Keep the computer plugged in and set Windows *Sleep* to *Never*. Sleep pauses the run.
- Rebuild the reports at any time, even mid-run from another terminal:

  ```bash
  .venv\Scripts\python -m bench.report --config config.yaml
  ```

## Running on other computers

Every computer runs the whole experiment itself, from the same repo, and its results stay separate.

- **One primary computer per model.** `run.primary_machine` in `config.yaml` names the computer whose results
  the papers use, and a model can name its own. The others appear only in a **Hardware comparison** section,
  never pooled in.
- **Results are labelled.** Each computer writes to `results/full/<computer name>/`, with a `manifest.json`
  recording its hardware, Ollama version, exact model build and code version. The computer name is its
  hostname unless you pass `--machine NAME` or set `BENCH_MACHINE`. Use the same name every time.
- **The experiment can't drift.** Seeds, trials, temperature and token limits are shared, and the config's
  `machines:` section can only change timeouts, time estimates, the Ollama address and which models to skip.
  A different model build is rejected. If something that matters changes partway through, the run stops
  rather than mixing two experiments.
- **Caches are never shared**, so a computer can't pass off another computer's replies as its own.

On each computer:

```bash
git pull
```

```bash
.venv\Scripts\python -m bench.doctor --config config.yaml
```

```bash
.venv\Scripts\python -m bench.run --config config.yaml
```

Then share its results. Each computer only touches its own folder, so these never conflict:

```bash
git add results/full
```

```bash
git commit -m "Add results from this computer"
```

```bash
git pull --rebase
```

```bash
git push
```

Once all computers have pushed, anyone can run `git pull` and `bench.report` to build the reports.

### Running the larger model

`llama3.1:8b` is a 4.9 GB download, so run it on a computer whose GPU has about 8 GB of memory or more. Pull it
there, then follow the steps above. `bench.doctor` shows the computer's name and whether the model is fully on
the GPU.

```bash
ollama pull llama3.1:8b
```

That computer also runs `llama3.2`, so the report can compare the two models on one computer, with hardware out
of the picture. To tell the papers which computer to use for the larger model, add `primary_machine` to its entry in
`config.yaml`. Until you do, the report uses whichever computer has the most results for it and shows a warning.

## Outputs

| File | Contents |
|---|---|
| `results/full/<computer>/<model>.jsonl` | One row per trial: computer, case id, category, channel, goal, defense, trial, seed, model, response, success, would_be_leak, blocked_by, error, cached, elapsed seconds. |
| `results/full/<computer>/manifest.json` | What produced those results. |
| `results/full/report_cyb240.md`, `report_cyb220.md` | Scope, method, models, per-model tables and findings, comparisons, limitations. |
| `results/full/heatmap_<report>_<model>.png` | Attack success by category and defense. |
| `results/full/summary.csv` | Successes, trials, rate and interval for every computer/model/category/defense. |
| `results/full/marker_spot_check.csv` | Every marker hit and whether it counted as obeyed, for checking by hand. |

Raw rows and manifests in `results/full/` are committed. Reports, charts and practice runs are rebuilt, so
they're git-ignored, as is the cache in `.cache/<computer>/`. Because D1, D3 and D7 send the same prompt as
D0, and D4 the same as D2, they reuse those replies. That makes them nearly free and makes the comparisons
paired.

## Project layout

| File | Job |
|---|---|
| `bench/config.py` | Loads and validates the YAML config, and applies per-computer settings. |
| `bench/provider.py` | Model interface: Ollama, Mock, and the disk cache. |
| `bench/app.py` | The toy target app (MailMate): system prompt, prompt assembly, benign task loader. |
| `bench/corpus.py` | Loads and validates `attacks/*.yaml`. |
| `bench/scoring.py` | Deterministic success detection, the two extra measures, and Wilson intervals. |
| `bench/defenses.py` | D0 to D7 as small input/prompt/output functions and a registry. |
| `bench/provenance.py` | Fingerprints the corpus and prompts, and keeps each computer's manifest. |
| `bench/doctor.py` | Checks a computer is ready to run. |
| `bench/run.py` | CLI runner: grid, resume, limits, progress/ETA, error handling. |
| `bench/report.py` | Tables, heatmaps, findings, hardware comparison, the reports. |
| `play.py` | Playground: send one attack or your own text through each defense and see every step. |
| `docs/guide.md` | Hands-on guide to using and extending the bench. |
| `docs/results_explained.md` | What the full run found, explained in plain terms. |
| `docs/threat_model.md` | Assets, attacker, goals, scope, metrics. |
| `docs/roadmap.md` | Out-of-scope future extensions and where they'd plug in. |

## Assumptions and limitations

- **Small local models.** Results may not transfer to larger or differently trained models.
- **Small, hand-written, static corpus.** Attacks don't adapt to defenses, so real attackers would do better.
- **Keyword scoring.** It misses partial or paraphrased leaks. The main marker score also counts a refusal
  that quotes the marker, which is why the reports show a stricter column beside it.
- **Delivery channel is tied to attack type.** Direct override only arrives by user message and indirect
  only by document, so only delimiter confusion gives a fair channel comparison.
- **Output filters are scored by the same checks they use**, so D3's near-zero attack success is an upper bound.
- **D6 and D7 can only affect the 17 attacks that try to leak the secret.** D6's zero real leaks hold by design,
  so read its would-be leak rate instead.
- **The fixed corpus can't exercise everything.** No attack can contain a D5 tag it has never seen, and no attack
  asks for a rot13 leak, so those paths are covered by unit tests only.
- **D5's tag is derived from a lab key** so runs repeat. A real app would use a fresh random value per request
  and keep its key out of the code.
- **D1 was written with this corpus in view**, so its catch rate is optimistic.
- **Seeds don't guarantee identical text.** On a GPU, the same seed mostly but not always gave the same reply
  when we tested it, even on one computer. The saved replies are the record of the experiment.
- **Mock results are simulated** and only demonstrate the pipeline.
