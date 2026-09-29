# Roadmap

Future extensions, and where each would plug into the code. None of these are built yet.

| Extension | What it adds | Where it plugs in |
|---|---|---|
| **RAG poisoning** | Attacks inside retrieved passages instead of one attached document; measure how poisoned passage rank and count affect success. | `bench/app.py`: add `Source("retrieved_passage", ...)` entries in `make_input` / `attack_input` (`build_prompt` already renders any source kind). New channel `retrieved` in `bench/corpus.py` `CHANNELS`. D2 already wraps every source. |
| **Tool-using agents** | The model can call fake tools (send_email, read_file); success means an unwanted tool call, not just text. | `bench/app.py`: tool results become `Source("tool_output", ...)`; a small loop that parses tool calls. New goal `unauthorized_tool_call` in `bench/corpus.py` `GOALS` and `bench/scoring.py` `attack_succeeded`. |
| **Guard models** | A second small model classifies input or output as injection/leak. | `bench/defenses.py`: one new input filter or output filter function that calls a `Provider`, registered as e.g. `D5` in `DEFENSES`. Its calls go through the same cache. |
| **Adaptive, LLM-generated attacks** | An attacker model rewrites failed payloads and retries, which is closer to a real attacker. | A new module (e.g. `bench/adaptive.py`) that reads failed rows from the results JSONL, asks an attacker `Provider` for variants, and writes new cases to `attacks/generated.yaml`. The corpus loader picks them up unchanged. |
| **More models** | Other local models (Qwen, Mistral, Phi, Gemma) or hosted ones. | `config.yaml`: add an entry under `models`. A new API needs one `Provider` subclass in `bench/provider.py` and a branch in `make_provider`. The report's comparison section handles any number of models. |
| **Better scoring** | Catch partial leaks and separate "quoted the marker while refusing" from "obeyed". | `bench/scoring.py`: extra detectors. An optional LLM judge would be a new function whose results are stored in a separate field, so deterministic scores stay comparable. |
