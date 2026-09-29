# Tests for bench/report.py: tables, dedupe/error handling, and the generated files.
import json

from bench.config import load_config
from bench.report import fmt, load_results, md_table, write_report
from bench.run import main
from tests.conftest import base_config, write_config


def row(**over):
    r = {"model": "m", "model_id": "m", "provider": "mock", "kind": "attack", "case_id": "DO01",
         "category": "direct_override", "channel": "user_message", "goal": "output_marker", "defense": "D0",
         "trial": 0, "seed": 1000, "temperature": 0.7, "max_tokens": 50, "response": "x", "success": True,
         "blocked_by": None, "error": None}
    r.update(over)
    return r


def test_fmt_and_md_table():
    assert fmt(3, 10) == "30% [11%, 60%] (3/10)"
    assert fmt(0, 0) == "-"
    assert md_table(["a", "b"], [[1, 2]]) == "| a | b |\n|---|---|\n| 1 | 2 |"


def test_load_results_dedupes_and_tracks_unresolved_errors(tmp_path):
    lines = [row(success=None, error="timeout"), row(success=False), row(success=True),  # retried; last wins
             row(case_id="DO02", success=None, error="timeout")]                     # never resolved
    text = "\n".join(json.dumps(r) for r in lines) + "\n{broken"
    (tmp_path / "m.jsonl").write_text(text, encoding="utf-8")
    ok, errors = load_results(tmp_path)
    assert len(ok) == 1 and bool(ok.iloc[0]["success"]) is True
    assert list(errors["case_id"]) == ["DO02"]


def test_report_from_mock_run_with_two_models(tmp_path):
    data = base_config(tmp_path)
    data["defaults"]["defenses"] = ["D0", "D1", "D2", "D3", "D4"]
    data["models"].append({"name": "mock2", "provider": "mock", "model": "mock2", "trials": 1,
                           "options": {"compliance": 0.1}})
    path = write_config(tmp_path, data)
    assert main(["--config", str(path)]) == 0
    out = tmp_path / "results"
    report = (out / "report.md").read_text(encoding="utf-8")
    for heading in ("## Scope", "## Method", "## Models", "## Results: mock", "## Results: mock2",
                    "## Model comparison", "### Findings", "## Limitations", "Simulated data"):
        assert heading in report
    assert (out / "heatmap_mock.png").stat().st_size > 1000
    assert (out / "summary.csv").exists()
    findings = report.split("### Findings")[1].split("##")[0]
    assert 3 <= findings.count("**") // 2 <= 5


def test_report_with_no_results(tmp_path):
    cfg = load_config(write_config(tmp_path, base_config(tmp_path)))
    text = write_report(cfg).read_text(encoding="utf-8")
    assert "No results yet" in text and "## Limitations" in text
