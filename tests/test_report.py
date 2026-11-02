# Tests for bench/report.py: tables, dedupe/error handling, and the generated files.
import json

import pandas as pd

from bench.config import load_config
from bench.report import fmt, load_results, md_table, versus, write_report
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
    (tmp_path / "box").mkdir()
    (tmp_path / "box" / "m.jsonl").write_text(text, encoding="utf-8")
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
    text = write_report(cfg)[0].read_text(encoding="utf-8")
    assert "No results yet" in text and "## Limitations" in text


def _report_config(tmp_path):
    data = base_config(tmp_path)
    data["defaults"]["defenses"] = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"]
    data["models"][0]["options"] = {"compliance": 0.7}
    data["run"]["primary_machine"] = "laptop"
    data["reports"] = [
        {"name": "cyb240", "title": "CYB 240", "defenses": ["D0", "D1", "D2", "D3", "D4"]},
        {"name": "cyb220", "title": "CYB 220", "defenses": ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"],
         "new_defenses": ["D5", "D6", "D7"]},
    ]
    return write_config(tmp_path, data)


def test_one_report_per_paper_with_only_its_defenses(tmp_path):
    path = _report_config(tmp_path)
    assert main(["--config", str(path), "--machine", "laptop"]) == 0
    out = tmp_path / "results"
    r240 = (out / "report_cyb240.md").read_text(encoding="utf-8")
    r220 = (out / "report_cyb220.md").read_text(encoding="utf-8")
    assert "D5" not in r240 and "D7" not in r240 and "New defenses against the baseline" not in r240
    for needed in ("New defenses against the baseline", "Would-be leaks", "vs D4", "Cryptography protects"):
        assert needed in r220
    for section in ("Attack success by attacker goal", "Delivery channel under D0", "with and without refusals", "attacks vs D0"):
        assert section in r240 and section in r220
    assert (out / "heatmap_cyb240_mock.png").exists() and (out / "heatmap_cyb220_mock.png").exists()
    assert (out / "marker_spot_check.csv").exists()


def test_papers_use_only_the_primary_computer_and_compare_the_rest(tmp_path):
    path = _report_config(tmp_path)
    main(["--config", str(path), "--machine", "laptop", "--no-report"])
    main(["--config", str(path), "--machine", "desktop"])
    text = (tmp_path / "results" / "report_cyb240.md").read_text(encoding="utf-8")
    assert "come from one computer, `laptop`" in text and "## Hardware comparison" in text
    assert "`desktop` against `laptop`: 100% same verdict" in text  # the mock answers identically everywhere
    trials = (36 + 17) * 2 * 5  # tasks x trials x the report's five defenses, for one computer
    assert f"| {trials} |" in text and f"| {trials * 2} |" not in text  # not pooled


def test_report_warns_when_the_primary_computer_has_no_results(tmp_path):
    path = _report_config(tmp_path)
    main(["--config", str(path), "--machine", "desktop"])
    text = (tmp_path / "results" / "report_cyb240.md").read_text(encoding="utf-8")
    assert "Primary computer missing" in text and "## Hardware comparison" not in text


def test_versus_uses_the_non_overlap_rule():
    low = pd.DataFrame({"success": [False] * 50})
    high = pd.DataFrame({"success": [True] * 50})
    assert versus(low, high) == "lower" and versus(high, low) == "higher"
    assert versus(low, low) == "overlap" and versus(low, low.iloc[0:0]) == "-"
