# Tests for bench/corpus.py: the shipped corpus is valid and big enough; bad files are skipped.
from collections import Counter

from bench.corpus import CATEGORIES, load_attacks
from tests.conftest import ROOT


def test_shipped_corpus_is_valid_and_complete():
    cases, problems = load_attacks(ROOT / "attacks")
    assert problems == []
    assert len(cases) >= 30
    counts = Counter(c.category for c in cases)
    assert all(counts[cat] >= 5 for cat in CATEGORIES), counts
    assert {c.goal for c in cases} == {"leak_secret", "output_marker"}
    assert {c.channel for c in cases} == {"user_message", "document"}
    assert all(c.category != "indirect_document" or c.channel == "document" for c in cases)


def test_bad_files_and_cases_are_skipped(tmp_path):
    (tmp_path / "a_good.yaml").write_text(
        "- {id: X1, category: encoded, channel: document, payload: hi, goal: leak_secret}\n"
        "- {id: X1, category: encoded, channel: document, payload: dup, goal: leak_secret}\n"
        "- {id: X2, category: nonsense, channel: document, payload: hi, goal: leak_secret}\n"
        "- {id: X3, category: encoded, channel: document, goal: leak_secret}\n"
        "- {id: X4, category: encoded, channel: email, payload: hi, goal: leak_secret}\n",
        encoding="utf-8")
    (tmp_path / "b_broken.yaml").write_text("- id: [unclosed\n", encoding="utf-8")
    (tmp_path / "c_notlist.yaml").write_text("id: X5\n", encoding="utf-8")
    cases, problems = load_attacks(tmp_path)
    assert [c.id for c in cases] == ["X1"]
    assert len(problems) == 6


def test_empty_dir_reports_problem(tmp_path):
    cases, problems = load_attacks(tmp_path)
    assert cases == [] and problems
