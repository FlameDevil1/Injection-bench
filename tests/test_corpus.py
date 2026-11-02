# Tests for bench/corpus.py: the shipped corpus is valid and big enough; bad files are skipped.
from collections import Counter

from bench.app import load_benign_tasks
from bench.config import load_config
from bench.corpus import CATEGORIES, load_attacks
from bench.provenance import corpus_hash
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


def test_shipped_configs_lock_the_current_corpus():
    attacks = load_attacks(ROOT / "attacks")[0]
    benign = load_benign_tasks(ROOT / "data" / "benign_tasks.yaml")[0]
    assert (len(attacks), len(benign)) == (36, 17)  # the numbers both proposals state
    for name in ("config.yaml", "config.small.yaml", "config.mock.yaml"):
        assert load_config(ROOT / name).corpus_sha256 == corpus_hash(attacks, benign)


def test_corpus_fingerprint_ignores_line_endings_and_catches_edits(tmp_path):
    text = (ROOT / "attacks" / "delimiter_confusion.yaml").read_bytes().replace(b"\r\n", b"\n")
    (tmp_path / "a.yaml").write_bytes(text)
    lf = corpus_hash(load_attacks(tmp_path)[0], [])
    (tmp_path / "a.yaml").write_bytes(text.replace(b"\n", b"\r\n"))
    assert corpus_hash(load_attacks(tmp_path)[0], []) == lf
    (tmp_path / "a.yaml").write_bytes(text.replace(b"Debug mode", b"Debug  mode"))
    assert corpus_hash(load_attacks(tmp_path)[0], []) != lf


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
