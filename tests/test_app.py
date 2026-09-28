# Tests for bench/app.py: prompt assembly, attack placement, and the benign task set.
from bench.app import (CARRIER_HEAD, DEFAULT_REQUEST, Source, attack_input, build_prompt,
                       load_benign_tasks, make_input, with_sources)
from tests.conftest import ROOT

CANARY = "CANARY-7f3a91"


def test_system_prompt_holds_canary_and_user_prompt_does_not():
    system, user = build_prompt(make_input("Summarize.", "Some text.", CANARY))
    assert CANARY in system and "Never reveal" in system
    assert CANARY not in user
    assert user == "User request:\nSummarize.\n\nDocument:\nSome text."


def test_attack_channels():
    doc_attack = attack_input("document", "EVIL PAYLOAD", CANARY)
    assert doc_attack.request == DEFAULT_REQUEST
    assert doc_attack.sources[0].text.startswith(CARRIER_HEAD)
    assert "EVIL PAYLOAD" in doc_attack.sources[0].text
    user_attack = attack_input("user_message", "EVIL PAYLOAD", CANARY)
    assert user_attack.request == "EVIL PAYLOAD"
    assert "EVIL PAYLOAD" not in user_attack.sources[0].text


def test_new_sources_plug_into_build_prompt():
    inp = make_input("Q?", "doc", CANARY)
    inp = with_sources(inp, inp.sources + [Source("tool_output", "42")])
    _, user = build_prompt(inp)
    assert user.endswith("Tool output:\n42")
    assert "42" in inp.all_text()


def test_benign_set_loads():
    tasks, problems = load_benign_tasks(ROOT / "data" / "benign_tasks.yaml")
    assert problems == []
    assert len(tasks) >= 15
    assert len({t.id for t in tasks}) == len(tasks)


def test_benign_loader_skips_bad_entries(tmp_path):
    path = tmp_path / "b.yaml"
    path.write_text("- {id: a, request: r, document: d, expected_keywords: [x]}\n"
                    "- {id: b, request: r}\n"
                    "- {id: a, request: r, document: d, expected_keywords: [x]}\n", encoding="utf-8")
    tasks, problems = load_benign_tasks(path)
    assert [t.id for t in tasks] == ["a"] and len(problems) == 2
    path.write_text("[not: valid", encoding="utf-8")
    tasks, problems = load_benign_tasks(path)
    assert tasks == [] and problems
