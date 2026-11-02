# Tests for bench/doctor.py: what it reports about a computer, with no model or network.
import requests

from bench import provider as prov
from bench.doctor import main
from tests.conftest import base_config, write_config


def test_reports_the_computer_and_corpus(tmp_path, config_path, capsys):
    main(["--config", str(config_path)])
    out = capsys.readouterr().out
    assert "Computer: testbox" in out
    assert "36 attacks, 17 benign tasks" in out
    assert "model calls for the full grid" in out


def test_flags_a_changed_corpus(tmp_path, capsys):
    data = base_config(tmp_path)
    data["app"]["corpus_sha256"] = "0" * 64
    assert main(["--config", str(write_config(tmp_path, data))]) == 1
    assert "doesn't match the locked fingerprint" in capsys.readouterr().out


def test_unreachable_ollama_is_a_problem(tmp_path, monkeypatch, capsys):
    def refuse(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(prov.requests, "get", refuse)
    data = base_config(tmp_path)
    data["models"] = [{"name": "local", "provider": "ollama", "model": "llama3.2"}]
    assert main(["--config", str(write_config(tmp_path, data))]) == 1
    assert "is Ollama running" in capsys.readouterr().out


def test_missing_optional_model_is_only_a_note(tmp_path, monkeypatch, capsys):
    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"models": [], "version": "1"}

    monkeypatch.setattr(prov.requests, "get", lambda *a, **k: Resp())
    data = base_config(tmp_path)
    data["models"].append({"name": "big", "provider": "ollama", "model": "llama3.1:8b"})
    main(["--config", str(write_config(tmp_path, data))])
    out = capsys.readouterr().out
    assert "It will be skipped." in out
    assert "big:" not in out.split("Not ready yet")[-1] or "Not ready yet" not in out
