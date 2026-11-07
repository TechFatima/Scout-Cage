import agent


def test_ai_failure_does_not_change_deterministic_verdict(monkeypatch, tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('clean')\n", encoding="utf-8")
    run = {
        "events": [],
        "execution_status": "COMPLETED",
        "diagnostic": "Sample completed successfully.",
        "stdout": "clean\n",
        "timed_out": False,
    }

    monkeypatch.setattr(agent, "run_sample", lambda path: run)
    monkeypatch.setattr(agent, "ask_ai", lambda events, findings: "")

    result = agent.investigate(str(sample))

    assert result["verdict"] == "LOW"
    assert result["execution_status"] == "COMPLETED"
    assert result["used_fallback"] is True
