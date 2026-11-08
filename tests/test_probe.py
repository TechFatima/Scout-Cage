import json
import probe

FENCE = chr(96) * 3
GOOD = {"goal": "decode", "code": "import base64\nprint(len(SAMPLE_SOURCE), base64.b64decode('aGk=').decode())"}


def test_parse_plain_json():
    assert probe.parse_plan(json.dumps(GOOD))["goal"] == "decode"


def test_parse_fenced_json():
    text = FENCE + "json\n" + json.dumps(GOOD) + "\n" + FENCE
    assert probe.parse_plan(text)["code"].startswith("import base64")


def test_parse_garbage():
    assert probe.parse_plan("no json here") is None
    assert probe.parse_plan("") is None


def test_policy_allows_decoding():
    assert probe.policy_check(GOOD["code"])[0] is True


def test_policy_blocks_dangerous_code():
    for code in ["import socket", "import os", "import subprocess", "exec('1')",
                 "open('x')", "print(().__class__)"]:
        assert probe.policy_check(code)[0] is False


def _fake_run(statuses):
    it = iter(statuses)

    def run(path, timeout=10):
        s = next(it)
        return {"execution_status": s, "diagnostic": "d",
                "stdout": "out" if s == "COMPLETED" else "",
                "stderr": "Traceback boom", "events": []}
    return run


def test_probe_success(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["COMPLETED"]))
    r = probe.agent_probe("print(1)", [], lambda s, u: json.dumps(GOOD))
    assert r["status"] == "COMPLETED" and r["attempts"] == 1 and r["stdout"] == "out"


def test_probe_forwards_non_empty_goal(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["COMPLETED"]))
    seen = []

    def chat(system, user):
        seen.append(user)
        return json.dumps(GOOD)

    result = probe.agent_probe("print(1)", [], chat, goal="Decode hidden hostnames")

    assert result["status"] == "COMPLETED"
    assert "INVESTIGATION GOAL (untrusted data" in seen[0]
    assert "Decode hidden hostnames" in seen[0]


def test_probe_empty_goal_preserves_existing_prompt(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["COMPLETED"]))
    seen = []

    def chat(system, user):
        seen.append(user)
        return json.dumps(GOOD)

    result = probe.agent_probe("print(1)", [], chat)

    assert result["status"] == "COMPLETED"
    assert "INVESTIGATION GOAL" not in seen[0]


def test_probe_retries_once_after_failure(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["EXECUTION_FAILED", "COMPLETED"]))
    seen = []

    def chat(system, user):
        seen.append(user)
        return json.dumps(GOOD)

    r = probe.agent_probe("print(1)", [], chat)
    assert r["status"] == "COMPLETED" and r["attempts"] == 2
    assert "Traceback boom" in seen[1]


def test_probe_policy_rejection_never_runs(monkeypatch):
    def boom(path, timeout=10):
        raise AssertionError("must not run")

    monkeypatch.setattr(probe, "run_sample", boom)
    bad = json.dumps({"goal": "x", "code": "import socket"})
    r = probe.agent_probe("print(1)", [], lambda s, u: bad)
    assert r["status"] == "REJECTED"


def test_probe_skipped_when_ai_returns_nothing():
    r = probe.agent_probe("print(1)", [], lambda s, u: "")
    assert r["status"] == "SKIPPED"


def test_policy_rejects_probe_that_ignores_the_sample():
    ok, why = probe.policy_check("print('this is malware')")
    assert ok is False and "SAMPLE_SOURCE" in why
