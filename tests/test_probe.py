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
                "stderr": "Traceback boom", "events": [],
                "host_evidence": [{
                    "source": "HOST_DOCKER",
                    "observation_type": "CONTAINER_STATE",
                    "collection_status": "COLLECTED",
                    "metadata": {"state": {
                        "Status": "exited",
                        "StartedAt": "2026-11-09T00:00:00Z",
                    }},
                }]}
    return run


def _docker_state_evidence(state, collection_status="COLLECTED"):
    return [{
        "source": "HOST_DOCKER",
        "observation_type": "CONTAINER_STATE",
        "collection_status": collection_status,
        "metadata": {"state": state},
    }]


def test_execution_occurred_requires_valid_nonzero_docker_timestamp():
    run = {"host_evidence": _docker_state_evidence({
        "Status": "exited", "StartedAt": "2026-11-09T00:00:00.123456789Z"
    })}

    assert probe._execution_occurred(run) is True


def test_execution_occurred_zero_docker_timestamp_is_false():
    run = {"host_evidence": _docker_state_evidence({
        "Status": "exited", "StartedAt": "0001-01-01T00:00:00Z"
    })}

    assert probe._execution_occurred(run) is False


def test_execution_occurred_created_state_is_false():
    run = {"host_evidence": _docker_state_evidence({"Status": "created"})}

    assert probe._execution_occurred(run) is False


def test_execution_occurred_created_state_with_zero_timestamp_is_false():
    run = {"host_evidence": _docker_state_evidence({
        "Status": "created", "StartedAt": "0001-01-01T00:00:00Z"
    })}

    assert probe._execution_occurred(run) is False


def test_execution_occurred_created_state_with_nonzero_timestamp_is_unknown():
    run = {"host_evidence": _docker_state_evidence({
        "Status": "created", "StartedAt": "2026-11-09T00:00:00.123456789Z"
    })}

    assert probe._execution_occurred(run) is None


def test_execution_occurred_missing_timestamp_is_unknown():
    run = {"host_evidence": _docker_state_evidence({"Status": "exited"})}

    assert probe._execution_occurred(run) is None


def test_execution_occurred_malformed_timestamp_is_unknown():
    run = {"host_evidence": _docker_state_evidence({
        "Status": "exited", "StartedAt": "yesterday-ish"
    })}

    assert probe._execution_occurred(run) is None


def test_execution_occurred_missing_or_failed_docker_evidence_is_unknown():
    missing = {"host_evidence": []}
    failed = {"host_evidence": _docker_state_evidence(
        {"Status": "exited", "StartedAt": "2026-11-09T00:00:00Z"},
        collection_status="COLLECTION_FAILED",
    )}

    assert probe._execution_occurred(missing) is None
    assert probe._execution_occurred(failed) is None


def test_probe_success(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["COMPLETED"]))
    r = probe.agent_probe("print(1)", [], lambda s, u: json.dumps(GOOD))
    assert r["status"] == "COMPLETED" and r["attempts"] == 1 and r["stdout"] == "out"
    assert r["attempt_log"][0]["policy_decision"] == "ACCEPTED"
    assert r["attempt_log"][0]["execution_attempted"] is True
    assert r["attempt_log"][0]["execution_occurred"] is True


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
    assert [a["execution_status"] for a in r["attempt_log"]] == [
        "EXECUTION_FAILED", "COMPLETED"
    ]
    assert "Traceback boom" in seen[1]


def test_probe_policy_rejection_never_runs(monkeypatch):
    def boom(path, timeout=10):
        raise AssertionError("must not run")

    monkeypatch.setattr(probe, "run_sample", boom)
    bad = json.dumps({"goal": "x", "code": "import socket"})
    r = probe.agent_probe("print(1)", [], lambda s, u: bad)
    assert r["status"] == "REJECTED"
    assert r["attempts"] == 3
    assert len(r["attempt_log"]) == 3
    assert all(a["policy_decision"] == "REJECTED" for a in r["attempt_log"])
    assert all(a["execution_attempted"] is False for a in r["attempt_log"])
    assert all(a["execution_occurred"] is False for a in r["attempt_log"])


def test_probe_records_rejection_then_successful_execution(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["COMPLETED"]))
    rejected = {"goal": "bad", "code": "import socket\nprint(SAMPLE_SOURCE)"}
    responses = iter([json.dumps(rejected), json.dumps(GOOD)])

    result = probe.agent_probe("print(1)", [], lambda s, u: next(responses))

    assert result["status"] == "COMPLETED"
    assert result["attempts"] == 2
    first, second = result["attempt_log"]
    assert first["policy_decision"] == "REJECTED"
    assert first["execution_attempted"] is False
    assert first["execution_occurred"] is False
    assert second["policy_decision"] == "ACCEPTED"
    assert second["execution_attempted"] is True
    assert second["execution_occurred"] is True


def test_probe_skipped_when_ai_returns_nothing():
    r = probe.agent_probe("print(1)", [], lambda s, u: "")
    assert r["status"] == "SKIPPED"
    assert r["attempts"] == 3
    assert [a["failure_category"] for a in r["attempt_log"]] == [
        "EMPTY_MODEL_RESPONSE"
    ] * 3


def test_probe_records_malformed_and_empty_generation_cycles(monkeypatch):
    monkeypatch.setattr(probe, "run_sample", _fake_run(["COMPLETED"]))
    responses = iter(["not json", "", json.dumps(GOOD)])
    result = probe.agent_probe("print(1)", [], lambda s, u: next(responses))

    assert result["status"] == "COMPLETED"
    assert result["attempts"] == 3
    assert [a["response_status"] for a in result["attempt_log"]] == [
        "MALFORMED", "EMPTY", "USABLE"
    ]


def test_probe_records_execution_metadata_and_sanitizes_exceptions(monkeypatch):
    def fail_execution(code, source):
        raise RuntimeError("secret API_KEY=do-not-expose")

    monkeypatch.setattr(probe, "execute", fail_execution)
    result = probe.agent_probe("print(1)", [], lambda s, u: json.dumps(GOOD))

    attempt = result["attempt_log"][0]
    assert result["status"] == "EXECUTION_FAILED"
    assert attempt["execution_attempted"] is True
    assert attempt["execution_occurred"] is None
    assert attempt["failure_category"] == "EXECUTION_ERROR"
    assert "do-not-expose" not in str(result)


def test_docker_failure_without_start_evidence_remains_unknown(monkeypatch):
    monkeypatch.setattr(probe, "execute", lambda code, source: {
        "execution_status": "DOCKER_FAILED",
        "diagnostic": "Docker could not start.",
        "host_evidence": [{
            "source": "HOST_DOCKER",
            "observation_type": "CONTAINER_STATE",
            "collection_status": "COLLECTION_FAILED",
            "metadata": {},
        }],
    })
    result = probe.agent_probe("print(1)", [], lambda s, u: json.dumps(GOOD))

    attempt = result["attempt_log"][0]
    assert result["status"] == "DOCKER_FAILED"
    assert attempt["execution_attempted"] is True
    assert attempt["execution_occurred"] is None


def test_probe_records_exit_code_and_duration(monkeypatch):
    def run(path, timeout=10):
        return {"execution_status": "COMPLETED", "diagnostic": "ok",
                "stdout": "out", "stderr": "", "exit_code": 0,
                "duration_s": 0.25}

    monkeypatch.setattr(probe, "run_sample", run)
    result = probe.agent_probe("print(1)", [], lambda s, u: json.dumps(GOOD))

    assert result["attempt_log"][0]["exit_code"] == 0
    assert result["attempt_log"][0]["duration_s"] == 0.25
    assert result["attempt_log"][0]["execution_occurred"] is None


def test_probe_records_generation_exception_without_details():
    def fail_chat(system, user):
        raise RuntimeError("credential=secret")

    result = probe.agent_probe("print(1)", [], fail_chat)

    assert result["attempts"] == 1
    assert result["status"] == "FAILED"
    assert result["attempt_log"][0]["failure_category"] == "AI_GENERATION_ERROR"
    assert "credential=secret" not in str(result)


def test_policy_rejects_probe_that_ignores_the_sample():
    ok, why = probe.policy_check("print('this is malware')")
    assert ok is False and "SAMPLE_SOURCE" in why


def test_policy_blocks_codecs_file_access():
    code = (
        "import codecs\n"
        "print(codecs.open('sample.txt'))\n"
        "print(SAMPLE_SOURCE)"
    )
    ok, why = probe.policy_check(code)
    assert ok is False


def test_policy_blocks_format_string_dunder_traversal():
    code = (
        "print(SAMPLE_SOURCE)\n"
        "print('{0.__class__}'.format(SAMPLE_SOURCE))"
    )
    ok, why = probe.policy_check(code)
    assert ok is False


def test_policy_allows_harmless_format_string():
    code = 'print("Length: {}".format(len(SAMPLE_SOURCE)))'
    assert probe.policy_check(code)[0] is True
