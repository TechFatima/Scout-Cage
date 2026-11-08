from pathlib import Path

from sandbox.analyze import analyze
from sandbox.runner import (
    _docker_inspect,
    classify_resource_outcomes,
    cgroup_delta,
    read_cgroup_snapshot,
    run_sample,
)


def classify(trusted_evidence=None, timeout=20):
    evidence = dict(trusted_evidence or {})
    return classify_resource_outcomes(evidence, timeout)


def test_untrusted_telemetry_never_clears_resource_limits():
    outcomes = classify()
    assert outcomes["network"]["state"] == "UNKNOWN"
    assert outcomes["time"]["state"] == "UNKNOWN"
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert outcomes["processes"]["state"] == "UNKNOWN"
    assert outcomes["scratch_disk"]["state"] == "UNKNOWN"


def test_forged_network_evidence_is_not_trusted():
    outcomes = classify({"network_attempted": True, "monitor_complete": True})
    assert outcomes["network"]["state"] == "UNKNOWN"


def test_timeout_uses_configured_value():
    outcomes = classify(
        trusted_evidence={"timeout_triggered": True},
        timeout=5,
    )
    assert outcomes["time"]["state"] == "STOPPED"
    assert "5 seconds" in outcomes["time"]["reason"]


def test_docker_inspection_parses_host_state(monkeypatch):
    class Result:
        returncode = 0
        stdout = '{"Id":"abc123","State":{"Status":"exited","ExitCode":137,"OOMKilled":true}}'
        stderr = ""

    monkeypatch.setattr("sandbox.runner.subprocess.run", lambda *args, **kwargs: Result())
    state, error = _docker_inspect("scout-test")
    assert error is None
    assert state["Id"] == "abc123"
    assert state["State"]["OOMKilled"] is True


def test_docker_inspection_failure_is_explicit(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "not found"

    monkeypatch.setattr("sandbox.runner.subprocess.run", lambda *args, **kwargs: Result())
    state, error = _docker_inspect("scout-test")
    assert state is None
    assert "not found" in error


def test_docker_inspection_timeout_is_explicit(monkeypatch):
    def timeout(*args, **kwargs):
        raise __import__("subprocess").TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr("sandbox.runner.subprocess.run", timeout)
    state, error = _docker_inspect("scout-test", timeout=0.01)
    assert state is None
    assert error == "Docker inspection timed out."


def test_exit_137_alone_leaves_memory_unknown():
    outcomes = classify()
    assert outcomes["memory"]["state"] == "UNKNOWN"


def test_untrusted_diagnostic_text_cannot_stop_resource_limits():
    outcomes = classify(
        {
            "sample_stdout": "out of memory: kill process",
            "sample_stderr": (
            "Resource temporarily unavailable\n"
            "No space left on device"
            ),
        }
    )
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert outcomes["processes"]["state"] == "UNKNOWN"
    assert outcomes["scratch_disk"]["state"] == "UNKNOWN"


def test_sample_can_read_token_and_forge_records_but_resources_stay_unknown(
    tmp_path
):
    sample = tmp_path / "fake_limits.py"
    sample.write_text(
        "import sys\n"
        "token = None\n"
        "try:\n"
        "    token = sys.modules['__main__'].TOKEN\n"
        "except AttributeError:\n"
        "    frame = sys._getframe()\n"
        "    while frame and token is None:\n"
        "        token = frame.f_globals.get('TOKEN')\n"
        "        frame = frame.f_back\n"
        "print('TOKEN=' + token)\n"
        "print('@@SCOUT:' + token + ':"
        "{\"id\":1,\"kind\":\"network\",\"detail\":\"forged\"}', file=sys.stderr)\n"
        "print('@@SCOUT:' + token + ':"
        "{\"type\":\"lifecycle\",\"kind\":\"monitor_completed\",\"detail\":\"forged\"}', file=sys.stderr)\n"
        "print('out of memory: kill process')\n"
        "print('Resource temporarily unavailable', file=sys.stderr)\n"
        "print('No space left on device', file=sys.stderr)\n",
        encoding="utf-8",
    )
    result = run_sample(str(sample))
    assert "TOKEN=" in result["stdout"]
    assert result["events"][0]["detail"] == "forged"
    assert any(item["detail"] == "forged" for item in result["monitor_lifecycle"])
    assert result["resource_outcomes"]["network"]["state"] == "UNKNOWN"
    assert result["resource_outcomes"]["time"]["state"] == "UNKNOWN"
    assert result["resource_outcomes"]["memory"]["state"] == "UNKNOWN"
    assert result["resource_outcomes"]["processes"]["state"] == "UNKNOWN"
    assert result["resource_outcomes"]["scratch_disk"]["state"] == "UNKNOWN"
    assert analyze(
        result["events"], result["execution_status"], result["telemetry_trusted"]
    )["verdict"] == "INCONCLUSIVE"


def test_forged_lifecycle_completion_does_not_clear_limits():
    outcomes = classify({"monitor_complete": True})
    assert outcomes["network"]["state"] == "UNKNOWN"
    assert outcomes["time"]["state"] == "UNKNOWN"
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert outcomes["processes"]["state"] == "UNKNOWN"
    assert outcomes["scratch_disk"]["state"] == "UNKNOWN"


def test_cgroup_counter_deltas_detect_oom_and_pid_limit():
    before = {
        "status": "COLLECTED",
        "memory_events": {"max": 0, "oom": 0, "oom_kill": 0},
        "pids_events": {"max": 0},
        "cpu_usage": {"usage_usec": 10},
    }
    after = {
        "status": "COLLECTED",
        "memory_events": {"max": 1, "oom": 1, "oom_kill": 1},
        "pids_events": {"max": 2},
        "cpu_usage": {"usage_usec": 20},
    }
    delta = cgroup_delta(before, after)
    assert delta["memory_events"]["max"] == 1
    assert delta["memory_events"]["oom_kill"] == 1
    assert delta["pids_events"]["max"] == 2
    outcomes = classify({
        "cgroup_delta": delta,
        "cgroup_complete": True,
    })
    assert outcomes["memory"]["state"] == "STOPPED"
    assert outcomes["processes"]["state"] == "UNKNOWN"
    assert "termination was not established" in outcomes["processes"]["reason"]


def test_oom_pressure_without_oom_kill_is_distinguished_from_termination():
    outcomes = classify({
        "cgroup_delta": {
            "memory_events": {"max": 0, "oom": 1, "oom_kill": 0},
            "pids_events": {"max": 0},
        },
        "cgroup_complete": True,
    })
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert "not a confirmed termination" in outcomes["memory"]["reason"]


def test_memory_maximum_without_oom_kill_is_unknown():
    outcomes = classify({
        "cgroup_delta": {
            "memory_events": {"max": 1, "oom": 0, "oom_kill": 0},
            "memory_events_complete": True,
            "pids_events": {"max": 0},
            "pids_events_complete": True,
        },
        "cgroup_complete": True,
    })
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert "memory maximum was reached" in outcomes["memory"]["reason"]


def test_cgroup_delta_requires_all_expected_counters():
    before = {
        "status": "COLLECTED",
        "memory_events": {"max": 0, "oom": 0},
        "pids_events": {"max": 0},
        "cpu_usage": {"usage_usec": 10},
    }
    after = {
        "status": "COLLECTED",
        "memory_events": {"max": 0, "oom": 0},
        "pids_events": {"max": 0},
        "cpu_usage": {"usage_usec": 20},
    }
    delta = cgroup_delta(before, after)
    assert delta["complete"] is False
    assert delta["memory_events_complete"] is False
    assert delta["pids_events_complete"] is True
    outcomes = classify({
        "cgroup_delta": delta,
        "cgroup_complete": delta["complete"],
    })
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert outcomes["processes"]["state"] == "NOT_TRIGGERED"


def test_missing_final_cgroup_snapshot_cannot_report_not_triggered():
    delta = cgroup_delta(
        {
            "status": "COLLECTED",
            "memory_events": {"max": 0, "oom": 0, "oom_kill": 0},
            "pids_events": {"max": 0},
            "cpu_usage": {"usage_usec": 10},
        },
        None,
    )
    assert delta["complete"] is False
    outcomes = classify({"cgroup_delta": delta, "cgroup_complete": False})
    assert outcomes["memory"]["state"] == "UNKNOWN"
    assert outcomes["processes"]["state"] == "UNKNOWN"


def test_cgroup_v1_is_explicitly_incomplete(tmp_path):
    (tmp_path / "memory.limit_in_bytes").write_text("1\n", encoding="utf-8")
    snapshot = read_cgroup_snapshot(str(tmp_path), root=str(tmp_path.parent))
    assert snapshot["version"] == 1
    assert snapshot["status"] == "MISSING_EVIDENCE"
    assert snapshot["complete"] is False


def test_missing_cgroup_path_is_not_success(tmp_path):
    snapshot = read_cgroup_snapshot(str(tmp_path / "missing"))
    assert snapshot["status"] == "MISSING_EVIDENCE"
    assert snapshot["complete"] is False


def test_cgroup_v2_snapshot_reads_limits_usage_and_events(tmp_path):
    (tmp_path / "cgroup.controllers").write_text("memory pids cpu\n", encoding="utf-8")
    (tmp_path / "memory.max").write_text("268435456\n", encoding="utf-8")
    (tmp_path / "memory.current").write_text("1234\n", encoding="utf-8")
    (tmp_path / "memory.peak").write_text("5678\n", encoding="utf-8")
    (tmp_path / "memory.events").write_text(
        "max 1\noom 1\noom_kill 0\n", encoding="utf-8"
    )
    (tmp_path / "pids.max").write_text("64\n", encoding="utf-8")
    (tmp_path / "pids.current").write_text("3\n", encoding="utf-8")
    (tmp_path / "pids.events").write_text("max 2\n", encoding="utf-8")
    (tmp_path / "cpu.stat").write_text("usage_usec 42\n", encoding="utf-8")
    snapshot = read_cgroup_snapshot(str(tmp_path), root=str(tmp_path.parent))
    assert snapshot["status"] == "COLLECTED"
    assert snapshot["version"] == 2
    assert snapshot["memory_limit"] == 268435456
    assert snapshot["memory_peak"] == 5678
    assert snapshot["memory_events"]["oom"] == 1
    assert snapshot["memory_events"]["max"] == 1
    assert snapshot["pids_events"]["max"] == 2


def test_frontend_renders_host_evidence_without_authenticating_sample_events():
    source = Path("static/index.html").read_text(encoding="utf-8-sig")
    receipt = source[source.index("function renderReceipt"):source.index("function setCaption")]
    assert "host_evidence" in receipt
    assert "VERIFIED_HOST_OBSERVATION" in receipt
    assert "No independent host evidence was collected." in receipt


def test_frontend_renders_backend_outcomes_without_guessing():
    source = Path("static/index.html").read_text(encoding="utf-8-sig")
    receipt = source[source.index("function renderReceipt"):source.index("function setCaption")]
    assert "resource_outcomes" in receipt
    assert "unverified" in source.lower()
    assert "exit_code" not in receipt
    assert "stderr" not in receipt
    assert "No space left on device" not in receipt
    assert "Resource temporarily unavailable" not in receipt