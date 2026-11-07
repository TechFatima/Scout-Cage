import subprocess

from sandbox.runner import run_sample


def test_hello_runs():
    r = run_sample("samples/hello.py")
    assert r["exit_code"] == 0
    assert "hello from the cage" in r["stdout"]
    assert r["execution_status"] == "COMPLETED"


def test_infinite_loop_is_killed():
    r = run_sample("samples/forever.py", timeout=5)
    assert r["timed_out"] is True
    assert r["execution_status"] == "TIMEOUT"


def test_nonzero_sample_exit_is_execution_failure(tmp_path):
    sample = tmp_path / "fails.py"
    sample.write_text("raise RuntimeError('intentional test failure')\n", encoding="utf-8")

    r = run_sample(str(sample))

    assert r["execution_status"] == "EXECUTION_FAILED"
    assert r["exit_code"] != 0
    assert r["timed_out"] is False
    assert [item["kind"] for item in r["monitor_lifecycle"]] == [
        "monitor_started",
        "sample_started",
        "monitor_completed",
    ]


def test_missing_docker_is_docker_failure(monkeypatch):
    def missing_docker(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(subprocess, "run", missing_docker)

    r = run_sample("samples/hello.py")

    assert r["execution_status"] == "DOCKER_FAILED"
    assert r["diagnostic"] == "Docker execution could not be started."
    assert r["exit_code"] == -1


def test_network_is_blocked():
    r = run_sample("samples/phone_home.py")
    assert "NETWORK_BLOCKED" in r["stdout"]
    assert "NETWORK_OPEN" not in r["stdout"]
    assert r["execution_status"] == "COMPLETED"
    assert {item["kind"] for item in r["monitor_lifecycle"]} == {
        "monitor_started",
        "sample_started",
        "monitor_completed",
    }


def test_missing_lifecycle_signal_is_monitor_failure(monkeypatch):
    class Result:
        stdout = "hello"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Result())
    r = run_sample("samples/hello.py")
    assert r["execution_status"] == "MONITOR_FAILED"
    assert r["diagnostic"] == "Security monitoring did not produce complete telemetry."


def test_malformed_lifecycle_telemetry_is_monitor_failure(monkeypatch):
    class Result:
        stdout = ""
        stderr = "@@SCOUT:token:{not-json}\n"
        returncode = 0

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Result())
    monkeypatch.setattr("sandbox.runner.uuid.uuid4", lambda: type("U", (), {"hex": "token"})())
    r = run_sample("samples/hello.py")
    assert r["execution_status"] == "MONITOR_FAILED"
