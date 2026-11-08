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
    assert r["resource_outcomes"]["time"]["state"] == "STOPPED"
    assert "5 seconds" in r["resource_outcomes"]["time"]["reason"]


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

    monkeypatch.setattr(subprocess, "Popen", missing_docker)

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
    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "hello", ""

        def kill(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        "sandbox.runner._docker_inspect",
        lambda name, timeout=None: (None, "inspection unavailable"),
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: type("Result", (), {"returncode": 0})()
    )
    r = run_sample("samples/hello.py")
    assert r["execution_status"] == "MONITOR_FAILED"
    assert r["diagnostic"] == "Security monitoring did not produce complete telemetry."


def test_malformed_lifecycle_telemetry_is_monitor_failure(monkeypatch):
    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "", "@@SCOUT:token:{not-json}\n"

        def kill(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        "sandbox.runner._docker_inspect",
        lambda name, timeout=None: (None, "inspection unavailable"),
    )
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: type("Result", (), {"returncode": 0})()
    )
    monkeypatch.setattr("sandbox.runner.uuid.uuid4", lambda: type("U", (), {"hex": "token"})())
    r = run_sample("samples/hello.py")
    assert r["execution_status"] == "MONITOR_FAILED"


def test_container_is_inspected_before_cleanup(monkeypatch):
    calls = []

    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "hello", ""

    def inspect(name, timeout=None):
        calls.append("inspect")
        return (
            {
                "Id": "container-id",
                "State": {
                    "Pid": 123,
                    "Status": "exited",
                    "ExitCode": 0,
                    "OOMKilled": False,
                },
            },
            None,
        )

    def run(command, **kwargs):
        calls.append("cleanup" if command[1:3] == ["rm", "-f"] else "other")
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr("sandbox.runner._docker_inspect", inspect)
    monkeypatch.setattr(subprocess, "run", run)
    result = run_sample("samples/hello.py")
    assert result["container_id"] == "container-id"
    assert calls[-1] == "cleanup"
    assert "inspect" in calls[:-1]


def test_cleanup_failure_is_reported(monkeypatch):
    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "hello", ""

    def inspect(name, timeout=None):
        return (
            {"Id": "container-id", "State": {"Pid": 0, "ExitCode": 0}},
            None,
        )

    def run(command, **kwargs):
        if command[1:3] == ["rm", "-f"]:
            return type("Result", (), {"returncode": 1, "stderr": "cleanup failed"})()
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr("sandbox.runner._docker_inspect", inspect)
    monkeypatch.setattr(subprocess, "run", run)
    result = run_sample("samples/hello.py")
    assert any(
        item["observation_type"] == "CONTAINER_CLEANUP"
        and item["collection_status"] == "MONITORING_FAILURE"
        for item in result["host_evidence"]
    )
    assert result["execution_status"] == "DOCKER_FAILED"


def test_host_oom_precedes_incomplete_monitor_telemetry(monkeypatch):
    class Process:
        returncode = 137

        def communicate(self, timeout=None):
            return "", ""

    def inspect(name, timeout=None):
        return (
            {
                "Id": "oom-container",
                "State": {
                    "Pid": 0,
                    "ExitCode": 137,
                    "OOMKilled": True,
                },
            },
            None,
        )

    def run(command, **kwargs):
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr("sandbox.runner._docker_inspect", inspect)
    monkeypatch.setattr(subprocess, "run", run)
    result = run_sample("samples/hello.py")
    assert result["execution_status"] == "RESOURCE_LIMIT_REACHED"
    assert "OOM termination" in result["diagnostic"]


def test_cgroup_oom_precedes_incomplete_monitor_telemetry(monkeypatch):
    class Process:
        returncode = 137

        def communicate(self, timeout=None):
            return "", ""

    def inspect(name, timeout=None):
        return (
            {
                "Id": "cgroup-oom-container",
                "State": {
                    "Pid": 0,
                    "ExitCode": 137,
                    "OOMKilled": False,
                },
            },
            None,
        )

    def run(command, **kwargs):
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr("sandbox.runner._docker_inspect", inspect)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        "sandbox.runner.cgroup_delta",
        lambda before, after: {
            "status": "COLLECTED",
            "complete": True,
            "memory_events": {"max": 1, "oom": 1, "oom_kill": 1},
            "memory_events_complete": True,
            "pids_events": {"max": 0},
            "pids_events_complete": True,
        },
    )
    result = run_sample("samples/hello.py")
    assert result["execution_status"] == "RESOURCE_LIMIT_REACHED"
    assert "OOM termination" in result["diagnostic"]


def test_pid_limit_status_does_not_claim_termination(monkeypatch):
    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "", ""

    def inspect(name, timeout=None):
        return (
            {
                "Id": "pid-container",
                "State": {
                    "Pid": 0,
                    "ExitCode": 0,
                    "OOMKilled": False,
                },
            },
            None,
        )

    def run(command, **kwargs):
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr("sandbox.runner._docker_inspect", inspect)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        "sandbox.runner.cgroup_delta",
        lambda before, after: {
            "status": "COLLECTED",
            "complete": True,
            "memory_events": {},
            "memory_events_complete": False,
            "pids_events": {"max": 1},
            "pids_events_complete": True,
        },
    )
    result = run_sample("samples/hello.py")
    assert result["resource_outcomes"]["processes"]["state"] == "UNKNOWN"
    assert "termination was not established" in result["diagnostic"]


def test_timeout_inspects_then_force_removes_container(monkeypatch):
    calls = []

    class Process:
        returncode = -9
        first = True

        def communicate(self, timeout=None):
            if self.first:
                self.first = False
                raise subprocess.TimeoutExpired("docker", timeout, output=b"partial")
            return "", ""

        def kill(self):
            calls.append("cli-kill")

    def inspect(name, timeout=None):
        calls.append("inspect")
        return (
            {
                "Id": "container-id",
                "State": {"Pid": 123, "ExitCode": -9, "OOMKilled": False},
            },
            None,
        )

    def run(command, **kwargs):
        calls.append("cleanup" if command[1:3] == ["rm", "-f"] else "other")
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr("sandbox.runner._docker_inspect", inspect)
    monkeypatch.setattr(subprocess, "run", run)
    result = run_sample("samples/hello.py", timeout=1)
    assert result["execution_status"] == "TIMEOUT"
    assert "cli-kill" in calls
    assert calls.index("inspect") < calls.index("cleanup")


def test_short_run_without_cgroup_snapshot_reports_missing_evidence(monkeypatch):
    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return "hello", ""

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        "sandbox.runner._docker_inspect",
        lambda name, timeout=None: (
            {"Id": "short-lived", "State": {"Pid": 0, "ExitCode": 0}},
            None,
        ),
    )
    monkeypatch.setattr(
        subprocess, "run",
        lambda *args, **kwargs: type("Result", (), {"returncode": 0, "stderr": ""})(),
    )
    result = run_sample("samples/hello.py")
    cgroup = [item for item in result["host_evidence"] if item["source"] == "HOST_CGROUP"]
    assert cgroup
    assert cgroup[0]["provenance"] == "MISSING_EVIDENCE"
    assert cgroup[0]["complete"] is False
