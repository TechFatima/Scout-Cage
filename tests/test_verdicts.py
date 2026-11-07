import pytest

from sandbox.analyze import analyze
from sandbox.runner import run_sample

THEFT = [
    {"id": 1, "kind": "env_read", "detail": "AWS_SECRET_ACCESS_KEY"},
    {"id": 2, "kind": "network", "detail": "connect example.test:443"},
]


@pytest.mark.parametrize(
    ("status", "events", "expected"),
    [
        ("COMPLETED", [], "LOW"),
        ("COMPLETED", THEFT[:1], "MEDIUM"),
        ("COMPLETED", THEFT, "HIGH"),
        ("TIMEOUT", [], "INCONCLUSIVE"),
        ("EXECUTION_FAILED", [], "INCONCLUSIVE"),
        ("DOCKER_FAILED", [], "INCONCLUSIVE"),
        ("MONITOR_FAILED", [], "INCONCLUSIVE"),
        (None, [], "INCONCLUSIVE"),
        ("UNKNOWN", [], "INCONCLUSIVE"),
        # Evidence already logged still counts when the run did not finish cleanly.
        ("TIMEOUT", THEFT, "HIGH"),
        ("EXECUTION_FAILED", THEFT, "HIGH"),
        ("MONITOR_FAILED", THEFT, "HIGH"),
        ("EXECUTION_FAILED", THEFT[:1], "MEDIUM"),
        (None, THEFT, "HIGH"),
    ],
)
def test_verdict_depends_on_execution_status(status, events, expected):
    assert analyze(events, status)["verdict"] == expected


def test_incomplete_execution_preserves_findings_and_evidence():
    result = analyze(THEFT, "TIMEOUT")
    assert result["verdict"] == "HIGH"
    assert [f["evidence"] for f in result["findings"]] == [[1], [2]]


def test_steal_then_crash_is_still_high():
    r = run_sample("samples/crasher.py")
    assert r["execution_status"] == "EXECUTION_FAILED"
    assert analyze(r["events"], r["execution_status"])["verdict"] == "HIGH"
