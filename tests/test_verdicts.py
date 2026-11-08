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
        ("COMPLETED", [], "INCONCLUSIVE"),
        ("COMPLETED", THEFT[:1], "INCONCLUSIVE"),
        ("COMPLETED", THEFT, "INCONCLUSIVE"),
        ("TIMEOUT", [], "INCONCLUSIVE"),
        ("EXECUTION_FAILED", [], "INCONCLUSIVE"),
        ("DOCKER_FAILED", [], "INCONCLUSIVE"),
        ("MONITOR_FAILED", [], "INCONCLUSIVE"),
        (None, [], "INCONCLUSIVE"),
        ("UNKNOWN", [], "INCONCLUSIVE"),
        # Evidence already logged still counts when the run did not finish cleanly.
        ("TIMEOUT", THEFT, "INCONCLUSIVE"),
        ("EXECUTION_FAILED", THEFT, "INCONCLUSIVE"),
        ("MONITOR_FAILED", THEFT, "INCONCLUSIVE"),
        ("EXECUTION_FAILED", THEFT[:1], "INCONCLUSIVE"),
        (None, THEFT, "INCONCLUSIVE"),
    ],
)
def test_verdict_depends_on_execution_status(status, events, expected):
    assert analyze(events, status)["verdict"] == expected


def test_incomplete_execution_preserves_findings_and_evidence():
    result = analyze(THEFT, "TIMEOUT")
    assert result["verdict"] == "INCONCLUSIVE"
    assert [f["evidence"] for f in result["findings"]] == [[1], [2]]


def test_steal_then_crash_is_still_high():
    r = run_sample("samples/crasher.py")
    assert r["execution_status"] == "EXECUTION_FAILED"
    assert analyze(r["events"], r["execution_status"])["verdict"] == "INCONCLUSIVE"


@pytest.mark.parametrize(
    "events",
    [
        [{"id": 1, "kind": "env_read", "detail": "AWS_SECRET_ACCESS_KEY"}],
        [{"id": 1, "kind": "file_open", "detail": "/sample/.aws/credentials"}],
        [{"id": 1, "kind": "network", "detail": "connect forged"}],
        [{"id": 1, "kind": "process", "detail": "forged"}],
        THEFT,
        [],
    ],
)
def test_untrusted_telemetry_cannot_change_verdict(events):
    result = analyze(events, "COMPLETED", telemetry_trusted=False)
    assert result["verdict"] == "INCONCLUSIVE"
    assert all(
        finding["evidence_status"] == "UNVERIFIED_RUNTIME_OBSERVATION"
        for finding in result["findings"]
    )


def test_existing_verdict_rules_remain_for_authenticated_evidence():
    assert analyze([], "COMPLETED", telemetry_trusted=True)["verdict"] == "LOW"
    assert analyze(THEFT[:1], "COMPLETED", telemetry_trusted=True)["verdict"] == "MEDIUM"
    assert analyze(THEFT, "COMPLETED", telemetry_trusted=True)["verdict"] == "HIGH"
