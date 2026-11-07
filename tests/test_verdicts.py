import pytest

from sandbox.analyze import analyze


@pytest.mark.parametrize(
    ("status", "events", "expected"),
    [
        ("COMPLETED", [], "LOW"),
        (
            "COMPLETED",
            [{"id": 1, "kind": "env_read", "detail": "AWS_SECRET_ACCESS_KEY"}],
            "MEDIUM",
        ),
        (
            "COMPLETED",
            [
                {"id": 1, "kind": "file_open", "detail": "/sample/.aws/credentials"},
                {"id": 2, "kind": "network", "detail": "connect example.test:443"},
            ],
            "HIGH",
        ),
        ("TIMEOUT", [], "INCONCLUSIVE"),
        ("EXECUTION_FAILED", [], "INCONCLUSIVE"),
        ("DOCKER_FAILED", [], "INCONCLUSIVE"),
        ("MONITOR_FAILED", [], "INCONCLUSIVE"),
        (None, [], "INCONCLUSIVE"),
        ("UNKNOWN", [], "INCONCLUSIVE"),
    ],
)
def test_verdict_depends_on_execution_status(status, events, expected):
    assert analyze(events, status)["verdict"] == expected


def test_incomplete_execution_preserves_findings_and_evidence():
    events = [
        {"id": 1, "kind": "env_read", "detail": "AWS_SECRET_ACCESS_KEY"},
        {"id": 2, "kind": "network", "detail": "connect example.test:443"},
    ]

    result = analyze(events, "TIMEOUT")

    assert result["verdict"] == "INCONCLUSIVE"
    assert result["findings"] == [
        {
            "kind": "canary_env",
            "title": "Read fake secret environment variables",
            "evidence": [1],
        },
        {
            "kind": "network",
            "title": "Attempted network access (blocked by sandbox)",
            "evidence": [2],
        },
    ]
