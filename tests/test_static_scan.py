from sandbox.static_scan import static_scan, static_risk, cross_check

THIEF = open("samples/stealer.py").read()
HIDDEN = ('import base64, os\n'
          'host = base64.b64decode("ZXZpbC5leGFtcGxlLmNvbQ==").decode()\n'
          'key = os.environ.get("AWS_SECRET_ACCESS_KEY")\n')


def kinds(r, conf=None):
    return {i["kind"] for i in r["indicators"] if conf is None or i["confidence"] == conf}


def test_fake_thief_is_described_statically():
    r = static_scan(THIEF)
    assert {"network", "credentials"} <= kinds(r, "high")
    assert all(i["line"] > 0 for i in r["indicators"])


def test_hidden_host_is_decoded_without_running_anything():
    r = static_scan(HIDDEN)
    assert r["hidden"][0]["decoded"] == "evil.example.com"
    assert "host" in kinds(r)


def test_base64_alone_is_not_flagged():
    r = static_scan('import base64\nprint(base64.b64decode("aGk=").decode())\n')
    assert r["indicators"] == [] and r["hidden"] == []


def test_harmless_script_has_no_indicators():
    assert static_scan('print("hello from the cage")\n')["indicators"] == []
    assert static_risk(static_scan('print("hello from the cage")\n'))["level"] == "LOW"


def test_static_risk_is_based_only_on_static_indicators():
    risk = static_risk({
        "parse_error": False,
        "indicators": [],
    })
    assert risk["level"] == "LOW"
    assert static_risk({"parse_error": True, "indicators": []})["level"] == "UNKNOWN"


def test_aliases_are_resolved():
    r = static_scan('import socket as s\ns.create_connection(("a.test", 1))\n')
    assert "network" in kinds(r, "high")


def test_dynamic_code_is_flagged():
    assert "dynamic" in kinds(static_scan('exec("1+1")\n'), "high")


def test_syntax_error_is_reported_not_raised():
    assert static_scan("def (:\n")["parse_error"] is True


def test_dormant_network_code_is_not_observed_at_runtime():
    src = 'if False:\n    import socket\n    socket.create_connection(("example.test", 443))\n'
    cc = cross_check(static_scan(src), [], "COMPLETED")
    assert [e["kind"] for e in cc["not_observed"]] == ["network"] and cc["complete"] is True
    assert cc["comparison_status"] == "REPORTED_OBSERVATIONS_ONLY"
    assert cc["not_observed"][0]["evidence_status"] == "NO_MATCHING_REPORTED_OBSERVATION"


def test_runtime_evidence_moves_a_category_to_observed():
    cc = cross_check(static_scan(THIEF), [{"id": 1, "kind": "network", "detail": "x"}], "COMPLETED")
    assert "network" in [e["kind"] for e in cc["observed"]]
    assert cc["observed"][0]["evidence_status"] == "UNVERIFIED_RUNTIME_OBSERVATION"


def test_incomplete_run_marks_the_comparison_incomplete():
    cc = cross_check(static_scan(THIEF), [], "TIMEOUT")
    assert cc["complete"] is False
    assert cc["comparison_status"] == "INCOMPLETE"


def test_forged_matching_event_is_only_reported_observation():
    cc = cross_check(
        static_scan('import socket\nsocket.create_connection(("x.test", 1))\n'),
        [{"id": 1, "kind": "network", "detail": "forged"}],
        "COMPLETED",
    )
    assert cc["observed"][0]["evidence_status"] == "UNVERIFIED_RUNTIME_OBSERVATION"


def test_frontend_does_not_claim_authenticated_static_runtime_agreement():
    source = open("static/index.html", encoding="utf-8-sig").read()
    assert "Static and runtime evidence agree" not in source
    assert "does not show that the capability did not execute" in source
    assert "unverified reports, not proof of execution" in source


def test_frontend_missing_cross_check_is_incomplete():
    source = open("static/index.html", encoding="utf-8-sig").read()
    assert (
        '{observed:[],not_observed:[],complete:false,comparison_status:"INCOMPLETE"}'
        in source
    )


def test_frontend_uses_replacement_low_verdict_wording():
    source = open("static/index.html", encoding="utf-8-sig").read()
    old = (
        "No monitored behavior was observed, but the code contains capabilities "
        "the cage did not see run (see the static scan). Treat this as unproven, not safe."
    )
    new = (
        "No corresponding unverified monitor observation was reported for some source "
        "indicators. This does not establish whether those capabilities executed. "
        "Treat the result as unproven, not safe."
    )
    assert old not in source
    assert new in source


def test_frontend_uses_conservative_evidence_wording():
    source = open("static/index.html", encoding="utf-8-sig").read()
    assert "Evidence proves." not in source
    assert "The AI explains unverified runtime observations and static source indicators" in source
    assert "A LOW result does not prove the code is safe" in source
    assert "runtime verdict remains INCONCLUSIVE" in source
    assert "Written by the AI from unverified observations and static source indicators." in source
