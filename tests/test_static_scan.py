from sandbox.static_scan import static_scan, cross_check

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


def test_runtime_evidence_moves_a_category_to_observed():
    cc = cross_check(static_scan(THIEF), [{"id": 1, "kind": "network", "detail": "x"}], "COMPLETED")
    assert "network" in [e["kind"] for e in cc["observed"]]


def test_incomplete_run_marks_the_comparison_incomplete():
    assert cross_check(static_scan(THIEF), [], "TIMEOUT")["complete"] is False
