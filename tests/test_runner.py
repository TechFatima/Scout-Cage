from sandbox.runner import run_sample

def test_hello_runs():
    r = run_sample("samples/hello.py")
    assert r["exit_code"] == 0
    assert "hello from the cage" in r["stdout"]

def test_infinite_loop_is_killed():
    r = run_sample("samples/forever.py", timeout=5)
    assert r["timed_out"] is True

def test_network_is_blocked():
    r = run_sample("samples/phone_home.py")
    assert "NETWORK_BLOCKED" in r["stdout"]
    assert "NETWORK_OPEN" not in r["stdout"]
