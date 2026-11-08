from sandbox.runner import run_sample
from sandbox.analyze import analyze


def test_stealer_is_caught():
    r = run_sample("samples/stealer.py")
    kinds = {e["kind"] for e in r["events"]}
    assert "env_read" in kinds
    assert "file_open" in kinds
    assert "network" in kinds
    assert "EXFIL_BLOCKED" in r["stdout"]
    assert r["execution_status"] == "COMPLETED"
    a = analyze(r["events"], r["execution_status"])
    assert a["verdict"] == "INCONCLUSIVE"
    assert all(f["evidence"] for f in a["findings"])


def test_hello_is_clean():
    r = run_sample("samples/hello.py")
    assert analyze(r["events"], r["execution_status"])["verdict"] == "INCONCLUSIVE"
