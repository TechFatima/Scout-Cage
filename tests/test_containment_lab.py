from sandbox.runner import run_sample


def test_memory_limit_kills_the_process():
    r = run_sample("samples/lab_memory.py", timeout=30)
    assert r["exit_code"] == 137 and not r["timed_out"]


def test_process_limit_refuses_new_processes():
    r = run_sample("samples/lab_spawn.py", timeout=30)
    assert "Resource temporarily unavailable" in r["stderr"]


def test_scratch_disk_is_capped():
    r = run_sample("samples/lab_disk.py", timeout=30)
    assert "No space left on device" in r["stderr"]
