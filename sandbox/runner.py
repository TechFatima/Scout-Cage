import os, shutil, subprocess, tempfile, time, uuid

IMAGE = "python:3.12-slim"

def run_sample(script_path, timeout=20, memory="256m", cpus="0.5"):
    """Run a script inside a locked-down, disposable Docker container."""
    name = f"scout-{uuid.uuid4().hex[:8]}"
    workdir = tempfile.mkdtemp(prefix="scout_")
    os.chmod(workdir, 0o755)
    target = os.path.join(workdir, "sample.py")
    shutil.copy(script_path, target)
    os.chmod(target, 0o644)

    cmd = [
        "docker", "run", "--rm", "--name", name,
        "--network", "none",
        "--memory", memory,
        "--cpus", cpus,
        "--pids-limit", "64",
        "--read-only",
        "--tmpfs", "/tmp:size=16m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "65534:65534",
        "-v", f"{workdir}:/sample:ro",
        IMAGE, "python", "/sample/sample.py",
    ]

    start = time.time()
    timed_out = False
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout, stderr, code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as e:
        timed_out = True
        out = e.stdout
        stdout = out.decode() if isinstance(out, bytes) else (out or "")
        stderr = "KILLED: time limit exceeded"
        code = -1
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return {
        "container": name,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": code,
        "timed_out": timed_out,
        "duration_s": round(time.time() - start, 2),
    }
