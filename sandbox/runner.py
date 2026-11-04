import json, os, shutil, subprocess, tempfile, time, uuid

IMAGE = "python:3.12-slim"
MONITOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
FAKE_KEY_ID = "AKIACANARY00000EXAMPLE"
FAKE_SECRET = "canary/FAKE/do-not-use"


def _split(stderr, token):
    prefix = "@@SCOUT:" + token + ":"
    events, clean = [], []
    for line in stderr.splitlines():
        if line.startswith(prefix):
            try:
                events.append(json.loads(line[len(prefix):]))
            except ValueError:
                pass
        else:
            clean.append(line)
    return events, "\n".join(clean)


def run_sample(script_path, timeout=20, memory="256m", cpus="0.5"):
    """Run a script in a locked-down, disposable container with bait secrets."""
    name = "scout-" + uuid.uuid4().hex[:8]
    token = uuid.uuid4().hex
    workdir = tempfile.mkdtemp(prefix="scout_")
    os.chmod(workdir, 0o755)

    target = os.path.join(workdir, "sample.py")
    shutil.copy(script_path, target)
    os.chmod(target, 0o644)
    mon = os.path.join(workdir, "monitor.py")
    shutil.copy(MONITOR, mon)
    os.chmod(mon, 0o644)

    aws_dir = os.path.join(workdir, ".aws")
    os.makedirs(aws_dir)
    os.chmod(aws_dir, 0o755)
    cred = os.path.join(aws_dir, "credentials")
    with open(cred, "w") as f:
        f.write("[default]\naws_access_key_id = " + FAKE_KEY_ID +
                "\naws_secret_access_key = " + FAKE_SECRET + "\n")
    os.chmod(cred, 0o644)

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
        "-e", "SCOUT_TOKEN=" + token,
        "-e", "HOME=/sample",
        "-e", "AWS_ACCESS_KEY_ID=" + FAKE_KEY_ID,
        "-e", "AWS_SECRET_ACCESS_KEY=" + FAKE_SECRET,
        "-v", workdir + ":/sample:ro",
        IMAGE, "python", "/sample/monitor.py",
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

    events, clean_stderr = _split(stderr, token)
    return {
        "container": name,
        "stdout": stdout,
        "stderr": clean_stderr,
        "events": events,
        "exit_code": code,
        "timed_out": timed_out,
        "duration_s": round(time.time() - start, 2),
    }
