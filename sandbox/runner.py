import datetime
import json, os, shutil, subprocess, tempfile, time, uuid

IMAGE = "python:3.12-slim"
MONITOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.py")
FAKE_KEY_ID = "AKIACANARY00000EXAMPLE"
FAKE_SECRET = "canary/FAKE/do-not-use"
DOCKER_ERROR_MARKERS = (
    "cannot connect to the docker daemon",
    "is the docker daemon running",
    "error response from daemon",
    "pull access denied",
    "repository does not exist",
    "manifest unknown",
    "no such image",
    "invalid reference format",
    "failed to create task",
    "oci runtime",
)
def _split(stderr, token):
    prefix = "@@SCOUT:" + token + ":"
    events, clean = [], []
    lifecycle = []
    malformed = False
    for line in stderr.splitlines():
        if line.startswith(prefix):
            try:
                record = json.loads(line[len(prefix):])
            except ValueError:
                malformed = True
                continue
            if not isinstance(record, dict):
                malformed = True
            elif record.get("type") == "lifecycle":
                if record.get("kind") and isinstance(record.get("detail"), str):
                    lifecycle.append(record)
                else:
                    malformed = True
            elif (
                type(record.get("id")) is int
                and isinstance(record.get("kind"), str)
                and isinstance(record.get("detail"), str)
            ):
                events.append(record)
            else:
                malformed = True
        else:
            clean.append(line)
    return events, "\n".join(clean), lifecycle, malformed


def _is_docker_failure(stderr, exit_code):
    if exit_code == 125:
        return True
    text = (stderr or "").lower()
    return any(marker in text for marker in DOCKER_ERROR_MARKERS)


def _resource_outcome(state, reason):
    return {"state": state, "reason": reason}


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


DOCKER_COMMAND_TIMEOUT = 1.0


def _docker_inspect(name, timeout=DOCKER_COMMAND_TIMEOUT):
    """Return Docker's host-side state before explicit cleanup."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format={{json .}}", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "Docker inspection timed out."
    except OSError as exc:
        return None, "Docker inspection could not be started: %s" % exc
    if getattr(result, "returncode", 1) != 0:
        return None, (getattr(result, "stderr", "") or "Docker inspection failed.").strip()
    try:
        value = json.loads(getattr(result, "stdout", ""))
    except (TypeError, ValueError):
        return None, "Docker inspection returned invalid JSON."
    if not isinstance(value, dict):
        return None, "Docker inspection returned an invalid object."
    return value, None


def _docker_remove(name, timeout=DOCKER_COMMAND_TIMEOUT):
    try:
        result = subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "Docker cleanup timed out."
    except OSError as exc:
        return None, "Docker cleanup could not be started: %s" % exc
    if result.returncode != 0:
        return result, (result.stderr or "Docker cleanup failed.").strip()
    return result, None


def _safe_cgroup_path(path, root="/sys/fs/cgroup"):
    if not isinstance(path, str) or not os.path.isabs(path):
        return None
    root = os.path.abspath(root)
    path = os.path.abspath(path)
    try:
        inside_root = os.path.commonpath([root, path]) == root
    except ValueError:
        inside_root = False
    if not inside_root:
        return None
    return path


def _read_number(path):
    with open(path, encoding="utf-8") as handle:
        value = handle.read().strip()
    if value == "max":
        return None
    return int(value)


def _read_key_values(path):
    values = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) == 2:
                try:
                    values[parts[0]] = int(parts[1])
                except ValueError:
                    continue
    return values


def read_cgroup_snapshot(cgroup_path, root="/sys/fs/cgroup"):
    """Read a validated cgroup v2 snapshot; report cgroup v1 as incomplete."""
    path = _safe_cgroup_path(cgroup_path, root)
    if path is None:
        return {
            "status": "MISSING_EVIDENCE",
            "complete": False,
            "error": "Cgroup path is missing or outside the cgroup root.",
        }
    try:
        version = 2 if os.path.exists(os.path.join(path, "cgroup.controllers")) else 1
        snapshot = {"status": "COLLECTED", "complete": True, "version": version}
        if version == 2:
            snapshot["memory_limit"] = _read_number(os.path.join(path, "memory.max"))
            snapshot["memory_usage"] = _read_number(os.path.join(path, "memory.current"))
            snapshot["memory_peak"] = _read_number(os.path.join(path, "memory.peak"))
            snapshot["memory_events"] = _read_key_values(os.path.join(path, "memory.events"))
            snapshot["pids_limit"] = _read_number(os.path.join(path, "pids.max"))
            snapshot["pids_usage"] = _read_number(os.path.join(path, "pids.current"))
            snapshot["pids_events"] = _read_key_values(os.path.join(path, "pids.events"))
            snapshot["cpu_usage"] = _read_key_values(os.path.join(path, "cpu.stat"))
        else:
            return {
                "status": "MISSING_EVIDENCE",
                "complete": False,
                "version": 1,
                "error": "Cgroup v1 controller paths are not safely established.",
            }
        return snapshot
    except (OSError, ValueError) as exc:
        return {
            "status": "COLLECTION_FAILED",
            "complete": False,
            "version": version,
            "error": "Cgroup snapshot failed: %s" % exc,
        }


def cgroup_delta(before, after):
    """Return counter deltas for one run, never treating missing data as zero."""
    if not before or not after or before.get("status") != "COLLECTED" or after.get("status") != "COLLECTED":
        return {"status": "MISSING_EVIDENCE", "complete": False}
    delta = {"status": "COLLECTED", "complete": True}
    expected = {
        "memory_events": {"max", "oom", "oom_kill"},
        "pids_events": {"max"},
        "cpu_usage": {"usage_usec"},
    }
    for key, required in expected.items():
        old, new = before.get(key), after.get(key)
        group_complete = (
            isinstance(old, dict)
            and isinstance(new, dict)
            and required <= set(old)
            and required <= set(new)
        )
        delta[key + "_complete"] = group_complete
        if not group_complete:
            delta["complete"] = False
            delta[key] = {}
        else:
            delta[key] = {
                name: new[name] - old[name]
                for name in required
                if new[name] >= old[name]
            }
            if len(delta[key]) != len(required):
                delta[key + "_complete"] = False
                delta["complete"] = False
    return delta


def _host_evidence(source, container_id, observation_type, metadata,
                   status="COLLECTED", complete=True):
    return {
        "source": source,
        "provenance": "VERIFIED_HOST_OBSERVATION" if status == "COLLECTED" else (
            "MISSING_EVIDENCE" if status == "MISSING_EVIDENCE" else "MONITORING_FAILURE"
        ),
        "container_id": container_id,
        "timestamp_host": _utc_now(),
        "observation_type": observation_type,
        "metadata": metadata,
        "collection_status": status,
        "complete": complete,
    }


def classify_resource_outcomes(trusted_evidence, timeout):
    """Classify limits using only evidence from outside the sample process."""
    outcomes = {}

    outcomes["network"] = _resource_outcome(
        "UNKNOWN",
        "Network telemetry runs in the sample process and is not trusted for resource classification.",
    )

    if trusted_evidence.get("timeout_triggered"):
        outcomes["time"] = _resource_outcome(
            "STOPPED",
            "The runner stopped execution at the configured timeout of %s seconds."
            % timeout,
        )
    else:
        outcomes["time"] = _resource_outcome(
            "UNKNOWN",
            "Only the host runner can establish timeout enforcement; completion is not trusted.",
        )

    memory_events = trusted_evidence.get("cgroup_delta", {}).get("memory_events", {})
    pids_events = trusted_evidence.get("cgroup_delta", {}).get("pids_events", {})
    if trusted_evidence.get("docker_oom_killed") or memory_events.get("oom_kill", 0) > 0:
        outcomes["memory"] = _resource_outcome(
            "STOPPED", "Docker/cgroup evidence recorded an OOM-kill event."
        )
    elif memory_events.get("max", 0) > 0:
        outcomes["memory"] = _resource_outcome(
            "UNKNOWN",
            "Cgroup evidence recorded that the memory maximum was reached, "
            "but termination was not confirmed.",
        )
    elif memory_events.get("oom", 0) > 0:
        outcomes["memory"] = _resource_outcome(
            "UNKNOWN",
            "Cgroup evidence recorded OOM pressure, but not a confirmed termination.",
        )
    elif memory_events.get("failcnt", 0) > 0:
        outcomes["memory"] = _resource_outcome(
            "UNKNOWN",
            "Cgroup evidence recorded a memory-limit failure, but not a confirmed termination.",
        )
    elif (
        trusted_evidence.get("cgroup_delta", {}).get("memory_events_complete")
    ):
        outcomes["memory"] = _resource_outcome(
            "NOT_TRIGGERED",
            "Cgroup memory maximum, OOM, and OOM-kill counters did not increase.",
        )
    else:
        outcomes["memory"] = _resource_outcome(
            "UNKNOWN", "No complete trusted host/cgroup memory evidence was collected."
        )
    if pids_events.get("max", 0) > 0:
        outcomes["processes"] = _resource_outcome(
            "UNKNOWN",
            "Cgroup evidence recorded a PID-limit event, but termination was not established.",
        )
    elif (
        trusted_evidence.get("cgroup_delta", {}).get("pids_events_complete")
    ):
        outcomes["processes"] = _resource_outcome(
            "NOT_TRIGGERED", "Cgroup PID-limit counter did not increase."
        )
    else:
        outcomes["processes"] = _resource_outcome(
            "UNKNOWN", "No complete trusted host/cgroup process evidence was collected."
        )
    outcomes["scratch_disk"] = _resource_outcome(
        "UNKNOWN", "No trusted host-side scratch-disk evidence is collected in this milestone."
    )
    return outcomes


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
        "docker", "run", "--name", name,
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
    started_at = _utc_now()
    timed_out = False
    execution_status = "COMPLETED"
    diagnostic = "Sample completed successfully."
    inspect = None
    inspect_error = None
    cgroup_before = None
    cgroup_path = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        inspect_deadline = time.time() + min(DOCKER_COMMAND_TIMEOUT, timeout)
        while time.time() < inspect_deadline:
            candidate, _ = _docker_inspect(name, timeout=min(0.25, DOCKER_COMMAND_TIMEOUT))
            if candidate and candidate.get("State", {}).get("Pid"):
                inspect = candidate
                pid = candidate["State"]["Pid"]
                try:
                    with open("/proc/%s/cgroup" % pid, encoding="utf-8") as handle:
                        relative = handle.read().strip().split(":", 2)[-1]
                    cgroup_path = _safe_cgroup_path(
                        os.path.join("/sys/fs/cgroup", relative.lstrip("/"))
                    )
                    if cgroup_path:
                        cgroup_before = read_cgroup_snapshot(cgroup_path)
                except (OSError, ValueError):
                    pass
                break
            time.sleep(0.01)
        remaining = max(0.01, timeout - (time.time() - start))
        stdout, stderr = proc.communicate(timeout=remaining)
        code = proc.returncode
    except subprocess.TimeoutExpired as e:
        timed_out = True
        out = e.stdout
        stdout = out.decode() if isinstance(out, bytes) else (out or "")
        stderr = "KILLED: time limit exceeded"
        code = -1
        proc.kill()
        proc.communicate()
        execution_status = "TIMEOUT"
        diagnostic = "Execution exceeded the time limit."
    except OSError:
        stdout, stderr, code = "", "", -1
        execution_status = "DOCKER_FAILED"
        diagnostic = "Docker execution could not be started."
    inspect, inspect_error = _docker_inspect(name)
    container_id = inspect.get("Id") if inspect else None
    state = inspect.get("State", {}) if inspect else {}
    finish_at = _utc_now()
    cgroup_after = None
    cgroup_status = "MISSING_EVIDENCE"
    if inspect and state.get("Pid") and not cgroup_path:
        try:
            with open("/proc/%s/cgroup" % state["Pid"], encoding="utf-8") as handle:
                cgroup_relative = handle.read().strip().split(":", 2)[-1]
            cgroup_path = _safe_cgroup_path(
                os.path.join("/sys/fs/cgroup", cgroup_relative.lstrip("/"))
            )
        except (OSError, ValueError):
            cgroup_status = "COLLECTION_FAILED"
    if cgroup_path:
        cgroup_after = read_cgroup_snapshot(cgroup_path)
        cgroup_status = cgroup_after.get("status")
    cgroup_diff = cgroup_delta(cgroup_before, cgroup_after)
    host_evidence = []
    if inspect:
        host_evidence.append(_host_evidence(
            "HOST_DOCKER", container_id, "CONTAINER_STATE",
            {"state": state, "exit_code": state.get("ExitCode"),
             "oom_killed": state.get("OOMKilled", False),
             "started_at": state.get("StartedAt"), "finished_at": state.get("FinishedAt")},
        ))
    else:
        host_evidence.append(_host_evidence(
            "HOST_DOCKER", None, "CONTAINER_STATE", {"error": inspect_error},
            status="COLLECTION_FAILED", complete=False,
        ))
    if timed_out:
        host_evidence.append(_host_evidence(
            "HOST_TIMEOUT", container_id, "HOST_TIMEOUT",
            {"timeout_seconds": timeout},
        ))
    if cgroup_status != "COLLECTED":
        host_evidence.append(_host_evidence(
            "HOST_CGROUP", container_id, "CGROUP_SNAPSHOT",
            {"error": cgroup_after.get("error") if cgroup_after else "Cgroup path unavailable."},
            status=cgroup_status, complete=False,
        ))
    else:
        host_evidence.append(_host_evidence(
            "HOST_CGROUP", container_id, "CGROUP_SNAPSHOT",
            {"version": cgroup_after.get("version"), "snapshot": cgroup_after},
        ))
    cleanup_result, cleanup_error = _docker_remove(name)
    if cleanup_error:
        host_evidence.append(_host_evidence(
            "HOST_DOCKER", container_id, "CONTAINER_CLEANUP",
            {"error": cleanup_error},
            status="MONITORING_FAILURE", complete=False,
        ))
        if execution_status == "COMPLETED":
            execution_status = "DOCKER_FAILED"
            diagnostic = "Docker cleanup could not be confirmed."
    trusted_evidence = {
        "timeout_triggered": timed_out,
        "docker_oom_killed": bool(state.get("OOMKilled")),
        "cgroup_delta": cgroup_diff,
        "cgroup_complete": cgroup_diff.get("complete", False),
    }
    try:
        shutil.rmtree(workdir)
    except OSError as exc:
        host_evidence.append(_host_evidence(
            "HOST_FILESYSTEM", container_id, "TEMPORARY_FILES_CLEANUP",
            {"path": workdir, "error": str(exc)},
            status="MONITORING_FAILURE", complete=False,
        ))

    events, clean_stderr, lifecycle, malformed = _split(stderr, token)
    lifecycle_kinds = [record["kind"] for record in lifecycle]
    monitor_complete = lifecycle_kinds == [
        "monitor_started",
        "sample_started",
        "monitor_completed",
    ]
    if not timed_out and execution_status == "COMPLETED":
        if state.get("OOMKilled") or cgroup_diff.get("memory_events", {}).get("oom_kill", 0) > 0:
            execution_status = "RESOURCE_LIMIT_REACHED"
            diagnostic = "Docker/cgroup evidence reported an OOM termination."
        elif _is_docker_failure(stderr, code):
            execution_status = "DOCKER_FAILED"
            diagnostic = "Docker could not start or complete the container."
        elif cgroup_diff.get("pids_events", {}).get("max", 0) > 0:
            execution_status = "RESOURCE_LIMIT_REACHED"
            diagnostic = (
                "Cgroup evidence reported a PID-limit event; "
                "termination was not established."
            )
        elif malformed or not monitor_complete:
            execution_status = "MONITOR_FAILED"
            diagnostic = "Security monitoring did not produce complete telemetry."
        elif code != 0:
            execution_status = "EXECUTION_FAILED"
            diagnostic = "The sample exited unsuccessfully (exit code %d)." % code
    return {
        "container": name,
        "container_id": container_id,
        "execution_started_at": started_at,
        "execution_finished_at": finish_at,
        "stdout": stdout,
        "stderr": clean_stderr,
        "events": events,
        "exit_code": code,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "duration_s": round(time.time() - start, 2),
        "execution_status": execution_status,
        "diagnostic": diagnostic,
        "monitor_lifecycle": lifecycle,
        "host_evidence": host_evidence,
        "telemetry_trusted": False,
        "resource_outcomes": classify_resource_outcomes(
            trusted_evidence, timeout
        ),
    }
