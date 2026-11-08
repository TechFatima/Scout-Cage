def analyze(events, execution_status=None, telemetry_trusted=False):
    findings = []

    def add(kind, title, evs):
        if evs:
            findings.append({"kind": kind, "title": title,
                             "evidence": [e["id"] for e in evs],
                             "evidence_status": (
                                 "AUTHENTICATED" if telemetry_trusted
                                 else "UNVERIFIED_RUNTIME_OBSERVATION"
                             )})

    env = [e for e in events if e["kind"] == "env_read"]
    files = [e for e in events if e["kind"] == "file_open"]
    net = [e for e in events if e["kind"] == "network"]
    proc = [e for e in events if e["kind"] == "process"]

    add("canary_env", "Read fake secret environment variables", env)
    add("canary_file", "Opened sensitive or credential files", files)
    add("network", "Attempted network access (blocked by sandbox)", net)
    add("process", "Spawned other processes", proc)

    if not telemetry_trusted:
        # The sample shares the monitor process and can forge or suppress events.
        verdict = "INCONCLUSIVE"
    elif (env or files) and net:
        verdict = "HIGH"
    elif findings:
        verdict = "MEDIUM"
    elif execution_status == "COMPLETED":
        verdict = "LOW"
    else:
        # Incomplete or untrusted run with nothing logged: never call it safe.
        verdict = "INCONCLUSIVE"
    return {"verdict": verdict, "findings": findings}
