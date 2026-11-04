def analyze(events):
    findings = []

    def add(kind, title, evs):
        if evs:
            findings.append({"kind": kind, "title": title,
                             "evidence": [e["id"] for e in evs]})

    env = [e for e in events if e["kind"] == "env_read"]
    files = [e for e in events if e["kind"] == "file_open"]
    net = [e for e in events if e["kind"] == "network"]
    proc = [e for e in events if e["kind"] == "process"]

    add("canary_env", "Read fake secret environment variables", env)
    add("canary_file", "Opened sensitive or credential files", files)
    add("network", "Attempted network access (blocked by sandbox)", net)
    add("process", "Spawned other processes", proc)

    if (env or files) and net:
        verdict = "HIGH"
    elif findings:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"
    return {"verdict": verdict, "findings": findings}
