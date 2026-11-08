"""Deterministic static scan of a submitted Python script.

This reads the source with the ast module. It never runs the code.
It lists capabilities found in the source; it is not proof of intent.
"""
import ast
import base64
import binascii
import re

NETWORK_CALL_PREFIXES = ("socket.", "urllib.request.", "http.client.", "requests.",
                         "httpx.", "ftplib.", "smtplib.", "telnetlib.", "urllib3.")
PROCESS_CALLS = ("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn",
                 "os.fork", "os.posix_spawn", "pty.spawn")
DYNAMIC_CALLS = {"exec", "eval", "compile", "__import__"}
SOCKET_METHODS = {"connect", "connect_ex", "sendall", "sendto"}
BULK_ENV_METHODS = {"items", "keys", "values", "copy"}

CRED_ENV = re.compile(r"(AWS_|SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
CRED_PATH = re.compile(r"(\.aws/credentials|\.ssh|id_rsa|id_ed25519|/etc/passwd|/etc/shadow|"
                       r"\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker/config\.json|(^|/)\.env$)", re.I)
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|xyz|top|ru|cn|info|biz|co|app|cloud|test)\b", re.I)


def _dotted(node, aliases):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(aliases.get(node.id, node.id))
        return ".".join(reversed(parts))
    return None


def _decode_b64(text):
    try:
        raw = base64.b64decode(text, validate=True)
        out = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not out or len(out) > 300 or not out.isprintable():
        return None
    return out


def _looks_like_target(text):
    return bool(URL_RE.search(text) or IP_RE.search(text) or HOST_RE.search(text) or CRED_PATH.search(text))


def static_scan(source):
    try:
        tree = ast.parse(source)
    except Exception:
        return {"indicators": [], "hidden": [], "parse_error": True}

    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    root = a.name.split(".")[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                aliases[a.asname or a.name] = node.module + "." + a.name

    found, hidden, seen = [], [], set()

    def add(kind, title, node, conf, detail=""):
        line = getattr(node, "lineno", 0)
        key = (kind, title, line)
        if key in seen:
            return
        seen.add(key)
        found.append({"kind": kind, "title": title, "line": line,
                      "confidence": conf, "detail": detail})

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = _dotted(func, aliases) if isinstance(func, (ast.Attribute, ast.Name)) else None
            if name:
                if name.startswith(NETWORK_CALL_PREFIXES):
                    add("network", "Network call", node, "high", name + "(...)")
                elif name.startswith(PROCESS_CALLS):
                    add("process", "Starts another process", node, "high", name + "(...)")
                elif name in DYNAMIC_CALLS:
                    add("dynamic", "Runs code built at runtime", node, "high", name + "(...)")
                elif name in ("os.getenv", "os.environ.get") and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and CRED_ENV.search(arg.value):
                        add("credentials", "Reads a credential-like environment variable", node, "high", arg.value)
                elif name == "open" and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and CRED_PATH.search(arg.value):
                        add("credentials", "Opens a credential-like file", node, "high", arg.value)
                elif name in ("base64.b64decode", "base64.urlsafe_b64decode") and node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        decoded = _decode_b64(arg.value)
                        if decoded and _looks_like_target(decoded):
                            hidden.append({"line": node.lineno, "encoded": arg.value[:80], "decoded": decoded})
                            add("host", "Hidden target after decoding", node, "medium", decoded)
                elif name == "dict" and node.args and _dotted(node.args[0], aliases) == "os.environ":
                    add("credentials", "Copies every environment variable", node, "medium", "dict(os.environ)")
            if isinstance(func, ast.Attribute):
                if func.attr in SOCKET_METHODS:
                    add("network", "Calls a socket-style method", node, "medium", "." + func.attr + "(...)")
                if func.attr in BULK_ENV_METHODS and _dotted(func.value, aliases) == "os.environ":
                    add("credentials", "Enumerates every environment variable", node, "medium", "os.environ." + func.attr + "()")
        elif isinstance(node, ast.Subscript):
            if _dotted(node.value, aliases) == "os.environ":
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and CRED_ENV.search(key.value):
                    add("credentials", "Reads a credential-like environment variable", node, "high", key.value)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if len(text) > 300:
                continue
            if CRED_PATH.search(text):
                add("credentials", "Mentions a credential-like path", node, "medium", text)
            if URL_RE.search(text) or IP_RE.search(text) or HOST_RE.search(text):
                add("host", "Hard-coded host or address", node, "medium", text)

    found.sort(key=lambda i: (i["line"], i["kind"]))
    return {"indicators": found, "hidden": hidden, "parse_error": False}


def cross_check(static, events, execution_status=None):
    """Compare what the code contains with what the cage observed."""
    kinds = {e.get("kind") for e in (events or []) if isinstance(e, dict)}
    observed, not_observed = [], []
    for cat, ev in (("network", {"network"}), ("process", {"process"}),
                    ("credentials", {"env_read", "file_open"})):
        highs = [i for i in static.get("indicators", []) if i["kind"] == cat and i["confidence"] == "high"]
        if not highs:
            continue
        entry = {"kind": cat, "lines": sorted({i["line"] for i in highs})}
        (observed if kinds & ev else not_observed).append(entry)
    return {"observed": observed, "not_observed": not_observed,
            "complete": execution_status == "COMPLETED"}
