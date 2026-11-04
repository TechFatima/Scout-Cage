import sys, os, json, runpy

TOKEN = os.environ.pop("SCOUT_TOKEN", "")
CANARY_KEYS = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
SENSITIVE = (".aws", "credentials", "passwd", "shadow", ".ssh", ".env")
_out = sys.stderr
_n = [0]
_busy = [False]

def emit(kind, detail):
    if _busy[0]:
        return
    _busy[0] = True
    try:
        _n[0] += 1
        rec = {"id": _n[0], "kind": kind, "detail": detail}
        _out.write("@@SCOUT:" + TOKEN + ":" + json.dumps(rec) + "\n")
        _out.flush()
    finally:
        _busy[0] = False

class Watched(dict):
    def get(self, key, default=None):
        if key in CANARY_KEYS:
            emit("env_read", key)
        return super().get(key, default)
    def __getitem__(self, key):
        if key in CANARY_KEYS:
            emit("env_read", key)
        return super().__getitem__(key)
    def items(self):
        emit("env_read", "ENUMERATE_ALL")
        return super().items()
    def keys(self):
        emit("env_read", "ENUMERATE_ALL")
        return super().keys()
    def values(self):
        emit("env_read", "ENUMERATE_ALL")
        return super().values()

os.environ = Watched(os.environ)

def hook(event, args):
    try:
        if event == "open":
            p = str(args[0])
            if any(s in p for s in SENSITIVE):
                emit("file_open", p)
        elif event == "socket.connect":
            emit("network", "connect " + str(args[1]))
        elif event == "socket.getaddrinfo":
            emit("network", "dns " + str(args[0]) + ":" + str(args[1]))
        elif event == "subprocess.Popen":
            emit("process", str(args[1])[:200])
        elif event == "os.system":
            emit("process", str(args[0])[:200])
    except Exception:
        pass

sys.addaudithook(hook)
sys.argv = ["sample.py"]
runpy.run_path("/sample/sample.py", run_name="__main__")
