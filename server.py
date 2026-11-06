import os, tempfile, threading, time
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from agent import investigate

app = FastAPI()
gate = threading.Semaphore(2)

PER_IP = int(os.environ.get("RATE_PER_IP", "10"))
WINDOW = 600
DAILY = int(os.environ.get("RATE_DAILY", "200"))

_lock = threading.Lock()
_hits = defaultdict(deque)
_daily = {"day": "", "n": 0}


def check_limits(ip):
    with _lock:
        now = time.time()
        q = _hits[ip]
        while q and now - q[0] > WINDOW:
            q.popleft()
        if len(q) >= PER_IP:
            raise HTTPException(429, "Rate limit: max %d runs per 10 minutes. Please wait a bit." % PER_IP)
        today = time.strftime("%Y-%m-%d")
        if _daily["day"] != today:
            _daily["day"], _daily["n"] = today, 0
        if _daily["n"] >= DAILY:
            raise HTTPException(503, "Daily demo limit reached. Please try again tomorrow.")
        q.append(now)
        _daily["n"] += 1


class Sample(BaseModel):
    code: str


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.post("/api/analyze")
def analyze_sample(s: Sample, request: Request):
    if len(s.code) > 20000:
        raise HTTPException(413, "Sample too large (20 KB max)")
    ip = request.client.host if request.client else "unknown"
    check_limits(ip)
    if not gate.acquire(blocking=False):
        raise HTTPException(429, "Busy, try again in a moment")
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=".py", prefix="upload_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(s.code)
        return investigate(path)
    finally:
        gate.release()
        if path and os.path.exists(path):
            os.remove(path)
