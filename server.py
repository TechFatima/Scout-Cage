import os, tempfile, threading
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from agent import investigate

app = FastAPI()
gate = threading.Semaphore(2)


class Sample(BaseModel):
    code: str


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.post("/api/analyze")
def analyze_sample(s: Sample):
    if len(s.code) > 20000:
        raise HTTPException(413, "Sample too large (20 KB max)")
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
