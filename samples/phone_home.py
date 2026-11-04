import socket
try:
    socket.create_connection(("1.1.1.1", 80), timeout=3)
    print("NETWORK_OPEN")
except Exception as e:
    print("NETWORK_BLOCKED:", type(e).__name__)
