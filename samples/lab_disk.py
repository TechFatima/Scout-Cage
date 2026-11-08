# Containment lab: try to write far more data than the scratch space allows.
with open("/tmp/fill.bin", "wb") as f:
    for i in range(100):
        f.write(b"x" * (1024 * 1024))
        f.flush()
        print("wrote", i + 1, "MB", flush=True)
