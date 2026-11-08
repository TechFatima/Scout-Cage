# Containment lab: try to allocate far more memory than the cage allows.
chunks = []
for i in range(100):
    chunks.append(b"x" * (10 * 1024 * 1024))
    print("allocated", (i + 1) * 10, "MB", flush=True)
