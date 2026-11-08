# Containment lab: try to start far more processes than the cage allows.
import subprocess
for i in range(200):
    subprocess.Popen(["sleep", "30"])
    print("started", i + 1, flush=True)
