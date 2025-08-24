import subprocess
import time
import os

REPEAT_TIMES = 50       # Number of repeated runs
INTERVAL_SEC = 1       # Interval between each run (in seconds)
SENDER_SCRIPT = os.path.join(os.getcwd(), "sender", "client_group_a.py")

# ====== Perform cyclic packet sending ======
print(f"[●] Starting Group A reproduction test ({REPEAT_TIMES} rounds)...\n")

for i in range(1, REPEAT_TIMES + 1):
    print(f"[→] Running client_group_a.py - Round {i}")
    subprocess.run(["python3", SENDER_SCRIPT])
    time.sleep(INTERVAL_SEC)

print(f"\n[✓] All {REPEAT_TIMES} test rounds completed.")
print("[✓] Please now stop the verifier and proceed to result analysis.")