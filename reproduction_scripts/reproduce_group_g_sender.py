import subprocess
import time

REPEAT_TIMES = 10  
SENDER_SCRIPT = "sender/client_group_g.py"

print("[★] Group G: Starting Missing Token test...")

for i in range(REPEAT_TIMES):
    print(f"[•] Sending attempt {i + 1}/{REPEAT_TIMES}...")
    try:
        subprocess.run(["python3", SENDER_SCRIPT], check=True)
    except subprocess.CalledProcessError:
        print(f"[✗] Error during attempt {i + 1}")
    time.sleep(1)

print("[✓] Group G missing token test completed.")