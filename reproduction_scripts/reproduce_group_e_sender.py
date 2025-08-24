import subprocess
import time

REPEAT_COUNT = 10  
print("[★] Group E: Starting Nonce Reuse Test (Replay Attack)...")

for i in range(REPEAT_COUNT):
    print(f"[•] Replaying attack iteration {i+1}/{REPEAT_COUNT}...")
    try:
        subprocess.run(["python3", "sender/client_group_e.py"], check=True)
    except subprocess.CalledProcessError:
        print(f"[✗] Error during iteration {i+1}")
    time.sleep(0.5)  

print("[✓] Group E Replay Attack Test Completed.")
