import subprocess
import time

REPEAT_TIMES = 10  
SENDER_PATH = "sender/client_group_c.py"

print(f"[★] Group C: Starting forged token test (invalid signature) - Repeating {REPEAT_TIMES} times")

for i in range(REPEAT_TIMES):
    print(f"\n[→] Run #{i + 1}")
    try:
        subprocess.run(["python3", SENDER_PATH], check=True)
        print(f"[✓] Run #{i + 1} completed.")
    except subprocess.CalledProcessError:
        print(f"[✗] Error occurred during run #{i + 1}")

    time.sleep(0.5)  

print(f"\n[✓] All {REPEAT_TIMES} forged packets dispatched for Group C.")