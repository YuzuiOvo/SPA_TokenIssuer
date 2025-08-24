import subprocess
import time

SENDER_SCRIPT = "sender/client_group_b.py"
REPEAT = 10  

print("[*] Starting reproduction of Group B test...")

for i in range(REPEAT):
    print(f"\n[→] Running iteration {i+1}/{REPEAT}...")
    subprocess.run(["python3", SENDER_SCRIPT], check=True)
    time.sleep(1)

print(f"\n[✓] Group B traffic reproduction completed ({REPEAT} runs).")