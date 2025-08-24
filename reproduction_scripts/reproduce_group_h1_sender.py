import subprocess
import time

REPEAT = 10  
SENDER_A = "sender/client_h1_sender_a.py"
SENDER_B = "sender/client_h1_sender_b.py"

print(f"[★] Group H1: Starting multi-client test for {REPEAT} rounds...\n")

for i in range(REPEAT):
    print(f"[{i+1}/{REPEAT}] Sending packets from Client A...")
    subprocess.run(["python3", SENDER_A])
    time.sleep(0.5)
    print(f"[{i+1}/{REPEAT}] Sending packets from Client B...")
    subprocess.run(["python3", SENDER_B])
    time.sleep(1)

print("\n[✓] Group H1 traffic sending completed.")
print("[→] Please stop verifier and run 'analyze_group_h1_result.py' to generate the result chart.")