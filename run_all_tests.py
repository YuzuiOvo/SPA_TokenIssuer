import os
import time
import subprocess

SENDER_DIR = "sender"
SCRIPT_SEQUENCE = [
    "client_group_a.py",
    "client_group_b.py",
    "client_group_c.py",
    "client_group_d.py",
    "client_group_e.py",
    "client_group_f.py",
    "client_group_g.py"
]
ROUNDS = 20
SLEEP_INTERVAL = 5 

def run_script(script_path):
    try:
        print(f"[+] Running: {script_path}")
        subprocess.run(["sudo", "python", script_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Script failed: {script_path}")
        print(f"    Error: {e}")

if __name__ == "__main__":
    print(f"[*] Starting {ROUNDS} full test rounds (A–G), each separated by {SLEEP_INTERVAL} seconds...\n")
    
    for round_num in range(1, ROUNDS + 1):
        print(f"\n==== Round {round_num}/{ROUNDS} ====\n")
        for script in SCRIPT_SEQUENCE:
            script_path = os.path.join(SENDER_DIR, script)
            run_script(script_path)
            time.sleep(SLEEP_INTERVAL)
    
    print("\n[✓] All rounds completed. You can now stop the verifier and collect logs.")