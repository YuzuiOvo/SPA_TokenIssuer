import os
import subprocess
import time
import json

# ====== Attack type and corresponding script file name ======
ATTACK_TYPES = {
    "missing_token": "missing_token_attacker.py",
    "invalid_signature": "invalid_signature_attacker.py",
    "expired_token": "expired_token_attacker.py",
    "nonce_reuse": "nonce_reuse_attacker.py",
    "ip_mismatch": "ip_mismatch_attacker.py"
}

ATTACK_DIR = "group_j_ddos_simulation/attack_types"
VERIFIER_SCRIPT = "group_j_ddos_simulation/edge_verifier_j.py"
LOG_FILE = "group_j_ddos_simulation/verification_log_j.json"
OUTPUT_SUMMARY = "group_j_ddos_simulation/group_j_ddos_multi_type_summary.json"
NUM_ROUNDS = 5
WAIT_TIMEOUT = 20

# ====== Wait for the log file ======
def wait_for_log(timeout=WAIT_TIMEOUT):
    waited = 0
    while waited < timeout:
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r") as f:
                    json.load(f)
                return True
            except json.JSONDecodeError:
                pass
        time.sleep(1)
        waited += 1
    return False

summary = {}

for attack_type, script_name in ATTACK_TYPES.items():
    print(f"\n=== [★] Testing Attack Type: {attack_type} ===")
    summary[attack_type] = []

    for round_num in range(1, NUM_ROUNDS + 1):
        print(f"\n→ Round {round_num}")

        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)

        # Start the validator
        verifier = subprocess.Popen(["sudo", "python3", VERIFIER_SCRIPT])
        time.sleep(1)

        # Start the attack packet sending script
        script_path = os.path.join(ATTACK_DIR, script_name)
        try:
            subprocess.run(["sudo", "python3", script_path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[✗] Attack script failed: {e}")
            verifier.terminate()
            continue

        print("[•] Waiting for verifier to finish... (Ctrl+C to stop)")
        try:
            verifier.wait()
        except KeyboardInterrupt:
            print("[✓] Manually stopped verifier.")

        # Wait for the log to be written
        if not wait_for_log():
            print("[✗] Timeout waiting for verification log.")
            continue

        # Read the result
        try:
            with open(LOG_FILE, "r") as f:
                result = json.load(f)
                result["round"] = round_num
                summary[attack_type].append(result)
                print(f"[✓] Round {round_num} done. Packets received: {result.get('total_received', 0)}")
        except Exception as e:
            print(f"[✗] Failed to read log: {e}")

# ====== Output the summary result ======
with open(OUTPUT_SUMMARY, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n[✓] All attack types tested. Summary saved to: {OUTPUT_SUMMARY}")