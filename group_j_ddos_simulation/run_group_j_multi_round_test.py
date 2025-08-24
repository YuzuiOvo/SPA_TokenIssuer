import subprocess
import time
import json
import os

ATTACKER_SCRIPT = "group_j_ddos_simulation/client_j_ddos_attacker.py"
LEGIT_SCRIPT = "group_j_ddos_simulation/client_j_legit_sender.py"
VERIFIER_SCRIPT = "group_j_ddos_simulation/edge_verifier_j.py"
LOG_FILE = "group_j_ddos_simulation/verification_log_j.json"
SUMMARY_FILE = "group_j_ddos_simulation/group_j_summary.json"

NUM_ROUNDS = 5

summary = []

for round_num in range(1, NUM_ROUNDS + 1):
    print(f"\n[★] Starting Group J Round {round_num}...")

    # Clear old logs
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    # Start the listener (child process)
    verifier = subprocess.Popen(["sudo", "python3", VERIFIER_SCRIPT])
    time.sleep(1)  # 

    # Send attack traffic
    subprocess.run(["python3", ATTACKER_SCRIPT], check=True)

    # Send legal traffic
    subprocess.run(["python3", LEGIT_SCRIPT], check=True)

    print("[•] Waiting for verifier to finish (press Ctrl+C when done)...")
    try:
        verifier.wait()
    except KeyboardInterrupt:
        print("[!] Caught Ctrl+C. Proceeding to save logs...")

    # Load and parse the logs
    if not os.path.exists(LOG_FILE):
        print(f"[✗] Log not found for round {round_num}, skipping.")
        continue

    with open(LOG_FILE, "r") as f:
        log = json.load(f)

    accepted = log.get("accepted", 0)
    total_received = log.get("total_received", 0)

    dropped_total = sum([
        log.get("dropped_signature_invalid", 0),
        log.get("dropped_expired_token", 0),
        log.get("dropped_nonce_reuse", 0),
        log.get("dropped_ip_mismatch", 0),
        log.get("dropped_missing_token", 0),
        log.get("dropped_other", 0)
    ])

    round_summary = {
        "round": round_num,
        "accepted": accepted,
        "total_received": total_received,
        "dropped_signature_invalid": log.get("dropped_signature_invalid", 0),
        "dropped_expired_token": log.get("dropped_expired_token", 0),
        "dropped_nonce_reuse": log.get("dropped_nonce_reuse", 0),
        "dropped_ip_mismatch": log.get("dropped_ip_mismatch", 0),
        "dropped_missing_token": log.get("dropped_missing_token", 0),
        "dropped_other": log.get("dropped_other", 0),
        "dropped_total": dropped_total
    }

    summary.append(round_summary)
    print(f"[✓] Round {round_num} complete. Accepted: {accepted}, Dropped: {dropped_total}")

with open(SUMMARY_FILE, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n[✓] All rounds complete. Summary saved to: {SUMMARY_FILE}")