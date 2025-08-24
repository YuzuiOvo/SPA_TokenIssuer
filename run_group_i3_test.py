import subprocess
import time
import json
import os

SENDER_SCRIPT = "sender/client_i3_sender.py"
VERIFIER_SCRIPT = "verifier/edge_verifier_i3.py"
VERIFICATION_LOG = "verification_log.json"
OUTPUT_RESULT = "group_i3_throughput_summary.json"

NUM_ROUNDS = 5
WAIT_FOR_LOG_TIMEOUT = 20
WAIT_INTERVAL = 1

def wait_for_log(timeout=WAIT_FOR_LOG_TIMEOUT, interval=WAIT_INTERVAL):
    waited = 0
    while waited < timeout:
        if os.path.exists(VERIFICATION_LOG):
            try:
                with open(VERIFICATION_LOG, "r") as f:
                    json.load(f)  
                return True
            except json.JSONDecodeError:
                pass
        time.sleep(interval)
        waited += interval
    return False

summary = []

for round_num in range(1, NUM_ROUNDS + 1):
    print(f"\n[★] Starting Round {round_num} of Group I3 Throughput Test")

    if os.path.exists(VERIFICATION_LOG):
        os.remove(VERIFICATION_LOG)

    verifier = subprocess.Popen(["sudo", "python3", VERIFIER_SCRIPT])
    time.sleep(1)

    start = time.time()
    try:
        subprocess.run(["sudo", "python3", SENDER_SCRIPT], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[✗] Sender failed in round {round_num}: {e}")
        verifier.terminate()
        continue
    verifier.wait()
    end = time.time()

    if not wait_for_log():
        print(f"[✗] Timeout waiting for log in round {round_num}")
        continue

    try:
        with open(VERIFICATION_LOG, "r") as f:
            log = json.load(f)
    except Exception as e:
        print(f"[✗] Failed to parse log: {e}")
        continue

    accepted = log.get("accepted", 0)
    duration = end - start
    throughput = accepted / duration if duration > 0 else 0

    round_result = {
        "round": round_num,
        "accepted": accepted,
        "duration_sec": duration,
        "throughput_pps": round(throughput, 3)
    }

    summary.append(round_result)
    print(f"[✓] Round {round_num} throughput = {round_result['throughput_pps']} pps")

with open(OUTPUT_RESULT, "w") as f:
    json.dump(summary, f, indent=2)

print(f"\n[✓] All rounds complete. Summary saved to: {OUTPUT_RESULT}")