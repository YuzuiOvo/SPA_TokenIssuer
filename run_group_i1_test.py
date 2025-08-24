import time
import json
import base64
import uuid
import os
from sender.client_i1_sender import send_token_packet  

LOG_FILE = "verification_log_i1.json"
REPEAT = 20
INTERVAL = 2  

delays = []
print("[*] Starting Group I1 automated delay test...")

for i in range(REPEAT):
    print(f"===== Round {i + 1} =====")
    delay_ms = send_token_packet(verbose=True)
    if delay_ms is not None:
        delays.append(delay_ms)
    time.sleep(INTERVAL)

summary = {
    "avg": round(sum(delays) / len(delays), 3) if delays else 0.0,
    "max": round(max(delays), 3) if delays else 0.0,
    "min": round(min(delays), 3) if delays else 0.0,
    "stddev": round((sum((x - sum(delays)/len(delays))**2 for x in delays)/len(delays))**0.5, 3) if delays else 0.0,
}

result = {
    "stats": {
        "total_sent": REPEAT,
        "valid_delays_recorded": len(delays)
    },
    "delay_samples": delays,
    "delay_summary_ms": summary
}

with open(LOG_FILE, "w") as f:
    json.dump(result, f, indent=2)

print(f"[✓] Test completed. Log saved to {LOG_FILE}")