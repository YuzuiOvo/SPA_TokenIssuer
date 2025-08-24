import json
import csv

INPUT_LOG_FILE = "verification_log.json"
OUTPUT_CSV_FILE = "chart_data.csv"

groups = {
    "Group A": "accepted",
    "Group B": "dropped_nonce_reuse",
    "Group C": "dropped_signature_invalid",
    "Group D": "dropped_ip_mismatch",
    "Group E": "dropped_missing_token",
    "Group F": "dropped_expired_token",
    "Group G": "dropped_nonce_reuse"
}

with open(INPUT_LOG_FILE, "r") as f:
    stats = json.load(f)

with open(OUTPUT_CSV_FILE, "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Group", "Passed", "Dropped"])

    for group, key in groups.items():
        if group == "Group A":
            passed, dropped = stats.get(key, 0), 0
        elif group == "Group G":
            passed = 1  
            dropped = stats.get(key, 0) - passed
        else:
            passed, dropped = 0, stats.get(key, 0)

        writer.writerow([group, passed, dropped])

print(f"[✓] CSV data saved to: {OUTPUT_CSV_FILE}")