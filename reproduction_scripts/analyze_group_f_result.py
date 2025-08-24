import json
import os
import matplotlib.pyplot as plt

LOG_FILE = "verification_log.json"
OUTPUT_DIR = "result/figures"
os.makedirs(OUTPUT_DIR, exist_ok=True)
FIG_PATH = os.path.join(OUTPUT_DIR, "group_f_verification_chart.png")

if not os.path.exists(LOG_FILE):
    print(f"[✗] Log file not found: {LOG_FILE}")
    exit(1)

with open(LOG_FILE, "r") as f:
    data = json.load(f)

labels = [
    "Accepted",
    "Invalid Signature",
    "Expired Token",
    "Nonce Reuse",
    "IP Mismatch",
    "Missing Token",
    "Malformed JSON",
    "Other Drop"
]

keys = [
    "accepted",
    "dropped_signature_invalid",
    "dropped_expired_token",
    "dropped_nonce_reuse",
    "dropped_ip_mismatch",
    "dropped_missing_token",
    "dropped_malformed_json",
    "dropped_other"
]

values = [data.get(k, 0) for k in keys]

plt.figure(figsize=(10, 6))
bars = plt.bar(labels, values, color=["green"] + ["red"] * (len(labels) - 1))

for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2.0, height + 0.5, f"{int(height)}", ha='center', va='bottom', fontsize=10)

plt.title("Group F Verification Result (Nonce Reuse Test)", fontsize=14)
plt.ylabel("Packet Count", fontsize=12)
plt.xticks(rotation=30, ha='right', fontsize=11)
plt.yticks(fontsize=11)
plt.ylim(0, max(values) + 5)
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()

plt.savefig(FIG_PATH, dpi=300)
print(f"[✓] Chart saved to: {FIG_PATH}")