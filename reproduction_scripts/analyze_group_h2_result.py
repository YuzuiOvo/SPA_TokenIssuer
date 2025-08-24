import json
import os
import matplotlib.pyplot as plt

LOG_FILE = "verification_log.json"  # 可替换为 verification_log_h2.json
OUTPUT_DIR = "result/figures"
OUTPUT_IMG = os.path.join(OUTPUT_DIR, "group_h2_verification_chart.png")

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
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.5, int(yval), ha='center', va='bottom', fontsize=10)

plt.title("Group H2 Verification Result (Multi-Token Test)", fontsize=14)
plt.ylabel("Packet Count", fontsize=12)
plt.xticks(rotation=30, ha='right', fontsize=10)
plt.yticks(fontsize=10)
plt.ylim(0, max(values) + 5)
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()

os.makedirs(OUTPUT_DIR, exist_ok=True)
plt.savefig(OUTPUT_IMG, dpi=300)

print(f"[✓] Chart saved to: {OUTPUT_IMG}")