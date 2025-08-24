import json
import matplotlib.pyplot as plt
import os

LOG_PATH = "verification_log.json"
OUTPUT_DIR = "result/figures"
os.makedirs(OUTPUT_DIR, exist_ok=True)
FIG_PATH = os.path.join(OUTPUT_DIR, "group_c_verification_chart.png")

if not os.path.exists(LOG_PATH):
    print(f"[✗] Log file not found: {LOG_PATH}")
    exit(1)

with open(LOG_PATH, "r") as f:
    data = json.load(f)

# ====== Define fields and labels ======
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

counts = [data.get(k, 0) for k in keys]

plt.figure(figsize=(10, 6))
bars = plt.bar(labels, counts, color=["green"] + ["red"] * (len(labels) - 1))

for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2.0, yval + 0.5, f"{int(yval)}", ha='center', va='bottom', fontsize=11)

plt.title("Group C: Signature Forgery Detection Result", fontsize=14)
plt.ylabel("Packet Count", fontsize=12)
plt.xticks(rotation=30, ha="right", fontsize=11)
plt.yticks(fontsize=11)
plt.ylim(0, max(counts) + 5)
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig(FIG_PATH, dpi=300)

print(f"[✓] Chart saved to: {FIG_PATH}")