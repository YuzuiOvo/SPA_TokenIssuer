import json
import os
import matplotlib.pyplot as plt

LOG_FILE = "verification_log.json"
OUTPUT_DIR = "result/figures"
OUTPUT_IMG = os.path.join(OUTPUT_DIR, "group_b_verification_chart.png")

if not os.path.exists(LOG_FILE):
    print(f"[✗] Log file not found: {LOG_FILE}")
    exit(1)

with open(LOG_FILE, "r") as f:
    data = json.load(f)

stats = {
    "Accepted": data.get("accepted", 0),
    "Invalid Signature": data.get("dropped_signature_invalid", 0),
    "Expired Token": data.get("dropped_expired_token", 0),
    "Nonce Reuse": data.get("dropped_nonce_reuse", 0),
    "IP Mismatch": data.get("dropped_ip_mismatch", 0),
    "Missing Token": data.get("dropped_missing_token", 0),
    "Malformed JSON": data.get("dropped_malformed_json", 0),
    "Other Drop": data.get("dropped_other", 0),
}

print("[✓] Log parsed:")
for k, v in stats.items():
    print(f"    {k}: {v}")

plt.figure(figsize=(10, 6))
bars = plt.bar(stats.keys(), stats.values(), color=["green"] + ["red"] * (len(stats) - 1))

for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.5, f"{yval}", ha='center', va='bottom', fontsize=10)

plt.title("Group B Verification Result (Replay Attack Simulation)", fontsize=14)
plt.ylabel("Packet Count", fontsize=12)
plt.xticks(rotation=30, fontsize=10)
plt.yticks(fontsize=10)
plt.ylim(0, max(stats.values()) + 10)
plt.grid(axis="y", linestyle="--", alpha=0.6)

os.makedirs(OUTPUT_DIR, exist_ok=True)
plt.tight_layout()
plt.savefig(OUTPUT_IMG, dpi=300)
print(f"[✓] Chart saved to: {OUTPUT_IMG}")