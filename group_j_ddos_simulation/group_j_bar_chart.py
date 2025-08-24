import json
import os
import matplotlib.pyplot as plt

SUMMARY_FILE = "group_j_ddos_simulation/group_j_ddos_multi_type_summary.json"
OUTPUT_IMG = "result/figures/group_j_ddos_attack_comparison_chart.png"

# ====== Make sure the output directory exists ======
os.makedirs(os.path.dirname(OUTPUT_IMG), exist_ok=True)

# ====== Load data ======
if not os.path.exists(SUMMARY_FILE):
    print(f"[✗] Summary file not found: {SUMMARY_FILE}")
    exit(1)

with open(SUMMARY_FILE, "r") as f:
    data = json.load(f)

# ====== Extract the cumulative value of each type of attack ======
attack_types = []
accepted = []
dropped_sig = []
dropped_expired = []
dropped_nonce = []
dropped_ip = []
dropped_missing = []
dropped_other = []

for attack, records in data.items():
    attack_types.append(attack.replace("_", " ").title())
    accepted.append(sum(r["accepted"] for r in records))
    dropped_sig.append(sum(r.get("dropped_signature_invalid", 0) for r in records))
    dropped_expired.append(sum(r.get("dropped_expired_token", 0) for r in records))
    dropped_nonce.append(sum(r.get("dropped_nonce_reuse", 0) for r in records))
    dropped_ip.append(sum(r.get("dropped_ip_mismatch", 0) for r in records))
    dropped_missing.append(sum(r.get("dropped_missing_token", 0) for r in records))
    dropped_other.append(sum(r.get("dropped_other", 0) for r in records))

# ====== Draw a stacked bar chart ======
bar_width = 0.6
plt.figure(figsize=(12, 7))

bottom = [0] * len(attack_types)
plt.bar(attack_types, accepted, label="Accepted", color="green", bottom=bottom)
bottom = [i + j for i, j in zip(bottom, accepted)]

plt.bar(attack_types, dropped_sig, label="Invalid Signature", color="#e6194b", bottom=bottom)
bottom = [i + j for i, j in zip(bottom, dropped_sig)]

plt.bar(attack_types, dropped_expired, label="Expired Token", color="#ffe119", bottom=bottom)
bottom = [i + j for i, j in zip(bottom, dropped_expired)]

plt.bar(attack_types, dropped_nonce, label="Nonce Reuse", color="#4363d8", bottom=bottom)
bottom = [i + j for i, j in zip(bottom, dropped_nonce)]

plt.bar(attack_types, dropped_ip, label="IP Mismatch", color="#f58231", bottom=bottom)
bottom = [i + j for i, j in zip(bottom, dropped_ip)]

plt.bar(attack_types, dropped_missing, label="Missing Token", color="#911eb4", bottom=bottom)
bottom = [i + j for i, j in zip(bottom, dropped_missing)]

plt.bar(attack_types, dropped_other, label="Other", color="gray", bottom=bottom)

plt.title("Group J – DDoS Attack Type Comparison (Stacked)", fontsize=14)
plt.ylabel("Total Packet Count", fontsize=12)
plt.xticks(rotation=30, ha="right")
plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()

plt.savefig(OUTPUT_IMG, dpi=300)
print(f"[✓] Chart saved to: {OUTPUT_IMG}")