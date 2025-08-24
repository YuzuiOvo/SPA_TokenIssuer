import json
import os
import matplotlib.pyplot as plt

SUMMARY_FILE = "group_j_ddos_simulation/group_j_ddos_multi_type_summary.json"
OUTPUT_DIR = "result/figures"
OUTPUT_IMG = os.path.join(OUTPUT_DIR, "group_j_ddos_multi_type_chart.png")

with open(SUMMARY_FILE, "r") as f:
    data = json.load(f)

# ====== Group data integration: Aggregate multiple rounds for each attack type ======
attack_labels = []
summarized_data = []

for attack_type, entries in data.items():
    total_entry = {
        "attack_type": attack_type,
        "accepted": 0,
        "dropped_signature_invalid": 0,
        "dropped_expired_token": 0,
        "dropped_nonce_reuse": 0,
        "dropped_ip_mismatch": 0,
        "dropped_missing_token": 0,
        "dropped_other": 0,
        "total_received": 0
    }
    for entry in entries:
        for key in total_entry.keys():
            if key in entry:
                total_entry[key] += entry[key]
    summarized_data.append(total_entry)
    attack_labels.append(attack_type.replace("_", " ").title())

# ====== Set the drawing configuration ======
x = list(range(len(summarized_data)))

drop_fields = [
    ("dropped_signature_invalid", "Signature Invalid", "#1f77b4"),  # 深蓝
    ("dropped_expired_token", "Expired Token", "#ff7f0e"),         # 橙色
    ("dropped_nonce_reuse", "Nonce Reuse", "#2ca02c"),             # 深绿
    ("dropped_ip_mismatch", "IP Mismatch", "#d62728"),             # 红
    ("dropped_missing_token", "Missing Token", "#9467bd"),         # 紫
    ("dropped_other", "Other", "#8c564b")                           # 棕
]

plt.figure(figsize=(12, 6))
bottoms = [0] * len(summarized_data)

# ====== Stacked drawing ======
for field, label, color in drop_fields:
    values = [entry.get(field, 0) for entry in summarized_data]
    bars = plt.bar(x, values, bottom=bottoms, label=label, color=color)
    bottoms = [b + v for b, v in zip(bottoms, values)]

# ====== Image detail Settings ======
plt.xticks(x, attack_labels, rotation=30, ha='right', fontsize=10)
plt.ylabel("Dropped Packet Count", fontsize=12)
plt.title("Group J: Multi-Type DDoS Attack Interception Result", fontsize=14)
plt.legend(title="Drop Reason", loc="upper right", fontsize=10)
plt.tight_layout()
plt.grid(axis="y", linestyle="--", alpha=0.5)

os.makedirs(OUTPUT_DIR, exist_ok=True)
plt.savefig(OUTPUT_IMG, dpi=300)
print(f"[✓] Chart saved to: {OUTPUT_IMG}")