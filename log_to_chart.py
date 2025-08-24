import json
import matplotlib.pyplot as plt

INPUT_LOG_FILE = "verification_log.json"
OUTPUT_PNG_FILE = "verification_result_chart.png"

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

x_labels = list(groups.keys())
pass_counts = []
fail_counts = []

for group, stat_key in groups.items():
    if group == "Group A":
        pass_count = stats.get(stat_key, 0)
        fail_count = 0
    elif group == "Group G":
        pass_count = 1
        fail_count = stats.get(stat_key, 0) - pass_count
    else:
        pass_count = 0
        fail_count = stats.get(stat_key, 0)

    pass_counts.append(pass_count)
    fail_counts.append(fail_count)

x = range(len(x_labels))
bar_width = 0.4

plt.figure(figsize=(10, 6))
plt.bar(x, pass_counts, width=bar_width, label="Passed", color="green")
plt.bar([i + bar_width for i in x], fail_counts, width=bar_width, label="Dropped", color="red")
plt.xticks([i + bar_width / 2 for i in x], x_labels)
plt.ylabel("Packet Count")
plt.title("SPA Attack Identification — Group A–G")
plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.7)

plt.tight_layout()
plt.savefig(OUTPUT_PNG_FILE, dpi=300)
print(f"[✓] Chart saved as: {OUTPUT_PNG_FILE}")
plt.show()