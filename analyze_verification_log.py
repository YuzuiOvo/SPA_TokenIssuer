import json
import matplotlib.pyplot as plt
import os

LOG_FILE = "verification_log.json"

if not os.path.exists(LOG_FILE):
    print(f"[✗] The log file was not found: {LOG_FILE}")
    exit(1)

with open(LOG_FILE, "r") as f:
    stats = json.load(f)

total = stats.get("total_received", 0)
print(f"\n[✓] The total number of received data packets: {total}\n")

print("📊 Detailed statistics (quantity/proportion):")
labels = []
counts = []
ratios = []

for key, value in stats.items():
    if key == "total_received":
        continue
    labels.append(key)
    counts.append(value)
    ratio = (value / total) * 100 if total > 0 else 0
    ratios.append(ratio)
    print(f"- {key:<25}: {value:>3} ({ratio:.2f}%)")

plt.figure(figsize=(10, 6))
bars = plt.bar(labels, counts)

for bar, ratio in zip(bars, ratios):
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, height + 1,
             f"{height} ({ratio:.1f}%)", ha='center', va='bottom')

plt.title("Statistical results of multi-round validation of Group H1 (including proportion)")
plt.xlabel("Verification result type")
plt.ylabel("The number of data packets")
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.xticks(rotation=30)
plt.tight_layout()

output_image = "verification_summary.png"
plt.savefig(output_image)
print(f"\n[✓] The chart has been saved as: {output_image}")

plt.show()