import json
import os
import matplotlib.pyplot as plt

INPUT_FILE = "group_i3_throughput_summary.json"
OUTPUT_DIR = "result/figures"
OUTPUT_IMG = os.path.join(OUTPUT_DIR, "group_i3_throughput_chart.png")

if not os.path.exists(INPUT_FILE):
    print(f"[✗] Summary file not found: {INPUT_FILE}")
    exit(1)

with open(INPUT_FILE, "r") as f:
    data = json.load(f)

if not data:
    print("[✗] No data to plot.")
    exit(1)

labels = [f"Run {entry['round']}" for entry in data]
values = [entry["throughput_pps"] for entry in data]

plt.figure(figsize=(10, 6))
bars = plt.bar(labels, values, color="skyblue")

for bar, val in zip(bars, values):
    plt.text(bar.get_x() + bar.get_width() / 2.0, bar.get_height() + 0.5, f"{val:.2f}", 
             ha='center', va='bottom', fontsize=10)

plt.title("Group I3 Throughput Test (Multiple Runs)", fontsize=14)
plt.ylabel("Throughput (packets/sec)", fontsize=12)
plt.ylim(0, max(values) + 5)
plt.xticks(rotation=30, ha='right')
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()

os.makedirs(OUTPUT_DIR, exist_ok=True)
plt.savefig(OUTPUT_IMG, dpi=300)
print(f"[✓] Chart saved to: {OUTPUT_IMG}")