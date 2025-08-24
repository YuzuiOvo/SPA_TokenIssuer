import json
import os
import matplotlib.pyplot as plt

LOG_FILE = "i1_verification_log.json"
OUTPUT_DIR = "result/figures"
OUTPUT_IMG = os.path.join(OUTPUT_DIR, "group_i1_delay_chart.png")

if not os.path.exists(LOG_FILE):
    print(f"[✗] Log file not found: {LOG_FILE}")
    exit(1)

with open(LOG_FILE, "r") as f:
    data = json.load(f)

samples = data.get("delay_samples", [])
summary = data.get("delay_summary_ms", {})

if not samples:
    print("[✗] No delay samples found in log.")
    exit(1)

plt.figure(figsize=(10, 6))
plt.bar(range(len(samples)), samples, color="blue")

plt.title("Group I1: Packet Verification Delays (ms)", fontsize=14)
plt.xlabel("Packet Index", fontsize=12)
plt.ylabel("Verification Delay (ms)", fontsize=12)
plt.xticks(range(len(samples)), [f"Pkt {i+1}" for i in range(len(samples))], rotation=45, fontsize=9)
plt.yticks(fontsize=10)
plt.grid(axis="y", linestyle="--", alpha=0.6)

summary_text = f"Avg: {summary.get('avg', 0)} ms\nMax: {summary.get('max', 0)} ms\nMin: {summary.get('min', 0)} ms\nStddev: {summary.get('stddev', 0)} ms"
plt.gca().text(1.02, 0.95, summary_text, transform=plt.gca().transAxes,
               fontsize=10, verticalalignment='top', bbox=dict(facecolor='lightyellow', edgecolor='gray'))

plt.tight_layout()
os.makedirs(OUTPUT_DIR, exist_ok=True)
plt.savefig(OUTPUT_IMG, dpi=300)

print(f"[✓] Delay chart saved to: {OUTPUT_IMG}")