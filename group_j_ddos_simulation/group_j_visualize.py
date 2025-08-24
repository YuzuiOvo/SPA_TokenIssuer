import json
import os
import matplotlib.pyplot as plt

SUMMARY_FILE = "group_j_ddos_simulation/group_j_summary.json"
OUTPUT_DIR = "result/figures"
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(SUMMARY_FILE, "r") as f:
    data = json.load(f)

if not data:
    print("[✗] No data found in summary file.")
    exit(1)

last = data[-1]
accepted = last["accepted"]
dropped_total = sum([
    last["dropped_signature_invalid"],
    last["dropped_expired_token"],
    last["dropped_nonce_reuse"],
    last["dropped_ip_mismatch"],
    last["dropped_missing_token"],
    last["dropped_other"]
])

plt.figure(figsize=(6, 6))
plt.pie(
    [accepted, dropped_total],
    labels=["Accepted (Legitimate)", "Dropped (Attacks)"],
    colors=["green", "red"],
    autopct="%1.1f%%",
    startangle=140
)
plt.title("Group J - Legitimate vs DDoS Packets (Last Round)")
plt.axis("equal")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "group_j_pie_chart.png"), dpi=300)

drop_labels = [
    "Signature Invalid", "Expired Token", "Nonce Reuse",
    "IP Mismatch", "Missing Token", "Other"
]
drop_keys = [
    "dropped_signature_invalid", "dropped_expired_token",
    "dropped_nonce_reuse", "dropped_ip_mismatch",
    "dropped_missing_token", "dropped_other"
]

drop_totals = [sum(r[k] for r in data) for k in drop_keys]

plt.figure(figsize=(10, 6))
bars = plt.bar(drop_labels, drop_totals, color="tomato")
for bar in bars:
    y = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, y + 1, str(y), ha='center', va='bottom')
plt.title("Group J - Dropped Packet Reasons (Across Rounds)", fontsize=14)
plt.ylabel("Count", fontsize=12)
plt.xticks(rotation=30, ha='right')
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "group_j_drops_bar_chart.png"), dpi=300)

rounds = [r["round"] for r in data]
accepted_counts = [r["accepted"] for r in data]

plt.figure(figsize=(10, 6))
plt.plot(rounds, accepted_counts, marker="o", linestyle="-", color="green")
for x, y in zip(rounds, accepted_counts):
    plt.text(x, y + 1, str(y), ha="center", fontsize=10)
plt.title("Group J - Accepted Packets Over Rounds", fontsize=14)
plt.xlabel("Round", fontsize=12)
plt.ylabel("Accepted Packets", fontsize=12)
plt.grid(True, linestyle="--", alpha=0.6)
plt.xticks(rounds)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "group_j_accepted_line_chart.png"), dpi=300)

print("[✓] All Group J charts saved to result/figures/")