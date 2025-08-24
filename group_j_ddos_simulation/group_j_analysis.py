import json
import matplotlib.pyplot as plt

# ====== Load the log file ======
LOG_FILE = "group_j_ddos_simulation/verification_log_j.json"

with open(LOG_FILE, "r") as f:
    stats = json.load(f)

# ====== Extract key data ======
accepted = stats.get("accepted", 0)
dropped = stats.get("total_received", 0) - accepted

labels = ["Accepted (Legitimate)", "Dropped (Blocked Attacks)"]
sizes = [accepted, dropped]
colors = ["green", "red"]

plt.figure(figsize=(6, 6))
plt.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=140)
plt.title("Group J: Legitimate vs. DDoS Packets")
plt.axis("equal")
plt.tight_layout()
plt.show()

print("\n=== Group J - DDoS Simulation Summary ===")
print(f"Total Packets Received : {stats['total_received']}")
print(f"Accepted (Legitimate)  : {accepted}")
print(f"Dropped (Blocked Attacks): {dropped}")