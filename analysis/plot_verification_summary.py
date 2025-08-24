import matplotlib.pyplot as plt

# Classification statistics (only for valid script test packages)
labels = [
    "Accepted (A)", 
    "Sig. Invalid (C)", 
    "Expired Token (F)", 
    "Nonce Reuse (B+G)", 
    "IP Mismatch (D)"
]
values = [26, 20, 20, 74, 20]

colors = ["#4CAF50", "#F44336", "#FF9800", "#2196F3", "#9C27B0"]

plt.figure(figsize=(10, 6))
bars = plt.bar(labels, values, color=colors)

# Add numeric labels
for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2, yval + 2, f'{yval}', ha='center', fontsize=11)

plt.title("Verification Outcomes of SPA Token Experiment (140 Packets)", fontsize=14)
plt.xlabel("Test Case Categories")
plt.ylabel("Packet Count")
plt.ylim(0, max(values) + 10)
plt.grid(axis='y', linestyle='--', alpha=0.6)
plt.tight_layout()
plt.show()