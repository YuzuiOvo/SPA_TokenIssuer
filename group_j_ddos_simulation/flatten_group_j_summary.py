import json
import os
from collections import defaultdict

INPUT_FILE = "group_j_ddos_simulation/group_j_ddos_multi_type_summary.json"
OUTPUT_FILE = "group_j_ddos_simulation/group_j_ddos_multi_type_summary_flat.json"

with open(INPUT_FILE, "r") as f:
    nested_data = json.load(f)

flat_summary = []

for attack_type, rounds in nested_data.items():
    agg = defaultdict(int)
    for entry in rounds:
        for k, v in entry.items():
            if k != "round":
                agg[k] += v
    agg["attack_type"] = attack_type
    flat_summary.append(dict(agg))

with open(OUTPUT_FILE, "w") as f:
    json.dump(flat_summary, f, indent=2)

print(f"[✓] Flattened summary saved to: {OUTPUT_FILE}")