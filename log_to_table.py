import json
import csv

INPUT_LOG_FILE = "verification_log.json"
OUTPUT_CSV_FILE = "verification_table.csv"
OUTPUT_LATEX_FILE = "verification_table.tex"

field_map = {
    "accepted": "Accepted (Group A)",
    "dropped_signature_invalid": "Dropped: Signature Invalid (Group C)",
    "dropped_expired_token": "Dropped: Token Expired (Group F)",
    "dropped_nonce_reuse": "Dropped: Nonce Reuse (Group B/G)",
    "dropped_ip_mismatch": "Dropped: IP Mismatch (Group D)",
    "dropped_missing_token": "Dropped: Missing Token (Group E)",
    "dropped_other": "Dropped: Other Errors",
    "total_received": "Total Received"
}

with open(INPUT_LOG_FILE, "r") as f:
    data = json.load(f)

with open(OUTPUT_CSV_FILE, "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Metric", "Count"])
    for key, label in field_map.items():
        writer.writerow([label, data.get(key, 0)])

print(f"[✓] CSV table written to: {OUTPUT_CSV_FILE}")

with open(OUTPUT_LATEX_FILE, "w") as texfile:
    texfile.write("\\begin{tabular}{|l|r|}\n\\hline\n")
    texfile.write("Metric & Count \\\\\n\\hline\n")
    for key, label in field_map.items():
        texfile.write(f"{label} & {data.get(key, 0)} \\\\\n")
    texfile.write("\\hline\n\\end{tabular}\n")

print(f"[✓] LaTeX table written to: {OUTPUT_LATEX_FILE}")