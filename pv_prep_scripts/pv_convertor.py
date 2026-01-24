# Extracts data from selected fields from all primevul_*.jsonl and stores as primevul_*.xlsx

import json
import pandas as pd

# --- CONFIGURATION ---
source_file = 'primevul_valid_paired.jsonl'  # Update this if your filename is different
output_file = 'primevul_valid_paired.xlsx'

# The specific columns you requested
target_columns = ["project", "commit_id", "project_url", "cwe", "cve"]

extracted_data = []

print(f"Reading {source_file} line by line...")

try:
    with open(source_file, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            try:
                # 1. Parse the JSON line manually
                item = json.loads(line)

                # 2. Extract ONLY the fields we need
                # We use .get() so it doesn't crash if a field is missing
                row = {
                    "project": item.get("project"),
                    "commit_id": item.get("commit_id"),
                    "project_url": item.get("project_url"),
                    "cwe": item.get("cwe"),
                    "cve": item.get("cve")
                }

                # 3. Clean the 'cwe' list immediately (["CWE-123"] -> "CWE-123")
                if isinstance(row["cwe"], list):
                    row["cwe"] = ", ".join(row["cwe"])

                extracted_data.append(row)

                # Optional: Print progress every 10,000 rows
                if (i + 1) % 10000 == 0:
                    print(f"Processed {i + 1} rows...")

            except json.JSONDecodeError:
                print(f"Skipping bad JSON at line {i+1}")

    print(f"Finished reading. Total rows extracted: {len(extracted_data)}")
    print("Converting to Excel...")

    # 4. Convert the clean, small data to DataFrame
    df = pd.DataFrame(extracted_data)

    # 5. Save to Excel
    df.to_excel(output_file, index=False)
    print(f"Success! Saved as: {output_file}")

except FileNotFoundError:
    print(f"Error: Could not find file '{source_file}'")
except Exception as e:
    print(f"An error occurred: {e}")