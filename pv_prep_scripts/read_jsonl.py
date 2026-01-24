####### Code for extracting all the fields and their data from jsonl and exporting to the Excel with same name #######
import json
import pandas as pd

input_file = "primevul_valid.jsonl"
output_excel = "primevul_valid.xlsx"

records = []

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        try:
            obj = json.loads(line)

            if isinstance(obj, dict):
                records.append(obj)

        except json.JSONDecodeError:
            pass

# Convert to DataFrame
df = pd.DataFrame(records)

# Columns that must not be converted to scientific notation
cols_to_string = ["func_hash", "file_hash"]

for col in cols_to_string:
    if col in df.columns:
        df[col] = df[col].astype("string")  # convert to string so Excel won't change format

# Export to Excel
df.to_excel(output_excel, index=False)

print(f"Done! Saved {len(df)} objects to {output_excel} without scientific notation.")

####### Code for extracting all the fields and their data from jsonl and exporting to the Excel with same name #######

####### Code for extracting unique project names from all Excel files and exporting to unique_projects.xlsx #######

# ----- YOUR EXCEL FILES -----
# excel_files = [
#     "primevul_test.xlsx",
#     "primevul_test_paired.xlsx",
#     "primevul_train.xlsx",
#     "primevul_train_paired.xlsx",
#     "primevul_valid.xlsx",
#     "primevul_valid_paired.xlsx",
# ]
#
# output_file = "unique_projects.xlsx"
# # ----------------------------
#
# # Storage for unique project + URL pairs
# unique_pairs = set()
#
# # Step 1: Extract project + URL from input Excel files
# for file in excel_files:
#     print(f"Reading: {file}")
#     try:
#         df = pd.read_excel(file)
#
#         if "project" not in df.columns or "project_url" not in df.columns:
#             print(f"Warning: Missing 'project' or 'project_url' in {file}")
#             continue
#
#         for proj, url in zip(df["project"], df["project_url"]):
#             if pd.notna(proj):
#                 unique_pairs.add((proj, url))
#
#     except Exception as e:
#         print(f"Error reading {file}: {e}")
#
# # Convert to DataFrame
# new_df = pd.DataFrame(sorted(unique_pairs), columns=["project", "project_url"])
#
#
# # Step 2: If output exists → append columns NOT overwrite
# if os.path.exists(output_file):
#     print(f"Preserving & appending to existing {output_file}...")
#     existing_df = pd.read_excel(output_file)
#
#     # Merge new + existing on "project"
#     if "project" in existing_df.columns:
#         final_df = existing_df.merge(new_df, on="project", how="outer", suffixes=("", "_new"))
#
#         # Fill missing project_url if needed
#         if "project_url" in existing_df.columns:
#             final_df["project_url"] = final_df["project_url"].fillna(final_df["project_url_new"])
#             final_df = final_df.drop(columns=["project_url_new"])
#         else:
#             final_df.rename(columns={"project_url_new": "project_url"}, inplace=True)
#
#     else:
#         # If somehow 'project' is missing in existing sheet → append columns directly
#         final_df = pd.concat([existing_df, new_df], axis=1)
#
# else:
#     # No previous file exists → create new file
#     final_df = new_df
#
# # Save the result
# final_df.to_excel(output_file, index=False)
#
# print(f"\n✨ Success! Updated {output_file} with {len(final_df)} unique projects.")
#
