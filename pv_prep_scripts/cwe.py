import pandas as pd
import re
import time

# Try importing scraping libraries.
try:
    import requests
    from bs4 import BeautifulSoup
    SCRAPING_AVAILABLE = True
except ImportError:
    SCRAPING_AVAILABLE = False
    print("Warning: 'requests' and 'beautifulsoup4' libraries not found.")

# --- Configuration: Robust Known Categories ---
KNOWN_CATEGORIES = {
    "core": "Core Framework",
    "curl": "Data Transfer",
    "exim": "Mail Server",
    "ffmpeg": "Multimedia Framework",
    "ghostpdl": "Print Rendering",
    "ghostscript": "PDF Interpreter",
    "gpac": "Multimedia Framework",
    "hhvm": "Virtual Machine",
    "imagemagick": "Image Processing",
    "imagemagick6": "Image Processing",
    "libarchive": "Compression Library",
    "libtiff": "Image Library",
    "libvncserver": "Remote Desktop",
    "libxml2": "XML Parser",
    "mruby": "Embedded Ruby",
    "oniguruma": "Regex Library",
    "openexr": "HDR Imaging",
    "openjpeg": "Image Library",
    "openssl": "Cryptography Library",
    "php": "Web Language",
    "php-src": "Web Language",
    "qemu": "Machine Emulator",
    "radare2": "Reverse Engineering",
    "samba": "File Sharing",
    "savannah": "Project Hosting",
    "sqlite": "Embedded Database",
    "systemd": "Init System",
    "tensorflow": "Machine Learning",
    "vim": "Text Editor",
    "tcpdump": "Packet Analyzer",
    "chrome": "Web Browser",
    "abrt": "Bug Reporting",
    "android": "Mobile OS",
    "ceph": "Distributed Storage",
    "crawl": "Roguelike Game",
    "exiv2": "Image Metadata",
    "file": "File Analysis",
    "flatpak": "Package Management",
    "freerdp": "Remote Desktop",
    "gimp": "Image Editor",
    "git": "Version Control",
    "gnutls": "Cryptography Library",
    "gpsd": "GPS Daemon",
    "jasper": "Image Library",
    "krb5": "Network Authentication",
    "kvm": "Virtualization",
    "libgd": "Graphics Library",
    "libgit2": "Version Control",
    "libpcap": "Packet Capture",
    "libraw": "RAW Decoding",
    "linux": "OS Kernel",
    "linux-2.6": "OS Kernel",
    "neomutt": "Email Client",
    "net": "Network Library",
    "ntp": "Time Sync",
    "openldap": "Directory Services",
    "pillow": "Python Imaging",
    "poppler": "PDF Rendering",
    "postgres": "SQL Database",
    "pure-ftpd": "FTP Server",
    "redis": "In-memory Database",
    "server": "Server Application",
    "src": "System Source",
    "thrift": "RPC Framework",
    "tor": "Privacy Network",
    "virglrenderer": "Virtual GPU",
    "w3m": "Text Browser",
    "wireshark": "Protocol Analyzer",
    "xserver": "Display Server"
}

# Fallback keywords if a project is NOT in the list above
CATEGORY_KEYWORDS = [
    "Library", "Framework", "Database", "Compiler", "Kernel", "Emulator", 
    "Virtualization", "Middleware", "Protocol", "Utility", "SDK", "API",
    "Server", "Client", "Driver", "Firmware", "Bootloader", "Cryptocurrency",
    "Blockchain", "CMS", "Operating System", "Hypervisor"
]

def get_category(project_name, url):
    """
    Returns the category using the robust known list first, then falls back to web scraping.
    """
    # 1. Check Known List (Exact match or case-insensitive)
    p_lower = project_name.lower().strip()
    if p_lower in KNOWN_CATEGORIES:
        return KNOWN_CATEGORIES[p_lower]

    # 2. If scraping is unavailable or no URL
    if not SCRAPING_AVAILABLE or not isinstance(url, str) or not url.startswith('http'):
        return "Unknown"

    # 3. Attempt Web Scraping (Fallback)
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=3)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            text_content = ""

            # Get description from meta tag or GitHub specific area
            meta = soup.find('meta', attrs={'name': 'description'})
            if meta and meta.get('content'):
                text_content = meta['content']
            elif "github.com" in url:
                desc = soup.find('p', class_='f4')
                if desc:
                    text_content = desc.get_text()
            
            # Check for generic keywords if specific category not found
            for keyword in CATEGORY_KEYWORDS:
                if keyword.lower() in text_content.lower():
                    return keyword

    except Exception:
        pass

    return "Software"

def generate_cwe_workbook(input_file, output_file):
    # 1. Define the Top-25 CWE list
    top_25_cwes = set([
        "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-20", "CWE-200", "CWE-22",
        "CWE-284", "CWE-306", "CWE-352", "CWE-416", "CWE-434", "CWE-476", "CWE-502",
        "CWE-639", "CWE-77", "CWE-770", "CWE-78", "CWE-787", "CWE-79", "CWE-862",
        "CWE-863", "CWE-89", "CWE-918", "CWE-94"
    ])

    print(f"Processing {input_file}...")

    try:
        # Load the Input Excel file
        df = pd.read_excel(input_file)
        
        # Standardize column names
        df.columns = [c.strip().lower() for c in df.columns]
        
        # Verify required columns
        required_columns = ['project', 'commit_id', 'cwe']
        if not all(col in df.columns for col in required_columns):
            print(f"Error: Missing one of the required columns: {required_columns}")
            return

        # Create a lookup dictionary for Project URLs
        url_lookup = {}
        if 'project_url' in df.columns:
            url_lookup = df.dropna(subset=['project_url']).groupby('project')['project_url'].first().to_dict()

        # ==========================================
        # LOGIC FOR SHEET 1
        # ==========================================
        sheet1_data = []
        grouped = df.groupby('project')

        print("Generating Sheet 1 data...")
        for project_name, group in grouped:
            total_cwe_commits = len(group)
            
            cwe_counts = group['cwe'].value_counts()
            unique_cwes_list = [f"{cwe} ({count})" for cwe, count in cwe_counts.items()]
            unique_cwes_str = ", ".join(unique_cwes_list)

            project_unique_cwes = set(group['cwe'].unique())
            intersection = project_unique_cwes.intersection(top_25_cwes)
            covered_top25_list = sorted(list(intersection))
            covered_top25_str = ", ".join(covered_top25_list)

            total_top25_count = len(covered_top25_list)

            sheet1_data.append({
                "project": project_name,
                "total_cwe_commits": total_cwe_commits,
                "unique_cwes": unique_cwes_str,
                "covered_top25": covered_top25_str,
                "total_top25": total_top25_count
            })

        df_sheet1 = pd.DataFrame(sheet1_data)
        df_sheet1 = df_sheet1.sort_values(by='total_top25', ascending=False)

        # ==========================================
        # LOGIC FOR SHEET 2
        # ==========================================
        print("Generating Sheet 2 data...")
        sorted_top_25_cols = sorted(list(top_25_cwes))
        sheet2_mapping = {cwe: [] for cwe in sorted_top_25_cols}

        for row in df_sheet1.to_dict('records'):
            p_name = row['project']
            p_total_commits = row['total_cwe_commits']
            p_covered_str = row['covered_top25']

            if not p_covered_str:
                continue

            covered_cwes = [x.strip() for x in p_covered_str.split(',') if x.strip()]
            entry_str = f"{p_name}({p_total_commits})"

            for cwe in covered_cwes:
                if cwe in sheet2_mapping:
                    sheet2_mapping[cwe].append(entry_str)

        for cwe in sheet2_mapping:
            sheet2_mapping[cwe].sort(
                key=lambda x: int(re.search(r'\((\d+)\)', x).group(1)), 
                reverse=True
            )

        df_sheet2 = pd.DataFrame({k: pd.Series(v) for k, v in sheet2_mapping.items()})

        # ==========================================
        # LOGIC FOR SHEET 3 (Updated Category)
        # ==========================================
        print("Generating Sheet 3 data (Fetching Categories)...")
        sheet3_data = []

        sheet3_candidates = [row for row in sheet1_data if row['total_cwe_commits'] >= 10]
        sheet3_candidates.sort(key=lambda x: x['total_cwe_commits'], reverse=True)

        for row in sheet3_candidates:
            p_name = row['project']
            p_count = row['total_cwe_commits']
            p_url = url_lookup.get(p_name, "")
            
            project_display = f"{p_name}({p_count})"
            
            # Fetch Category from robust list
            category_val = get_category(p_name, p_url)
            
            sheet3_data.append({
                "selected_projects": project_display,
                "found_in_CWEs": row['total_top25'],
                "category": category_val,
                "project_url": p_url
            })
            
            # Tiny sleep only if we actually hit the web
            if SCRAPING_AVAILABLE and p_name.lower() not in KNOWN_CATEGORIES and p_url:
                time.sleep(0.3)

        df_sheet3 = pd.DataFrame(sheet3_data)
        
        if df_sheet3.empty:
             print("Warning: No projects found with 10 or more commits for Sheet 3.")

        # ==========================================
        # WRITE TO EXCEL
        # ==========================================
        print("Writing to Excel...")
        with pd.ExcelWriter(output_file) as writer:
            df_sheet1.to_excel(writer, sheet_name='Sheet1', index=False)
            df_sheet2.to_excel(writer, sheet_name='Sheet2', index=False)
            df_sheet3.to_excel(writer, sheet_name='Sheet3', index=False)
            
            # Optional formatting for Sheet 3 columns
            worksheet3 = writer.sheets['Sheet3']
            worksheet3.set_column('A:A', 25)
            worksheet3.set_column('C:C', 25)
            worksheet3.set_column('D:D', 40)

        print(f"Success! Workbook created at: {output_file}")

    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# --- Execution ---
if __name__ == "__main__":
    input_xlsx = 'primevul_filtered.xlsx'
    output_xlsx = 'cwe_breakup.xlsx'
    
    generate_cwe_workbook(input_xlsx, output_xlsx)

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# import pandas as pd
# import json
# import os
# import re  # Imported to handle the sorting logic

# # --- Part 1: Original Processing Function ---
# def process_primevul_data(input_file, output_file):
#     # Define the Top-25 CWE list
#     top_25_cwes = set([
#         "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-20", "CWE-200", "CWE-22",
#         "CWE-284", "CWE-306", "CWE-352", "CWE-416", "CWE-434", "CWE-476", "CWE-502",
#         "CWE-639", "CWE-77", "CWE-770", "CWE-78", "CWE-787", "CWE-79", "CWE-862",
#         "CWE-863", "CWE-89", "CWE-918", "CWE-94"
#     ])

#     try:
#         # Load the Excel file
#         df = pd.read_excel(input_file)
        
#         # Ensure column names are standardized
#         df.columns = [c.strip().lower() for c in df.columns]
        
#         # Validation
#         required_columns = ['project', 'commit_id', 'cwe', 'cve']
#         if not all(col in df.columns for col in required_columns):
#             print(f"Error: Excel file must contain columns: {required_columns}")
#             return False

#         results = []
#         grouped = df.groupby('project')

#         for project_name, group in grouped:
#             # 1. Total commits count
#             total_cwe_commits = len(group)

#             # 2 & 2.1. Unique CWEs and occurrences
#             cwe_counts = group['cwe'].value_counts()
#             unique_cwes_list = [f"{cwe}({count})" for cwe, count in cwe_counts.items()]
#             unique_cwes_str = ", ".join(unique_cwes_list)

#             # 4. Filter Top-25
#             project_cwes = set(group['cwe'].unique())
#             covered_top_25_list = list(project_cwes.intersection(top_25_cwes))
#             covered_top_25_str = ", ".join(sorted(covered_top_25_list))

#             project_record = {
#                 "project": project_name,
#                 "total_cwe_commits": total_cwe_commits,
#                 "unique_cwes": unique_cwes_str,
#                 "covered_top_25": covered_top_25_str
#             }
#             results.append(project_record)

#         with open(output_file, 'w') as f:
#             json.dump(results, f, indent=4)
        
#         print(f"Step 1 Complete: Processed {len(results)} projects into {output_file}")
#         return True

#     except Exception as e:
#         print(f"An error occurred in Step 1: {e}")
#         return False

# # --- Part 2: New Mapping Function (Updated with Sorting) ---
# def generate_t25_mappings(json_input_file, xlsx_output_file, json_output_file):
#     # List of Top 25 CWEs
#     top_25_list = sorted([
#         "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-20", "CWE-200", "CWE-22",
#         "CWE-284", "CWE-306", "CWE-352", "CWE-416", "CWE-434", "CWE-476", "CWE-502",
#         "CWE-639", "CWE-77", "CWE-770", "CWE-78", "CWE-787", "CWE-79", "CWE-862",
#         "CWE-863", "CWE-89", "CWE-918", "CWE-94"
#     ])
    
#     # Initialize dictionary
#     mapping_data = {cwe: [] for cwe in top_25_list}

#     try:
#         # Load the JSON data generated in Step 1
#         with open(json_input_file, 'r') as f:
#             projects_data = json.load(f)

#         # Process each project
#         for record in projects_data:
#             project_name = record.get('project')
#             total_commits = record.get('total_cwe_commits')
#             covered_cwes_str = record.get('covered_top_25', "")

#             if not covered_cwes_str:
#                 continue

#             formatted_entry = f"{project_name}({total_commits})"
            
#             # Split the CSV string into a list
#             covered_cwes = [x.strip() for x in covered_cwes_str.split(',') if x.strip()]

#             # Assign to columns
#             for cwe in covered_cwes:
#                 if cwe in mapping_data:
#                     mapping_data[cwe].append(formatted_entry)

#         # --- NEW: Sort Logic ---
#         # Sort each CWE list by the count inside the parentheses (descending)
#         for cwe in mapping_data:
#             mapping_data[cwe].sort(
#                 key=lambda x: int(re.search(r'\((\d+)\)', x).group(1)), 
#                 reverse=True
#             )

#         # --- Generate Excel (t25_proj_mapping.xlsx) ---
#         # Convert dict to DataFrame using pd.Series to align columns
#         df_mapping = pd.DataFrame({k: pd.Series(v) for k, v in mapping_data.items()})
#         df_mapping.to_excel(xlsx_output_file, index=False)
#         print(f"Step 2 (Excel) Complete: Mapping saved to {xlsx_output_file}")

#         # --- Generate JSON (t25_proj_mapping.json) ---
#         # Since mapping_data lists are now sorted, the joined strings will also be sorted
#         json_mapping = {k: ", ".join(v) for k, v in mapping_data.items()}
        
#         with open(json_output_file, 'w') as f:
#             json.dump(json_mapping, f, indent=4)
#         print(f"Step 2 (JSON) Complete: Mapping saved to {json_output_file}")

#     except Exception as e:
#         print(f"An error occurred in Step 2: {e}")

# # --- Execution ---
# if __name__ == "__main__":
#     # File Names
#     input_xlsx = 'primevul_all.xlsx'
#     intermediate_json = 'primvul_all.json'
    
#     output_mapping_xlsx = 't25_proj_mapping.xlsx'
#     output_mapping_json = 't25_proj_mapping.json'
    
#     # Run Step 1
#     if process_primevul_data(input_xlsx, intermediate_json):
#         # Run Step 2 (Only if Step 1 succeeded)
#         generate_t25_mappings(intermediate_json, output_mapping_xlsx, output_mapping_json)


# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Maps 2025 Top-25 CWEs from primevul_all.xlsx to a JSON file with project-wise summaries.

# import pandas as pd
# import json
# import os

# # --- Part 1: Original Processing Function ---
# def process_primevul_data(input_file, output_file):
#     # Define the Top-25 CWE list
#     top_25_cwes = set([
#         "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-20", "CWE-200", "CWE-22",
#         "CWE-284", "CWE-306", "CWE-352", "CWE-416", "CWE-434", "CWE-476", "CWE-502",
#         "CWE-639", "CWE-77", "CWE-770", "CWE-78", "CWE-787", "CWE-79", "CWE-862",
#         "CWE-863", "CWE-89", "CWE-918", "CWE-94"
#     ])

#     try:
#         # Load the Excel file
#         df = pd.read_excel(input_file)
        
#         # Ensure column names are standardized
#         df.columns = [c.strip().lower() for c in df.columns]
        
#         # Validation
#         required_columns = ['project', 'commit_id', 'cwe', 'cve']
#         if not all(col in df.columns for col in required_columns):
#             print(f"Error: Excel file must contain columns: {required_columns}")
#             return False

#         results = []
#         grouped = df.groupby('project')

#         for project_name, group in grouped:
#             # 1. Total commits count
#             total_cwe_commits = len(group)

#             # 2 & 2.1. Unique CWEs and occurrences
#             cwe_counts = group['cwe'].value_counts()
#             unique_cwes_list = [f"{cwe}({count})" for cwe, count in cwe_counts.items()]
#             unique_cwes_str = ", ".join(unique_cwes_list)

#             # 4. Filter Top-25
#             project_cwes = set(group['cwe'].unique())
#             covered_top_25_list = list(project_cwes.intersection(top_25_cwes))
#             covered_top_25_str = ", ".join(sorted(covered_top_25_list))

#             project_record = {
#                 "project": project_name,
#                 "total_cwe_commits": total_cwe_commits,
#                 "unique_cwes": unique_cwes_str,
#                 "covered_top_25": covered_top_25_str
#             }
#             results.append(project_record)

#         with open(output_file, 'w') as f:
#             json.dump(results, f, indent=4)
        
#         print(f"Step 1 Complete: Processed {len(results)} projects into {output_file}")
#         return True

#     except Exception as e:
#         print(f"An error occurred in Step 1: {e}")
#         return False

# # --- Part 2: New Mapping Function ---
# def generate_t25_mappings(json_input_file, xlsx_output_file, json_output_file):
#     # List of Top 25 CWEs (to ensure columns are created even if no project has them)
#     top_25_list = sorted([
#         "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-20", "CWE-200", "CWE-22",
#         "CWE-284", "CWE-306", "CWE-352", "CWE-416", "CWE-434", "CWE-476", "CWE-502",
#         "CWE-639", "CWE-77", "CWE-770", "CWE-78", "CWE-787", "CWE-79", "CWE-862",
#         "CWE-863", "CWE-89", "CWE-918", "CWE-94"
#     ])
    
#     # Initialize dictionary to hold lists of projects for each CWE
#     mapping_data = {cwe: [] for cwe in top_25_list}

#     try:
#         # Load the JSON data generated in Step 1
#         with open(json_input_file, 'r') as f:
#             projects_data = json.load(f)

#         # Process each project
#         for record in projects_data:
#             project_name = record.get('project')
#             total_commits = record.get('total_cwe_commits')
#             covered_cwes_str = record.get('covered_top_25', "")

#             if not covered_cwes_str:
#                 continue

#             # Create the formatted string "project(count)"
#             formatted_entry = f"{project_name}({total_commits})"
            
#             # Split the CSV string into a list
#             # We strip whitespace to be safe
#             covered_cwes = [x.strip() for x in covered_cwes_str.split(',') if x.strip()]

#             # Assign project to the specific CWE columns
#             for cwe in covered_cwes:
#                 if cwe in mapping_data:
#                     mapping_data[cwe].append(formatted_entry)

#         # --- Generate Excel (t25_proj_mapping.xlsx) ---
#         # Convert dict to DataFrame. 
#         # Since lists have different lengths, we use pd.Series to auto-align/fill NaNs
#         df_mapping = pd.DataFrame({k: pd.Series(v) for k, v in mapping_data.items()})
        
#         # Write to Excel without the index (row numbers)
#         df_mapping.to_excel(xlsx_output_file, index=False)
#         print(f"Step 2 (Excel) Complete: Mapping saved to {xlsx_output_file}")

#         # --- Generate JSON (t25_proj_mapping.json) ---
#         # Convert list values to comma-separated strings
#         json_mapping = {k: ", ".join(v) for k, v in mapping_data.items()}
        
#         with open(json_output_file, 'w') as f:
#             json.dump(json_mapping, f, indent=4)
#         print(f"Step 2 (JSON) Complete: Mapping saved to {json_output_file}")

#     except Exception as e:
#         print(f"An error occurred in Step 2: {e}")

# # --- Execution ---
# if __name__ == "__main__":
#     # File Names
#     input_xlsx = 'primevul_all.xlsx'
#     intermediate_json = 'primvul_all.json'
    
#     output_mapping_xlsx = 't25_proj_mapping.xlsx'
#     output_mapping_json = 't25_proj_mapping.json'
    
#     # Run Step 1
#     if process_primevul_data(input_xlsx, intermediate_json):
#         # Run Step 2 (Only if Step 1 succeeded)
#         generate_t25_mappings(intermediate_json, output_mapping_xlsx, output_mapping_json)

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Maps 2025 Top-25 CWEs from primevul_all.xlsx to a JSON file with project-wise summaries.
        
# import pandas as pd
# import json

# def process_primevul_data(input_file, output_file):
#     # 1. Define the Top-25 CWE list
#     top_25_cwes = set([
#         "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-20", "CWE-200", "CWE-22",
#         "CWE-284", "CWE-306", "CWE-352", "CWE-416", "CWE-434", "CWE-476", "CWE-502",
#         "CWE-639", "CWE-77", "CWE-770", "CWE-78", "CWE-787", "CWE-79", "CWE-862",
#         "CWE-863", "CWE-89", "CWE-918", "CWE-94"
#     ])

#     try:
#         # Load the Excel file
#         df = pd.read_excel(input_file)
        
#         # Ensure column names are stripped of whitespace and consistent
#         df.columns = [c.strip().lower() for c in df.columns]
        
#         # Check if required columns exist
#         required_columns = ['project', 'commit_id', 'cwe', 'cve']
#         if not all(col in df.columns for col in required_columns):
#             print(f"Error: Excel file must contain columns: {required_columns}")
#             return

#         results = []

#         # Group data by 'project'
#         grouped = df.groupby('project')

#         for project_name, group in grouped:
#             # 1. Count total "commit_id" (assuming total rows/instances found against a project)
#             # If you specifically need unique commit_ids, change to: group['commit_id'].nunique()
#             total_cwe_commits = len(group)

#             # 2 & 2.1. Find unique CWEs and their counts
#             cwe_counts = group['cwe'].value_counts()
            
#             # Format as "CWE-ID(Count)" and join with commas
#             unique_cwes_list = [f"{cwe}({count})" for cwe, count in cwe_counts.items()]
#             unique_cwes_str = ", ".join(unique_cwes_list)

#             # 4. Filter for Top-25 CWEs present in this project
#             # Get the set of unique CWEs in the project
#             project_cwes = set(group['cwe'].unique())
            
#             # Find intersection with Top-25
#             covered_top_25_list = list(project_cwes.intersection(top_25_cwes))
#             covered_top_25_str = ", ".join(sorted(covered_top_25_list))

#             # Construct the dictionary for this project
#             project_record = {
#                 "project": project_name,
#                 "total_cwe_commits": total_cwe_commits,
#                 "unique_cwes": unique_cwes_str,
#                 "covered_top_25": covered_top_25_str
#             }
            
#             results.append(project_record)

#         # Write results to JSON file
#         with open(output_file, 'w') as f:
#             json.dump(results, f, indent=4)
        
#         print(f"Successfully processed {len(results)} projects. Output saved to {output_file}")

#     except FileNotFoundError:
#         print(f"Error: The file '{input_file}' was not found.")
#     except Exception as e:
#         print(f"An unexpected error occurred: {e}")

# # --- Execution ---
# if __name__ == "__main__":
#     input_xlsx = 'primevul_all.xlsx'
#     output_json = 'primvul_all.json'
    
#     process_primevul_data(input_xlsx, output_json)