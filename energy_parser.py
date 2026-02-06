import os
import csv
import glob
import statistics
import requests
import sys
import logging

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_NAME = "vim"

# URLs and Paths
GIST_CSV_URL = "https://gist.githubusercontent.com/waheed-sep/935cfc1ba42b2475d45336a4c779cbc8/raw/cwe_projects.csv"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "final_eng_csvs", PROJECT_NAME, "energy_measurements")

# New Output Directory Structure: final_results/<project>_final/
OUTPUT_DIR = os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final")

os.makedirs(OUTPUT_DIR, exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

EVENT_MAP = {
    "power/energy-pkg/": "energy_pkg",
    "power/energy-ram/": "energy_ram",
    "cycles": "cycles",
    "instructions": "instr"
}

def download_project_metadata():
    logging.info(f"Downloading metadata from Gist...")
    try:
        response = requests.get(GIST_CSV_URL)
        response.raise_for_status()
        decoded_content = response.content.decode('utf-8')
        cr = csv.DictReader(decoded_content.splitlines(), delimiter=',')
        return [row for row in cr if row['project'].strip().lower() == PROJECT_NAME.lower()]
    except Exception as e:
        logging.error(f"Failed to download metadata: {e}")
        sys.exit(1)

def parse_perf_csv(filepath):
    """Parses a single CSV file and returns a dictionary of metrics."""
    data = {}
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            if len(lines) < 3: return None
            reader = csv.reader(lines[2:]) 
            for row in reader:
                if not row or len(row) < 5: continue
                try:
                    raw_val = float(row[0])
                    event_name = row[2].strip()
                    runtime_ns = float(row[3])
                    reliability = float(row[4])
                except ValueError:
                    continue 
                if event_name in EVENT_MAP:
                    key = EVENT_MAP[event_name]
                    data[key] = raw_val
                    data[f"{key}_duration"] = runtime_ns / 1_000_000.0
                    data[f"{key}_reliability"] = reliability
        return data
    except Exception as e:
        return None

def calculate_medians(aggregated_data):
    """Helper to calculate medians from a dictionary of lists."""
    final_metrics = {}
    for key, values in aggregated_data.items():
        if values: final_metrics[key] = statistics.median(values)
        else: final_metrics[key] = "" 
    return final_metrics

def get_commit_metrics(commit_hash):
    """Aggregates ALL files for a commit into a single median (Project Level)."""
    search_pattern = os.path.join(INPUT_DIR, f"{commit_hash}*.csv")
    files = glob.glob(search_pattern)
    if not files: return None

    aggregated_data = {
        "energy_pkg": [], "energy_pkg_duration": [], "energy_pkg_reliability": [],
        "energy_ram": [], "energy_ram_duration": [], "energy_ram_reliability": [],
        "cycles": [], "cycles_duration": [], "cycles_reliability": [],
        "instr": [], "instr_duration": [], "instr_reliability": []
    }

    for filepath in files:
        file_metrics = parse_perf_csv(filepath)
        if file_metrics:
            for key, val in file_metrics.items():
                if key in aggregated_data: aggregated_data[key].append(val)

    return calculate_medians(aggregated_data)

def get_per_test_metrics(commit_hash):
    """
    Groups files by TEST NAME and calculates median per test.
    Returns: { "test_name_A": {metrics}, "test_name_B": {metrics} }
    """
    search_pattern = os.path.join(INPUT_DIR, f"{commit_hash}*.csv")
    files = glob.glob(search_pattern)
    if not files: return {}

    # Dictionary to hold lists of values per test
    # Structure: { "test_name": { "energy_pkg": [val1, val2...], ... } }
    tests_map = {}

    for filepath in files:
        # Extract Test Name from filename
        # Format: <hash>__<testname>__<iter>.csv
        filename = os.path.basename(filepath)
        try:
            # We split by double underscore as per previous description
            parts = filename.split("__")
            if len(parts) >= 2:
                test_name = parts[1]
            else:
                # Fallback if naming convention fails
                test_name = "unknown_test"
        except Exception:
            test_name = "unknown_test"

        if test_name not in tests_map:
            tests_map[test_name] = {
                "energy_pkg": [], "energy_pkg_duration": [], "energy_pkg_reliability": [],
                "energy_ram": [], "energy_ram_duration": [], "energy_ram_reliability": [],
                "cycles": [], "cycles_duration": [], "cycles_reliability": [],
                "instr": [], "instr_duration": [], "instr_reliability": []
            }

        file_metrics = parse_perf_csv(filepath)
        if file_metrics:
            for key, val in file_metrics.items():
                if key in tests_map[test_name]:
                    tests_map[test_name][key].append(val)

    # Calculate Medians for each test
    final_test_results = {}
    for test_name, metrics_lists in tests_map.items():
        final_test_results[test_name] = calculate_medians(metrics_lists)

    return final_test_results

def main():
    pairs = download_project_metadata()
    if not pairs: return

    # File Paths in new directory
    output_csv = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_final_results.csv")
    missed_csv = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_missed_commits.csv")
    pertest_csv = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_final_pertest.csv")
    
    logging.info(f"Looking for data in: {INPUT_DIR}")
    logging.info(f"Writing results to: {OUTPUT_DIR}")
    
    with open(output_csv, 'w', newline='') as f_out, \
         open(missed_csv, 'w', newline='') as f_miss, \
         open(pertest_csv, 'w', newline='') as f_test:
        
        # 1. Main CSV Headers
        headers = [
            "vuln_commit", "vuln_energy_pkg", "vuln_energy_ram", "vuln_cycles", "vuln_instr", "vuln_duration", "vuln_reliability",
            "fix_commit", "fix_energy_pkg", "fix_energy_ram", "fix_cycles", "fix_instr", "fix_duration", "fix_reliability",
            "cwe", "cve"
        ]
        writer = csv.DictWriter(f_out, fieldnames=headers)
        writer.writeheader()

        # 2. Missed CSV Headers
        missed_writer = csv.DictWriter(f_miss, fieldnames=["commit", "missed_commits"])
        missed_writer.writeheader()

        # 3. Per-Test CSV Headers (Same as Main + Test Names)
        test_headers = [
            "vuln_commit", "vuln_testname", 
            "vuln_energy_pkg", "vuln_energy_ram", "vuln_cycles", "vuln_instr", "vuln_duration", "vuln_reliability",
            "fix_commit", "fix_testname",
            "fix_energy_pkg", "fix_energy_ram", "fix_cycles", "fix_instr", "fix_duration", "fix_reliability",
            "cwe", "cve"
        ]
        test_writer = csv.DictWriter(f_test, fieldnames=test_headers)
        test_writer.writeheader()

        success_count = 0
        partial_count = 0
        empty_count = 0
        per_test_rows = 0

        for i, pair in enumerate(pairs):
            vuln_hash = pair.get('vuln_commit')
            fix_hash = pair.get('fix_commit')
            if not vuln_hash or not fix_hash: continue

            # --- PART A: AGGREGATE METRICS (Original Logic) ---
            vuln_agg = get_commit_metrics(vuln_hash)
            fix_agg = get_commit_metrics(fix_hash)

            if vuln_agg and fix_agg:
                # Write Main Result
                row = {
                    "vuln_commit": vuln_hash,
                    "vuln_energy_pkg": vuln_agg.get("energy_pkg"),
                    "vuln_energy_ram": vuln_agg.get("energy_ram"),
                    "vuln_cycles": vuln_agg.get("cycles"),
                    "vuln_instr": vuln_agg.get("instr"),
                    "vuln_duration": vuln_agg.get("energy_pkg_duration"), 
                    "vuln_reliability": vuln_agg.get("energy_pkg_reliability"),

                    "fix_commit": fix_hash,
                    "fix_energy_pkg": fix_agg.get("energy_pkg"),
                    "fix_energy_ram": fix_agg.get("energy_ram"),
                    "fix_cycles": fix_agg.get("cycles"),
                    "fix_instr": fix_agg.get("instr"),
                    "fix_duration": fix_agg.get("energy_pkg_duration"),
                    "fix_reliability": fix_agg.get("energy_pkg_reliability"),

                    "cwe": pair.get("cwe", ""),
                    "cve": pair.get("cve", "")
                }
                writer.writerow(row)
                success_count += 1

                # --- PART B: PER-TEST METRICS (New Logic) ---
                # Only proceed if we have valid data for both
                vuln_tests = get_per_test_metrics(vuln_hash)
                fix_tests = get_per_test_metrics(fix_hash)

                # We match tests by name. 
                # If a test exists in both Vuln and Fix, we record it.
                common_tests = set(vuln_tests.keys()) & set(fix_tests.keys())
                
                for t_name in common_tests:
                    v_t = vuln_tests[t_name]
                    f_t = fix_tests[t_name]
                    
                    test_row = {
                        "vuln_commit": vuln_hash,
                        "vuln_testname": t_name,
                        "vuln_energy_pkg": v_t.get("energy_pkg"),
                        "vuln_energy_ram": v_t.get("energy_ram"),
                        "vuln_cycles": v_t.get("cycles"),
                        "vuln_instr": v_t.get("instr"),
                        "vuln_duration": v_t.get("energy_pkg_duration"), 
                        "vuln_reliability": v_t.get("energy_pkg_reliability"),

                        "fix_commit": fix_hash,
                        "fix_testname": t_name,
                        "fix_energy_pkg": f_t.get("energy_pkg"),
                        "fix_energy_ram": f_t.get("energy_ram"),
                        "fix_cycles": f_t.get("cycles"),
                        "fix_instr": f_t.get("instr"),
                        "fix_duration": f_t.get("energy_pkg_duration"),
                        "fix_reliability": f_t.get("energy_pkg_reliability"),

                        "cwe": pair.get("cwe", ""),
                        "cve": pair.get("cve", "")
                    }
                    test_writer.writerow(test_row)
                    per_test_rows += 1

            elif vuln_agg and not fix_agg:
                missed_writer.writerow({"commit": "vuln", "missed_commits": vuln_hash})
                partial_count += 1

            elif fix_agg and not vuln_agg:
                missed_writer.writerow({"commit": "fix", "missed_commits": fix_hash})
                partial_count += 1

            else:
                missed_writer.writerow({"commit": "both_missing_vuln", "missed_commits": vuln_hash})
                missed_writer.writerow({"commit": "both_missing_fix", "missed_commits": fix_hash})
                empty_count += 1

    print("\n" + "="*40)
    print(f"PROCESSING COMPLETE FOR PROJECT: {PROJECT_NAME}")
    print("="*40)
    print(f"Total Pairs Found:            {len(pairs)}")
    print(f"Aggregated Rows (Success):    {success_count}")
    print(f"Per-Test Rows Written:        {per_test_rows}")
    print(f"Pairs with Partial Data:      {partial_count}")
    print(f"Pairs with NO Data:           {empty_count}")
    print(f"Output Directory:             {OUTPUT_DIR}")
    print("="*40)

if __name__ == "__main__":
    main()