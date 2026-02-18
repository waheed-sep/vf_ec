import os
import csv
import glob
import statistics
import requests
import sys

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_NAME = "libxml2"
GIST_CSV_URL = "https://gist.githubusercontent.com/waheed-sep/935cfc1ba42b2475d45336a4c779cbc8/raw/cwe_projects.csv"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, "final_eng_csvs", PROJECT_NAME, "energy_measurements")
OUTPUT_DIR = os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final")

os.makedirs(OUTPUT_DIR, exist_ok=True)

EVENT_MAP = {
    "power/energy-pkg/": "energy_pkg",
    "power/energy-ram/": "energy_ram",
    "cycles": "cycles",
    "instructions": "instr"
}

def download_project_metadata():
    print(f"[*] Fetching metadata for project: {PROJECT_NAME}...")
    try:
        response = requests.get(GIST_CSV_URL)
        response.raise_for_status()
        decoded_content = response.content.decode('utf-8')
        cr = csv.DictReader(decoded_content.splitlines(), delimiter=',')
        return [row for row in cr if row['project'].strip().lower() == PROJECT_NAME.lower()]
    except Exception as e:
        print(f"[!] Error downloading metadata: {e}")
        sys.exit(1)

def parse_perf_csv(filepath):
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
                except ValueError: continue 
                if event_name in EVENT_MAP:
                    key = EVENT_MAP[event_name]
                    data[key] = raw_val
        return data
    except Exception:
        return None

def get_commit_metrics_median(commit_hash):
    search_pattern = os.path.join(INPUT_DIR, f"{commit_hash}*.csv")
    files = glob.glob(search_pattern)
    if not files: return None

    agg = {k: [] for k in ["energy_pkg", "energy_ram", "cycles", "instr"]}
    for f in files:
        m = parse_perf_csv(f)
        if m:
            for k in agg.keys():
                if k in m: agg[k].append(m[k])
    
    if not any(agg.values()): return None
    return {k: (statistics.median(v) if v else "") for k, v in agg.items()}

def get_raw_iterations_per_test(commit_hash):
    search_pattern = os.path.join(INPUT_DIR, f"{commit_hash}*.csv")
    files = sorted(glob.glob(search_pattern))
    tests_map = {}
    for filepath in files:
        filename = os.path.basename(filepath)
        parts = filename.split("__")
        test_name = parts[1] if len(parts) >= 2 else "unknown_test"
        if test_name not in tests_map: tests_map[test_name] = []
        metrics = parse_perf_csv(filepath)
        if metrics: tests_map[test_name].append(metrics)
    return tests_map

def main():
    if not os.path.exists(INPUT_DIR):
        print(f"[!] Error: {INPUT_DIR} not found.")
        return

    pairs = download_project_metadata()
    output_csv = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_final_results.csv")
    missed_csv = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_missed_commits.csv")
    pertest_csv = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_final_pertest.csv")
    
    with open(output_csv, 'w', newline='') as f_out, \
         open(missed_csv, 'w', newline='') as f_miss, \
         open(pertest_csv, 'w', newline='') as f_test:
        
        # 1. Per-Commit Medians Writer
        writer = csv.DictWriter(f_out, fieldnames=["vuln_commit", "vuln_energy_pkg", "fix_commit", "fix_energy_pkg", "cwe", "cve"])
        writer.writeheader()

        # 2. Missed Commits Writer (Fixed Header: commit -> status)
        missed_writer = csv.DictWriter(f_miss, fieldnames=["status", "missed_commits"])
        missed_writer.writeheader()

        # 3. Per-Test Iterations Writer
        test_headers = ["vuln_commit", "vuln_testname", "vuln_energy_pkg", "fix_commit", "fix_testname", "fix_energy_pkg", "cwe", "cve"]
        test_writer = csv.DictWriter(f_test, fieldnames=test_headers)
        test_writer.writeheader()

        success_count = 0

        for pair in pairs:
            v_hash, f_hash = pair.get('vuln_commit'), pair.get('fix_commit')
            
            v_agg = get_commit_metrics_median(v_hash)
            f_agg = get_commit_metrics_median(f_hash)

            if v_agg and f_agg:
                # Write Aggregate Data
                writer.writerow({
                    "vuln_commit": v_hash, "vuln_energy_pkg": v_agg["energy_pkg"],
                    "fix_commit": f_hash, "fix_energy_pkg": f_agg["energy_pkg"],
                    "cwe": pair.get("cwe", ""), "cve": pair.get("cve", "")
                })
                success_count += 1

                # Write Per-Test Iterations
                v_tests = get_raw_iterations_per_test(v_hash)
                f_tests = get_raw_iterations_per_test(f_hash)
                common_tests = set(v_tests.keys()) & set(f_tests.keys())

                for t_name in common_tests:
                    v_list, f_list = v_tests[t_name], f_tests[t_name]
                    num_iters = min(len(v_list), len(f_list))
                    
                    for i in range(num_iters):
                        test_writer.writerow({
                            "vuln_commit": v_hash,
                            "vuln_testname": f"{t_name}_{i}",
                            "vuln_energy_pkg": v_list[i]["energy_pkg"],
                            "fix_commit": f_hash,
                            "fix_testname": f"{t_name}_{i}",
                            "fix_energy_pkg": f_list[i]["energy_pkg"],
                            "cwe": pair.get("cwe", ""),
                            "cve": pair.get("cve", "")
                        })
            else:
                # Log Missing Data
                if not v_agg and not f_agg:
                    missed_writer.writerow({"status": "both_missing", "missed_commits": f"{v_hash} | {f_hash}"})
                elif not v_agg:
                    missed_writer.writerow({"status": "vuln_missing", "missed_commits": v_hash})
                elif not f_agg:
                    missed_writer.writerow({"status": "fix_missing", "missed_commits": f_hash})

    print(f"\n[+] Processing complete. {success_count} pairs matched.")
    print(f"[+] Files generated in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()