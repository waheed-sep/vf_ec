import os
import csv
import logging
import json
import sys
import importlib
import urllib.request
import vfec_output  # The Common Engine

# ==========================================
# CONFIGURATION
# ==========================================
# 1. Get Repo Name from Environment (Default is empty)
REPO_NAME = os.getenv("REPO_NAME", "")

# 2. Check if user forgot to provide it
if not REPO_NAME:
    print("\n[ERROR] No repository name provided!")
    print("Please specify the target repository using the REPO_NAME environment variable.\n")
    print("Usage (Docker):")
    print("  docker run -e REPO_NAME=FFmpeg ...\n")
    print("Usage (Manual):")
    print("  REPO_NAME=FFmpeg python3 vfec_init.py\n")
    sys.exit(1)

TARGET_DURATION = 2.0
TEST_LIMIT = None

GIST_CSV_URL = "https://gist.githubusercontent.com/waheed-sep/935cfc1ba42b2475d45336a4c779cbc8/raw/ea91568360d87979373a7eca38f289c9bf30d103/cwe_projects.csv"

# ==========================================
# PATHS
# ==========================================
BASE_DIR = "/app"
INPUT_DIR = os.path.join(BASE_DIR, "inputs")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
INPUT_CSV = os.path.join(INPUT_DIR, "cwe_projects.csv")
PROJECT_DIR = os.path.join(INPUT_DIR, REPO_NAME)
LOG_DIR = os.path.join(OUTPUT_DIR, "log")
CACHE_DIR = os.path.join(LOG_DIR, "cache")

for d in [INPUT_DIR, OUTPUT_DIR, LOG_DIR, CACHE_DIR]:
    if not os.path.exists(d): os.makedirs(d)

# Setup Logging via Engine
vfec_output.setup_logging(os.path.join(LOG_DIR, "pipeline_execution.log"))

# ==========================================
# PLUGIN LOADING
# ==========================================
try:
    # Loads {repo}_engine.py (e.g., ffmpeg_engine.py)
    plugin_name = f"{REPO_NAME.lower()}_engine"
    project_engine = importlib.import_module(plugin_name)
    logging.info(f"Loaded Project Engine: {plugin_name}")
except ImportError as e:
    logging.error(f"Could not load engine for {REPO_NAME}. Ensure {plugin_name}.py exists. Error: {e}")
    print(f"\n[ERROR] Plugin not found: {plugin_name}.py")
    print(f"Make sure you have created the engine file for '{REPO_NAME}'.")
    sys.exit(1)

# ==========================================
# HELPERS
# ==========================================
def save_cache(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)

def load_cache(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f: return json.load(f)
        except: return {}
    return {}

def download_csv_if_missing():
    if not os.path.exists(INPUT_CSV):
        print(f"Downloading CSV to {INPUT_CSV}...")
        try:
            urllib.request.urlretrieve(GIST_CSV_URL, INPUT_CSV)
        except Exception as e:
            print(f"Error downloading CSV: {e}")
            sys.exit(1)

def get_git_diff_files(cwd, commit_hash):
    cmd = f"git diff-tree --no-commit-id --name-only -r {commit_hash}"
    import subprocess
    result = subprocess.run(cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE, text=True)
    return {f for f in result.stdout.strip().split('\n') if f}

# ==========================================
# PHASE 1: COVERAGE
# ==========================================
def run_phase_1(vuln, fix, csv_manager, checkpoint_path):
    cache = load_cache(checkpoint_path)
    if cache.get("status") == "COMPLETE_P1":
        return True # Already done

    logging.info(f"--- Phase 1: Coverage {vuln} -> {fix} ---")
    
    # 1. Checkout Fix & Diff
    vfec_output.clean_repo(PROJECT_DIR)
    if not vfec_output.run_command(f"git checkout -f {fix}", PROJECT_DIR): return False
    target_files = get_git_diff_files(PROJECT_DIR, fix)
    
    if not target_files:
        logging.error("No target files found in git diff.")
        return False

    vuln_results = cache.get("results", {})

    # 2. Build & Test VULN
    if not cache.get("vuln_done"):
        logging.info(f"Building Vuln {vuln} (Coverage)...")
        vfec_output.clean_repo(PROJECT_DIR)
        vfec_output.run_command(f"git checkout -f {vuln}", PROJECT_DIR)
        
        project_engine.build_coverage(PROJECT_DIR)
        suite = project_engine.get_tests(PROJECT_DIR, TEST_LIMIT)
        
        print(f"Running {len(suite)} tests for Vuln Commit...")
        for i, test in enumerate(suite):
            if test['name'] in vuln_results: continue
            if i % 20 == 0: print(f"  [P1-Vuln] {i}/{len(suite)}: {test['name']}")
            
            # Run Test
            vfec_output.run_command("find . -name '*.gcda' -delete", PROJECT_DIR)
            vfec_output.run_command(test['cmd'], PROJECT_DIR, ignore_errors=True)
            
            # Check Coverage
            covered = vfec_output.get_covered_files(PROJECT_DIR)
            relevant = [f for f in covered if f in target_files]
            
            if relevant:
                vuln_results[test['name']] = relevant
                save_cache(checkpoint_path, {"vuln_done": False, "results": vuln_results})
        
        save_cache(checkpoint_path, {"vuln_done": True, "results": vuln_results})

    # 3. Build & Test FIX
    logging.info(f"Building Fix {fix} (Coverage)...")
    vfec_output.clean_repo(PROJECT_DIR)
    vfec_output.run_command(f"git checkout -f {fix}", PROJECT_DIR)
    
    project_engine.build_coverage(PROJECT_DIR)
    suite = project_engine.get_tests(PROJECT_DIR, TEST_LIMIT)
    
    print(f"Running {len(suite)} tests for Fix Commit...")
    for i, test in enumerate(suite):
        t_name = test['name']
        if i % 20 == 0: print(f"  [P1-Fix] {i}/{len(suite)}: {t_name}")
        
        vfec_output.run_command("find . -name '*.gcda' -delete", PROJECT_DIR)
        vfec_output.run_command(test['cmd'], PROJECT_DIR, ignore_errors=True)
        
        covered = vfec_output.get_covered_files(PROJECT_DIR)
        
        # Cross-reference
        for target in target_files:
            v_covered = (t_name in vuln_results) and (target in vuln_results[t_name])
            f_covered = target in covered

            if v_covered or f_covered:
                v_entry = t_name if v_covered else ""
                f_entry = t_name if f_covered else ""
                csv_manager.add_p1([REPO_NAME, vuln, v_entry, fix, f_entry, target])

    csv_manager.flush_all()
    cache["status"] = "COMPLETE_P1"
    save_cache(checkpoint_path, cache)
    return True

# ==========================================
# PHASE 2: ENERGY
# ==========================================
def run_phase_2(master_p1_csv, csv_manager, checkpoint_path, current_vuln, current_fix):
    logging.info(f"--- Phase 2: Energy {current_vuln} -> {current_fix} ---")
    
    if os.geteuid() != 0:
        logging.error("Phase 2 requires root permissions.")
        return False

    # 1. Parse Phase 1 CSV to find what tests to run
    relevant_tests = {"vuln": set(), "fix": set()}
    rows_to_process = []
    
    if os.path.exists(master_p1_csv):
        with open(master_p1_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['vuln_commit'] == current_vuln and row['fix_commit'] == current_fix:
                    if row['v_testname']: relevant_tests["vuln"].add(row['v_testname'])
                    if row['f_testname']: relevant_tests["fix"].add(row['f_testname'])
                    rows_to_process.append(row)

    if not rows_to_process: return True

    cache = load_cache(checkpoint_path)
    pkg_event = vfec_output.detect_rapl()

    # 2. Measure VULN & FIX
    for commit, tests in [(current_vuln, relevant_tests["vuln"]), (current_fix, relevant_tests["fix"])]:
        if commit not in cache: cache[commit] = {}
        todos = [t for t in tests if t not in cache[commit]]
        
        if not todos: continue
        
        logging.info(f"Building {commit} (Energy)...")
        vfec_output.clean_repo(PROJECT_DIR)
        vfec_output.run_command(f"git checkout -f {commit}", PROJECT_DIR)
        
        project_engine.build_energy(PROJECT_DIR)

        for i, t_name in enumerate(todos):
            print(f"  [P2-Measure] {commit[:8]} - {t_name} ({i+1}/{len(todos)})")
            
            # Plugin gives the command
            cmd = project_engine.get_energy_test_cmd(t_name, PROJECT_DIR, INPUT_DIR)
            
            # Engine does the measuring
            pkg_energy = vfec_output.measure_energy(cmd, PROJECT_DIR, TARGET_DURATION, pkg_event)
            
            if pkg_energy is not None:
                cache[commit][t_name] = pkg_energy
                save_cache(checkpoint_path, cache)

    # 3. Write Phase 2 CSV
    for row in rows_to_process:
        v_pkg = cache.get(current_vuln, {}).get(row['v_testname'], 0)
        f_pkg = cache.get(current_fix, {}).get(row['f_testname'], 0)

        # Format: project, v_commit, v_test, v_pkg, f_commit, f_test, source, f_pkg
        csv_manager.add_p2([
            row['project'], row['vuln_commit'], row['v_testname'], f"{v_pkg:.4f}",
            row['fix_commit'], row['f_testname'], row['sourcefile'], f"{f_pkg:.4f}"
        ])

    csv_manager.flush_all()
    return True

# ==========================================
# MAIN
# ==========================================
def main():
    download_csv_if_missing()

    MASTER_P1_CSV = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_MASTER_testCompile.csv")
    MASTER_P2_CSV = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_MASTER_energyperf.csv")
    
    csv_manager = vfec_output.CSVManager(MASTER_P1_CSV, MASTER_P2_CSV)

    pairs = []
    print(f"Reading {INPUT_CSV} for project: {REPO_NAME}...")
    try:
        with open(INPUT_CSV, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('project') == REPO_NAME and 'vuln_commit' in row and 'fix_commit' in row:
                    pairs.append((row['vuln_commit'], row['fix_commit']))
    except Exception as e:
        print(f"Error reading input CSV: {e}")
        sys.exit(1)

    if not pairs:
        print(f"No pairs found for project '{REPO_NAME}'.")
        print("Check if the repository name matches the 'project' column in your CSV.")
        sys.exit(1)

    print(f"Found {len(pairs)} pairs for {REPO_NAME}.")
    print(f"Outputs will be at: {OUTPUT_DIR}")

    for i, (vuln, fix) in enumerate(pairs):
        print(f"\n[{i+1}/{len(pairs)}] Processing Pair: {vuln[:8]} -> {fix[:8]}")
        
        p1_ckpt = os.path.join(CACHE_DIR, f"ckpt_cov_{vuln[:8]}.json")
        p2_ckpt = os.path.join(CACHE_DIR, f"ckpt_eng_{vuln[:8]}_{fix[:8]}.json")

        success = run_phase_1(vuln, fix, csv_manager, p1_ckpt)
        if success:
            run_phase_2(MASTER_P1_CSV, csv_manager, p2_ckpt, vuln, fix)
            print(f"Pair {i+1} Completed.")
        else:
            print("Skipping Phase 2 due to P1 failure.")

if __name__ == "__main__":
    main()