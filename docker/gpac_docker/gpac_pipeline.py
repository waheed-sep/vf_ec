import os
import subprocess
import csv
import logging
import json
import time
import math
import sys
import urllib.request
import glob

# ==========================================
# CONFIGURATION
# ==========================================
REPO_NAME = "gpac"
TARGET_DURATION_SEC = 2.0
CSV_WRITE_INTERVAL = 50
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

LOG_FILE = os.path.join(LOG_DIR, "pipeline_execution.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# ==========================================
# HELPERS
# ==========================================
def run_command(command, cwd, ignore_errors=False):
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        result = subprocess.run(command, cwd=cwd, shell=True, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode != 0 and not ignore_errors:
            logging.error(f"FAIL: {command}\nSTDERR: {result.stderr.strip()}")
            return False
        return True
    except Exception as e:
        logging.error(f"EXCEPTION: {e}")
        return False

def save_json(filepath, data):
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logging.error(f"JSON Save Error: {e}")

def load_json(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def clean_repo(cwd):
    # CRITICAL UPDATE: Exclude media folders from cleaning.
    # In legacy versions, 'tests/media' is untracked. cleaning it forces a redownload (slow).
    run_command("git reset --hard", cwd)
    
    # Clean but keep media folders in both possible locations
    run_command("git clean -fdx -e tests/media -e testsuite/media", cwd)
    
    # Submodules (if they exist)
    if os.path.exists(os.path.join(cwd, ".gitmodules")):
        run_command("git submodule foreach --recursive git reset --hard", cwd)
        run_command("git submodule foreach --recursive git clean -fdx", cwd)

def download_csv_if_missing():
    if not os.path.exists(INPUT_CSV):
        print(f"Downloading input CSV from Gist to {INPUT_CSV}...")
        try:
            urllib.request.urlretrieve(GIST_CSV_URL, INPUT_CSV)
            print("Download complete.")
        except Exception as e:
            print(f"Error downloading CSV: {e}")
            sys.exit(1)

def get_git_diff_files(cwd, commit_hash):
    cmd = f"git diff-tree --no-commit-id --name-only -r {commit_hash}"
    result = subprocess.run(cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE, text=True)
    return {f for f in result.stdout.strip().split('\n') if f}

def get_covered_files(cwd):
    covered = set()
    for root, dirs, files in os.walk(cwd):
        for file in files:
            if file.endswith(".gcda"):
                source_name = file.replace(".gcda", ".c")
                rel_dir = os.path.relpath(root, cwd)
                full_path = source_name if rel_dir == "." else os.path.join(rel_dir, source_name)
                if full_path.startswith("./"):
                    full_path = full_path[2:]
                covered.add(full_path)
    return list(covered)

def flush_buffer_to_csv(filepath, buffer, fieldnames):
    if not buffer: return
    file_exists = os.path.exists(filepath)
    try:
        with open(filepath, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(fieldnames)
            writer.writerows(buffer)
            f.flush()
            os.fsync(f.fileno())
        buffer.clear()
    except Exception as e:
        logging.error(f"Failed to write CSV: {e}")

# ==========================================
# GPAC SPECIFIC: SETUP & TESTS
# ==========================================
def detect_test_folder(cwd):
    """Returns the name of the test folder: 'testsuite' (Modern) or 'tests' (Legacy)"""
    if os.path.exists(os.path.join(cwd, "testsuite", "make_tests.sh")):
        return "testsuite"
    if os.path.exists(os.path.join(cwd, "tests", "make_tests.sh")):
        return "tests"
    return None

def setup_gpac_test_environment(cwd):
    folder = detect_test_folder(cwd)
    if not folder:
        logging.warning("No test suite found (testsuite/ or tests/ missing).")
        return

    test_dir = os.path.join(cwd, folder)
    
    # Init submodule only if it is one (Modern)
    if folder == "testsuite" and os.path.exists(os.path.join(cwd, ".gitmodules")):
        logging.info("Initializing Test Suite Submodule...")
        run_command("git submodule update --init --recursive", cwd)
    
    # Download media
    # We check if media dir is empty to avoid redundant work (clean_repo now excludes it)
    media_dir = os.path.join(test_dir, "media")
    if not os.path.exists(media_dir) or not os.listdir(media_dir):
        logging.info(f"Downloading Test Media into {folder}/media...")
        run_command(f"cd {folder} && ./make_tests.sh -sync-media", cwd)

def get_gpac_tests(cwd):
    tests = []
    
    # Detect Layout
    folder = detect_test_folder(cwd)
    if not folder:
        logging.error("Could not find test folder (testsuite or tests).")
        return []

    logging.info(f"Detected Test Folder: {folder}")
    
    # Scan scripts
    scripts_dir = os.path.join(cwd, folder, "scripts")
    if os.path.exists(scripts_dir):
        script_files = glob.glob(os.path.join(scripts_dir, "*.sh"))
        for script in script_files:
            t_name = os.path.basename(script)
            # The runner expects "scripts/name.sh"
            rel_path = os.path.relpath(script, os.path.join(cwd, folder))
            
            # Command: cd FOLDER && ./make_tests.sh ...
            cmd = f"(cd {folder} && ./make_tests.sh -no-hash -clean {rel_path})"
            tests.append({"name": t_name, "cmd": cmd})

    if TEST_LIMIT and tests: 
        tests = tests[:TEST_LIMIT]
            
    return tests

# ==========================================
# PHASE 1: COVERAGE
# ==========================================
def run_phase_1_coverage(vuln, fix, master_csv_path, checkpoint_path):
    if os.path.exists(master_csv_path):
        with open(master_csv_path, 'r') as f:
            if f"{vuln},{fix}" in f.read():
                logging.info(f"Skipping P1 for {vuln}->{fix} (Found in Master CSV)")
                return True

    logging.info(f"--- Phase 1: Coverage {vuln} -> {fix} ---")
    
    clean_repo(PROJECT_DIR)
    if not run_command(f"git checkout -f {fix}", PROJECT_DIR): return False
    
    # Try updating submodules (harmless if none)
    run_command("git submodule update --init --recursive", PROJECT_DIR, ignore_errors=True)
    
    target_files = get_git_diff_files(PROJECT_DIR, fix)
    if not target_files:
        logging.error("No target files found in git diff.")
        return False

    setup_gpac_test_environment(PROJECT_DIR)

    cached_data = load_json(checkpoint_path)
    vuln_results = cached_data.get("results", {})

    # A. VULN COMMIT
    if cached_data.get("status") != "COMPLETE":
        logging.info(f"Building Vuln {vuln} (Coverage)...")
        clean_repo(PROJECT_DIR)
        run_command(f"git checkout -f {vuln}", PROJECT_DIR)
        run_command("git submodule update --init --recursive", PROJECT_DIR, ignore_errors=True)
        
        # Configure with --unittests + DISABLE FFmpeg
        config_cmd = "./configure --enable-debug --enable-gcov --disable-x11 --disable-oss-audio --disable-ffmpeg --unittests"
        run_command(config_cmd, PROJECT_DIR)
        run_command("make -j$(nproc)", PROJECT_DIR)
        
        suite = get_gpac_tests(PROJECT_DIR)
        print(f"Running {len(suite)} tests for Vuln Commit...")

        for i, test in enumerate(suite):
            t_name = test['name']
            if t_name in vuln_results: continue
            
            if i % 20 == 0: print(f"  [P1-Vuln] {i}/{len(suite)}: {t_name}")
            
            run_command("find . -name '*.gcda' -delete", PROJECT_DIR)
            run_command(test['cmd'], PROJECT_DIR, ignore_errors=True)
            
            covered = get_covered_files(PROJECT_DIR)
            relevant = [f for f in covered if f in target_files]
            
            if relevant:
                vuln_results[t_name] = relevant
                save_json(checkpoint_path, {"status": "IN_PROGRESS", "results": vuln_results})
        
        save_json(checkpoint_path, {"status": "COMPLETE", "results": vuln_results})

    # B. FIX COMMIT
    logging.info(f"Building Fix {fix} (Coverage)...")
    clean_repo(PROJECT_DIR)
    run_command(f"git checkout -f {fix}", PROJECT_DIR)
    run_command("git submodule update --init --recursive", PROJECT_DIR, ignore_errors=True)
    
    run_command("./configure --enable-debug --enable-gcov --disable-x11 --disable-oss-audio --disable-ffmpeg --unittests", PROJECT_DIR)
    run_command("make -j$(nproc)", PROJECT_DIR)

    suite = get_gpac_tests(PROJECT_DIR)
    csv_buffer = []
    csv_header = ["project", "vuln_commit", "v_testname", "fix_commit", "f_testname", "sourcefile"]
    
    print(f"Running {len(suite)} tests for Fix Commit...")
    for i, test in enumerate(suite):
        t_name = test['name']
        if i % 20 == 0: print(f"  [P1-Fix] {i}/{len(suite)}: {t_name}")

        run_command("find . -name '*.gcda' -delete", PROJECT_DIR)
        run_command(test['cmd'], PROJECT_DIR, ignore_errors=True)
        
        covered = get_covered_files(PROJECT_DIR)
        
        for target in target_files:
            v_covered = (t_name in vuln_results) and (target in vuln_results[t_name])
            f_covered = target in covered

            if v_covered or f_covered:
                v_entry = t_name if v_covered else ""
                f_entry = t_name if f_covered else ""
                csv_buffer.append([REPO_NAME, vuln, v_entry, fix, f_entry, target])

        if len(csv_buffer) >= CSV_WRITE_INTERVAL:
            flush_buffer_to_csv(master_csv_path, csv_buffer, csv_header)

    flush_buffer_to_csv(master_csv_path, csv_buffer, csv_header)
    return True

# ==========================================
# PHASE 2: ENERGY
# ==========================================
def detect_rapl():
    res = subprocess.run("perf list", shell=True, stdout=subprocess.PIPE, text=True)
    out = res.stdout
    pkg = "power/energy-pkg/" if "power/energy-pkg/" in out else "power/energy-pkg"
    core = "power/energy-cores/" if "power/energy-cores/" in out else "power/energy-cores"
    return pkg, core

def measure_test(test_cmd, pkg_event, core_event):
    cmd = test_cmd
    start = time.time()
    
    if not run_command(cmd, PROJECT_DIR, ignore_errors=True): 
        logging.warning(f"Measurement pre-check failed: {cmd}")

    duration = max(time.time() - start, 0.001)
    iterations = math.ceil(TARGET_DURATION_SEC / duration)
    loop_cmd = f"for i in $(seq 1 {iterations}); do {cmd} >/dev/null 2>&1; done"
    perf_cmd = f"perf stat -a -e {pkg_event},{core_event},cycles,instructions -x, sh -c '{loop_cmd}'"
    
    res = subprocess.run(perf_cmd, cwd=PROJECT_DIR, shell=True, stderr=subprocess.PIPE, text=True)
    
    metrics = {"energy_pkg": 0.0, "energy_core": 0.0, "cycles": 0, "instructions": 0}
    parse_success = False

    for line in res.stderr.split('\n'):
        parts = line.split(',')
        if len(parts) < 3: continue
        try:
            val = float(parts[0])
            evt = parts[2]
            if "energy-pkg" in evt: 
                metrics["energy_pkg"] = val
                parse_success = True
            elif "energy-cores" in evt: metrics["energy_core"] = val
            elif "cycles" in evt: metrics["cycles"] = val
            elif "instructions" in evt: metrics["instructions"] = val
        except ValueError: continue

    if not parse_success:
        if res.returncode != 0: 
            logging.error(f"Perf execution failed: {res.stderr}")
        return None

    if iterations > 0:
        return {k: v / iterations for k, v in metrics.items()}
    return None

def run_phase_2_energy(master_p1_csv, master_p2_csv, checkpoint_path, current_vuln, current_fix):
    logging.info(f"--- Phase 2: Energy {current_vuln} -> {current_fix} ---")
    
    if os.geteuid() != 0:
        logging.error("Phase 2 requires root permissions.")
        return False

    relevant_rows = []
    if os.path.exists(master_p1_csv):
        with open(master_p1_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['vuln_commit'] == current_vuln and row['fix_commit'] == current_fix:
                    relevant_rows.append(row)
    
    if not relevant_rows:
        return True

    EVENT_PKG, EVENT_CORE = detect_rapl()
    cache = load_json(checkpoint_path)

    tasks = {}
    for row in relevant_rows:
        if row['v_testname']: tasks.setdefault(current_vuln, set()).add(row['v_testname'])
        if row['f_testname']: tasks.setdefault(current_fix, set()).add(row['f_testname'])

    for commit, test_set in tasks.items():
        if commit not in cache: cache[commit] = {}
        todos = [t for t in test_set if t not in cache[commit]]
        if not todos: continue
        
        logging.info(f"Building {commit} (Standard)...")
        clean_repo(PROJECT_DIR)
        run_command(f"git checkout -f {commit}", PROJECT_DIR)
        run_command("git submodule update --init --recursive", PROJECT_DIR, ignore_errors=True)
        
        run_command("./configure --static-bin --disable-x11 --disable-oss-audio --disable-ffmpeg --unittests", PROJECT_DIR)
        run_command("make -j$(nproc)", PROJECT_DIR)

        suite = get_gpac_tests(PROJECT_DIR)
        test_map = {t['name']: t['cmd'] for t in suite}

        for i, test_name in enumerate(todos):
            print(f"  [P2-Measure] {commit[:8]} - {test_name} ({i+1}/{len(todos)})")
            
            if test_name not in test_map:
                logging.warning(f"Test {test_name} not found.")
                continue

            cmd = test_map[test_name]
            metrics = measure_test(cmd, EVENT_PKG, EVENT_CORE)
            if metrics:
                cache[commit][test_name] = metrics
                save_json(checkpoint_path, cache)

    csv_buffer = []
    csv_header = [
        "project", "vuln_commit", "v_testname", "v_energy_pkg", "v_energy_core", "v_cycles", "v_ipc",
        "fix_commit", "f_testname", "sourcefile", "f_energy_pkg", "f_energy_core", "f_cycles", "f_ipc"
    ]

    for row in relevant_rows:
        v_pkg, v_core, v_cyc, v_ipc = "0", "0", "0", "0"
        vc, vt = row['vuln_commit'], row['v_testname']
        if vt and vc in cache and vt in cache[vc]:
            m = cache[vc][vt]
            v_pkg = f"{m['energy_pkg']:.4f}"
            v_core = f"{m['energy_core']:.4f}"
            v_cyc = f"{m['cycles']:.0f}"
            v_ipc = f"{m['instructions']/m['cycles']:.4f}" if m['cycles'] > 0 else "0"

        f_pkg, f_core, f_cyc, f_ipc = "0", "0", "0", "0"
        fc, ft = row['fix_commit'], row['f_testname']
        if ft and fc in cache and ft in cache[fc]:
            m = cache[fc][ft]
            f_pkg = f"{m['energy_pkg']:.4f}"
            f_core = f"{m['energy_core']:.4f}"
            f_cyc = f"{m['cycles']:.0f}"
            f_ipc = f"{m['instructions']/m['cycles']:.4f}" if m['cycles'] > 0 else "0"

        csv_buffer.append([
            row['project'], row['vuln_commit'], row['v_testname'], 
            v_pkg, v_core, v_cyc, v_ipc,
            row['fix_commit'], row['f_testname'], row['sourcefile'],
            f_pkg, f_core, f_cyc, f_ipc
        ])

    flush_buffer_to_csv(master_p2_csv, csv_buffer, csv_header)
    return True

# ==========================================
# MAIN
# ==========================================
def main():
    download_csv_if_missing()

    MASTER_P1_CSV = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_MASTER_testCompile.csv")
    MASTER_P2_CSV = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_MASTER_energyperf.csv")
    
    pairs = []
    try:
        with open(INPUT_CSV, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('project') == REPO_NAME and 'vuln_commit' in row and 'fix_commit' in row:
                    pairs.append((row['vuln_commit'], row['fix_commit']))
    except Exception as e:
        sys.exit(1)

    print(f"Found {len(pairs)} pairs for {REPO_NAME}.")
    for i, (vuln, fix) in enumerate(pairs):
        print(f"\n[{i+1}/{len(pairs)}] Processing Pair: {vuln[:8]} -> {fix[:8]}")
        
        p1_cache = os.path.join(CACHE_DIR, f"ckpt_cov_{vuln[:8]}.json")
        p2_cache = os.path.join(CACHE_DIR, f"ckpt_eng_{vuln[:8]}_{fix[:8]}.json")

        success_p1 = run_phase_1_coverage(vuln, fix, MASTER_P1_CSV, p1_cache)
        if success_p1:
            run_phase_2_energy(MASTER_P1_CSV, MASTER_P2_CSV, p2_cache, vuln, fix)
        else:
            print("Skipping Phase 2 due to P1 failure.")

if __name__ == "__main__":
    main()