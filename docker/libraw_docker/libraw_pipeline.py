import os
import subprocess
import csv
import logging
import json
import time
import sys
import urllib.request
import re
import shlex
import yaml

# [KEEP] Project-Independent Helpers (Exact Copy)
class ProgressBar:
    def __init__(self, total, length=40, step=1):
        self.total = total
        self.length = length
        self.step = step
        self.current = 0

    def update(self, i):
        self.current = i
        progress = (i + 1) / self.total
        filled = int(self.length * progress)
        bar = '█' * filled + '░' * (self.length - filled)
        print(f"\r[{bar}] {i+1}/{self.total}", end='', flush=True)

    def log(self, msg):
        print()
        print(msg)
        self.update(self.current)

    def set(self, i):
        self.current = i
        self.update(i)

# ==========================================
# CONFIGURATION
# ==========================================
REPO_NAME = "libraw" 
TARGET_DURATION_SEC = 2.0
CSV_WRITE_INTERVAL = 50
TEST_LIMIT = None

GIST_CSV_URL = "https://gist.githubusercontent.com/waheed-sep/935cfc1ba42b2475d45336a4c779cbc8/raw/cwe_projects.csv"

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
GCDA_DIR = os.path.join(OUTPUT_DIR, "gcda_files") 

ITERATIONS = 5
DEFAULT_TIMEOUT_MS = 2000
COOL_DOWN_TO_SEC = 1.0

ENERGY_RE = re.compile(r'\bpower/energy-[^/\s]+/?\b')

def prepare_directories():
    for d in [INPUT_DIR, OUTPUT_DIR, LOG_DIR, CACHE_DIR, GCDA_DIR]:
        if not os.path.exists(d): os.makedirs(d)

def setup_logging():
    LOG_FILE = os.path.join(LOG_DIR, "pipeline_execution.log")
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command, cwd, ignore_errors=False):
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        result = subprocess.run(command, cwd=cwd, shell=True, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, errors='replace')
        if result.returncode != 0 and not ignore_errors:
            logging.error(f"FAIL: {command}\nSTDERR: {result.stderr.strip()}")
            return False
        return True
    except Exception as e:
        logging.error(f"EXCEPTION: {e}")
        return False

def save_json(filepath, data):
    try:
        with open(filepath, 'w') as f: json.dump(data, f, indent=4)
    except Exception as e: logging.error(f"JSON Save Error: {e}")

def load_json(filepath):
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f: return json.load(f)
        except: return {}
    return {}

def clean_repo(cwd):
    run_command("git reset --hard", cwd)
    run_command("git clean -fdx", cwd)

def download_csv_if_missing():
    if not os.path.exists(INPUT_CSV):
        print(f"Downloading input CSV from Gist to {INPUT_CSV}...")
        try:
            urllib.request.urlretrieve(GIST_CSV_URL, INPUT_CSV)
            print("Download complete.")
        except Exception as e:
            print(f"Error downloading CSV: {e}")
            sys.exit(1)
            
    # [FIX] Download a sample CR2 image for LibRaw workload execution
    raw_sample = os.path.join(INPUT_DIR, "sample.cr2")
    if not os.path.exists(raw_sample):
        print("Downloading sample CR2 raw image for workload...")
        raw_url = "https://raw.githubusercontent.com/waheed-sep/vf_ec/main/docker/libraw_docker/sample.cr2"
        try:
            urllib.request.urlretrieve(raw_url, raw_sample)
        except Exception as e:
            print(f"Error downloading sample image: {e}")

def get_git_diff_files(cwd, commit_hash):
    cmd = f"git diff-tree --no-commit-id --name-only -r {commit_hash}"
    result = subprocess.run(cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE, text=True)
    return {f for f in result.stdout.strip().split('\n') if f}

def get_gcda_files(cwd):
    gcda_files = []
    for root, dirs, files in os.walk(cwd):
        for file in files:
            if file.endswith(".gcda"):
                gcda_files.append(os.path.join(root, file))
    return gcda_files

def force_patch_powf64(cwd):
    """
    Aggressively finds and renames 'powf64' to 'libraw_powf64' 
    to prevent conflicts with the system math library.
    """
    # Look for the file in common LibRaw locations
    candidates = [
        os.path.join(cwd, "internal", "dcraw_common.cpp"),
        os.path.join(cwd, "src", "dcraw_common.cpp"),
        os.path.join(cwd, "dcraw_common.cpp")
    ]
    
    patched = False
    for fpath in candidates:
        if os.path.exists(fpath):
            try:
                # Read the file
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check if it needs patching
                if 'powf64' in content:
                    logging.info(f"Found 'powf64' in {fpath}. Patching...")
                    # Replace definitions and calls
                    new_content = content.replace('powf64', 'libraw_powf64')
                    
                    # Write it back
                    with open(fpath, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    logging.info("SUCCESS: Patched 'powf64' to 'libraw_powf64'.")
                    patched = True
                else:
                    logging.info(f"Checked {fpath}: No 'powf64' found (already patched?).")
            except Exception as e:
                logging.error(f"Failed to patch {fpath}: {e}")

    if not patched:
        logging.warning("WARNING: Could not find 'dcraw_common.cpp' to patch.")

# ==========================================
# LIBRAW SPECIFIC
# ==========================================
def configure_libraw(cwd, coverage=False):
    # Ensure autotools files exist
    if not os.path.exists(os.path.join(cwd, "configure")):
        if not run_command("autoreconf -i", cwd):
            logging.error("Failed to run autoreconf")
            return False

    config_args = [
        "./configure",
        "--enable-static",
        "--disable-shared"
    ]

    # Fallback: try multiple C++ standards
    std_candidates = ["gnu++98", "gnu++11", "gnu++14"]

    for std in std_candidates:
        # Base flags (include Wno-error to avoid warnings stopping build)
        flags = f"-O0 -Wno-error -Wno-narrowing -fpermissive -std={std}"
        libs = "-lstdc++"

        if coverage:
            flags += " --coverage"
            libs += " -lgcov"

        # Clean configure cache between attempts (important!)
        run_command("rm -f config.cache", cwd, ignore_errors=True)

        full_cmd = (
            f'CC=g++ CXX=g++ '
            f'CFLAGS="{flags}" CXXFLAGS="{flags}" LDFLAGS="{flags}" '
            f'LIBS="{libs}" {" ".join(config_args)}'
        )

        logging.info(f"Trying configure with -std={std} (coverage={coverage})")
        if run_command(full_cmd, cwd):
            logging.info(f"Configure succeeded with -std={std}")
            return True

        logging.warning(f"Configure failed with -std={std}")

    logging.error("Configure failed for all fallback C++ standards.")
    return False



def build_libraw(cwd):
    return run_command("make -j$(nproc)", cwd)

def get_libraw_tests(cwd):
    raw_sample = os.path.join(INPUT_DIR, "sample.cr2")
    tests = [
        {
            "name": "libraw-identify",
            # [FIX] Execute the actual binary against the downloaded image to generate coverage
            "cmd": f"./bin/raw-identify {raw_sample}", 
            "type": "binary"
        }
    ]
    return tests

# ==========================================
# PHASE 1 & 2 LOGIC
# ==========================================

def process_commit(commit: str, coverage: bool = True):
    logging.info(f"Building {commit[:8]} (Coverage)...")
    clean_repo(PROJECT_DIR)
    run_command(f"git checkout -f {commit}", PROJECT_DIR)
    
    run_command("git submodule update --init --recursive", PROJECT_DIR)

    # 2. Apply Patch IMMEDIATELY AFTER Checkout
    force_patch_powf64(PROJECT_DIR)

    commit_results = { "hash": commit, "tests": [] }

    if not configure_libraw(PROJECT_DIR, coverage=coverage): return None
    if not build_libraw(PROJECT_DIR): return None
    
    suite = get_libraw_tests(PROJECT_DIR)
    print(f"\nRunning {len(suite)} tests...")

    pb = ProgressBar(len(suite), step=10)
    for i, t in enumerate(suite):
        pb.set(i)

        test = {
            "name": t['name'],
            "failed": False,
            "cmd": t['cmd'],
            "covered_files": []
        }
        
        if not run_command(test.get('cmd'), PROJECT_DIR):
            logging.warning(f"Test Build/Run Failed: {test.get('name')}")
            test['failed'] = True
            commit_results['tests'].append(test)
            continue
        
        # [UPDATED] GCOV LOOP
        # We process files from the Project Root so gcov can find the source code
        gcda_files = get_gcda_files(PROJECT_DIR)
        for gcda in gcda_files:
            # We pass the absolute path to the .gcda file
            # We run from PROJECT_DIR so relative source paths (e.g. 'internal/dcraw.c') resolve correctly
            run_command(f"gcov -p {gcda}", cwd=PROJECT_DIR, ignore_errors=True)

        test['covered_files'] = [os.path.basename(f) for f in gcda_files]

        test_safe_name = t['name'].replace(" ", "_").replace("/", "_")
        test_gcov_dir = os.path.join(GCDA_DIR, commit[:8], test_safe_name)
        os.makedirs(test_gcov_dir, exist_ok=True)

        # [UPDATED] Move files from Project Root
        # Because we ran gcov in PROJECT_DIR, the .gcov files are generated there
        run_command(f"find . -maxdepth 1 -name '*.gcov' -exec mv {{}} {test_gcov_dir}/ \\;", PROJECT_DIR)

        # Cleanup
        run_command("find . -name '*.gcda' -delete", PROJECT_DIR)
        run_command("find . -name '*.gcov' -delete", PROJECT_DIR)

        commit_results['tests'].append(test)
        
    return commit_results

def prepare_for_energy_measurement():
    print("\nPreparing project for energy measurement...")
    clean_repo(PROJECT_DIR)
    configure_libraw(PROJECT_DIR, coverage=False)
    build_libraw(PROJECT_DIR)
    
def run_phase_1_coverage(vuln, fix):
    logging.info(f"--- Phase 1: Coverage {vuln[:8]} -> {fix[:8]} ---")
    coverage_results = {
        "project": REPO_NAME,
        "vuln_commit": { "hash": vuln, "failed":{ "status": False, "reason": "" }, "tests": [] },
        "fix_commit": { "hash": fix, "failed": { "status": False, "reason": "" }, "tests": [] }
    }
    
    clean_repo(PROJECT_DIR)
    if not run_command(f"git checkout -f {fix}", PROJECT_DIR): return None
    
    # [NEW] Apply patch for FIX commit
    force_patch_powf64(PROJECT_DIR)

    git_changed_files= get_git_diff_files(PROJECT_DIR, fix)
    if not git_changed_files: return None
    
    # FIX COMMIT
    coverage_results['fix_commit'] = process_commit(fix)
    if not coverage_results['fix_commit'] or all(t.get('failed', True) for t in coverage_results['fix_commit'].get('tests', [])):
        return None
    
    extract_test_covering_git_changes(coverage_results.get('fix_commit', {}), git_changed_files)
    logging.info(f"Extracted tests covering changed files in pair ({vuln[:8]}, {fix[:8]}).")
    logging.info(f"Now computing energy for {fix[:8]}.")
    
    rapl_pkg = detect_rapl()
    kept_tests = [t for t in coverage_results['fix_commit'].get('tests', []) if t.get('keep', True) and not t.get('failed', True)]

    prepare_for_energy_measurement()
    for test in kept_tests:
        measure_test(rapl_pkg, test, fix)

    # VULN COMMIT
    coverage_results['vuln_commit'] = process_commit(vuln)
    if not coverage_results['vuln_commit'] or all(t.get('failed', True) for t in coverage_results['vuln_commit'].get('tests', [])):
        return None

    extract_test_covering_git_changes(coverage_results.get('vuln_commit', {}), git_changed_files)
    logging.info(f"Extracted tests covering changed files in pair ({vuln[:8]}, {fix[:8]}).")
    logging.info(f"Now computing energy for {vuln[:8]}.")
    
    kept_tests = [t for t in coverage_results.get('vuln_commit', {}).get('tests', []) if t.get('keep', True) and not t.get('failed', True)]
    
    prepare_for_energy_measurement()
    for test in kept_tests:
        measure_test(rapl_pkg, test, vuln)

    return coverage_results
    
def extract_test_covering_git_changes(coverage_results, target_files):  
    target_bases = {os.path.splitext(os.path.basename(f))[0] for f in target_files}

    for test in coverage_results.get('tests', []):
        if test.get('failed', False):
            test['keep'] = False
            continue

        covered_bases = {os.path.splitext(f)[0] for f in test.get('covered_files', [])}
        has_overlap = len(target_bases.intersection(covered_bases)) > 0
        test['keep'] = has_overlap

# ==========================================
# PHASE 2: ENERGY 
# ==========================================
def detect_rapl(perf_bin="perf"):
    cmd = [perf_bin, "list", "--no-desc"]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        out = subprocess.check_output([perf_bin, "list"], text=True, stderr=subprocess.STDOUT)

    events = set()
    for line in out.splitlines():
        for m in ENERGY_RE.findall(line):
            if not m.endswith("/"): m += "/"
            events.add(m)
    return sorted(events)

def _wrap_until_timeout(test_cmd: str, timeout_ms: int) -> str:
    timeout_s = max(1, int((timeout_ms + 999) / 1000))
    wrapped = (
        "bash -lc "
        + shlex.quote(
            f"""
            set -e
            end=$((SECONDS + {timeout_s}))
            while [ $SECONDS -lt $end ]; do
              {test_cmd}
            done
            """
        )
    )
    return wrapped

def measure_test(pkg_event, test, commit):
    if isinstance(pkg_event, (list, tuple, set)):
        events = [str(e).strip() for e in pkg_event if str(e).strip()]
    elif pkg_event:
        events = [str(pkg_event).strip()]
    else:
        events = []
    if not events: events = ["power/energy-pkg/"]
    perf_events = ",".join(events + ["cycles", "instructions"])
    
    pb = ProgressBar(ITERATIONS)
    perf_dir = os.path.join(OUTPUT_DIR, REPO_NAME, "perf")
    os.makedirs(perf_dir, exist_ok=True)

    timeout_ms = test.get("timeout_ms", DEFAULT_TIMEOUT_MS)
    print(f"\nMeasuring energy for test '{test.get('name')}': {ITERATIONS} iters")

    for iteration in range(ITERATIONS):
        pb.set(iteration)
        perf_out = os.path.join(perf_dir, f"{commit}_{test.get('name')}___iter{iteration}.csv")
        wrapped_cmd = _wrap_until_timeout(test["cmd"], timeout_ms)
        perf_argv = ["perf", "stat", "-a", "-e", f"{perf_events}", "-x,", "--output", perf_out, "--", "sh", "-c", wrapped_cmd]

        res = subprocess.run(perf_argv, cwd=PROJECT_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
        
        if res.returncode != 0: 
            logging.error(f"[STD ERR] {test.get('name')}: {res.stderr}")
            if os.path.exists(perf_out): os.remove(perf_out)
            return None
        
        time.sleep(COOL_DOWN_TO_SEC)
    return None

def read_configuration():
    config_file = os.path.join(BASE_DIR, "config.yaml")
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f: return yaml.safe_load(f)
        except Exception: pass

# ==========================================
# MAIN
# ==========================================
def main():
    prepare_directories()
    setup_logging()
    download_csv_if_missing()
    read_configuration() 

    pairs = []
    try:
        with open(INPUT_CSV, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                p_name = row.get('project', '').strip()
                if p_name.lower() == REPO_NAME.lower():
                    if row.get('vuln_commit') and row.get('fix_commit'):
                        pairs.append((row['vuln_commit'], row['fix_commit']))
    except Exception as e:
        sys.exit(1)

    if not pairs:
        sys.exit(1)

    for i, (vuln, fix) in enumerate(pairs):
        print(f"\n[{i+1}/{len(pairs)}] Processing Pair: {vuln[:8]} -> {fix[:8]}")
        
        coverage_dict = run_phase_1_coverage(vuln, fix)
        if coverage_dict is None:
            continue

        coverage_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_{vuln[:8]}_{fix[:8]}_coverage.json")
        with open(coverage_path, "w") as f:
                json.dump(coverage_dict, f, indent=2)

if __name__ == "__main__":
    main()