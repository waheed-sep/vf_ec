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

# [KEEP] Project-Independent Helpers (Restored Exact Original)
class ProgressBar:
    def __init__(self, total, length=40, step=1):
        self.total = total
        self.length = length
        self.step = step

    def update(self, i):
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
REPO_NAME = "tensorflow"
TARGET_DURATION_SEC = 2.0
CSV_WRITE_INTERVAL = 50
TEST_LIMIT = None

# [FIX] Updated URL
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
DEFAULT_TIMEOUT_MS = 10000 
COOL_DOWN_TO_SEC = 1.0

ENERGY_RE = re.compile(r'\bpower/energy-[^/\s]+/?\b')

def prepare_directories():
    for d in [INPUT_DIR, OUTPUT_DIR, LOG_DIR, CACHE_DIR, GCDA_DIR]:
        if not os.path.exists(d): os.makedirs(d)

def setup_logging():
    LOG_FILE = os.path.join(LOG_DIR, "pipeline_execution.log")
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# [KEEP] Restored Exact Original
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
# [UPDATED] TENSORFLOW SPECIFIC
# ==========================================
def configure_tensorflow(cwd, coverage=False):
    # 1. Run Configure (Non-Interactive via Env Vars)
    # We prefix variables strictly in the command string, preserving run_command's independence.
    config_cmd = (
        "TF_NEED_CUDA=0 TF_NEED_ROCM=0 TF_DOWNLOAD_CLANG=0 "
        "CC_OPT_FLAGS='-Wno-sign-compare' "
        "PYTHON_BIN_PATH=$(which python3) "
        "USE_DEFAULT_PYTHON_LIB_PATH=1 "
        "./configure"
    )
    
    if not run_command(config_cmd, cwd, ignore_errors=True):
        return False

    # 2. Modify .bazelrc to control Phase 1 vs Phase 2
    # This allows us to use the EXACT SAME test command in both phases, 
    # complying with the generic script logic.
    bazelrc_path = os.path.join(cwd, ".bazelrc")
    
    # Base flags (Common)
    flags = "build --nocache_test_results --test_output=errors\n"
    
    if coverage:
        # Phase 1: Enable GCOV
        flags += "build --collect_code_coverage --instrumentation_filter=//tensorflow/core/...\n"
    else:
        # Phase 2: Enable Optimization (Energy)
        flags += "build -c opt\n"

    try:
        with open(bazelrc_path, "a") as f: # Append to existing config
            f.write(flags)
        return True
    except Exception as e:
        logging.error(f"Failed to write .bazelrc: {e}")
        return False

def build_tensorflow(cwd):
    # Verify Bazel is ready
    if run_command("bazel version", cwd):
        return True
    logging.error("Bazel check failed.")
    return False

def get_tensorflow_tests(cwd):
    tests = []
    logging.info("Querying Bazel for tests...")
    
    # Query for C++ tests
    cmd = "bazel query 'kind(cc_test, //tensorflow/core/...)'"
    
    try:
        # We must run this directly to parse stdout
        res = subprocess.run(cmd, cwd=cwd, shell=True, stdout=subprocess.PIPE, text=True)
        found_targets = [l.strip() for l in res.stdout.split('\n') if l.strip()]
        
        for target in found_targets:
            t_name = target.replace("//", "").replace("/", "_").replace(":", "_")
            
            # GENERIC COMMAND: We rely on .bazelrc (configured above) 
            # to switch between coverage/energy modes.
            tests.append({
                "name": t_name,
                "cmd": f"bazel test {target}",
                "type": "bazel"
            })
            
    except Exception as e:
        logging.error(f"Bazel query failed: {e}")

    if TEST_LIMIT and tests: 
        tests = tests[:TEST_LIMIT]
        
    return tests

# ==========================================
# PHASE 1: COVERAGE (Restored Exact Original)
# ==========================================

def process_commit(commit: str, coverage: bool = True) -> (dict | None):
    """ 
    Process a single commit: checkout, build with coverage, run tests, collect coverage data.

    :param commit: The git commit hash to process
    :param coverage: Whether to build with coverage instrumentation
    :return: A dictionary with test results and coverage data, or None if build fails
    """
    
    logging.info(f"Building {commit[:8]} (Coverage)...")
    clean_repo(PROJECT_DIR)
    run_command(f"git checkout -f {commit}", PROJECT_DIR)
    
    commit_results = {
        "hash": commit,
        "tests": []
    }

    # [UPDATED CALLS]
    if not configure_tensorflow(PROJECT_DIR, coverage=coverage): return None
    if not build_tensorflow(PROJECT_DIR): return None
    
    # [UPDATED CALL]
    suite = get_tensorflow_tests(PROJECT_DIR)
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

        # Clean previous coverage data
        run_command("find . -name '*.gcda' -delete", PROJECT_DIR)
        
        if not run_command(test.get('cmd'), PROJECT_DIR):
            logging.warning(f"Test Build/Run Failed: {test.get('name')}")
            test['failed'] = True
            commit_results['tests'].append(test)
            continue
        
        covered = get_covered_files(PROJECT_DIR)
        test['covered_files'] = covered
        commit_results['tests'].append(test)
        
    return commit_results

def prepare_for_energy_measurement():
    """
    Prepare the project for energy measurement.
    Build the project without coverage.
    """
    print("\nPreparing project for energy measurement...")

    # [UPDATED CALLS]
    configure_tensorflow(PROJECT_DIR, coverage=False)
    build_tensorflow(PROJECT_DIR)
    
def run_phase_1_coverage(vuln, fix):
    logging.info(f"--- Phase 1: Coverage {vuln[:8]} -> {fix[:8]} ---")
    coverage_results = {
        "project": REPO_NAME,
        "vuln_commit": {
            "hash": vuln,
            "failed":{
                "status": False,
                "reason": ""
            },
            "tests": []
        },
        "fix_commit": {
            "hash": fix,
            "failed": {
                "status": False,
                "reason": ""
            },
            "tests": []
        }
    }
    
    clean_repo(PROJECT_DIR)
    if not run_command(f"git checkout -f {fix}", PROJECT_DIR):
        logging.error(f"Failed to checkout fix commit: {fix}")
        return None
    
    git_changed_files= get_git_diff_files(PROJECT_DIR, fix)
    
    if not git_changed_files:
        logging.error("No target files found in git diff.")
        return None
    
    # FIX COMMIT
    coverage_results['fix_commit'] = process_commit(fix)
    if not coverage_results['fix_commit'] or all(t.get('failed', True) for t in coverage_results['fix_commit'].get('tests', [])):
        logging.error("No successful tests in fix commit. Skipping processing.")
        return None
    
    extract_test_covering_git_changes(coverage_results.get('fix_commit', {}), git_changed_files)
    logging.info(f"Extracted tests covering changed files in pair ({vuln[:8]}, {fix[:8]}).")
    
    logging.info(f"Now computing energy for {fix[:8]}.")
    
    # extract RAPL package events
    rapl_pkg = detect_rapl()

    kept_tests = [t for t in coverage_results['fix_commit'].get('tests', []) if t.get('keep', True) and not t.get('failed', True)]

    prepare_for_energy_measurement()
    for test in kept_tests:
        measure_test(rapl_pkg, test, fix)

    # VULN COMMIT
    coverage_results['vuln_commit'] = process_commit(vuln)
    if not coverage_results['vuln_commit'] or all(t.get('failed', True) for t in coverage_results['vuln_commit'].get('tests', [])):
        logging.error("No successful tests in vuln commit. Skipping processing.")
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
    for target in target_files:
        for test in coverage_results.get('tests', []):
            if coverage_results.get('failed', {}).get('status', True):
                continue
        
            for test in coverage_results.get('tests', []):
                covered_files = test.get('covered_files', [])
                test['keep'] = target in covered_files

# ==========================================
# PHASE 2: ENERGY (Restored Exact Original)
# ==========================================
def detect_rapl(perf_bin="perf"):
    # --no-desc makes output easier to parse if supported; if not, fall back.
    cmd = [perf_bin, "list", "--no-desc"]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        out = subprocess.check_output([perf_bin, "list"], text=True, stderr=subprocess.STDOUT)

    events = set()
    for line in out.splitlines():
        # Grab all matches from the line (some lines may include multiple tokens)
        for m in ENERGY_RE.findall(line):
            # Normalize to the canonical perf selector form with trailing '/'
            if not m.endswith("/"):
                m += "/"
            events.add(m)

    return sorted(events)


def _wrap_until_timeout(test_cmd: str, timeout_ms: int) -> str:
    timeout_s = max(1, int((timeout_ms + 999) / 1000))  # ceil to seconds

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

def measure_test(pkg_event, test, commit):#, core_event):
    # Accept a list from detect_rapl() or a single event string.
    if isinstance(pkg_event, (list, tuple, set)):
        events = [str(e).strip() for e in pkg_event if str(e).strip()]
    elif pkg_event:
        events = [str(pkg_event).strip()]
    else:
        events = []

    if not events:
        events = ["power/energy-pkg/"]

    perf_events = ",".join(events + ["cycles", "instructions"])
    
    pb = ProgressBar(ITERATIONS)
    perf_dir = os.path.join(OUTPUT_DIR, REPO_NAME, "perf")
    os.makedirs(perf_dir, exist_ok=True)

    timeout_ms = test.get("timeout_ms", DEFAULT_TIMEOUT_MS)  # e.g. 5s default, tune per test
    print(f"\nMeasuring energy for test '{test.get('name')}': "
          f"{ITERATIONS} iterations × {timeout_ms}ms timeout each")

    for iteration in range(ITERATIONS):
        pb.set(iteration)

        perf_out = os.path.join(perf_dir, f"{commit}_{test.get('name')}__{iteration}.csv")

        wrapped_cmd = _wrap_until_timeout(test["cmd"], timeout_ms)

        # Build perf as argv list (safer than huge shell string)
        perf_argv = [
            "perf", "stat",
            "-a",
            "-e", f"{perf_events}",
            "-x,", "--output", perf_out,
            "--",
        ]
        perf_argv += ["sh", "-c", wrapped_cmd]

        res = subprocess.run(
            perf_argv, 
            cwd=PROJECT_DIR, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True)
        
        if res.returncode != 0: 
            logging.error(f"[STD ERR] {test.get('name')}: {res.stderr}")
            if os.path.exists(perf_out):
                os.remove(perf_out)
            logging.error(f"Perf Measurement removed due to error.")
            return None
        
        time.sleep(COOL_DOWN_TO_SEC)
        
    return None

def read_configuration():
    config_file = os.path.join(BASE_DIR, "config.yaml")
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                logging.info(f"Configuration loaded from {config_file}")
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error reading configuration file: {e}")
    else:
        logging.info(f"No configuration file found at {config_file}")

# ==========================================
# MAIN (Restored Logic + CSV Fix)
# ==========================================
def main():
    prepare_directories()
    setup_logging()
    download_csv_if_missing()
    read_configuration() 

    pairs = []
    # [FIX] Keep the CSV fix (utf-8-sig + case insensitive) as accepted
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
        print(f"[ERROR] No pairs found for {REPO_NAME}")
        sys.exit(1)

    for i, (vuln, fix) in enumerate(pairs):
        print(f"\n[{i+1}/{len(pairs)}] Processing Pair: {vuln[:8]} -> {fix[:8]}")
        
        coverage_dict = run_phase_1_coverage(vuln, fix)
        if coverage_dict is None:
            print(f"\nSkipping Phase 2 due to Phase 1 failure.")
            continue

        coverage_path = os.path.join(OUTPUT_DIR, f"{REPO_NAME}_{vuln[:8]}_{fix[:8]}_coverage.json")
        with open(coverage_path, "w") as f:
                json.dump(coverage_dict, f, indent=2)

if __name__ == "__main__":
    main()