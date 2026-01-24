import os
import subprocess
import csv
import logging
import json
import time
import math
import sys

# ==========================================
# FILE SYSTEM & LOGGING HELPERS
# ==========================================
def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, 
                       format='%(asctime)s - %(levelname)s - %(message)s')
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger('').addHandler(console)

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

def clean_repo(cwd):
    run_command("git reset --hard", cwd)
    run_command("git clean -fdx", cwd)

def get_covered_files(cwd):
    """Common logic to find all .c files that generated a .gcda file"""
    covered = set()
    for root, dirs, files in os.walk(cwd):
        for file in files:
            if file.endswith(".gcda"):
                source_name = file.replace(".gcda", ".c")
                rel_dir = os.path.relpath(root, cwd)
                full_path = source_name if rel_dir == "." else os.path.join(rel_dir, source_name)
                covered.add(full_path)
    return list(covered)

# ==========================================
# MEASUREMENT ENGINE (PERF / ENERGY)
# ==========================================
def detect_rapl():
    """Detects the specific RAPL event name for Package energy"""
    res = subprocess.run("perf list", shell=True, stdout=subprocess.PIPE, text=True)
    out = res.stdout
    if "power/energy-pkg/" in out: return "power/energy-pkg/"
    return "power/energy-pkg" # Fallback

def measure_energy(cmd, cwd, target_duration=2.0, pkg_event="power/energy-pkg/"):
    """
    Runs the command, stabilizes duration, and captures ONLY Energy-PKG.
    Returns: float (Joules) or None
    """
    start = time.time()
    
    # 1. Pre-check (Relaxed)
    if not run_command(cmd, cwd, ignore_errors=True): 
        logging.warning(f"Measurement pre-check failed: {cmd}")

    # 2. Calculate Iterations
    duration = max(time.time() - start, 0.001)
    iterations = math.ceil(target_duration / duration)
    
    # 3. Construct Loop Command
    loop_cmd = f"for i in $(seq 1 {iterations}); do {cmd} >/dev/null 2>&1; done"
    
    # 4. Perf Command (PKG ONLY)
    # -x, means CSV output format
    perf_cmd = f"perf stat -a -e {pkg_event} -x, sh -c '{loop_cmd}'"
    
    res = subprocess.run(perf_cmd, cwd=cwd, shell=True, stderr=subprocess.PIPE, text=True)
    
    # 5. Parse Output
    energy_pkg = None
    
    # Output format example: 12.34,Joules,power/energy-pkg/,100.00,,
    for line in res.stderr.split('\n'):
        parts = line.split(',')
        if len(parts) < 3: continue
        try:
            val = float(parts[0])
            evt = parts[2]
            if "energy-pkg" in evt: 
                energy_pkg = val
                break # Found it, stop looking
        except ValueError: continue

    if energy_pkg is None:
        if res.returncode != 0:
            logging.error(f"Perf execution failed: {res.stderr}")
        return None

    if iterations > 0:
        return energy_pkg / iterations
    return None

# ==========================================
# CSV OUTPUT HANDLER
# ==========================================
class CSVManager:
    def __init__(self, p1_path, p2_path, write_interval=50):
        self.p1_path = p1_path
        self.p2_path = p2_path
        self.interval = write_interval
        self.buffer_p1 = []
        self.buffer_p2 = []
        
        # Define Headers
        self.header_p1 = ["project", "vuln_commit", "v_testname", "fix_commit", "f_testname", "sourcefile"]
        self.header_p2 = ["project", "vuln_commit", "v_testname", "v_energy_pkg",
                          "fix_commit", "f_testname", "sourcefile", "f_energy_pkg"]

    def add_p1(self, row):
        self.buffer_p1.append(row)
        if len(self.buffer_p1) >= self.interval:
            self.flush(self.p1_path, self.buffer_p1, self.header_p1)

    def add_p2(self, row):
        self.buffer_p2.append(row)
        if len(self.buffer_p2) >= self.interval:
            self.flush(self.p2_path, self.buffer_p2, self.header_p2)

    def flush_all(self):
        self.flush(self.p1_path, self.buffer_p1, self.header_p1)
        self.flush(self.p2_path, self.buffer_p2, self.header_p2)

    def flush(self, filepath, buffer, header):
        if not buffer: return
        file_exists = os.path.exists(filepath)
        try:
            with open(filepath, 'a', newline='') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(header)
                writer.writerows(buffer)
                f.flush()
                os.fsync(f.fileno())
            buffer.clear()
        except Exception as e:
            logging.error(f"Failed to write CSV {filepath}: {e}")