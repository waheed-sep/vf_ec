import os
import subprocess
import logging

# ==========================================
# FFMPEG PROJECT DEFINITION
# ==========================================

def run_cmd(command, cwd, ignore_errors=False):
    # Helper to run shell commands
    try:
        env = os.environ.copy()
        env["LC_ALL"] = "C"
        subprocess.run(command, cwd=cwd, shell=True, env=env, check=not ignore_errors, 
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        if not ignore_errors:
            logging.error(f"FFmpeg Engine Error: {command}")

def ensure_samples(input_dir):
    """
    Checks for FATE samples. If missing, downloads them via rsync.
    """
    samples_dir = os.path.join(input_dir, "fate-samples")
    
    # Check if exists and not empty
    if not os.path.exists(samples_dir) or not os.listdir(samples_dir):
        logging.info("FATE Samples not found. Downloading (this is huge)...")
        try:
            # Create dir
            os.makedirs(samples_dir, exist_ok=True)
            # Standard FFmpeg FATE rsync command
            cmd = f"rsync -aL rsync://fate-suite.ffmpeg.org/fate-suite/ {samples_dir}/"
            run_cmd(cmd, input_dir)
            logging.info("FATE Samples download complete.")
        except Exception as e:
            logging.error(f"Failed to download FATE samples: {e}")

def build_coverage(cwd):
    """Builds FFmpeg with GCOV enabled"""
    # 1. Ensure samples exist before we start relying on them
    # cwd is /app/inputs/FFmpeg, so input_dir is /app/inputs
    ensure_samples(os.path.dirname(cwd))
    
    logging.info("FFmpeg: Configuring for Coverage...")
    run_cmd("./configure --disable-asm --disable-doc --extra-cflags='--coverage' --extra-ldflags='--coverage'", cwd)
    run_cmd("make -j$(nproc)", cwd)

def build_energy(cwd):
    """Builds FFmpeg in standard mode"""
    # Ensure samples here too (in case Phase 1 was skipped)
    ensure_samples(os.path.dirname(cwd))
    
    logging.info("FFmpeg: Configuring for Energy (Standard)...")
    run_cmd("./configure --disable-asm --disable-doc", cwd)
    run_cmd("make -j$(nproc)", cwd)

def get_tests(cwd, limit=None):
    """
    Returns list of tests with the SAMPLES path injected.
    """
    # Locate Samples Directory
    base_input = os.path.dirname(cwd) 
    samples_dir = os.path.join(base_input, "fate-samples")
    
    # 1. Ask Make for the list
    res = subprocess.run("make fate-list", cwd=cwd, shell=True, stdout=subprocess.PIPE, text=True)
    tests = [l.strip() for l in res.stdout.split('\n') if l.strip().startswith("fate-")]
    
    if limit:
        tests = tests[:limit]

    # 2. Return test objects
    # CRITICAL: We pass SAMPLES=... here so Phase 1 finds the files
    return [{"name": t, "cmd": f"make {t} SAMPLES={samples_dir} -j$(nproc)"} for t in tests]

def get_energy_test_cmd(test_name, cwd, input_dir):
    """
    Returns the command for Phase 2 (Energy).
    """
    samples_dir = os.path.join(input_dir, "fate-samples")
    # CRITICAL: We pass SAMPLES=... here so Phase 2 finds the files
    return f"make {test_name} SAMPLES={samples_dir} -j1"