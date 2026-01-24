# Finding vuln_commits of fix_commit in cwe_projects.csv

import pandas as pd
import os
from git import Repo, exc
import sys

# --- Configuration ---
CSV_FILE = '../inputs/cwe_gist.csv'
REPO_BASE_PATH = '/home/mwk/UCD/vf_ec/ds_projects/'

def get_parent_commit(repo_path, fix_commit_hash):
    """
    Finds the first parent of a specific commit hash in a git repo.
    Strategies:
    1. Check local.
    2. Fetch all (update branches).
    3. Surgical fetch (fetch specific hash directly from origin).
    """
    try:
        repo = Repo(repo_path)
        
        # --- Attempt 1: Local Lookup ---
        try:
            commit = repo.commit(fix_commit_hash)
        except (ValueError, exc.BadName):
            # --- Attempt 2: General Fetch ---
            print(f"  [!] Commit {fix_commit_hash[:7]} missing in {os.path.basename(repo_path)}. Running general fetch...")
            try:
                repo.git.fetch('--all')
                commit = repo.commit(fix_commit_hash)
                print(f"  [+] Found after general fetch.")
            except (ValueError, exc.BadName, exc.GitCommandError):
                # --- Attempt 3: Surgical Fetch (Specific Hash) ---
                print(f"  [!] General fetch failed. Trying surgical fetch for {fix_commit_hash[:7]}...")
                try:
                    # Equivalent to: git fetch origin <hash>
                    repo.git.fetch('origin', fix_commit_hash)
                    commit = repo.commit(fix_commit_hash)
                    print(f"  [+] Found after surgical fetch.")
                except Exception as e:
                    print(f"  [!] CRITICAL: Could not retrieve commit {fix_commit_hash[:7]} even after surgical fetch. Reason: {e}")
                    return None

        # Check if the commit has parents (initial commits do not)
        if not commit.parents:
            return None
            
        # We take the first parent as the pre-fix (vulnerable) state.
        parent_hash = commit.parents[0].hexsha
        return parent_hash
        
    except (exc.NoSuchPathError, exc.InvalidGitRepositoryError):
        print(f"  [!] Error: Repository not found or invalid at {repo_path}")
        return None
    except Exception as e:
        print(f"  [!] Error processing commit {fix_commit_hash}: {e}")
        return None

def main():
    # 1. Load the CSV
    if not os.path.exists(CSV_FILE):
        print(f"Error: {CSV_FILE} not found.")
        sys.exit(1)
        
    print(f"Reading {CSV_FILE}...")
    df = pd.read_csv(CSV_FILE)

    # Ensure vuln_commit column exists
    if 'vuln_commit' not in df.columns:
        df['vuln_commit'] = ""
    
    # 2. Iterate through the rows
    updates_count = 0
    
    print(f"Processing {len(df)} rows against repos in {REPO_BASE_PATH}...\n")

    for index, row in df.iterrows():
        project_name = str(row['project']).strip()
        fix_commit = str(row['fix_commit']).strip()
        
        # Skip if fix_commit is missing
        if not fix_commit or fix_commit.lower() == 'nan':
            continue

        # Construct full path to the local repository
        repo_full_path = os.path.join(REPO_BASE_PATH, project_name)

        # Get the parent commit
        parent = get_parent_commit(repo_full_path, fix_commit)

        if parent:
            df.at[index, 'vuln_commit'] = parent
            updates_count += 1
        else:
            print(f"  [-] Could not identify parent for {project_name} (Fix: {fix_commit[:7]})")

    # 3. Save the updated CSV
    print(f"\nProcessing complete. identified {updates_count} vulnerable commits.")
    print(f"Overwriting {CSV_FILE}...")
    
    df.to_csv(CSV_FILE, index=False)
    print("Done.")

if __name__ == "__main__":
    main()