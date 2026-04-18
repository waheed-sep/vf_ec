import pandas as pd
import re
from pathlib import Path

def combine_test_data():
    # 1. Setup Relative Paths
    # __file__ refers to test_combiner.py, so its parent is the vf_ec directory
    base_dir = Path(__file__).resolve().parent
    input1_base = base_dir / 'final_results'
    input2_base = base_dir / 'ds_projects' / 'diffs'
    output_path = input1_base / 'test_combiner.csv'

    # Regex to extract <project> from <project>_final folder names
    project_regex = re.compile(r'^(.+)_final$')
    
    combined_dataframes = []

    print("Scanning directories and compiling data...")

    # 2. Iterate through all items in the final_results directory
    if not input1_base.exists():
        print(f"Error: Directory {input1_base} does not exist.")
        return

    for project_dir in input1_base.iterdir():
        if not project_dir.is_dir():
            continue
            
        # Check if directory matches <project>_final
        match = project_regex.match(project_dir.name)
        if not match:
            continue
            
        project_name = match.group(1)
        stats_csv_path = project_dir / f"{project_name}_detailed_stats_fdr.csv"
        
        # Check if Input1 file exists
        if not stats_csv_path.exists():
            continue
            
        # Read Input1
        try:
            df_stats = pd.read_csv(stats_csv_path)
        except Exception as e:
            print(f"Failed to read {stats_csv_path}: {e}")
            continue

        # Verify required columns exist in Input1
        required_stats_cols = {'fix_commit', 'base_testname', 'hedges_g'}
        if not required_stats_cols.issubset(df_stats.columns):
            continue
            
        # Clean up missing commits to prevent errors
        df_stats = df_stats.dropna(subset=['fix_commit'])
        unique_commits = df_stats['fix_commit'].unique()
        
        # 3. Look for matching commits in Input2
        for commit in unique_commits:
            # Using glob to handle the <project>* pattern mentioned in the requirements
            commit_files = list(input2_base.glob(f"{project_name}*/{commit}.csv"))
            
            if not commit_files:
                continue
                
            # If found, read the first matching commit CSV
            commit_csv_path = commit_files[0] 
            try:
                df_diff = pd.read_csv(commit_csv_path)
            except Exception as e:
                print(f"Failed to read {commit_csv_path}: {e}")
                continue

            # Only consider in_diff rows
            df_diff = df_diff[df_diff['scope'] == 'in_diff']

            # Filter out filenames like test* and version* (filenames are full paths, so we check the last part after the last '/')
            df_diff = df_diff[~df_diff['file'].str.split('/').str[-1].str.startswith('test') & ~df_diff['file'].str.split('/').str[-1].str.startswith('version')]

            required_diff_cols = {'file', 'type', 'kind'}
            if not required_diff_cols.issubset(df_diff.columns):
                continue
                
            # Filter stats for this specific commit only
            df_stats_commit = df_stats[df_stats['fix_commit'] == commit].copy()
            
            # Cross-merge: Map every base_testname to every file/type/kind for this commit
            # We do this by creating a temporary 'key' column to perform a Cartesian product
            df_stats_commit['key'] = 1
            df_diff['key'] = 1
            
            merged = pd.merge(
                df_stats_commit[['fix_commit', 'base_testname', 'hedges_g', 'key']], 
                df_diff[['file', 'type', 'kind', 'key']], 
                on='key'
            ).drop('key', axis=1)
            
            # 4. Format outputs mapping
            # Create comma-separated type-kind field
            merged['type-kind'] = merged['type'].astype(str) + ',' + merged['kind'].astype(str)
            merged['project'] = project_name
            
            # Rename columns to match final Output schema
            merged = merged.rename(columns={
                'base_testname': 'test',
                'file': 'filename'
            })
            
            # Keep only the requested fields in the correct order
            final_cols = ['project', 'fix_commit', 'test', 'hedges_g', 'filename', 'type-kind']
            combined_dataframes.append(merged[final_cols])

    # 5. Output Generation
    if combined_dataframes:
        final_df = pd.concat(combined_dataframes, ignore_index=True)
        # Ensure output directory exists before writing
        output_path.parent.mkdir(parents=True, exist_ok=True)
        final_df.to_csv(output_path, index=False)
        print(f"Success! Output generated at: {output_path}")
    else:
        print("No matching cross-referenced data was found to combine.")

if __name__ == "__main__":
    combine_test_data()