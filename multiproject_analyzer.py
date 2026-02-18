import sys
import os
import glob
import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
import statsmodels.api as sm

# ==========================================
# CONFIGURATION
# ==========================================
# 1. SETUP INPUT: Search recursively in this directory
SEARCH_ROOT_DIR = "final_results"
FILE_PATTERN = "**/*_final_pertest.csv" # Finds any matching file in subfolders

# 2. SETUP OUTPUT: Results will be saved here
OUTPUT_DIR = "multi_project_results"

MIN_COMMITS_THRESHOLD = 3 
ALPHA_THRESHOLD = 0.05

if not os.path.exists(OUTPUT_DIR): 
    os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==========================================
# HELPERS
# ==========================================
def calculate_hedges_g_and_se(v_data, f_data):
    n1, n2 = len(v_data), len(f_data)
    if n1 < 2 or n2 < 2: return 0.0, 0.0
    
    m1, m2 = np.mean(v_data), np.mean(f_data)
    s1, s2 = np.std(v_data, ddof=1), np.std(f_data, ddof=1)
    
    numerator = ((n1 - 1) * (s1 ** 2)) + ((n2 - 1) * (s2 ** 2))
    denominator = n1 + n2 - 2
    if denominator <= 0: return 0.0, 0.0
    
    s_pooled = np.sqrt(numerator / denominator)
    J = 1 - (3 / (4 * denominator - 1))
    
    if s_pooled == 0: return 0.0, 0.0
    g = ((m2 - m1) / s_pooled) * J
    
    se_g = np.sqrt(((n1 + n2) / (n1 * n2)) + (g ** 2) / (2 * (n1 + n2)))
    return g, se_g

def analyze_test_raw(group):
    v_vals = pd.to_numeric(group['vuln_energy_pkg'], errors='coerce').dropna().values
    f_vals = pd.to_numeric(group['fix_energy_pkg'], errors='coerce').dropna().values
    
    if len(v_vals) < 3 or len(f_vals) < 3:
        return pd.Series({'hedges_g': 0.0, 'se_g': 0.0})

    g, se_g = calculate_hedges_g_and_se(v_vals, f_vals)
    return pd.Series({'hedges_g': g, 'se_g': se_g})

def aggregate_commit(group):
    g_values = group['hedges_g'].values
    se_values = group['se_g'].values
    valid_indices = se_values > 1e-9
    
    if not np.any(valid_indices):
        return pd.Series({'g_commit': 0.0, 'se_commit': 0.0})
        
    g_valid = g_values[valid_indices]
    se_valid = se_values[valid_indices]
    
    weights = 1.0 / (se_valid ** 2)
    sum_w = np.sum(weights)
    
    g_commit = np.sum(weights * g_valid) / sum_w
    se_commit = np.sqrt(1.0 / sum_w)
    
    return pd.Series({'g_commit': g_commit, 'se_commit': se_commit})

# ==========================================
# VISUALIZATION
# ==========================================
def generate_rq1_multi_plot(project_results):
    print("    [+] Generating RQ1 Multi-Project Plot...")
    
    labels = [k for k in project_results.keys() if k != 'OVERALL']
    labels.sort()
    labels.append('OVERALL')
        
    g_vals = [project_results[l]['g'] for l in labels]
    cis_low = [project_results[l]['ci_lower'] for l in labels]
    cis_high = [project_results[l]['ci_upper'] for l in labels]
    
    plt.figure(figsize=(10, 3 + len(labels)*1))
    
    x_err_lower = [g - low for g, low in zip(g_vals, cis_low)]
    x_err_upper = [high - g for high, g in zip(cis_high, g_vals)]
    
    y_pos = np.arange(len(labels))
    
    for i, label in enumerate(labels):
        is_overall = (label == 'OVERALL')
        color = 'black' if is_overall else 'gray'
        marker = 'D' if is_overall else 'o'
        size = 12 if is_overall else 8
        lw = 2 if is_overall else 1.5
        
        plt.errorbar(x=g_vals[i], y=i, xerr=[[x_err_lower[i]], [x_err_upper[i]]], 
                     fmt=marker, color=color, ecolor='red' if is_overall else 'blue', 
                     capsize=5, markersize=size, elinewidth=lw)
        
        plt.text(g_vals[i], i + 0.1, f"{g_vals[i]:.3f}", ha='center', va='bottom', fontsize=9, fontweight='bold')

    plt.axvline(x=0, color='blue', linestyle='--', linewidth=1, label='Neutral')
    plt.yticks(y_pos, labels, fontsize=11)
    plt.xlabel("Hedges' g (Effect Size)\nPositive = Increase | Negative = Savings", fontsize=10)
    plt.title("RQ1: Energy Impact by Project & Overall", fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.grid(axis='x', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "RQ1_Multi_Project.png"), dpi=300)
    plt.close()

def generate_beta_plot(results_df):
    print("    [+] Generating RQ2 Regression Plot...")
    results_df = results_df.sort_values(by='coef', ascending=True)
    plot_df = results_df[~results_df.index.str.contains("project", case=False)]
    
    plt.figure(figsize=(10, 8))
    y_err = [plot_df['coef'] - plot_df['ci_lower'], plot_df['ci_upper'] - plot_df['coef']]
    
    plt.errorbar(x=plot_df['coef'], y=plot_df.index, xerr=y_err, 
                 fmt='o', color='black', ecolor='red', capsize=5)
    
    plt.axvline(x=0, color='blue', linestyle='--')
    plt.title("RQ2: Regression Analysis (Pooled Data)", fontsize=14)
    plt.xlabel("Energy Cost (Beta Coefficient)", fontsize=12)
    plt.grid(axis='x', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "RQ2_Regression.png"), dpi=300)
    plt.close()

# ==========================================
# MAIN
# ==========================================
def main():
    print("="*60)
    print("MULTI-PROJECT ANALYSIS PIPELINE")
    print("="*60)
    
    all_commits_df = pd.DataFrame()
    project_rq1_results = {}
    
    # 1. FIND AND LOAD CSVs
    search_path = os.path.join(SEARCH_ROOT_DIR, FILE_PATTERN)
    csv_files = glob.glob(search_path, recursive=True)
    
    if not csv_files:
        print(f"[!] ERROR: No CSV files found matching '{search_path}'")
        print(f"    Check that your 'final_results' folder exists and contains '_final_pertest.csv' files.")
        return

    print(f"[+] Found {len(csv_files)} project file(s).")

    for filepath in csv_files:
        filename = os.path.basename(filepath)
        project_name = filename.split('_')[0] 
        print(f"\n[+] Processing Project: {project_name} ({filename})")
        
        try:
            df = pd.read_csv(filepath)
            
            if 'vuln_energy_pkg' not in df.columns:
                print(f"    [!] SKIPPING: File missing 'vuln_energy_pkg' column.")
                continue

            if 'cwe' not in df.columns: df['cwe'] = 'Unknown'
            df['cwe'] = df['cwe'].fillna('Unknown')
            
            df['base_testname'] = df['vuln_testname'].astype(str).apply(lambda x: x.rsplit('_', 1)[0])
            
            # -------------------------------------------------
            # FIX 1: Add include_groups=False
            # -------------------------------------------------
            grouped = df.groupby(['vuln_commit', 'fix_commit', 'base_testname', 'cwe'])
            stats_df = grouped.apply(analyze_test_raw, include_groups=False).reset_index()
            
            # -------------------------------------------------
            # FIX 2: Add include_groups=False
            # -------------------------------------------------
            commit_grouped = stats_df.groupby(['vuln_commit', 'cwe'])
            commit_stats = commit_grouped.apply(aggregate_commit, include_groups=False).reset_index()
            
            commit_stats['project'] = project_name 
            
            # C. Store for Global Analysis
            all_commits_df = pd.concat([all_commits_df, commit_stats], ignore_index=True)
            
            # D. Calculate RQ1 for THIS Project
            valid_commits = commit_stats[commit_stats['se_commit'] > 1e-9]
            if not valid_commits.empty:
                w = 1.0 / (valid_commits['se_commit'] ** 2)
                g_proj = np.sum(w * valid_commits['g_commit']) / np.sum(w)
                se_proj = np.sqrt(1.0 / np.sum(w))
                
                project_rq1_results[project_name] = {
                    'g': g_proj, 
                    'ci_lower': g_proj - 1.96*se_proj, 
                    'ci_upper': g_proj + 1.96*se_proj
                }
                print(f"    -> Project Mean g: {g_proj:.4f}")
        except Exception as e:
            print(f"    [!] Error processing file: {e}")

    if all_commits_df.empty:
        print("[!] No valid data found. Exiting.")
        return

    # ---------------------------------------------------------
    # STAGE 2: GLOBAL RQ1 (OVERALL)
    # ---------------------------------------------------------
    print("\n[+] Calculating OVERALL Global Impact...")
    valid_all = all_commits_df[all_commits_df['se_commit'] > 1e-9]
    
    if not valid_all.empty:
        w_all = 1.0 / (valid_all['se_commit'] ** 2)
        g_overall = np.sum(w_all * valid_all['g_commit']) / np.sum(w_all)
        se_overall = np.sqrt(1.0 / np.sum(w_all))
        
        project_rq1_results['OVERALL'] = {
            'g': g_overall,
            'ci_lower': g_overall - 1.96*se_overall,
            'ci_upper': g_overall + 1.96*se_overall
        }
        
        generate_rq1_multi_plot(project_rq1_results)
    else:
        print("[!] Not enough valid data for global analysis.")

    # ---------------------------------------------------------
    # STAGE 3: IDENTIFYING & MAPPING RARE CWEs
    # ---------------------------------------------------------
    print("\n[+] Identifying Rare CWEs...")
    
    # 1. Identify which CWEs are rare
    cwe_counts = all_commits_df['cwe'].value_counts()
    rare_cwes = cwe_counts[cwe_counts < MIN_COMMITS_THRESHOLD].index.tolist()
    
    print(f"    -> Threshold: < {MIN_COMMITS_THRESHOLD} commits")
    print(f"    -> Rare CWEs identified: {len(rare_cwes)} types")

    # 2. GENERATE MAPPING FILE (Row-by-Row)
    other_mapping_df = all_commits_df[all_commits_df['cwe'].isin(rare_cwes)].copy()
    
    # Use vuln_commit as the identifier since that's what we grouped by
    mapping_output_cols = ['project', 'vuln_commit', 'cwe', 'g_commit']
    # Ensure columns exist before selecting
    available_cols = [c for c in mapping_output_cols if c in other_mapping_df.columns]
    other_mapping_df = other_mapping_df[available_cols].sort_values(by=['project', 'cwe'])
    
    mapping_file = os.path.join(OUTPUT_DIR, "cwe_other_mapping.csv")
    other_mapping_df.to_csv(mapping_file, index=False)
    print(f"    -> Detailed mapping saved to: {mapping_file}")

    # 3. GENERATE SUMMARY TEXT
    summary_file = os.path.join(OUTPUT_DIR, "cwe_other_summary.txt")
    with open(summary_file, "w") as f:
        f.write("SUMMARY OF 'OTHER' CATEGORY COMPOSITION\n")
        f.write("=======================================\n\n")
        
        for proj in other_mapping_df['project'].unique():
            f.write(f"Project: {proj}\n")
            f.write(f"{'-'*len(proj)}\n")
            
            proj_data = other_mapping_df[other_mapping_df['project'] == proj]
            counts = proj_data['cwe'].value_counts()
            
            for cwe_name, count in counts.items():
                f.write(f"  - {cwe_name}: {count} commit(s)\n")
            f.write("\n")
            
    print(f"    -> Summary text saved to: {summary_file}")

    # 4. Apply Grouping for Regression
    regression_df = all_commits_df.copy()
    regression_df.loc[regression_df['cwe'].isin(rare_cwes), 'cwe'] = 'Other'

    # ---------------------------------------------------------
    # STAGE 4: RQ2 REGRESSION (POOLED)
    # ---------------------------------------------------------
    print("\n[+] Running RQ2 Regression on Pooled Data...")
    
    # Dummies: CWE + Project (Control)
    X = pd.get_dummies(regression_df['cwe'], dtype=float)
    
    # Control for Project (Drop first to avoid collinearity)
    proj_dummies = pd.get_dummies(regression_df['project'], prefix='project', drop_first=True, dtype=float)
    X = pd.concat([X, proj_dummies], axis=1)

    y = regression_df['g_commit']
    weights = 1.0 / (regression_df['se_commit'].replace(0, 1e-9) ** 2)
    
    try:
        model = sm.WLS(y, X, weights=weights)
        results = model.fit()
        
        print(results.summary())
        
        results_df = pd.DataFrame({
            'coef': results.params,
            'ci_lower': results.conf_int()[0],
            'ci_upper': results.conf_int()[1]
        })
        results_df.to_csv(os.path.join(OUTPUT_DIR, "RQ2_Regression_Results.csv"))
        
        generate_beta_plot(results_df)
        
    except Exception as e:
        print(f"[!] Regression Failed: {e}")

    print(f"\n[+] DONE. Results saved in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()