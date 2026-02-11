import pandas as pd
import numpy as np
from scipy.stats import mannwhitneyu
import seaborn as sns
import matplotlib.pyplot as plt
import os

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_NAME = "vim"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final", f"{PROJECT_NAME}_final_pertest.csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final")

# THRESHOLD: Group CWEs with fewer than this many commits into "Other"
# The PDF suggests 10-20. Since your dataset might be smaller, I set it to 3 for now.
# You can change this to 5 or 10.
MIN_COMMITS_THRESHOLD = 3 

# Output Files
DETAILED_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_detailed_stats.csv")
SUMMARY_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_cwe_summary.csv")
HEATMAP_FULL = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_heatmap_full.png")
HEATMAP_RISK = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_heatmap_risk_only.png")

def calculate_hedges_g(v_data, f_data):
    """Calculates Hedges' g effect size with small sample correction (J)."""
    n1, n2 = len(v_data), len(f_data)
    m1, m2 = np.mean(v_data), np.mean(f_data)
    s1, s2 = np.std(v_data, ddof=1), np.std(f_data, ddof=1)
    
    numerator = ((n1 - 1) * (s1 ** 2)) + ((n2 - 1) * (s2 ** 2))
    denominator = n1 + n2 - 2
    s_pooled = np.sqrt(numerator / denominator)
    
    J = 1 - (3 / (4 * denominator - 1))
    
    if s_pooled == 0: return 0.0
    return ((m2 - m1) / s_pooled) * J

def analyze_test_group(group):
    """Performs Stats Analysis (Mann-Whitney + Hedges g) for one test case."""
    v_data = group['vuln_energy_pkg'].astype(float).values
    f_data = group['fix_energy_pkg'].astype(float).values
    
    try:
        stat, p_value = mannwhitneyu(f_data, v_data, alternative='two-sided')
    except ValueError:
        p_value = 1.0 

    hedges_g = calculate_hedges_g(v_data, f_data)
    is_significant = p_value < 0.05
    
    if not is_significant: result_class = "Neutral"
    elif hedges_g > 0: result_class = "Increase" 
    else: result_class = "Decrease" 

    return pd.Series({
        'p_value': p_value,
        'hedges_g': hedges_g,
        'result_class': result_class
    })

def generate_heatmaps(summary_df):
    """Generates heatmaps from the summary dataframe."""
    print("\n[*] Generating Heatmaps...")
    required_cols = ['%_Increase', '%_Decrease', '%_Neutral']
    for col in required_cols:
        if col not in summary_df.columns: summary_df[col] = 0.0

    # 1. Full Heatmap
    plt.figure(figsize=(10, 6))
    sns.heatmap(summary_df[required_cols], annot=True, fmt=".1f", cmap="Blues", linewidths=.5)
    plt.title(f"RQ4: Energy Impact by CWE (Grouped < {MIN_COMMITS_THRESHOLD} commits)", fontsize=14)
    plt.tight_layout()
    plt.savefig(HEATMAP_FULL, dpi=300)
    plt.close()

    # 2. Risk Heatmap
    if not summary_df[['%_Increase', '%_Decrease']].empty:
        plt.figure(figsize=(8, 6))
        sns.heatmap(summary_df[['%_Increase', '%_Decrease']], annot=True, fmt=".1f", cmap="Reds", linewidths=.5)
        plt.title("RQ4: Significant Energy Risks (Rare CWEs grouped)", fontsize=14)
        plt.tight_layout()
        plt.savefig(HEATMAP_RISK, dpi=300)
        plt.close()

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[!] Input file not found: {INPUT_FILE}")
        return

    df = pd.read_csv(INPUT_FILE)
    df['base_testname'] = df['vuln_testname'].apply(lambda x: x.rsplit('_', 1)[0])

    print("[*] Running Statistical Analysis per Test...")
    grouped = df.groupby(['vuln_commit', 'fix_commit', 'base_testname', 'cwe'])
    stats_df = grouped.apply(analyze_test_group).reset_index()
    stats_df.to_csv(DETAILED_OUTPUT, index=False)

    # --- NEW STEP: Group Rare CWEs ---
    print(f"\n[*] Grouping CWEs with fewer than {MIN_COMMITS_THRESHOLD} commits into 'Other'...")
    
    # 1. Count unique commits per CWE
    # We use 'vuln_commit' as the identifier for the commit
    cwe_counts = stats_df.groupby('cwe')['vuln_commit'].nunique()
    
    # 2. Identify rare CWEs
    rare_cwes = cwe_counts[cwe_counts < MIN_COMMITS_THRESHOLD].index.tolist()
    print(f"    -> Found {len(rare_cwes)} rare CWEs: {rare_cwes}")
    
    # 3. Replace rare CWE names with "Other" in a COPY of the dataframe
    # We use a copy so we don't lose the original data in detailed_stats.csv
    summary_df_input = stats_df.copy()
    summary_df_input.loc[summary_df_input['cwe'].isin(rare_cwes), 'cwe'] = 'Other'

    # --- Generate Summary ---
    summary = summary_df_input.groupby(['cwe', 'result_class']).size().unstack(fill_value=0)
    summary['Total_Tests'] = summary.sum(axis=1)
    
    for col in ['Increase', 'Decrease', 'Neutral']:
        if col in summary.columns:
            summary[f'%_{col}'] = (summary[col] / summary['Total_Tests'] * 100).round(1)
        else:
            summary[f'%_{col}'] = 0.0

    print("\n" + "="*60)
    print("CWE ENERGY IMPACT SUMMARY (RQ4) - GROUPED")
    print("="*60)
    print(summary[['Total_Tests', '%_Increase', '%_Decrease', '%_Neutral']])
    
    summary.to_csv(SUMMARY_OUTPUT)
    generate_heatmaps(summary)
    print(f"\n[+] Processing Complete. Heatmaps saved in {OUTPUT_DIR}")

if __name__ == "__main__":
    main()