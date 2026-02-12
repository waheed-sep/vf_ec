import sys
import os
import matplotlib
matplotlib.use('Agg') 
import matplotlib.pyplot as plt

try:
    import pandas as pd
    import numpy as np
    from scipy.stats import mannwhitneyu
    import seaborn as sns
    from statsmodels.stats.multitest import multipletests
except ImportError as e:
    print(f"[!] CRITICAL ERROR: Missing Library. {e}")
    sys.exit(1)

# ==========================================
# CONFIGURATION
# ==========================================
PROJECT_NAME = "vim"
MIN_COMMITS_THRESHOLD = 3 
ALPHA_THRESHOLD = 0.05

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Try finding the file in multiple locations
POSSIBLE_PATHS = [
    os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final", f"{PROJECT_NAME}_final_pertest.csv"),
    os.path.join(BASE_DIR, f"{PROJECT_NAME}_final_pertest.csv"),
    os.path.join(os.getcwd(), f"{PROJECT_NAME}_final_pertest.csv")
]

OUTPUT_DIR = os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final")
if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR, exist_ok=True)

DETAILED_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_detailed_stats_fdr.csv")
SUMMARY_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_cwe_summary_fdr.csv")
HEATMAP_FULL = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_heatmap_full.png")
HEATMAP_RISK = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_heatmap_risk_only.png")

def calculate_hedges_g(v_data, f_data):
    n1, n2 = len(v_data), len(f_data)
    if n1 < 2 or n2 < 2: return 0.0
    m1, m2 = np.mean(v_data), np.mean(f_data)
    s1, s2 = np.std(v_data, ddof=1), np.std(f_data, ddof=1)
    numerator = ((n1 - 1) * (s1 ** 2)) + ((n2 - 1) * (s2 ** 2))
    denominator = n1 + n2 - 2
    if denominator <= 0: return 0.0
    s_pooled = np.sqrt(numerator / denominator)
    J = 1 - (3 / (4 * denominator - 1))
    if s_pooled == 0: return 0.0
    return ((m2 - m1) / s_pooled) * J

def analyze_test_raw(group):
    # Extract data
    v_data = pd.to_numeric(group['vuln_energy_pkg'], errors='coerce').dropna().values
    f_data = pd.to_numeric(group['fix_energy_pkg'], errors='coerce').dropna().values
    
    if len(v_data) < 3 or len(f_data) < 3:
        return pd.Series({'raw_p_value': 1.0, 'hedges_g': 0.0})

    try:
        stat, p_value = mannwhitneyu(f_data, v_data, alternative='two-sided')
    except ValueError:
        p_value = 1.0 

    hedges_g = calculate_hedges_g(v_data, f_data)
    return pd.Series({'raw_p_value': p_value, 'hedges_g': hedges_g})

def generate_heatmaps(summary_df):
    print("    [+] Generating Heatmaps...")
    
    # Ensure columns exist and fill with 0
    for col in ['%_Increase', '%_Decrease', '%_Neutral']:
        if col not in summary_df.columns: summary_df[col] = 0.0

    # 1. Full Heatmap (Blue)
    plt.figure(figsize=(10, 6))
    sns.heatmap(summary_df[['%_Increase', '%_Decrease', '%_Neutral']], annot=True, fmt=".1f", cmap="Blues", linewidths=.5)
    plt.title(f"RQ4: Energy Impact by CWE (FDR Corrected)")
    plt.tight_layout()
    plt.savefig(HEATMAP_FULL, dpi=300)
    plt.close()

    # 2. Risk Heatmap (Red) - FORCED GENERATION
    # Even if data is all 0, we generate it to show "No Risk"
    plt.figure(figsize=(8, 6))
    sns.heatmap(summary_df[['%_Increase', '%_Decrease']], annot=True, fmt=".1f", cmap="Reds", linewidths=.5, vmin=0, vmax=100)
    plt.title("RQ4: Significant Energy Risks (Neutral Excluded)")
    plt.tight_layout()
    plt.savefig(HEATMAP_RISK, dpi=300)
    plt.close()
    print(f"    [+] Risk heatmap saved (even if empty/zero risks).")

def main():
    print("="*50)
    print("STARTING ANALYSIS (FDR Corrected - Forced Heatmaps)")
    print("="*50)

    # 1. Load Data
    input_path = None
    for p in POSSIBLE_PATHS:
        if os.path.exists(p):
            input_path = p
            break
    if not input_path:
        print(f"[!] ERROR: Could not find '{PROJECT_NAME}_final_pertest.csv'.")
        return
    
    df = pd.read_csv(input_path)
    df['base_testname'] = df['vuln_testname'].astype(str).apply(lambda x: x.rsplit('_', 1)[0])
    df['cwe'] = df['cwe'].fillna('Unknown')

    # 2. Raw Stats
    print("[*] Calculating Raw Stats...")
    # Explicitly select columns to fix FutureWarning
    cols_needed = ['vuln_energy_pkg', 'fix_energy_pkg']
    # Group by the keys, select the columns, then apply
    grouped = df.groupby(['vuln_commit', 'fix_commit', 'base_testname', 'cwe'])[cols_needed]
    stats_df = grouped.apply(analyze_test_raw).reset_index()

    # 3. FDR Correction
    print("[*] Applying Benjamini-Hochberg FDR Correction...")
    pvals = stats_df['raw_p_value'].values
    reject, pvals_corrected, _, _ = multipletests(pvals, alpha=ALPHA_THRESHOLD, method='fdr_bh')
    
    stats_df['p_value_corrected'] = pvals_corrected
    stats_df['is_significant'] = reject

    # 4. Classify Results
    def classify_result(row):
        if not row['is_significant']: return "Neutral"
        elif row['hedges_g'] > 0: return "Increase"
        else: return "Decrease"

    stats_df['result_class'] = stats_df.apply(classify_result, axis=1)
    stats_df.to_csv(DETAILED_OUTPUT, index=False)
    print(f"    -> Detailed stats saved to: {DETAILED_OUTPUT}")

    # 5. Group Rare CWEs
    print(f"[*] Grouping rare CWEs (< {MIN_COMMITS_THRESHOLD} commits)...")
    cwe_counts = stats_df.groupby('cwe')['vuln_commit'].nunique()
    rare_cwes = cwe_counts[cwe_counts < MIN_COMMITS_THRESHOLD].index.tolist()
    
    summary_input = stats_df.copy()
    if rare_cwes:
        summary_input.loc[summary_input['cwe'].isin(rare_cwes), 'cwe'] = 'Other'

    # 6. Generate Summary
    summary = summary_input.groupby(['cwe', 'result_class']).size().unstack(fill_value=0)
    
    # FORCE Ensure all columns exist
    for col in ['Increase', 'Decrease', 'Neutral']:
        if col not in summary.columns: summary[col] = 0

    summary['Total_Tests'] = summary.sum(axis=1)
    
    # Calculate Percentages
    for col in ['Increase', 'Decrease', 'Neutral']:
        summary[f'%_{col}'] = (summary[col] / summary['Total_Tests'] * 100).round(1)

    print("\n" + "="*60)
    print("FINAL RESULTS (RQ4 Summary - FDR Corrected)")
    print("="*60)
    
    display_cols = ['Total_Tests', 'Increase', 'Decrease', 'Neutral', '%_Increase', '%_Decrease', '%_Neutral']
    print(summary[display_cols])
    
    summary.to_csv(SUMMARY_OUTPUT)
    generate_heatmaps(summary)
    print(f"\n[+] DONE! Heatmaps saved in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()