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

# Output Files
DETAILED_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_detailed_stats.csv")
SUMMARY_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_cwe_summary.csv")
HEATMAP_FULL = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_heatmap_full.png")
HEATMAP_RISK = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_heatmap_risk_only.png")

def calculate_hedges_g(v_data, f_data):
    """
    Calculates Hedges' g effect size with small sample correction (J).
    """
    n1 = len(v_data)
    n2 = len(f_data)
    
    # Means
    m1 = np.mean(v_data)
    m2 = np.mean(f_data)
    
    # Standard Deviations (ddof=1 for Sample SD)
    s1 = np.std(v_data, ddof=1)
    s2 = np.std(f_data, ddof=1)
    
    # Pooled Standard Deviation Formula
    numerator = ((n1 - 1) * (s1 ** 2)) + ((n2 - 1) * (s2 ** 2))
    denominator = n1 + n2 - 2
    s_pooled = np.sqrt(numerator / denominator)
    
    # Small Sample Correction Factor (J)
    df = denominator
    J = 1 - (3 / (4 * df - 1))
    
    # Hedges' g
    if s_pooled == 0:
        return 0.0
    g = ((m2 - m1) / s_pooled) * J
    return g

def analyze_test_group(group):
    """
    Performs the Stats Analysis for one specific Test Case (contains 5 iterations).
    """
    # Extract the 5 runs for Vuln and Fix
    v_data = group['vuln_energy_pkg'].astype(float).values
    f_data = group['fix_energy_pkg'].astype(float).values
    
    # 1. Descriptive Stats
    mean_v = np.mean(v_data)
    mean_f = np.mean(f_data)
    median_v = np.median(v_data)
    median_f = np.median(f_data)
    
    # 2. Mann-Whitney U Test
    try:
        stat, p_value = mannwhitneyu(f_data, v_data, alternative='two-sided')
    except ValueError:
        p_value = 1.0 

    # 3. Effect Size
    hedges_g = calculate_hedges_g(v_data, f_data)
    
    # 4. Classification
    is_significant = p_value < 0.05
    
    if not is_significant:
        result_class = "Neutral"
    elif hedges_g > 0:
        result_class = "Increase" 
    else:
        result_class = "Decrease" 

    return pd.Series({
        'mean_vuln': mean_v,
        'mean_fix': mean_f,
        'median_vuln': median_v,
        'median_fix': median_f,
        'p_value': p_value,
        'hedges_g': hedges_g,
        'result_class': result_class
    })

def generate_heatmaps(summary_df):
    """Generates and saves the heatmap visualizations."""
    print("\n[*] Generating Heatmaps...")
    
    # Ensure necessary columns exist (fill with 0 if missing)
    required_cols = ['%_Increase', '%_Decrease', '%_Neutral']
    for col in required_cols:
        if col not in summary_df.columns:
            summary_df[col] = 0.0

    # 1. FULL HEATMAP (Neutral Included)
    plt.figure(figsize=(10, 6))
    data_full = summary_df[required_cols]
    sns.heatmap(data_full, annot=True, fmt=".1f", cmap="Blues", linewidths=.5)
    plt.title(f"RQ4: Energy Impact by CWE Type ({PROJECT_NAME})\n(Numbers represent % of tests)", fontsize=14)
    plt.ylabel("Vulnerability Type (CWE)")
    plt.xlabel("Energy Impact Category")
    plt.tight_layout()
    plt.savefig(HEATMAP_FULL, dpi=300)
    print(f"[+] Full Heatmap saved to: {HEATMAP_FULL}")
    plt.close()

    # 2. RISK HEATMAP (Neutral Excluded)
    plt.figure(figsize=(8, 6))
    cols_risk = ['%_Increase', '%_Decrease']
    data_risk = summary_df[cols_risk]
    
    # Only plot if we have data, otherwise it errors
    if not data_risk.empty:
        sns.heatmap(data_risk, annot=True, fmt=".1f", cmap="Reds", linewidths=.5)
        plt.title(f"RQ4: Significant Energy Changes Only\n(Excluding Neutral Cases)", fontsize=14)
        plt.ylabel("Vulnerability Type (CWE)")
        plt.xlabel("Energy Impact")
        plt.tight_layout()
        plt.savefig(HEATMAP_RISK, dpi=300)
        print(f"[+] Risk Heatmap saved to: {HEATMAP_RISK}")
    plt.close()

def main():
    print(f"[*] Loading data from: {INPUT_FILE}")
    if not os.path.exists(INPUT_FILE):
        print("[!] Input file not found.")
        return

    df = pd.read_csv(INPUT_FILE)

    # --- Step A: Data Transformation ---
    # Strip iteration suffix to group test cases
    df['base_testname'] = df['vuln_testname'].apply(lambda x: x.rsplit('_', 1)[0])

    print("[*] Grouping iterations (n=5) per test...")
    grouped = df.groupby(['vuln_commit', 'fix_commit', 'base_testname', 'cwe'])
    stats_df = grouped.apply(analyze_test_group).reset_index()

    # Save Detailed Results
    stats_df.to_csv(DETAILED_OUTPUT, index=False)
    print(f"[+] Detailed statistics saved to: {DETAILED_OUTPUT}")

    # --- Step B: CWE Summary & Visualization ---
    print("\n[*] Generating CWE Summary (Sanity Check)...")
    
    # Count occurrences per CWE
    summary = stats_df.groupby(['cwe', 'result_class']).size().unstack(fill_value=0)
    summary['Total_Tests'] = summary.sum(axis=1)
    
    # Calculate Percentages
    cols = [c for c in ['Increase', 'Decrease', 'Neutral'] if c in summary.columns]
    for col in cols:
        summary[f'%_{col}'] = (summary[col] / summary['Total_Tests'] * 100).round(1)

    # Display in Terminal
    print("\n" + "="*60)
    print("CWE ENERGY IMPACT SUMMARY (RQ4)")
    print("="*60)
    display_cols = ['Total_Tests'] + [c for c in summary.columns if '%' in c]
    print(summary[display_cols])
    
    summary.to_csv(SUMMARY_OUTPUT)
    print(f"\n[+] Summary saved to: {SUMMARY_OUTPUT}")

    # --- Step C: Generate Heatmaps ---
    generate_heatmaps(summary)

if __name__ == "__main__":
    main()