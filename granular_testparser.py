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
    import statsmodels.api as sm
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
POSSIBLE_PATHS = [
    os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final", f"{PROJECT_NAME}_final_pertest.csv"),
    os.path.join(BASE_DIR, f"{PROJECT_NAME}_final_pertest.csv"),
    os.path.join(os.getcwd(), f"{PROJECT_NAME}_final_pertest.csv")
]

OUTPUT_DIR = os.path.join(BASE_DIR, "final_results", f"{PROJECT_NAME}_final")
if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR, exist_ok=True)

# Output Files
DETAILED_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_detailed_stats_fdr.csv")
COMMIT_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_commit_stats.csv")
REGRESSION_OUTPUT = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_cwe_regression_results.csv")
HEATMAP_FILE = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_commit_heatmap.png")
BETA_PLOT_FILE = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_regression_betas.png")

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
    
    # Standard Error of Hedges' g
    se_g = np.sqrt(((n1 + n2) / (n1 * n2)) + (g ** 2) / (2 * (n1 + n2)))
    return g, se_g

def analyze_test_raw(group):
    v_data = pd.to_numeric(group['vuln_energy_pkg'], errors='coerce').dropna().values
    f_data = pd.to_numeric(group['fix_energy_pkg'], errors='coerce').dropna().values
    
    if len(v_data) < 3 or len(f_data) < 3:
        return pd.Series({'raw_p_value': 1.0, 'hedges_g': 0.0, 'se_g': 0.0})

    try:
        stat, p_value = mannwhitneyu(f_data, v_data, alternative='two-sided')
    except ValueError:
        p_value = 1.0 

    g, se_g = calculate_hedges_g_and_se(v_data, f_data)
    return pd.Series({'raw_p_value': p_value, 'hedges_g': g, 'se_g': se_g})

def aggregate_commit(group):
    """Combines multiple tests in a commit into one score."""
    g_values = group['hedges_g'].values
    se_values = group['se_g'].values
    
    # Filter valid SE
    valid_indices = se_values > 1e-9
    if not np.any(valid_indices):
        return pd.Series({'g_commit': 0.0, 'se_commit': 0.0, 'ci_lower': 0.0, 'ci_upper': 0.0})
        
    g_valid = g_values[valid_indices]
    se_valid = se_values[valid_indices]
    
    # Inverse-Variance Weighting
    # Used Meta-Analysis / Weighted Regression instead of FDR correction. 
    # This is more powerful than FDR for combining effect sizes, especially when we have varying precision (SE) across tests.
    weights = 1.0 / (se_valid ** 2)
    sum_w = np.sum(weights)
    g_commit = np.sum(weights * g_valid) / sum_w
    se_commit = np.sqrt(1.0 / sum_w)
    
    # 95% CI
    ci_lower = g_commit - (1.96 * se_commit)
    ci_upper = g_commit + (1.96 * se_commit)
    
    return pd.Series({
        'g_commit': g_commit,
        'se_commit': se_commit,
        'ci_lower': ci_lower,
        'ci_upper': ci_upper
    })

# ==========================================
# VISUALIZATION FUNCTIONS
# ==========================================

def generate_commit_heatmap(commit_df):
    """Generates a heatmap based on Commit-Level Classifications."""
    print("    [+] Generating Commit-Level Heatmap...")
    
    # Group by CWE and Result Class
    summary = commit_df.groupby(['cwe', 'result_class']).size().unstack(fill_value=0)
    
    # Ensure columns exist
    for col in ['Increase', 'Decrease', 'Neutral']:
        if col not in summary.columns: summary[col] = 0

    summary['Total'] = summary.sum(axis=1)
    
    # Calculate Percentages
    plot_data = summary.copy()
    for col in ['Increase', 'Decrease', 'Neutral']:
        plot_data[col] = (plot_data[col] / plot_data['Total'] * 100).round(1)
    
    # Plot
    plt.figure(figsize=(10, 6))
    sns.heatmap(plot_data[['Increase', 'Decrease', 'Neutral']], annot=True, fmt=".1f", cmap="Blues", linewidths=.5)
    plt.title(f"RQ4: Energy Impact by CWE (Commit Level Aggregation)")
    plt.ylabel("Vulnerability Type (CWE)")
    plt.xlabel("Percentage of Commits")
    plt.tight_layout()
    plt.savefig(HEATMAP_FILE, dpi=300)
    plt.close()

def generate_beta_plot(results_df):
    """Generates a Forest Plot of Regression Betas (Energy Impact)."""
    print("    [+] Generating Regression Beta Plot (Forest Plot)...")
    
    # Sort by coefficient value for cleaner plot
    results_df = results_df.sort_values(by='coef', ascending=True)
    
    # Clean CWE names (remove 'cwe_' prefix from dummy variables if present)
    # Statsmodels often names columns like "cwe[T.CWE-122]"
    results_df['label'] = results_df.index
    
    plt.figure(figsize=(10, 6))
    
    # Plot Points (Coefficients) and Error Bars (Confidence Intervals)
    # Error bars: needs shape (2, N) -> [[lower_errors], [upper_errors]]
    y_err = [
        results_df['coef'] - results_df['ci_lower'], 
        results_df['ci_upper'] - results_df['coef']
    ]
    
    plt.errorbar(x=results_df['coef'], y=results_df['label'], xerr=y_err, 
                 fmt='o', color='black', ecolor='red', capsize=5, label='Beta (Impact)')
    
    # Add Reference Line at 0 (Neutral)
    plt.axvline(x=0, color='blue', linestyle='--', linewidth=1, label='Neutral (0)')
    
    plt.title("Regression Analysis: Energy Impact per CWE (Beta Coefficients)")
    plt.xlabel("Energy Impact (Hedges' g)\nPositive = Increases Energy | Negative = Saves Energy")
    plt.ylabel("Vulnerability Type")
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(BETA_PLOT_FILE, dpi=300)
    plt.close()

# ==========================================
# MAIN
# ==========================================

def main():
    print("="*60)
    print("STARTING META-ANALYSIS & VISUALIZATION PIPELINE")
    print("="*60)

    # 1. Load Data
    input_path = None
    for p in POSSIBLE_PATHS:
        if os.path.exists(p):
            input_path = p
            break
    if not input_path:
        print(f"[!] ERROR: Could not find input CSV.")
        return
    
    df = pd.read_csv(input_path)
    df['base_testname'] = df['vuln_testname'].astype(str).apply(lambda x: x.rsplit('_', 1)[0])
    df['cwe'] = df['cwe'].fillna('Unknown')

    # ---------------------------------------------------------
    # STAGE 1: Per-Test Analysis
    # ---------------------------------------------------------
    print("[1/3] Running Per-Test Analysis...")
    cols_needed = ['vuln_energy_pkg', 'fix_energy_pkg']
    grouped = df.groupby(['vuln_commit', 'fix_commit', 'base_testname', 'cwe'])[cols_needed]
    stats_df = grouped.apply(analyze_test_raw).reset_index()
    stats_df.to_csv(DETAILED_OUTPUT, index=False)

    # ---------------------------------------------------------
    # STAGE 2: Per-Commit Aggregation (Option A)
    # ---------------------------------------------------------
    print("\n[2/3] Aggregating Results per Commit...")
    
    commit_grouped = stats_df.groupby(['vuln_commit', 'cwe'])
    # Need to select columns to apply function cleanly
    # cols_agg = ['hedges_g', 'se_g']
    commit_stats = commit_grouped.apply(aggregate_commit).reset_index()
    
    # Classify based on CI
    def classify_commit(row):
        if row['ci_lower'] > 0: return "Increase"
        if row['ci_upper'] < 0: return "Decrease"
        return "Neutral"

    commit_stats['result_class'] = commit_stats.apply(classify_commit, axis=1)
    
    # Group Rare CWEs for Visualization
    cwe_counts = commit_stats['cwe'].value_counts()
    rare_cwes = cwe_counts[cwe_counts < MIN_COMMITS_THRESHOLD].index
    commit_stats.loc[commit_stats['cwe'].isin(rare_cwes), 'cwe'] = 'Other'
    
    commit_stats.to_csv(COMMIT_OUTPUT, index=False)
    print(f"      -> Commit-level stats saved to: {COMMIT_OUTPUT}")
    
    # GENERATE HEATMAP
    generate_commit_heatmap(commit_stats)

    # ---------------------------------------------------------
    # STAGE 3: Weighted Regression
    # ---------------------------------------------------------
    print("\n[3/3] Running CWE Regression Analysis...")
    
    # Filter out "Other" or keep them? PDF says group them. 
    # We already grouped them in commit_stats above.
    
    # Prepare Regression Data
    X = pd.get_dummies(commit_stats['cwe'], dtype=float)
    y = commit_stats['g_commit']
    se = commit_stats['se_commit'].replace(0, 1e-9)
    weights = 1.0 / (se ** 2)
    
    try:
        model = sm.WLS(y, X, weights=weights)
        results = model.fit()
        
        print("\n" + "="*60)
        print("WEIGHTED REGRESSION RESULTS (Beta)")
        print("="*60)
        print(results.summary())
        
        # Save results
        results_df = pd.DataFrame({
            'coef': results.params,
            'ci_lower': results.conf_int()[0],
            'ci_upper': results.conf_int()[1]
        })
        results_df.to_csv(REGRESSION_OUTPUT)
        
        # GENERATE BETA PLOT
        generate_beta_plot(results_df)
        
    except Exception as e:
        print(f"[!] Regression failed: {e}")

    print(f"\n[+] PIPELINE COMPLETE. Visualizations saved in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()