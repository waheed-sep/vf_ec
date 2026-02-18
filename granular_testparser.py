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
PROJECT_NAME = "libxml2"
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
RQ1_PLOT_FILE = os.path.join(OUTPUT_DIR, f"{PROJECT_NAME}_rq1_global_impact.png") # NEW FILE

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
    # Ensure numeric conversion happens safely
    v_vals = pd.to_numeric(group['vuln_energy_pkg'], errors='coerce').dropna().values
    f_vals = pd.to_numeric(group['fix_energy_pkg'], errors='coerce').dropna().values
    
    if len(v_vals) < 3 or len(f_vals) < 3:
        return pd.Series({'raw_p_value': 1.0, 'hedges_g': 0.0, 'se_g': 0.0})

    try:
        stat, p_value = mannwhitneyu(f_vals, v_vals, alternative='two-sided')
    except ValueError:
        p_value = 1.0 

    g, se_g = calculate_hedges_g_and_se(v_vals, f_vals)
    return pd.Series({'raw_p_value': p_value, 'hedges_g': g, 'se_g': se_g})

def aggregate_commit(group):
    """Combines multiple tests in a commit into one score."""
    g_values = group['hedges_g'].values
    se_values = group['se_g'].values
    
    # Filter valid SE (avoid division by zero)
    valid_indices = se_values > 1e-9
    
    if not np.any(valid_indices):
        return pd.Series({'g_commit': 0.0, 'se_commit': 0.0, 'ci_lower': 0.0, 'ci_upper': 0.0})
        
    g_valid = g_values[valid_indices]
    se_valid = se_values[valid_indices]
    
    # Inverse-Variance Weighting (Meta-Analysis Approach)
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
    # Ensure we count properly
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
    """Generates a Forest Plot of Regression Betas (RQ3)."""
    print("    [+] Generating Regression Beta Plot (RQ3)...")
    
    # Sort by coefficient value for cleaner plot
    results_df = results_df.sort_values(by='coef', ascending=True)
    results_df['label'] = results_df.index
    
    plt.figure(figsize=(10, 6))
    
    # Error bars format: [[lower_errors], [upper_errors]]
    y_err = [
        results_df['coef'] - results_df['ci_lower'], 
        results_df['ci_upper'] - results_df['coef']
    ]
    
    plt.errorbar(x=results_df['coef'], y=results_df['label'], xerr=y_err, 
                 fmt='o', color='black', ecolor='red', capsize=5, label='Beta (Impact)')
    
    plt.axvline(x=0, color='blue', linestyle='--', linewidth=1, label='Neutral (0)')
    
    plt.title("RQ3: Regression Analysis (Energy Impact per CWE)")
    plt.xlabel("Energy Impact (Hedges' g)\nPositive = Increases Energy | Negative = Saves Energy")
    plt.ylabel("Vulnerability Type")
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(BETA_PLOT_FILE, dpi=300)
    plt.close()

def generate_rq1_plot(g_global, ci_lower, ci_upper):
    """Generates a Single Point Plot for RQ1 (Overall Impact)."""
    print("    [+] Generating RQ1 Global Impact Plot...")
    
    plt.figure(figsize=(8, 3))
    
    # Calculate error lengths for matplotlib
    x_err = [[g_global - ci_lower], [ci_upper - g_global]]
    
    # Plot the point
    plt.errorbar(x=g_global, y=[0], xerr=x_err, 
                 fmt='D', markersize=10, color='black', ecolor='red', 
                 capsize=10, elinewidth=2, label='Global Weighted Mean')
    
    # Add Neutral Line
    plt.axvline(x=0, color='blue', linestyle='--', linewidth=1.5, label='Neutral (0)')
    
    # Formatting
    plt.yticks([]) # Hide Y-axis ticks
    plt.ylabel("All Commits")
    plt.xlabel("Global Hedges' g (Effect Size)\nPositive = Increases Energy | Negative = Saves Energy")
    plt.title(f"RQ1: Overall Energy Impact of Vulnerability Fixes\n(g = {g_global:.3f}, 95% CI: [{ci_lower:.3f}, {ci_upper:.3f}])")
    
    # Add text annotation
    verdict = "NEUTRAL" if (ci_lower <= 0 <= ci_upper) else ("INCREASE" if g_global > 0 else "DECREASE")
    color = "green" if verdict == "NEUTRAL" else "red"
    
    plt.text(g_global, 0.1, f"Verdict: {verdict}", 
             ha='center', va='bottom', fontsize=12, fontweight='bold', color=color)

    plt.grid(axis='x', linestyle='--', alpha=0.5)
    plt.ylim(-0.5, 0.5) # Center the dot vertically
    plt.tight_layout()
    plt.savefig(RQ1_PLOT_FILE, dpi=300)
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
    # Extract base testname (remove suffixes if present)
    df['base_testname'] = df['vuln_testname'].astype(str).apply(lambda x: x.rsplit('_', 1)[0])
    df['cwe'] = df['cwe'].fillna('Unknown')

    # ---------------------------------------------------------
    # STAGE 1: Per-Test Analysis
    # ---------------------------------------------------------
    print("[1/3] Running Per-Test Analysis...")
    cols_needed = ['vuln_energy_pkg', 'fix_energy_pkg']
    
    # Apply raw analysis
    grouped = df.groupby(['vuln_commit', 'fix_commit', 'base_testname', 'cwe'])[cols_needed]
    stats_df = grouped.apply(analyze_test_raw).reset_index()
    stats_df.to_csv(DETAILED_OUTPUT, index=False)

    # ---------------------------------------------------------
    # STAGE 2: Per-Commit Aggregation
    # ---------------------------------------------------------
    print("\n[2/3] Aggregating Results per Commit...")
    
    commit_grouped = stats_df.groupby(['vuln_commit', 'cwe'])
    commit_stats = commit_grouped.apply(aggregate_commit).reset_index()
    
    # Classify based on CI
    def classify_commit(row):
        if row['ci_lower'] > 0: return "Increase"
        if row['ci_upper'] < 0: return "Decrease"
        return "Neutral"

    commit_stats['result_class'] = commit_stats.apply(classify_commit, axis=1)
    
    # Save Full Commit Stats
    commit_stats.to_csv(COMMIT_OUTPUT, index=False)
    print(f"      -> Commit-level stats saved to: {COMMIT_OUTPUT}")

    # ---------------------------------------------------------
    # STAGE 2.5: GLOBAL AGGREGATION (RQ1 ANSWER)
    # ---------------------------------------------------------
    print("\n[2.5] Calculating Global Weighted Mean (RQ1)...")
    
    # Filter valid commits (avoid division by zero if se_commit is 0)
    valid_commits = commit_stats[commit_stats['se_commit'] > 1e-9].copy()
    
    if not valid_commits.empty:
        # Inverse-Variance Weighting across ALL commits
        weights = 1.0 / (valid_commits['se_commit'] ** 2)
        sum_w = np.sum(weights)
        
        g_global = np.sum(weights * valid_commits['g_commit']) / sum_w
        se_global = np.sqrt(1.0 / sum_w)
        
        ci_lower_global = g_global - (1.96 * se_global)
        ci_upper_global = g_global + (1.96 * se_global)
        
        print(f"      -> Global g: {g_global:.4f}")
        print(f"      -> 95% CI: [{ci_lower_global:.4f}, {ci_upper_global:.4f}]")
        
        # GENERATE RQ1 PLOT
        generate_rq1_plot(g_global, ci_lower_global, ci_upper_global)
    else:
        print("      [!] No valid commits found for Global Aggregation.")

    # ---------------------------------------------------------
    # STAGE 3: Weighted Regression & Visualization
    # ---------------------------------------------------------
    print("\n[3/3] Running CWE Regression Analysis & Visualization...")
    
    # Prepare Data for Heatmap: Group Rare CWEs
    cwe_counts = commit_stats['cwe'].value_counts()
    rare_cwes = cwe_counts[cwe_counts < MIN_COMMITS_THRESHOLD].index
    
    # Create a copy for visualization so we don't mess up the raw data for regression
    viz_df = commit_stats.copy()
    viz_df.loc[viz_df['cwe'].isin(rare_cwes), 'cwe'] = 'Other'
    
    # GENERATE HEATMAP
    generate_commit_heatmap(viz_df)

    # Prepare Data for Regression: (Use viz_df to keep 'Other' grouping or commit_stats for full?)
    # Usually better to use the grouped version to avoid noisy singletons
    X = pd.get_dummies(viz_df['cwe'], dtype=float)
    y = viz_df['g_commit']
    se = viz_df['se_commit'].replace(0, 1e-9)
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
        
        # GENERATE BETA PLOT (RQ3)
        generate_beta_plot(results_df)
        
    except Exception as e:
        print(f"[!] Regression failed: {e}")

    print(f"\n[+] PIPELINE COMPLETE. Visualizations saved in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()