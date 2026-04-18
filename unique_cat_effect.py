import pandas as pd
import numpy as np
import scipy.stats as stats
from statsmodels.stats.multitest import multipletests
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

def plot_energy_distributions(df, valid_categories, output_dir, top_n=10):
    print(f"\nGenerating violin plot for the top {top_n} most frequent categories...")
    
    # Filter the dataset to only include the top N categories for readability
    top_cats = df['type-kind'].value_counts().nlargest(top_n).index
    plot_data = df[df['type-kind'].isin(top_cats)]
    
    # Set up the plot style
    plt.figure(figsize=(14, 8))
    sns.set_theme(style="whitegrid")
    
    # Create the violin plot
    # inner="quartile" shows the median and quartiles inside the violin
    # cut=0 prevents the plot from extending past the actual min/max data points
    ax = sns.violinplot(
        data=plot_data, 
        x='type-kind', 
        y='hedges_g', 
        inner="quartile", 
        cut=0,
        palette="muted",
        hue='type-kind',
        legend=False
    )
    
    # Add a bold red dashed line at exactly 0 (the baseline)
    plt.axhline(0, color='red', linestyle='--', linewidth=2, label='Zero Impact Baseline')
    
    # Formatting
    plt.title(f"Energy Impact Distribution (Top {top_n} Vulnerability Fix Categories)", fontsize=16, pad=15)
    plt.xticks(rotation=45, ha='right', fontsize=11)
    plt.ylabel("Energy Impact (hedges_g)", fontsize=12)
    plt.xlabel("Code Change Category", fontsize=12)
    plt.legend()
    plt.tight_layout()
    
    # Save the plot
    plot_path = output_dir / "energy_impact_violins.png"
    plt.savefig(plot_path, dpi=300)
    print(f"Violin plot successfully saved to: {plot_path}")
    plt.close()

def evaluate_isolated_effects(input_csv, output_csv, min_samples=30):
    print(f"Loading data from {input_csv}...")
    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"Error: Could not find {input_csv}. Ensure you are running this from /vf_ec/.")
        return

    if 'type-kind' not in df.columns or 'hedges_g' not in df.columns:
        print("Error: Required columns ('type-kind', 'hedges_g') missing from dataset.")
        return

    category_counts = df['type-kind'].value_counts()
    valid_categories = category_counts[category_counts >= min_samples].index
    
    results = []
    print(f"Analyzing {len(valid_categories)} categories for isolated energy impact...")
    
    for category in valid_categories:
        group_data = df[df['type-kind'] == category]['hedges_g'].dropna().values
        n_samples = len(group_data)
        
        if n_samples < min_samples:
            continue
            
        median_g = np.median(group_data)
        mean_g = np.mean(group_data)
        
        if np.all(group_data == 0):
            p_val = 1.0
            stat = 0.0
        else:
            try:
                stat, p_val = stats.wilcoxon(group_data, alternative='two-sided')
            except ValueError:
                p_val = 1.0
                stat = np.nan
                
        results.append({
            'type-kind': category,
            'Sample Count': n_samples,
            'Median hedges_g': median_g,
            'Mean hedges_g': mean_g,
            'Wilcoxon Stat': stat,
            'Raw P-Value': p_val
        })
        
    results_df = pd.DataFrame(results)
    
    print("Applying Benjamini-Hochberg FDR correction...")
    reject, pvals_corrected, _, _ = multipletests(results_df['Raw P-Value'], alpha=0.05, method='fdr_bh')
    results_df['Adjusted P-Value (FDR)'] = pvals_corrected
    results_df['Significant'] = reject
    
    # Updated determination logic handling zero-inflation
    def determine_verdict(row):
        if not row['Significant']:
            return "No Significant Impact"
        elif row['Median hedges_g'] > 0:
            return "Significant Increase (Median)"
        elif row['Median hedges_g'] < 0:
            return "Significant Decrease (Median)"
        elif row['Mean hedges_g'] > 0:
            return "Significant Increase (Mean-Driven)"
        elif row['Mean hedges_g'] < 0:
            return "Significant Decrease (Mean-Driven)"
        else:
            return "No Significant Impact"
            
    results_df['Energy Impact Verdict'] = results_df.apply(determine_verdict, axis=1)
    results_df = results_df.sort_values(by='Mean hedges_g', ascending=False)
    
    final_cols = [
        'type-kind', 'Sample Count', 'Energy Impact Verdict', 
        'Median hedges_g', 'Mean hedges_g', 'Adjusted P-Value (FDR)', 'Raw P-Value'
    ]
    results_df = results_df[final_cols]
    
    output_path = Path(output_csv)
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results_df.to_csv(output_path, index=False)
    print(f"\nAnalysis complete! Results successfully saved to: {output_csv}")
    print("\nPreview of top 5 categories by mean energy impact:")
    print(results_df[['type-kind', 'Sample Count', 'Energy Impact Verdict', 'Mean hedges_g']].head())

    # Call the plotting function
    plot_energy_distributions(df, valid_categories, output_dir=output_dir)

if __name__ == "__main__":
    INPUT_FILE = "final_results/test_combiner.csv"
    OUTPUT_FILE = "final_results/isolated_energy_effects.csv"
    
    evaluate_isolated_effects(INPUT_FILE, OUTPUT_FILE)