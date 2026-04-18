import pandas as pd
import numpy as np
import scipy.stats as stats
import scikit_posthocs as sp
from pathlib import Path

def analyze_and_export_energy_impact(csv_path, output_excel="statistical_results.xlsx", min_samples=30):
    print("Loading data...")
    df = pd.read_csv(csv_path)
    
    # 1. Filter out low-frequency categories
    category_counts = df['type-kind'].value_counts()
    valid_categories = category_counts[category_counts >= min_samples].index
    
    df_filtered = df[df['type-kind'].isin(valid_categories)]
    remaining_cats = df_filtered['type-kind'].nunique()
    
    print(f"Filtered down to {remaining_cats} categories (minimum {min_samples} samples required).")
    
    if remaining_cats < 2:
        print("Not enough categories remaining to perform statistical comparison.")
        return

    # 2. Prepare data for Kruskal-Wallis
    grouped_data = [group['hedges_g'].values for name, group in df_filtered.groupby('type-kind')]
    
    # 3. Run Kruskal-Wallis H Test
    print("Running Kruskal-Wallis test...")
    h_stat, p_val = stats.kruskal(*grouped_data)
    
    # 4. Calculate Effect Size (Epsilon-Squared)
    n = len(df_filtered)
    epsilon_sq = h_stat / (n - 1)
    
    if epsilon_sq < 0.01:
        magnitude = "Negligible effect"
    elif epsilon_sq < 0.04:
        magnitude = "Weak effect"
    elif epsilon_sq < 0.16:
        magnitude = "Moderate effect"
    else:
        magnitude = "Strong effect"
        
    # Compile the summary data
    summary_data = {
        "Metric": [
            "Total Samples Analyzed", 
            "Categories Analyzed", 
            "Kruskal-Wallis H-Statistic", 
            "P-Value", 
            "Significant (p < 0.05)", 
            "Epsilon-Squared Effect Size", 
            "Effect Magnitude"
        ],
        "Value": [
            n, 
            remaining_cats, 
            h_stat, 
            p_val, 
            "Yes" if p_val < 0.05 else "No", 
            epsilon_sq, 
            magnitude
        ]
    }
    df_summary = pd.DataFrame(summary_data)
    
    # 5. Post-Hoc Analysis
    df_posthoc = pd.DataFrame()
    if p_val < 0.05:
        print("Running Dunn's Post-Hoc Test (this may take a moment)...")
        df_posthoc = sp.posthoc_dunn(df_filtered, val_col='hedges_g', group_col='type-kind', p_adjust='fdr_bh')
        
    # 6. Export everything to Excel
    print(f"Exporting results to {output_excel}...")
    with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
        # Write Summary Sheet
        df_summary.to_excel(writer, sheet_name='Overall_Summary', index=False)
        
        # Write Category Counts Sheet
        df_counts = category_counts[category_counts >= min_samples].reset_index()
        df_counts.columns = ['type-kind', 'Sample Count']
        df_counts.to_excel(writer, sheet_name='Category_Counts', index=False)
        
        # Write Post-Hoc Matrix Sheet (if significant)
        if not df_posthoc.empty:
            # Leave index=True here so the row names (type-kind) show up on the left side of the matrix
            df_posthoc.to_excel(writer, sheet_name='PostHoc_PValues', index=True)
            
    print(f"Success! All results are saved in '{output_excel}'.")

if __name__ == "__main__":
    # Point this to your combiner output, and optionally name your Excel file
    input_csv = "final_results/test_combiner.csv"
    output_xlsx = "final_results/energy_impact_stats.xlsx"
    
    # Create the directory if it doesn't exist
    Path(output_xlsx).parent.mkdir(parents=True, exist_ok=True)
    
    analyze_and_export_energy_impact(input_csv, output_excel=output_xlsx)