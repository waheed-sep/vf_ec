import pandas as pd
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import fpgrowth, association_rules
from pathlib import Path

def analyze_commit_patterns(input_csv, output_dir, min_support=0.05):
    print(f"Loading data from {input_csv}...")
    df = pd.read_csv(input_csv)
    
    # 1. Data Preparation
    print("Grouping code changes by commit...")
    df_unique_items = df.drop_duplicates(subset=['fix_commit', 'type-kind'])
    
    # Create a list of items (type-kinds) for each commit
    transactions = df_unique_items.groupby('fix_commit')['type-kind'].apply(list).values.tolist()
    
    print(f"Total unique commits (baskets) to analyze: {len(transactions)}")
    
    # 2. One-Hot Encoding
    print("Encoding transactions into a boolean matrix...")
    te = TransactionEncoder()
    te_ary = te.fit(transactions).transform(transactions)
    df_encoded = pd.DataFrame(te_ary, columns=te.columns_)
    
    # 3. Frequent Itemset Mining (FP-Growth)
    print(f"Running FP-Growth algorithm (Minimum Support: {min_support*100}%)...")
    frequent_itemsets = fpgrowth(df_encoded, min_support=min_support, use_colnames=True)
    
    if frequent_itemsets.empty:
        print("No frequent itemsets found at this support level. Try lowering min_support.")
        return
        
    frequent_itemsets = frequent_itemsets.sort_values(by='support', ascending=False)
    
    # 4. Generate Association Rules
    print("Generating Association Rules...")
    # Generate rules FIRST while frequent_itemsets still contains frozenset objects
    rules = association_rules(frequent_itemsets, metric="confidence", min_threshold=0.5, support_only=False)
    
    if not rules.empty:
        # Sort by confidence and lift
        rules = rules.sort_values(by=['confidence', 'lift'], ascending=[False, False])
        
        # NOW format the rule columns to readable strings for the CSV
        rules['antecedents'] = rules['antecedents'].apply(lambda x: ' + '.join(list(x)))
        rules['consequents'] = rules['consequents'].apply(lambda x: ' + '.join(list(x)))
    
    # NOW format the itemsets column to readable strings for the CSV
    frequent_itemsets['itemsets'] = frequent_itemsets['itemsets'].apply(lambda x: ' + '.join(list(x)))
    
    # 5. Export Results
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    itemsets_file = out_path / "frequent_patch_itemsets.csv"
    rules_file = out_path / "patch_association_rules.csv"
    
    frequent_itemsets.to_csv(itemsets_file, index=False)
    if not rules.empty:
        rules.to_csv(rules_file, index=False)
        print(f"Saved {len(rules)} association rules to {rules_file}")
    
    print(f"Saved {len(frequent_itemsets)} frequent itemsets to {itemsets_file}")
    print("\nTop 5 Most Frequent Patch Combinations:")
    print(frequent_itemsets.head())

if __name__ == "__main__":
    INPUT_FILE = "final_results/test_combiner.csv"
    OUTPUT_DIR = "final_results/basket_analysis/"
    
    analyze_commit_patterns(INPUT_FILE, OUTPUT_DIR, min_support=0.05)