# This script processes CSV files containing code change labels, transforming them into structured feature matrices. 
# It handles both a contextual version (with hierarchical relationships) and a flat version (without context). The script includes robust error handling and logging for better traceability.

##### Contextual Feature Matrix Parser
# import os
# import pandas as pd
# import re
# from collections import Counter

# class ContextualFeatureParser:
#     def __init__(self, input_dir='cwe_csvs', output_dir='final_results'):
#         self.input_dir = input_dir
#         self.output_dir = output_dir
#         os.makedirs(self.output_dir, exist_ok=True)

#     def parse_with_context(self, label_str):
#         features = Counter()
        
#         # Safely handle missing/empty data rows
#         if pd.isna(label_str) or str(label_str).strip() == "":
#             return features
            
#         # 1. Sibling & Typo Sanitization
#         clean_label = re.sub(r';(?!\d)', '.', str(label_str))
#         clean_label = clean_label.replace('..', '.')
        
#         # Filter out empty strings caused by trailing dots
#         parts = [p.strip() for p in clean_label.split('.') if p.strip()]
        
#         context_stack = []
        
#         # Define structures that push deeper into the stack
#         context_keywords = [
#             'If', 'IfBody', 'Loop', 'LoopBody', 'While', 'For', 
#             'Switch', 'SwitchCase', 'SwitchDefault', 'Else', 'ElseBody', 
#             'NestedIf', 'MacroBody', 'FuncBody'
#         ]

#         for part in parts:
#             base_node = part.split(';')[0]
            
#             # Frequency extraction
#             try:
#                 count = int(part.split(';')[1]) if ';' in part else 1
#             except ValueError:
#                 count = 1

#             # 2. Scope Exiting (The "Pop" mechanic)
#             is_exit_tag = (
#                 (base_node.startswith('E') and len(base_node) > 1 and base_node[1].isupper()) 
#                 or base_node in ['Eif', 'EUnion']
#             )
#             if is_exit_tag:
#                 if context_stack:
#                     context_stack.pop()
#                 continue 

#             # Build current path and record the feature
#             current_path = ":".join(context_stack + [base_node]) if context_stack else base_node
#             features[current_path] += count

#             # 3. Scope Entering (The "Push" mechanic)
#             if any(k in base_node for k in context_keywords) and not base_node.startswith('E'):
#                 context_stack.append(base_node)
        
#         return features

#     def run(self):
#         # Verify input directory exists
#         if not os.path.exists(self.input_dir):
#             print(f"CRITICAL ERROR: Input directory '{self.input_dir}' not found.")
#             return

#         csv_files = [f for f in os.listdir(self.input_dir) if f.endswith('.csv')]
        
#         if not csv_files:
#             print(f"CRITICAL ERROR: No CSV files found in '{self.input_dir}'.")
#             return

#         for file_name in csv_files:
#             print(f"\n--- Processing {file_name} ---")
#             file_path = os.path.join(self.input_dir, file_name)
            
#             try:
#                 df = pd.read_csv(file_path)
#             except Exception as e:
#                 print(f"Error reading {file_name}: {e}")
#                 continue
            
#             # Verify required columns exist
#             required_cols = ['project', 'commit', 'filename', 'label']
#             missing_cols = [col for col in required_cols if col not in df.columns]
#             if missing_cols:
#                 print(f"Warning: Missing columns {missing_cols} in {file_name}. Skipping file.")
#                 continue

#             # Filter dataset
#             initial_rows = len(df)
#             df = df[df['label'] != "IgnoreFileChanges"]
#             print(f"Filtered out {initial_rows - len(df)} 'IgnoreFileChanges' rows. {len(df)} rows remaining.")
            
#             if len(df) == 0:
#                 print(f"Warning: No data left in {file_name} after filtering. Skipping.")
#                 continue

#             # Aggregate at the file level
#             file_data = []
#             grouped = df.groupby(['project', 'commit', 'filename'])
            
#             for (proj, comm, fname), group in grouped:
#                 file_features = Counter()
#                 for label in group['label']:
#                     file_features.update(self.parse_with_context(label))
                
#                 row = {'project': proj, 'commit': comm, 'filename': fname}
#                 row.update(file_features)
#                 file_data.append(row)
            
#             # Create Matrix
#             matrix_df = pd.DataFrame(file_data).fillna(0)
            
#             # Reorder columns to put project info first
#             cols = ['project', 'commit', 'filename']
#             feature_cols = sorted([c for c in matrix_df.columns if c not in cols])
#             matrix_df = matrix_df[cols + feature_cols]
            
#             output_path = os.path.join(self.output_dir, f"Context_Matrix_{file_name}")
#             matrix_df.to_csv(output_path, index=False)
#             print(f"SUCCESS: Generated matrix saved to {output_path} (Shape: {matrix_df.shape})")

# if __name__ == "__main__":
#     print("Starting script...")
#     parser = ContextualFeatureParser()
#     parser.run()
#     print("\nExecution finished.")


############# FLAT MATRIX VERSION BELOW #############

import os
import pandas as pd
import re
from collections import Counter

class FlatFeatureParser:
    def __init__(self, input_dir='cwe_csvs', output_dir='final_results'):
        self.input_dir = input_dir
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def parse_flat_label(self, label_str):
        features = Counter()
        
        # Safely handle missing/empty data rows
        if pd.isna(label_str) or str(label_str).strip() == "":
            return features
            
        # 1. Sibling & Typo Sanitization
        # Replace sibling ';' (not followed by a digit) with '.'
        clean_label = re.sub(r';(?!\d)', '.', str(label_str))
        # Fix accidental double dots
        clean_label = clean_label.replace('..', '.')
        
        # Filter out empty strings caused by trailing dots
        parts = [p.strip() for p in clean_label.split('.') if p.strip()]

        for part in parts:
            base_node = part.split(';')[0]
            
            # Frequency extraction (handles the ;N notation)
            try:
                count = int(part.split(';')[1]) if ';' in part else 1
            except ValueError:
                count = 1

            # Add directly to features without any context prefix
            features[base_node] += count
        
        return features

    def run(self):
        # Verify input directory exists
        if not os.path.exists(self.input_dir):
            print(f"CRITICAL ERROR: Input directory '{self.input_dir}' not found.")
            return

        csv_files = [f for f in os.listdir(self.input_dir) if f.endswith('.csv')]
        
        if not csv_files:
            print(f"CRITICAL ERROR: No CSV files found in '{self.input_dir}'.")
            return

        for file_name in csv_files:
            print(f"\n--- Processing {file_name} (Flat Version) ---")
            file_path = os.path.join(self.input_dir, file_name)
            
            try:
                df = pd.read_csv(file_path)
            except Exception as e:
                print(f"Error reading {file_name}: {e}")
                continue
            
            # Verify required columns exist
            required_cols = ['project', 'commit', 'filename', 'label']
            missing_cols = [col for col in required_cols if col not in df.columns]
            if missing_cols:
                print(f"Warning: Missing columns {missing_cols} in {file_name}. Skipping file.")
                continue

            # Filter dataset
            initial_rows = len(df)
            df = df[df['label'] != "IgnoreFileChanges"]
            print(f"Filtered out {initial_rows - len(df)} 'IgnoreFileChanges' rows. {len(df)} rows remaining.")
            
            if len(df) == 0:
                print(f"Warning: No data left in {file_name} after filtering. Skipping.")
                continue

            # Aggregate at the file level
            file_data = []
            grouped = df.groupby(['project', 'commit', 'filename'])
            
            for (proj, comm, fname), group in grouped:
                file_features = Counter()
                for label in group['label']:
                    file_features.update(self.parse_flat_label(label))
                
                row = {'project': proj, 'commit': comm, 'filename': fname}
                row.update(file_features)
                file_data.append(row)
            
            # Create Matrix
            matrix_df = pd.DataFrame(file_data).fillna(0)
            
            # Reorder columns to put project info first
            cols = ['project', 'commit', 'filename']
            feature_cols = sorted([c for c in matrix_df.columns if c not in cols])
            matrix_df = matrix_df[cols + feature_cols]
            
            output_path = os.path.join(self.output_dir, f"Flat_Matrix_{file_name}")
            matrix_df.to_csv(output_path, index=False)
            print(f"SUCCESS: Generated flat matrix saved to {output_path} (Shape: {matrix_df.shape})")

if __name__ == "__main__":
    print("Starting flat parsing script...")
    parser = FlatFeatureParser()
    parser.run()
    print("\nExecution finished.")