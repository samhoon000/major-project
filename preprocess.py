import pandas as pd
import numpy as np
import os

def preprocess_data(input_file="data/CICIDS2017.csv", output_file="data/cleaned_dataset.csv", sample_size=50000):
    print("Loading data...")
    
    columns = [
        'Source IP',
        'Destination IP',
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Flow Bytes/s',
        'Flow Packets/s',
        'Label'
    ]
    
    # Read only required columns, handling possible whitespace in CSV header
    df = pd.read_csv(input_file, usecols=lambda x: x.strip() in columns)
    
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    print("Sampling...")
    # Sample early to prevent memory issues
    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
    else:
        df = df.sample(frac=1, random_state=42).reset_index(drop=True) # Shuffle if smaller
        
    print("Cleaning...")
    
    # Encode label: BENIGN -> 0, Attack -> 1
    if "Label" in df.columns:
        df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
        
    # Replace infinite values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Drop NaN rows
    df.dropna(inplace=True)
    
    # Convert all float64 to float32 to reduce memory usage
    float_cols = df.select_dtypes(include=['float64']).columns
    df[float_cols] = df[float_cols].astype('float32')
    
    print(f"Cleaned dataset shape: {df.shape}")
    
    # Save cleaned dataset
    df.to_csv(output_file, index=False)
    print(f"Cleaned dataset saved to {output_file}")

if __name__ == "__main__":
    if not os.path.exists("data"):
        os.makedirs("data")
    preprocess_data()
