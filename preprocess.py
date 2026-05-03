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
    
    df = pd.read_csv(input_file, usecols=lambda x: x.strip() in columns)
    df.columns = df.columns.str.strip()
    
    print("Sampling...")
    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
    else:
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
    print("Cleaning...")
    
    if "Label" in df.columns:
        df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
        
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    float_cols = df.select_dtypes(include=['float64']).columns
    df[float_cols] = df[float_cols].astype('float32')
    
    print(f"Cleaned dataset shape: {df.shape}")
    df.to_csv(output_file, index=False)
    print(f"Saved to {output_file}")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    preprocess_data()