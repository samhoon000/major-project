import pandas as pd
import numpy as np
import joblib
import argparse
import random
import os
import warnings

warnings.filterwarnings('ignore')

def main():
    parser = argparse.ArgumentParser(description="Test Network Anomaly Detection (Tabular)")
    parser.add_argument("--data", type=str, default="data/CICIDS2017.csv", help="Optional dataset path to sample features from")
    args = parser.parse_args()
    
    # 1. Load model pipeline
    if not os.path.exists('model.pkl'):
        print("Error: model.pkl not found. Please run train.py first.")
        return
        
    print("Loading trained Random Forest model...")
    pipeline = joblib.load('model.pkl')
    model = pipeline['model']
    scaler = pipeline['scaler']
    features = pipeline['features']
    
    # 2. Get test features.
    # Since passing 50+ features via CLI is impractical, we sample a random flow from the CSV
    if os.path.exists(args.data):
        print(f"Randomly sampling a network flow from {args.data}...")
        df = pd.read_csv(args.data)
        df.columns = df.columns.str.strip()
        
        # Clean infinite values so we don't crash
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(subset=features, inplace=True)
        
        if len(df) == 0:
            print("Error: Dataset is empty or all rows have NaN values.")
            return
            
        sample_row = df.sample(1, random_state=random.randint(0, 100000))
        
        # Ground truth if available
        label_col = 'Attack Type'
        ground_truth = None
        for col in sample_row.columns:
            if 'ATTACK TYPE' in col.upper():
                ground_truth = sample_row[col].values[0]
                break
                
        X_test = sample_row[features]
        print(f"\nSampled Flow Features (Showing top 3):")
        for f in features[:3]:
            print(f"  - {f}: {X_test[f].values[0]}")
            
    else:
        print(f"Warning: {args.data} not found. Generating synthetic feature values (all zeros)...")
        X_test = pd.DataFrame(np.zeros((1, len(features))), columns=features)
        ground_truth = "Unknown (Synthetic)"

    # 3. Preprocess and Predict
    X_test_scaled = scaler.transform(X_test)
    pred = model.predict(X_test_scaled)[0]
    
    print("\n" + "="*50)
    print("                PREDICTION RESULT                 ")
    print("="*50)
    if ground_truth:
        print(f"Actual Type (from dataset) : {ground_truth}")
        
    if pred == 0:
        print(f"Model Prediction           : ✅ Normal Traffic")
    else:
        print(f"Model Prediction           : 🚨 Anomalous Traffic")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
