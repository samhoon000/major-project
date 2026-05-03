import pandas as pd
import glob
import os

def safe_read_csv(file):
    try:
        return pd.read_csv(file, low_memory=False, encoding='utf-8')
    except:
        try:
            return pd.read_csv(file, low_memory=False, encoding='latin1')
        except:
            return pd.read_csv(file, low_memory=False, encoding='cp1252')

def merge_cicids(input_folder="data/raw", output_file="data/full_dataset.csv", sample_size=80000):
    print("Merging CICIDS2017 dataset...")

    files = glob.glob(os.path.join(input_folder, "*.csv"))
    df_list = []

    for file in files:
        print(f"Reading: {file}")

        df = safe_read_csv(file)

        df.columns = df.columns.str.strip()
        df_list.append(df)

    df = pd.concat(df_list, ignore_index=True)
    print("Combined shape:", df.shape)

    # Label encoding
    df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    # Clean
    df.replace([float("inf"), float("-inf")], pd.NA, inplace=True)
    df.dropna(inplace=True)

    # Sample (important)
    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)

    os.makedirs("data", exist_ok=True)
    df.to_csv(output_file, index=False)

    print(f"Saved to {output_file}")

if __name__ == "__main__":
    merge_cicids()