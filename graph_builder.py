import pandas as pd
import numpy as np
import torch
from torch_geometric.data import Data
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split

def build_graphs(input_file="data/full_dataset.csv"):
    print(f"Loading data from {input_file}...")

    df = pd.read_csv(input_file)
    df.columns = df.columns.str.strip()

    print("Label distribution:")
    print(df["Label"].value_counts())

    # -------------------------------
    # ❗ NO BALANCING (REALISTIC)
    # -------------------------------
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # -------------------------------
    # EDGE SPLIT
    # -------------------------------
    train_df, test_df = train_test_split(
        df,
        test_size=0.2,
        stratify=df["Label"],
        random_state=42
    )

    print("\nTrain label distribution:")
    print(train_df["Label"].value_counts())

    print("\nTest label distribution:")
    print(test_df["Label"].value_counts())

    # -------------------------------
    # NODE ENCODING
    # -------------------------------
    all_ips = list(set(df["Source IP"]).union(set(df["Destination IP"])))
    ip_encoder = LabelEncoder()
    ip_encoder.fit(all_ips)

    # -------------------------------
    # 🔥 HARDER FEATURE SET
    # -------------------------------
    numeric_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s"
    ]

    # -------------------------------
    # NODE FEATURES (TRAIN ONLY)
    # -------------------------------
    node_df = pd.DataFrame(index=all_ips)

    src_feat = train_df.groupby("Source IP")[numeric_cols].mean()
    dst_feat = train_df.groupby("Destination IP")[numeric_cols].mean()

    node_df = node_df.join(src_feat, how="left")
    node_df = node_df.combine_first(dst_feat).fillna(0)

    node_df["id"] = ip_encoder.transform(node_df.index)
    node_df = node_df.sort_values("id").drop(columns=["id"])

    scaler_node = StandardScaler()
    x = torch.tensor(scaler_node.fit_transform(node_df.values), dtype=torch.float)

    # -------------------------------
    # EDGE FEATURES
    # -------------------------------
    scaler_edge = StandardScaler()
    scaler_edge.fit(train_df[numeric_cols])

    def build_edges(df_part):
        src = ip_encoder.transform(df_part["Source IP"])
        dst = ip_encoder.transform(df_part["Destination IP"])

        edge_index = torch.tensor(np.array([src, dst]), dtype=torch.long)

        edge_attr = torch.tensor(
            scaler_edge.transform(df_part[numeric_cols]),
            dtype=torch.float
        )

        y = torch.tensor(df_part["Label"].values, dtype=torch.long)

        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)

    train_data = build_edges(train_df)
    test_data = build_edges(test_df)

    print(f"\nTrain Graph: {train_data.edge_index.shape[1]} edges")
    print(f"Test Graph: {test_data.edge_index.shape[1]} edges")

    return train_data, test_data