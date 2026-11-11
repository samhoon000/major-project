import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ml.preprocessing import (
    EDGE_FEATURE_COLS,
    NODE_FEATURE_NAMES,
    preprocess_features_log,
    compute_inductive_node_features
)

def build_inductive_graph(df_part, node_scaler=None, edge_scaler=None, is_fit=False):
    """
    Constructs a PyG Data object from a dataframe of network flows using INDUCTIVE node features
    and log-stabilized distributions.
    """
    src_ips = df_part["Source IP"].astype(str).tolist()
    dst_ips = df_part["Destination IP"].astype(str).tolist()

    unique_ips = list(dict.fromkeys(src_ips + dst_ips))
    raw_node_features, ip_to_idx = compute_inductive_node_features(
        unique_ips, src_ips, dst_ips, df_part[EDGE_FEATURE_COLS]
    )

    raw_edge_features = df_part[EDGE_FEATURE_COLS].to_numpy(dtype=np.float32)

    # Log1p stabilization
    log_node_features = preprocess_features_log(raw_node_features)
    log_edge_features = preprocess_features_log(raw_edge_features)

    if is_fit:
        node_scaler = StandardScaler()
        edge_scaler = StandardScaler()
        norm_node_features = node_scaler.fit_transform(log_node_features)
        norm_edge_features = edge_scaler.fit_transform(log_edge_features)
    else:
        norm_node_features = node_scaler.transform(log_node_features) if node_scaler else log_node_features
        norm_edge_features = edge_scaler.transform(log_edge_features) if edge_scaler else log_edge_features

    src_indices = [ip_to_idx[s] for s in src_ips]
    dst_indices = [ip_to_idx[d] for d in dst_ips]

    edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long)
    edge_count = int(edge_index.shape[1])
    assert len(raw_edge_features) == len(df_part) == edge_count, (
        "Flow features and labels must remain in one-to-one row/edge order: "
        f"features={len(raw_edge_features)}, rows={len(df_part)}, edges={edge_count}"
    )
    edge_attr = torch.tensor(norm_edge_features, dtype=torch.float)
    x = torch.tensor(norm_node_features, dtype=torch.float)

    data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
    data.num_nodes = len(unique_ips)
    data.unique_ips = unique_ips
    data.source_ips = src_ips
    data.destination_ips = dst_ips

    if "Label" in df_part.columns:
        assert len(df_part["Label"]) == edge_count, (
            f"Edge labels={len(df_part['Label'])} do not match graph edges={edge_count}"
        )
        data.y = torch.tensor(df_part["Label"].to_numpy(dtype=np.int64), dtype=torch.long)

    return data, node_scaler, edge_scaler

def load_and_prepare_dataset(csv_path="data/cleaned_dataset.csv", test_size=0.2, seed=42):
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=EDGE_FEATURE_COLS + ["Source IP", "Destination IP", "Label"], inplace=True)

    print(f"Dataset shape after cleaning: {df.shape}")
    print("Label distribution:")
    print(df["Label"].value_counts())

    train_df, test_df = train_test_split(
        df, test_size=test_size, stratify=df["Label"], random_state=seed
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    print(f"Building inductive train graph ({len(train_df)} flows)...")
    train_data, node_scaler, edge_scaler = build_inductive_graph(train_df, is_fit=True)

    print(f"Building inductive test graph ({len(test_df)} flows)...")
    test_data, _, _ = build_inductive_graph(test_df, node_scaler=node_scaler, edge_scaler=edge_scaler, is_fit=False)

    print(f"Train Graph: {train_data.num_nodes} nodes, {train_data.edge_index.shape[1]} edges")
    print(f"Test Graph: {test_data.num_nodes} nodes, {test_data.edge_index.shape[1]} edges")

    return train_data, test_data, train_df, test_df, node_scaler, edge_scaler
