import pandas as pd
import numpy as np
import torch
from torch_geometric.data import Data
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler

def build_graph(input_file="data/cleaned_dataset.csv"):
    print(f"Loading data from {input_file} for graph construction...")
    
    required_cols = [
        "Source IP",
        "Destination IP",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Label"
    ]
    
    # Read CSV with low_memory=True and usecols to filter required columns (ignoring leading/trailing spaces)
    df = pd.read_csv(
        input_file,
        usecols=lambda x: x.strip() in required_cols,
        low_memory=True
    )
    
    # Strip column names just in case they have spaces
    df.columns = df.columns.str.strip()
    
    # Convert numeric columns to float32
    numeric_cols = df.select_dtypes(include=['number']).columns
    df[numeric_cols] = df[numeric_cols].astype('float32')
    
    # Sample data
    df = df.sample(n=min(50000, len(df)), random_state=42)
    
    print(f"Dataset loaded. Shape: {df.shape}")
    
    # Ensure IP columns exist
    if "Source IP" not in df.columns or "Destination IP" not in df.columns:
        raise ValueError("Source IP or Destination IP column missing from dataset")
        
    print("Encoding IPs to nodes...")
    # Get all unique IPs
    all_ips = list(set(df["Source IP"]).union(set(df["Destination IP"])))
    ip_encoder = LabelEncoder()
    ip_encoder.fit(all_ips)
    
    # Create edges
    src_nodes = ip_encoder.transform(df["Source IP"])
    dst_nodes = ip_encoder.transform(df["Destination IP"])
    
    # PyTorch Geometric requires edge_index in shape [2, num_edges]
    edge_index = torch.tensor(np.array([src_nodes, dst_nodes]), dtype=torch.long)
    
    # Select numeric features
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    # Remove label from features if present
    if "Label" in numeric_cols:
        numeric_cols.remove("Label")
        
    print("Aggregating features per node...")
    # Aggregate features by Source IP
    src_features = df.groupby("Source IP")[numeric_cols].mean()
    # Aggregate features by Destination IP
    dst_features = df.groupby("Destination IP")[numeric_cols].mean()
    
    # Combine features: prioritize Source IP features, fill missing with Destination IP features, then fill remaining with 0
    node_features_df = pd.DataFrame(index=all_ips)
    node_features_df.index.name = "IP"
    
    # Ensure indices match
    src_features.index.name = "IP"
    dst_features.index.name = "IP"
    
    node_features_df = node_features_df.join(src_features, how="left")
    node_features_df = node_features_df.combine_first(dst_features).fillna(0)
    
    # Sort by encoded node indices (0 to num_nodes - 1)
    node_features_df["encoded_id"] = ip_encoder.transform(node_features_df.index)
    node_features_df = node_features_df.sort_values("encoded_id").drop(columns=["encoded_id"])
    
    # Normalize features
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(node_features_df.values)
    x = torch.tensor(x_scaled, dtype=torch.float)
    
    print("Creating labels...")
    # Label Strategy: Node is anomalous if it participates in attack flows (Label == 1)
    if "Label" in df.columns:
        attack_flows = df[df["Label"] == 1]
        attack_ips = set(attack_flows["Source IP"]).union(set(attack_flows["Destination IP"]))
        
        labels = np.zeros(len(all_ips))
        # Find indices of attack IPs
        if len(attack_ips) > 0:
            attack_encoded = ip_encoder.transform(list(attack_ips))
            labels[attack_encoded] = 1
            
        y = torch.tensor(labels, dtype=torch.long)
    else:
        y = None
        
    print(f"Graph constructed: {len(all_ips)} nodes, {edge_index.shape[1]} edges.")
    
    data = Data(x=x, edge_index=edge_index, y=y)
    
    # Save IP encoder mapping for later visualization or interpretation
    ip_mapping = dict(zip(ip_encoder.transform(ip_encoder.classes_), ip_encoder.classes_))
    
    return data, ip_mapping

if __name__ == "__main__":
    data, mapping = build_graph()
    print("Data object:", data)
