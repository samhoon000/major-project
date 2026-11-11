import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

EDGE_FEATURE_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s"
]

NODE_FEATURE_NAMES = [
    "in_degree",
    "out_degree",
    "total_packets",
    "total_bytes",
    "avg_duration"
]

def preprocess_features_log(arr):
    """
    Applies non-negative log1p transformation to stabilize heavy-tailed network metrics.
    """
    clean_arr = np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=0.0)
    return np.log1p(np.maximum(0.0, clean_arr))

def compute_inductive_node_features(unique_ips, src_ips, dst_ips, flow_metrics_df):
    """
    Computes 5 inductive, live-observable node features for each unique IP in a graph:
    1. in_degree: count of incoming flows
    2. out_degree: count of outgoing flows
    3. total_packets: sum of all forward + backward packets on incident flows
    4. total_bytes: sum of flow bytes/s * duration or approximate volume
    5. avg_duration: mean flow duration of incident flows

    Works for ANY set of IPs dynamically (no static IP dictionary).
    """
    ip_to_idx = {ip: i for i, ip in enumerate(unique_ips)}
    num_nodes = len(unique_ips)

    in_degree = np.zeros(num_nodes, dtype=np.float32)
    out_degree = np.zeros(num_nodes, dtype=np.float32)
    total_packets = np.zeros(num_nodes, dtype=np.float32)
    total_bytes = np.zeros(num_nodes, dtype=np.float32)
    duration_sum = np.zeros(num_nodes, dtype=np.float32)
    incident_count = np.zeros(num_nodes, dtype=np.float32)

    fwd_pkts = flow_metrics_df["Total Fwd Packets"].to_numpy(dtype=np.float32)
    bwd_pkts = flow_metrics_df["Total Backward Packets"].to_numpy(dtype=np.float32)
    durations = flow_metrics_df["Flow Duration"].to_numpy(dtype=np.float32)
    bytes_per_sec = flow_metrics_df["Flow Bytes/s"].to_numpy(dtype=np.float32)

    # Approximate volume
    flow_bytes = np.maximum(0.0, bytes_per_sec * np.maximum(durations, 1.0) / 1e6)

    for i in range(len(src_ips)):
        src = src_ips[i]
        dst = dst_ips[i]
        u = ip_to_idx[src]
        v = ip_to_idx[dst]

        out_degree[u] += 1.0
        in_degree[v] += 1.0

        pkts = fwd_pkts[i] + bwd_pkts[i]
        b = flow_bytes[i]
        d = durations[i]

        total_packets[u] += pkts
        total_packets[v] += pkts

        total_bytes[u] += b
        total_bytes[v] += b

        duration_sum[u] += d
        duration_sum[v] += d

        incident_count[u] += 1.0
        incident_count[v] += 1.0

    avg_duration = np.zeros(num_nodes, dtype=np.float32)
    valid_mask = incident_count > 0
    avg_duration[valid_mask] = duration_sum[valid_mask] / incident_count[valid_mask]

    node_features = np.stack([
        in_degree,
        out_degree,
        total_packets,
        total_bytes,
        avg_duration
    ], axis=1)

    return node_features, ip_to_idx
