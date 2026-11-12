"""Live graph construction matching the restored ml/ GATv2 preprocessing."""
from __future__ import annotations

FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s"]
NODE_FEATURES = ["in_degree", "out_degree", "total_packets", "total_bytes", "avg_duration"]


def _log1p_nonnegative(values):
    import numpy as np
    clean = np.nan_to_num(values, nan=0.0, posinf=1e9, neginf=0.0)
    return np.log1p(np.maximum(0.0, clean))


def build_live_graph(flows: list[dict], node_scaler, edge_scaler):
    """Build inductive node/edge features, log-transform, then apply saved scalers."""
    if not flows:
        raise ValueError("At least one finalized flow is required")
    try:
        import numpy as np
        import torch
        from torch_geometric.data import Data
    except ImportError as exc:
        raise RuntimeError("Live graph inference needs numpy, torch, and torch-geometric") from exc
    if node_scaler is None or edge_scaler is None:
        raise RuntimeError("Saved training node and edge scalers are required; live graph cannot be scaled safely")

    # Preserve first-seen order as in ml/graph_builder.py's inductive construction.
    ips = list(dict.fromkeys(str(ip) for flow in flows
                             for ip in (flow["source_ip"], flow["destination_ip"])))
    ip_to_index = {ip: index for index, ip in enumerate(ips)}
    node_values = np.zeros((len(ips), len(NODE_FEATURES)), dtype=np.float64)
    duration_totals = np.zeros(len(ips), dtype=np.float64)
    incident_counts = np.zeros(len(ips), dtype=np.float64)
    edge_rows, source_indices, destination_indices = [], [], []

    for flow in flows:
        src, dst = str(flow["source_ip"]), str(flow["destination_ip"])
        features = flow.get("features")
        if not features:
            raise ValueError("Flow is missing canonical CICIDS feature values")
        row = [float(features[name]) for name in FEATURES]
        edge_rows.append(row)
        source_index, destination_index = ip_to_index[src], ip_to_index[dst]
        source_indices.append(source_index)
        destination_indices.append(destination_index)

        duration_us = row[0]
        packet_count = row[1] + row[2]
        # Matches ml/preprocessing.py: Flow Duration is in microseconds here.
        flow_bytes = max(0.0, row[3] * max(duration_us, 1.0) / 1_000_000.0)
        node_values[source_index, 1] += 1.0  # out_degree
        node_values[destination_index, 0] += 1.0  # in_degree
        for index in (source_index, destination_index):
            node_values[index, 2] += packet_count
            node_values[index, 3] += flow_bytes
            duration_totals[index] += duration_us
            incident_counts[index] += 1.0

    valid_nodes = incident_counts > 0
    node_values[valid_nodes, 4] = duration_totals[valid_nodes] / incident_counts[valid_nodes]
    edge_values = np.asarray(edge_rows, dtype=np.float64)
    logged_nodes = _log1p_nonnegative(node_values)
    logged_edges = _log1p_nonnegative(edge_values)
    model_node_values = node_scaler.transform(logged_nodes)
    model_edge_values = edge_scaler.transform(logged_edges)

    x = torch.tensor(model_node_values, dtype=torch.float)
    edge_attr = torch.tensor(model_edge_values, dtype=torch.float)
    edge_index = torch.tensor([source_indices, destination_indices], dtype=torch.long)
    graph = Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
    graph.ip_to_index = ip_to_index
    graph.flow_ids = [flow.get("flow_id") for flow in flows]
    graph.live_node_features = {ip: [float(value) for value in node_values[index].tolist()]
                                for ip, index in ip_to_index.items()}
    graph.live_edge_features = [[float(value) for value in row] for row in edge_values.tolist()]
    graph.live_node_model_features = {ip: [float(value) for value in model_node_values[index].tolist()]
                                      for ip, index in ip_to_index.items()}
    graph.live_edge_model_features = [[float(value) for value in row] for row in model_edge_values.tolist()]
    return graph
