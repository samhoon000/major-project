import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv

class GNNAnomalyDetector(nn.Module):
    """
    Existing GATv2 Anomaly Detection Architecture.
    Uses 2 GATv2Conv layers with multi-head attention and edge attributes,
    followed by an edge MLP classifier for edge (flow) anomaly detection.
    """
    def __init__(self, node_dim=5, edge_dim=5, hidden_dim=64, heads=4, dropout=0.35):
        super().__init__()

        self.node_dim = node_dim
        self.edge_dim = edge_dim
        self.hidden_dim = hidden_dim
        self.heads = heads

        self.gat1 = GATv2Conv(
            node_dim,
            self.hidden_dim,
            heads=self.heads,
            dropout=dropout,
            edge_dim=edge_dim,
            add_self_loops=False
        )
        self.gat2 = GATv2Conv(
            self.hidden_dim * self.heads,
            self.hidden_dim,
            heads=1,
            concat=False,
            dropout=dropout,
            edge_dim=edge_dim,
            add_self_loops=False
        )

        self.edge_mlp = nn.Sequential(
            nn.Linear(self.hidden_dim * 2 + edge_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )

    def forward(self, x, edge_index, edge_attr, return_attention=False):
        x = self.gat1(x, edge_index, edge_attr=edge_attr)
        x = F.elu(x)
        x = F.dropout(x, p=0.5, training=self.training)

        if return_attention:
            x, attention = self.gat2(
                x,
                edge_index,
                edge_attr=edge_attr,
                return_attention_weights=True
            )
        else:
            x = self.gat2(x, edge_index, edge_attr=edge_attr)

        x = F.elu(x)
        x = F.dropout(x, p=0.5, training=self.training)

        src, dst = edge_index

        # Concatenate source node representation, destination node representation, and edge features
        edge_features = torch.cat([x[src], x[dst], edge_attr], dim=1)

        logits = self.edge_mlp(edge_features)

        if return_attention:
            return logits, attention
        return logits

