import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv

class GNNAnomalyDetector(nn.Module):
    def __init__(self, node_dim, edge_dim):
        super().__init__()

        self.hidden_dim = 64
        self.heads = 4

        self.gat1 = GATv2Conv(
            node_dim,
            self.hidden_dim,
            heads=self.heads,
            dropout=0.35,
            edge_dim=edge_dim,
            add_self_loops=False
        )
        self.gat2 = GATv2Conv(
            self.hidden_dim * self.heads,
            self.hidden_dim,
            heads=1,
            concat=False,
            dropout=0.35,
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

        edge_features = torch.cat([x[src], x[dst], edge_attr], dim=1)

        logits = self.edge_mlp(edge_features)

        if return_attention:
            return logits, attention
        return logits
