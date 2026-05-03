import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

class GNNAnomalyDetector(nn.Module):
    def __init__(self, node_dim, edge_dim):
        super().__init__()

        self.conv1 = SAGEConv(node_dim, 64)
        self.conv2 = SAGEConv(64, 64)

        self.edge_mlp = nn.Sequential(
            nn.Linear(64 * 2 + edge_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 2)
        )

    def forward(self, x, edge_index, edge_attr):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.5, training=self.training)

        x = F.relu(self.conv2(x, edge_index))
        x = F.dropout(x, p=0.5, training=self.training)

        src, dst = edge_index

        edge_features = torch.cat([x[src], x[dst], edge_attr], dim=1)

        return self.edge_mlp(edge_features)