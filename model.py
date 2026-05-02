import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv

class GNNAnomalyDetector(torch.nn.Module):
    def __init__(self, num_features, hidden_size=64, num_classes=2, dropout_rate=0.4):
        super(GNNAnomalyDetector, self).__init__()
        # First GCN layer
        self.conv1 = GCNConv(num_features, hidden_size)
        # Second GCN layer
        self.conv2 = GCNConv(hidden_size, hidden_size)
        
        # Final classifier layer
        self.classifier = torch.nn.Linear(hidden_size, num_classes)
        self.dropout_rate = dropout_rate

    def forward(self, x, edge_index):
        # Layer 1
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout_rate, training=self.training)
        
        # Layer 2
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout_rate, training=self.training)
        
        # Classification
        out = self.classifier(x)
        return out
