import torch
import torch.nn as nn
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

from graph_builder import build_graphs
from model import GNNAnomalyDetector

class FocalLoss(nn.Module):
    def __init__(self, weight=None, gamma=2):
        super().__init__()
        self.weight = weight
        self.gamma = gamma

    def forward(self, inputs, targets):
        ce_loss = nn.functional.cross_entropy(inputs, targets, weight=self.weight, reduction='none')
        pt = torch.exp(-ce_loss)
        return ((1 - pt) ** self.gamma * ce_loss).mean()

def train_gnn():
    print("Building graphs...")
    train_data, test_data = build_graphs("data/full_dataset.csv")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print("Using device:", device)

    model = GNNAnomalyDetector(
        node_dim=train_data.x.shape[1],
        edge_dim=train_data.edge_attr.shape[1]
    ).to(device)

    train_data = train_data.to(device)
    test_data = test_data.to(device)

    y_train = train_data.y.cpu().numpy()

    count_0 = max((y_train == 0).sum(), 1)
    count_1 = max((y_train == 1).sum(), 1)
    total = count_0 + count_1

    weights = torch.tensor([total / count_0, total / count_1], dtype=torch.float).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=0.0005)
    criterion = FocalLoss(weight=weights)

    print("\nTraining...")
    for epoch in range(50):
        model.train()
        optimizer.zero_grad()

        out = model(train_data.x, train_data.edge_index, train_data.edge_attr)
        loss = criterion(out, train_data.y)

        loss.backward()
        optimizer.step()

        if epoch % 5 == 0:
            print(f"Epoch {epoch} Loss: {loss.item():.4f}")

    print("\nEvaluating...")
    model.eval()

    with torch.no_grad():
        out = model(test_data.x, test_data.edge_index, test_data.edge_attr)

        pred = out.argmax(dim=1)
        probs = torch.softmax(out, dim=1)[:, 1]

        y_true = test_data.y.cpu().numpy()
        y_pred = pred.cpu().numpy()
        y_prob = probs.cpu().numpy()

        print("\nAccuracy :", accuracy_score(y_true, y_pred))
        print("Precision:", precision_score(y_true, y_pred))
        print("Recall   :", recall_score(y_true, y_pred))
        print("F1 Score :", f1_score(y_true, y_pred))
        print("ROC-AUC  :", roc_auc_score(y_true, y_prob))

        print("\nConfusion Matrix:")
        print(confusion_matrix(y_true, y_pred))

    torch.save(model.state_dict(), "model.pth")
    print("\nModel saved")

if __name__ == "__main__":
    train_gnn()