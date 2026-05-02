import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import numpy as np
from graph_builder import build_graph
from model import GNNAnomalyDetector
import joblib

def train_gnn():
    print("Building graph...")
    data, ip_mapping = build_graph()
    
    # Save IP mapping for visualization
    joblib.dump(ip_mapping, "data/ip_mapping.pkl")
    # Save the PyTorch Geometric data object
    torch.save(data, "data/graph_data.pt")
    
    num_nodes = data.num_nodes
    print(f"Total nodes in graph: {num_nodes}")
    
    # Check class distribution
    normal_count = (data.y == 0).sum().item()
    anomaly_count = (data.y == 1).sum().item()
    print(f"Class distribution - Normal: {normal_count}, Anomalous: {anomaly_count}")
    
    # Create train (70%) and test (30%) masks
    indices = np.random.permutation(num_nodes)
    train_size = int(0.7 * num_nodes)
    
    train_idx = indices[:train_size]
    test_idx = indices[train_size:]
    
    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    
    train_mask[train_idx] = True
    test_mask[test_idx] = True
    
    data.train_mask = train_mask
    data.test_mask = test_mask
    
    # Initialize model
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")
    
    model = GNNAnomalyDetector(num_features=data.num_features, hidden_size=64, dropout_rate=0.4).to(device)
    data = data.to(device)
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    
    # Handle class imbalance with weighted loss
    if anomaly_count > 0:
        weight = torch.tensor([1.0, normal_count / anomaly_count]).to(device)
        criterion = nn.CrossEntropyLoss(weight=weight)
    else:
        criterion = nn.CrossEntropyLoss()
        
    # Training Loop
    epochs = 50
    print("Starting training...")
    for epoch in range(1, epochs + 1):
        model.train()
        optimizer.zero_grad()
        
        out = model(data.x, data.edge_index)
        loss = criterion(out[data.train_mask], data.y[data.train_mask])
        
        loss.backward()
        optimizer.step()
        
        if epoch % 5 == 0 or epoch == 1:
            print(f"Epoch {epoch:03d} | Loss: {loss.item():.4f}")
            
    # Evaluation
    print("Evaluating model...")
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        probs = torch.softmax(out, dim=1)[:, 1]
        
        y_true = data.y[data.test_mask].cpu().numpy()
        y_pred = pred[data.test_mask].cpu().numpy()
        y_probs = probs[data.test_mask].cpu().numpy()
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        try:
            roc_auc = roc_auc_score(y_true, y_probs)
        except ValueError:
            roc_auc = 0.0 # In case only one class is present in test set
            
        cm = confusion_matrix(y_true, y_pred)
        
        print("\n--- Evaluation Metrics ---")
        print(f"Accuracy:  {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        print(f"ROC-AUC:   {roc_auc:.4f}")
        print("\nConfusion Matrix:")
        print(cm)
        
    # Save the trained model
    torch.save(model.state_dict(), "model.pth")
    print("Model saved to model.pth")

if __name__ == "__main__":
    train_gnn()
