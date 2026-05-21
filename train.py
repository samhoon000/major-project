import argparse
import contextlib
import html
import io
import os
import random
import webbrowser
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from graph_builder import build_graphs
from model import GNNAnomalyDetector


REPORT_PATH = "data/training_report.html"
LOSS_GRAPH_PATH = "data/loss_curve.png"
CONFUSION_GRAPH_PATH = "data/confusion_matrix.png"
THRESHOLD_GRAPH_PATH = "data/threshold_search.png"
NETWORK_GRAPH_PATH = "data/network_graph.png"
INTERACTIVE_NETWORK_GRAPH_PATH = "data/network_graph_interactive.html"
GAT_ATTENTION_GRAPH_PATH = "data/gat_attention_output.png"
FEATURE_IMPORTANCE_PATH = "feature_importance.png"


def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


class Tee(io.StringIO):
    def __init__(self, *streams):
        super().__init__()
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return super().write(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()
        return super().flush()


class FocalLoss(nn.Module):
    def __init__(self, weight=None, gamma=2):
        super().__init__()
        self.weight = weight
        self.gamma = gamma

    def forward(self, inputs, targets):
        ce_loss = nn.functional.cross_entropy(inputs, targets, weight=self.weight, reduction="none")
        pt = torch.exp(-ce_loss)
        return ((1 - pt) ** self.gamma * ce_loss).mean()


def save_loss_curve(loss_history):
    if not loss_history:
        return

    epochs, losses = zip(*loss_history)
    plt.figure(figsize=(9, 5))
    plt.plot(epochs, losses, marker="o", color="#0f766e", linewidth=2)
    plt.title("Training Loss")
    plt.xlabel("Epoch")
    plt.ylabel("Loss")
    plt.grid(True, alpha=0.25)
    plt.tight_layout()
    plt.savefig(LOSS_GRAPH_PATH, dpi=220, bbox_inches="tight")
    plt.close()


def save_confusion_matrix_plot(matrix):
    if matrix is None:
        return

    plt.figure(figsize=(6.5, 5.5))
    plt.imshow(matrix, cmap="Blues")
    plt.title("Confusion Matrix")
    plt.xticks([0, 1], ["Normal", "Anomaly"])
    plt.yticks([0, 1], ["Normal", "Anomaly"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")

    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            plt.text(col, row, matrix[row, col], ha="center", va="center", color="#111827", fontweight="bold")

    plt.colorbar(fraction=0.046, pad=0.04)
    plt.tight_layout()
    plt.savefig(CONFUSION_GRAPH_PATH, dpi=220, bbox_inches="tight")
    plt.close()


def save_threshold_plot(threshold_history, target_recall):
    if not threshold_history:
        return

    thresholds = [item["threshold"] for item in threshold_history]
    precisions = [item["precision"] for item in threshold_history]
    recalls = [item["recall"] for item in threshold_history]

    plt.figure(figsize=(9, 5))
    plt.plot(thresholds, precisions, label="Precision", color="#2563eb", linewidth=2)
    plt.plot(thresholds, recalls, label="Recall", color="#c2410c", linewidth=2)
    plt.axhline(target_recall, label=f"Target recall {target_recall}", color="#111827", linestyle="--", linewidth=1.5)
    plt.title("Threshold Search")
    plt.xlabel("Threshold")
    plt.ylabel("Score")
    plt.ylim(0, 1.05)
    plt.grid(True, alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(THRESHOLD_GRAPH_PATH, dpi=220, bbox_inches="tight")
    plt.close()


def summarize_gat_attention(test_data, attention_scores, y_pred, y_prob, top_k=12):
    if attention_scores is None:
        return []

    scores = attention_scores.detach().cpu().numpy()
    if scores.ndim > 1:
        scores = scores.mean(axis=1)

    metadata_count = min(len(scores), int(test_data.edge_index.shape[1]))
    focus_scores = scores[:metadata_count] * y_prob[:metadata_count]
    rows = []
    for idx in np.argsort(focus_scores)[::-1][:top_k]:
        rows.append({
            "rank": len(rows) + 1,
            "flow_id": int(idx),
            "source_ip": str(test_data.source_ip[idx]) if hasattr(test_data, "source_ip") else str(int(test_data.edge_index[0, idx])),
            "destination_ip": str(test_data.destination_ip[idx]) if hasattr(test_data, "destination_ip") else str(int(test_data.edge_index[1, idx])),
            "attention": float(scores[idx]),
            "focus_score": float(focus_scores[idx]),
            "prediction": "Anomaly" if int(y_pred[idx]) == 1 else "Normal",
            "probability": float(y_prob[idx])
        })
    return rows


def save_gat_attention_plot(test_data, attention_scores, y_pred, y_prob, top_k=20):
    if attention_scores is None:
        return

    scores = attention_scores.detach().cpu().numpy()
    if scores.ndim > 1:
        scores = scores.mean(axis=1)

    edge_count = min(len(scores), int(test_data.edge_index.shape[1]))
    if edge_count == 0:
        return

    focus_scores = scores[:edge_count] * y_prob[:edge_count]
    top_indices = np.argsort(focus_scores)[::-1][:top_k]
    labels = []
    colors = []
    for idx in top_indices:
        source = str(test_data.source_ip[idx]) if hasattr(test_data, "source_ip") else str(int(test_data.edge_index[0, idx]))
        destination = str(test_data.destination_ip[idx]) if hasattr(test_data, "destination_ip") else str(int(test_data.edge_index[1, idx]))
        labels.append(f"{source}\n-> {destination}")
        colors.append("#ef4444" if int(y_pred[idx]) == 1 else "#22c55e")

    plt.figure(figsize=(12, 7))
    y_pos = np.arange(len(top_indices))
    plt.barh(y_pos, focus_scores[top_indices], color=colors)
    plt.yticks(y_pos, labels, fontsize=8)
    plt.gca().invert_yaxis()
    plt.xlabel("GATv2 Focus Score (Attention x Anomaly Probability)")
    plt.title("GATv2 Output: High-Priority Traffic Connections")
    plt.grid(axis="x", alpha=0.25)

    for row, idx in enumerate(top_indices):
        plt.text(
            focus_scores[idx],
            row,
            f"  attention={scores[idx]:.2f}, P(anomaly)={y_prob[idx]:.2f}",
            va="center",
            fontsize=8,
            color="#111827"
        )

    plt.tight_layout()
    plt.savefig(GAT_ATTENTION_GRAPH_PATH, dpi=220, bbox_inches="tight")
    plt.close()


def generate_network_graph(test_data, y_pred=None, y_prob=None, attention_scores=None):
    os.makedirs("data", exist_ok=True)
    test_data = test_data.cpu()
    if y_pred is not None:
        test_data.pred_y = torch.tensor(y_pred, dtype=torch.long)
    if y_prob is not None:
        test_data.pred_prob = torch.tensor(y_prob, dtype=torch.float)
    if attention_scores is not None:
        scores = attention_scores.detach().cpu()
        if scores.ndim > 1:
            scores = scores.mean(dim=1)
        test_data.gat_attention = scores.float()

    torch.save(test_data.cpu(), "data/graph_data.pt")

    try:
        import visualize_graph

        visualize_graph.visualize(show=False)
    except Exception as exc:
        print(f"Could not generate network graph: {exc}")


def image_card(title, path):
    if not os.path.exists(path):
        return ""

    report_dir = os.path.dirname(REPORT_PATH)
    image_src = os.path.relpath(path, report_dir).replace("\\", "/")

    return f"""
      <article class="card image-card">
        <div class="card-title">{html.escape(title)}</div>
        <img src="{html.escape(image_src)}" alt="{html.escape(title)}">
      </article>
    """


def iframe_card(title, path):
    if not os.path.exists(path):
        return image_card(title, NETWORK_GRAPH_PATH)

    report_dir = os.path.dirname(REPORT_PATH)
    iframe_src = os.path.relpath(path, report_dir).replace("\\", "/")

    return f"""
      <article class="card image-card wide-card">
        <div class="card-title">{html.escape(title)}</div>
        <iframe src="{html.escape(iframe_src)}" title="{html.escape(title)}"></iframe>
      </article>
    """


def attention_table(rows):
    if not rows:
        return """
      <article class="card">
        <div class="card-title">Top GATv2 Connections</div>
        <div class="matrix">No GATv2 attention output was available for this run.</div>
      </article>
        """

    body = "\n".join(
        "<tr>"
        f"<td>{item['rank']}</td>"
        f"<td>{html.escape(item['source_ip'])}</td>"
        f"<td>{html.escape(item['destination_ip'])}</td>"
        f"<td>{item['attention']:.4f}</td>"
        f"<td>{item['focus_score']:.4f}</td>"
        f"<td>{html.escape(item['prediction'])}</td>"
        f"<td>{item['probability']:.4f}</td>"
        "</tr>"
        for item in rows
    )

    return f"""
      <article class="card wide-card">
        <div class="card-title">Top GATv2 Connections</div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Rank</th><th>Source IP</th><th>Destination IP</th><th>Attention</th><th>Focus Score</th><th>Prediction</th><th>Anomaly Prob.</th></tr>
            </thead>
            <tbody>{body}</tbody>
          </table>
        </div>
      </article>
    """


def generate_training_report(summary, terminal_output):
    os.makedirs("data", exist_ok=True)

    metrics = summary.get("metrics", {})
    matrix = summary.get("confusion_matrix")
    attention_rows = summary.get("gat_attention_rows", [])
    matrix_text = html.escape(str(matrix)) if matrix is not None else "Not available"
    status_text = "Strong anomaly detection run" if metrics.get("recall", 0) >= 0.9 else "Training run complete"

    report = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Training Report</title>
  <style>
    :root {{
      --ink: #172033;
      --muted: #667085;
      --line: #d9e0ea;
      --page: #f3f7fb;
      --teal: #0f766e;
      --blue: #2563eb;
      --orange: #c2410c;
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        linear-gradient(135deg, rgba(15, 118, 110, 0.10), transparent 34%),
        linear-gradient(315deg, rgba(37, 99, 235, 0.10), transparent 38%),
        var(--page);
    }}

    main {{
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 38px 0 48px;
    }}

    .hero {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(280px, 0.85fr);
      gap: 20px;
      align-items: stretch;
      margin-bottom: 20px;
    }}

    .hero-panel, .card {{
      background: rgba(255, 255, 255, 0.94);
      border: 1px solid rgba(217, 224, 234, 0.94);
      border-radius: 8px;
      box-shadow: 0 20px 45px rgba(23, 32, 51, 0.08);
    }}

    .hero-panel {{
      padding: 30px;
    }}

    .eyebrow {{
      margin: 0 0 10px;
      color: var(--teal);
      font-size: 0.78rem;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    h1 {{
      margin: 0;
      font-size: clamp(2.1rem, 5vw, 4.4rem);
      line-height: 0.98;
      letter-spacing: 0;
    }}

    .subtext {{
      max-width: 760px;
      margin: 16px 0 0;
      color: var(--muted);
      font-size: 1.02rem;
      line-height: 1.6;
    }}

    .summary {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1px;
      overflow: hidden;
      background: var(--line);
      border-radius: 8px;
      border: 1px solid var(--line);
    }}

    .metric {{
      min-height: 112px;
      padding: 18px;
      background: #fff;
    }}

    .metric span, .card-title {{
      display: block;
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 0.76rem;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .metric strong {{
      font-size: clamp(1.35rem, 3vw, 2.1rem);
      line-height: 1;
    }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 20px;
    }}

    .card {{
      padding: 20px;
      overflow: hidden;
    }}

    .image-card img {{
      display: block;
      width: 100%;
      height: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }}

    .wide-card {{
      grid-column: 1 / -1;
    }}

    iframe {{
      display: block;
      width: 100%;
      min-height: 720px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }}

    .terminal {{
      margin-top: 20px;
      padding: 0;
    }}

    .terminal .card-title {{
      padding: 18px 20px 0;
    }}

    pre {{
      margin: 0;
      max-height: 460px;
      overflow: auto;
      padding: 18px 20px 22px;
      background: #101828;
      color: #e5edf7;
      font-size: 0.9rem;
      line-height: 1.55;
      white-space: pre-wrap;
    }}

    .matrix {{
      padding: 18px;
      border-radius: 8px;
      background: #f8fafc;
      border: 1px solid var(--line);
      color: #172033;
    }}

    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 760px;
      font-size: 0.9rem;
    }}

    th, td {{
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }}

    th {{
      color: var(--muted);
      font-size: 0.72rem;
      font-weight: 900;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      background: #f8fafc;
    }}

    @media (max-width: 860px) {{
      .hero, .grid, .summary {{ grid-template-columns: 1fr; }}
      main {{ padding-top: 22px; }}
      .hero-panel {{ padding: 22px; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-panel">
        <p class="eyebrow">GNN Training Report</p>
        <h1>{html.escape(status_text)}</h1>
        <p class="subtext">Generated automatically after running <strong>python train.py</strong>. This report contains the same terminal details plus visual outputs from the model run.</p>
      </div>
      <div class="summary">
        <div class="metric"><span>Accuracy</span><strong>{metrics.get("accuracy", 0):.4f}</strong></div>
        <div class="metric"><span>Precision</span><strong>{metrics.get("precision", 0):.4f}</strong></div>
        <div class="metric"><span>Recall</span><strong>{metrics.get("recall", 0):.4f}</strong></div>
        <div class="metric"><span>F1 Score</span><strong>{metrics.get("f1_score", 0):.4f}</strong></div>
        <div class="metric"><span>ROC-AUC</span><strong>{metrics.get("roc_auc", 0):.4f}</strong></div>
        <div class="metric"><span>Best Threshold</span><strong>{summary.get("best_threshold", 0):.2f}</strong></div>
      </div>
    </section>

    <section class="grid">
      {image_card("Training Loss Curve", LOSS_GRAPH_PATH)}
      {image_card("Confusion Matrix", CONFUSION_GRAPH_PATH)}
      {image_card("Threshold Search", THRESHOLD_GRAPH_PATH)}
      {image_card("GATv2 Attention Output", GAT_ATTENTION_GRAPH_PATH)}
      {iframe_card("Interactive Network Traffic Graph", INTERACTIVE_NETWORK_GRAPH_PATH)}
      {attention_table(attention_rows)}
      {image_card("Feature Importance", FEATURE_IMPORTANCE_PATH)}
      <article class="card">
        <div class="card-title">Confusion Matrix Values</div>
        <pre class="matrix">{matrix_text}</pre>
      </article>
      <article class="card">
        <div class="card-title">Saved Outputs</div>
        <div class="matrix">Model: model.pth<br>Report: {html.escape(REPORT_PATH)}<br>Graph image: {html.escape(NETWORK_GRAPH_PATH)}<br>Interactive graph: {html.escape(INTERACTIVE_NETWORK_GRAPH_PATH)}<br>GAT output: {html.escape(GAT_ATTENTION_GRAPH_PATH)}</div>
      </article>
    </section>

    <section class="card terminal">
      <div class="card-title">Complete Terminal Output</div>
      <pre>{html.escape(terminal_output)}</pre>
    </section>
  </main>
</body>
</html>
"""

    with open(REPORT_PATH, "w", encoding="utf-8") as file:
        file.write(report)


def train_gnn():
    set_seed(42)
    os.makedirs("data", exist_ok=True)
    summary = {"metrics": {}, "best_threshold": 0, "confusion_matrix": None, "gat_attention_rows": []}
    loss_history = []
    threshold_history = []

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
    count_0 = (y_train == 0).sum()
    count_1 = (y_train == 1).sum()

    weights = torch.tensor([1.0, count_0 / max(count_1, 1)], dtype=torch.float).to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=0.0005)
    criterion = FocalLoss(weight=weights)

    print("\nTraining GATv2 anomaly detector...")
    for epoch in range(50):
        model.train()
        optimizer.zero_grad()

        out = model(train_data.x, train_data.edge_index, train_data.edge_attr)
        loss = criterion(out, train_data.y)

        loss.backward()
        optimizer.step()

        if epoch % 5 == 0:
            loss_value = loss.item()
            loss_history.append((epoch, loss_value))
            print(f"Epoch {epoch} Loss: {loss_value:.4f}")

    print("\nEvaluating...")
    model.eval()

    with torch.no_grad():
        out, attention_info = model(test_data.x, test_data.edge_index, test_data.edge_attr, return_attention=True)
        _, attention_scores = attention_info
        probs = torch.softmax(out, dim=1)[:, 1]

        y_true = test_data.y.cpu().numpy()
        y_prob = probs.cpu().numpy()

        best_threshold = 0.5
        best_precision = 0
        target_recall = 0.95

        for threshold in np.linspace(0.05, 0.95, 100):
            temp_pred = (y_prob > threshold).astype(int)
            recall = recall_score(y_true, temp_pred)
            precision = precision_score(y_true, temp_pred, zero_division=0)
            threshold_history.append({
                "threshold": float(threshold),
                "precision": float(precision),
                "recall": float(recall)
            })

            if recall >= target_recall and precision > best_precision:
                best_precision = precision
                best_threshold = threshold

        print(f"\nBest Threshold (Recall >= {target_recall}): {best_threshold:.2f}")

        y_pred = (y_prob > best_threshold).astype(int)

        metrics = {
            "accuracy": accuracy_score(y_true, y_pred),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred),
            "f1_score": f1_score(y_true, y_pred),
            "roc_auc": roc_auc_score(y_true, y_prob)
        }
        summary["metrics"] = metrics
        summary["best_threshold"] = float(best_threshold)

        print("\nAccuracy :", metrics["accuracy"])
        print("Precision:", metrics["precision"])
        print("Recall   :", metrics["recall"])
        print("F1 Score :", metrics["f1_score"])
        print("ROC-AUC  :", metrics["roc_auc"])

        print("\nConfusion Matrix:")
        matrix = confusion_matrix(y_true, y_pred)
        summary["confusion_matrix"] = matrix
        print(matrix)

        summary["gat_attention_rows"] = summarize_gat_attention(test_data, attention_scores, y_pred, y_prob)

        print("\nTop GATv2-attended connections:")
        for item in summary["gat_attention_rows"][:5]:
            print(
                f"{item['rank']}. {item['source_ip']} -> {item['destination_ip']} "
                f"attention={item['attention']:.4f} focus={item['focus_score']:.4f} prediction={item['prediction']} "
                f"prob={item['probability']:.4f}"
            )

    torch.save(model.state_dict(), "model.pth")
    print("\nModel saved")

    print("\nGenerating report graphs...")
    save_loss_curve(loss_history)
    save_confusion_matrix_plot(summary["confusion_matrix"])
    save_threshold_plot(threshold_history, target_recall)
    save_gat_attention_plot(test_data.cpu(), attention_scores, y_pred, y_prob)
    generate_network_graph(test_data, y_pred=y_pred, y_prob=y_prob, attention_scores=attention_scores)
    print(f"Training report saved to {REPORT_PATH}")

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the GNN anomaly detector and open a web report.")
    parser.add_argument("--no-browser", action="store_true", help="Create the report without opening it in a browser.")
    args = parser.parse_args()

    captured_output = Tee(os.sys.stdout)
    with contextlib.redirect_stdout(captured_output):
        report_summary = train_gnn()

    generate_training_report(report_summary, captured_output.getvalue())

    report_path = os.path.abspath(REPORT_PATH)
    print(f"\nOpen report: {report_path}")
    if not args.no_browser:
        webbrowser.open(Path(report_path).as_uri())
