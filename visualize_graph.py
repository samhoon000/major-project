import html
import json
import random

import matplotlib.pyplot as plt
import networkx as nx
import torch
from matplotlib.lines import Line2D


MAX_FLOWS = 160
MAX_DETECTED_ANOMALIES = 24
STATIC_GRAPH_PATH = "data/network_graph.png"
INTERACTIVE_GRAPH_PATH = "data/network_graph_interactive.html"


def protocol_name(value):
    text = str(value).strip()
    try:
        number = int(float(text))
    except ValueError:
        return text or "Unknown"

    names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return names.get(number, str(number))


def confidence_for(predicted_label, anomaly_probability):
    if predicted_label == 1:
        return anomaly_probability
    return 1.0 - anomaly_probability


def get_flow_metadata(data, flow_count):
    edge_index = data.edge_index.cpu().numpy()
    source_ip = getattr(data, "source_ip", [f"Node {node}" for node in edge_index[0]])
    destination_ip = getattr(data, "destination_ip", [f"Node {node}" for node in edge_index[1]])
    protocol = getattr(data, "protocol", ["Unknown"] * flow_count)
    packet_size = getattr(data, "packet_size", [0.0] * flow_count)
    gat_attention = getattr(data, "gat_attention", torch.zeros(flow_count)).cpu().numpy()

    return {
        "source_ip": list(source_ip)[:flow_count],
        "destination_ip": list(destination_ip)[:flow_count],
        "protocol": list(protocol)[:flow_count],
        "packet_size": list(packet_size)[:flow_count],
        "gat_attention": list(gat_attention)[:flow_count],
    }


def select_flow_indices(metadata, predicted_labels):
    random.seed(42)

    flow_indices = list(range(len(predicted_labels)))
    anomaly_indices = [idx for idx in flow_indices if predicted_labels[idx] == 1]
    normal_indices = [idx for idx in flow_indices if predicted_labels[idx] == 0]

    anomaly_target = min(MAX_DETECTED_ANOMALIES, len(anomaly_indices), max(1, MAX_FLOWS // 7))
    selected = set(random.sample(anomaly_indices, anomaly_target) if anomaly_target else [])

    selected_ips = set()
    for idx in selected:
        selected_ips.add(metadata["source_ip"][idx])
        selected_ips.add(metadata["destination_ip"][idx])

    connected_normals = [
        idx for idx in normal_indices
        if metadata["source_ip"][idx] in selected_ips or metadata["destination_ip"][idx] in selected_ips
    ]
    random.shuffle(connected_normals)

    for idx in connected_normals:
        if len(selected) >= MAX_FLOWS:
            break
        selected.add(idx)
        selected_ips.add(metadata["source_ip"][idx])
        selected_ips.add(metadata["destination_ip"][idx])

    if len(selected) < MAX_FLOWS:
        high_traffic_ips = {}
        for idx in flow_indices:
            high_traffic_ips[metadata["source_ip"][idx]] = high_traffic_ips.get(metadata["source_ip"][idx], 0) + 1
            high_traffic_ips[metadata["destination_ip"][idx]] = high_traffic_ips.get(metadata["destination_ip"][idx], 0) + 1

        top_ips = {ip for ip, _ in sorted(high_traffic_ips.items(), key=lambda item: item[1], reverse=True)[:8]}
        related_flows = [
            idx for idx in normal_indices
            if idx not in selected
            and (metadata["source_ip"][idx] in top_ips or metadata["destination_ip"][idx] in top_ips)
        ]
        random.shuffle(related_flows)

        for idx in related_flows:
            if len(selected) >= MAX_FLOWS:
                break
            selected.add(idx)

    return sorted(selected)


def build_flow_graph(selected_indices, metadata):
    G = nx.Graph()
    G.add_nodes_from(selected_indices)

    flows_by_ip = {}
    for idx in selected_indices:
        flows_by_ip.setdefault(metadata["source_ip"][idx], []).append(idx)
        flows_by_ip.setdefault(metadata["destination_ip"][idx], []).append(idx)

    for flows in flows_by_ip.values():
        unique_flows = list(dict.fromkeys(flows))
        if len(unique_flows) < 2:
            continue
        for left, right in zip(unique_flows, unique_flows[1:]):
            G.add_edge(left, right)

    isolates = list(nx.isolates(G))
    if isolates:
        G.remove_nodes_from(isolates)

    return G


def scale_positions(pos, width=1000, height=650, padding=55):
    xs = [point[0] for point in pos.values()]
    ys = [point[1] for point in pos.values()]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)

    x_span = max(max_x - min_x, 1e-9)
    y_span = max(max_y - min_y, 1e-9)

    scaled = {}
    for node, point in pos.items():
        x = padding + ((point[0] - min_x) / x_span) * (width - padding * 2)
        y = padding + ((point[1] - min_y) / y_span) * (height - padding * 2)
        scaled[node] = (round(x, 2), round(y, 2))

    return scaled


def graph_payload(G, pos, metadata, predicted_labels, anomaly_probabilities):
    nodes = []
    for node in G.nodes():
        label = "Anomaly" if predicted_labels[node] == 1 else "Normal"
        confidence = confidence_for(predicted_labels[node], anomaly_probabilities[node])
        packet_size = float(metadata["packet_size"][node])
        x, y = pos[node]

        nodes.append({
            "id": int(node),
            "x": x,
            "y": y,
            "label": label,
            "color": "#ef4444" if label == "Anomaly" else "#22c55e",
            "radius": 9 if label == "Anomaly" else 6,
            "sourceIp": str(metadata["source_ip"][node]),
            "destinationIp": str(metadata["destination_ip"][node]),
            "protocol": protocol_name(metadata["protocol"][node]),
            "packetSize": f"{packet_size:.2f}",
            "confidence": f"{confidence * 100:.2f}%",
            "gatAttention": f"{float(metadata['gat_attention'][node]):.4f}",
            "gatFocus": f"{float(metadata['gat_attention'][node]) * float(anomaly_probabilities[node]):.4f}",
        })

    edges = [{"source": int(left), "target": int(right)} for left, right in G.edges()]
    return {"nodes": nodes, "edges": edges}


def save_interactive_graph(payload, normal_count, anomaly_count, edge_count, label_source):
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Interactive Network Traffic Graph</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f8fafc;
      color: #111827;
    }}
    .wrap {{
      padding: 18px;
    }}
    .headline {{
      display: flex;
      flex-wrap: wrap;
      align-items: end;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }}
    h2 {{
      margin: 0;
      font-size: 1.2rem;
      line-height: 1.2;
    }}
    .stats {{
      color: #475569;
      font-size: 0.92rem;
      font-weight: 700;
    }}
    .graph {{
      position: relative;
      border: 1px solid #d9e0ea;
      border-radius: 8px;
      background: #ffffff;
      overflow: hidden;
    }}
    svg {{
      display: block;
      width: 100%;
      height: min(68vh, 680px);
      min-height: 540px;
    }}
    .edge {{
      stroke: #94a3b8;
      stroke-width: 1.1;
      stroke-opacity: 0.42;
    }}
    .node {{
      stroke: #0f172a;
      stroke-width: 1.4;
      cursor: pointer;
      transition: r 140ms ease, stroke-width 140ms ease;
    }}
    .node:hover {{
      stroke-width: 2.4;
    }}
    .legend {{
      position: absolute;
      left: 14px;
      bottom: 14px;
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
      padding: 10px 12px;
      border: 1px solid #d9e0ea;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.94);
      color: #334155;
      font-size: 0.9rem;
      font-weight: 700;
    }}
    .key {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
    }}
    .dot {{
      width: 13px;
      height: 13px;
      border: 2px solid #0f172a;
      border-radius: 50%;
    }}
    .line {{
      width: 24px;
      height: 2px;
      background: #94a3b8;
    }}
    .tooltip {{
      position: fixed;
      z-index: 20;
      width: max-content;
      max-width: min(360px, calc(100vw - 28px));
      pointer-events: none;
      opacity: 0;
      transform: translate(12px, 12px);
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      background: rgba(15, 23, 42, 0.96);
      color: #f8fafc;
      box-shadow: 0 18px 42px rgba(15, 23, 42, 0.22);
      padding: 12px;
      font-size: 0.88rem;
      line-height: 1.45;
    }}
    .tooltip strong {{
      display: block;
      margin-bottom: 7px;
      font-size: 0.96rem;
    }}
    .tooltip-row {{
      display: grid;
      grid-template-columns: 126px 1fr;
      gap: 10px;
    }}
    .tooltip-row span:first-child {{
      color: #cbd5e1;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="headline">
      <h2>Network Traffic Graph After Testing ({html.escape(label_source.title())})</h2>
      <div class="stats">Normal: {normal_count} | Anomaly: {anomaly_count} | Edges: {edge_count}</div>
    </div>
    <div class="graph">
      <svg id="graph" viewBox="0 0 1000 650" role="img" aria-label="Interactive network traffic graph"></svg>
      <div class="legend">
        <span class="key"><span class="dot" style="background:#22c55e"></span>Normal prediction</span>
        <span class="key"><span class="dot" style="background:#ef4444"></span>Anomaly prediction</span>
        <span class="key"><span class="line"></span>Shared traffic endpoint</span>
      </div>
    </div>
  </div>
  <div id="tooltip" class="tooltip"></div>
  <script>
    const graphData = {json.dumps(payload)};
    const svg = document.getElementById("graph");
    const tooltip = document.getElementById("tooltip");
    const positions = new Map(graphData.nodes.map(node => [node.id, node]));

    for (const edge of graphData.edges) {{
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) continue;

      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("class", "edge");
      line.setAttribute("x1", source.x);
      line.setAttribute("y1", source.y);
      line.setAttribute("x2", target.x);
      line.setAttribute("y2", target.y);
      svg.appendChild(line);
    }}

    function tooltipHtml(node) {{
      return `
        <strong>Node ID: ${{node.id}}</strong>
        <div class="tooltip-row"><span>Source IP</span><span>${{node.sourceIp}}</span></div>
        <div class="tooltip-row"><span>Destination IP</span><span>${{node.destinationIp}}</span></div>
        <div class="tooltip-row"><span>Protocol</span><span>${{node.protocol}}</span></div>
        <div class="tooltip-row"><span>Packet size</span><span>${{node.packetSize}}</span></div>
        <div class="tooltip-row"><span>GATv2 attention</span><span>${{node.gatAttention}}</span></div>
        <div class="tooltip-row"><span>GATv2 focus</span><span>${{node.gatFocus}}</span></div>
        <div class="tooltip-row"><span>Predicted label</span><span>${{node.label}}</span></div>
        <div class="tooltip-row"><span>Confidence score</span><span>${{node.confidence}}</span></div>
      `;
    }}

    function moveTooltip(event) {{
      const pad = 18;
      let left = event.clientX + 14;
      let top = event.clientY + 14;
      const rect = tooltip.getBoundingClientRect();

      if (left + rect.width + pad > window.innerWidth) {{
        left = event.clientX - rect.width - 14;
      }}
      if (top + rect.height + pad > window.innerHeight) {{
        top = event.clientY - rect.height - 14;
      }}

      tooltip.style.left = `${{Math.max(pad, left)}}px`;
      tooltip.style.top = `${{Math.max(pad, top)}}px`;
    }}

    for (const node of graphData.nodes) {{
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("class", "node");
      circle.setAttribute("cx", node.x);
      circle.setAttribute("cy", node.y);
      circle.setAttribute("r", node.radius);
      circle.setAttribute("fill", node.color);
      circle.addEventListener("mouseenter", event => {{
        tooltip.innerHTML = tooltipHtml(node);
        tooltip.style.opacity = "1";
        circle.setAttribute("r", node.radius + 3);
        moveTooltip(event);
      }});
      circle.addEventListener("mousemove", moveTooltip);
      circle.addEventListener("mouseleave", () => {{
        tooltip.style.opacity = "0";
        circle.setAttribute("r", node.radius);
      }});
      svg.appendChild(circle);
    }}
  </script>
</body>
</html>
"""

    with open(INTERACTIVE_GRAPH_PATH, "w", encoding="utf-8") as file:
        file.write(page)


def save_static_graph(G, pos, predicted_labels, normal_count, anomaly_count, edge_count, label_source):
    node_colors = ["#ef4444" if predicted_labels[node] == 1 else "#22c55e" for node in G.nodes()]
    node_sizes = [135 if predicted_labels[node] == 1 else 72 for node in G.nodes()]

    fig, ax = plt.subplots(figsize=(13, 10), facecolor="#f8fafc")
    ax.set_facecolor("#f8fafc")
    plt.title(
        f"Network Traffic Graph After Testing ({label_source.title()})\n"
        f"Green: Normal ({normal_count}) | Red: Detected Anomaly ({anomaly_count})",
        fontsize=16,
        fontweight="bold",
        color="#111827",
        pad=18
    )

    nx.draw_networkx_edges(G, pos, ax=ax, alpha=0.28, edge_color="#64748b", width=0.9)
    nx.draw_networkx_nodes(
        G,
        pos,
        ax=ax,
        node_color=node_colors,
        node_size=node_sizes,
        edgecolors="#0f172a",
        linewidths=0.45
    )

    legend_items = [
        Line2D([0], [0], marker="o", color="w", label="Normal prediction",
               markerfacecolor="#22c55e", markeredgecolor="#0f172a", markersize=9),
        Line2D([0], [0], marker="o", color="w", label="Anomaly prediction",
               markerfacecolor="#ef4444", markeredgecolor="#0f172a", markersize=11),
        Line2D([0], [0], color="#64748b", lw=1.4, label="Shared traffic endpoint")
    ]
    ax.legend(handles=legend_items, loc="lower left", frameon=True, facecolor="white", edgecolor="#cbd5e1")

    plt.axis("off")
    plt.tight_layout()
    plt.savefig(STATIC_GRAPH_PATH, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Graph visualization saved to {STATIC_GRAPH_PATH}")
    print(f"Interactive graph saved to {INTERACTIVE_GRAPH_PATH}")


def visualize(show=True):
    print("Loading graph data...")
    try:
        data = torch.load("data/graph_data.pt", weights_only=False)
    except FileNotFoundError:
        print("Graph data not found. Please run train.py first.")
        return

    flow_count = int(data.y.shape[0])
    label_source = "model predictions" if hasattr(data, "pred_y") else "ground-truth labels"
    predicted_labels = data.pred_y.cpu().numpy() if hasattr(data, "pred_y") else data.y.cpu().numpy()
    anomaly_probabilities = data.pred_prob.cpu().numpy() if hasattr(data, "pred_prob") else predicted_labels
    metadata = get_flow_metadata(data, flow_count)

    print("Building model-prediction flow graph...")
    selected_indices = select_flow_indices(metadata, predicted_labels)
    G = build_flow_graph(selected_indices, metadata)

    if G.number_of_nodes() == 0:
        print("Could not build a connected flow graph from the selected flows.")
        return

    if not nx.is_connected(G):
        largest_component = max(nx.connected_components(G), key=len)
        G = G.subgraph(largest_component).copy()

    normal_count = sum(1 for node in G.nodes() if predicted_labels[node] == 0)
    anomaly_count = sum(1 for node in G.nodes() if predicted_labels[node] == 1)
    edge_count = G.number_of_edges()

    print("\nVisualized Graph Statistics:")
    print(f"- Flow nodes: {G.number_of_nodes()}")
    print(f"- Edges: {edge_count}")
    print(f"- Normal predictions shown: {normal_count}")
    print(f"- Anomaly predictions shown: {anomaly_count}")

    pos = nx.spring_layout(G, seed=42, k=0.42, iterations=180, weight=None)
    scaled_pos = scale_positions(pos)
    payload = graph_payload(G, scaled_pos, metadata, predicted_labels, anomaly_probabilities)

    save_interactive_graph(payload, normal_count, anomaly_count, edge_count, label_source)
    save_static_graph(G, pos, predicted_labels, normal_count, anomaly_count, edge_count, label_source)

    if show:
        try:
            plt.show()
        except Exception:
            print("Could not display interactive plot (may be running headless). Saved image instead.")


if __name__ == "__main__":
    visualize()
