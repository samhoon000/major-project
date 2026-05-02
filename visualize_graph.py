import torch
import networkx as nx
import matplotlib.pyplot as plt
import random

def visualize():
    print("Loading graph data...")
    try:
        data = torch.load("data/graph_data.pt")
    except FileNotFoundError:
        print("Graph data not found. Please run train.py first.")
        return

    # Convert to NetworkX graph
    print("Converting to NetworkX format...")
    edge_index = data.edge_index.cpu().numpy()
    edges = list(zip(edge_index[0], edge_index[1]))
    
    G = nx.Graph()
    G.add_edges_from(edges)
    
    print(f"Original Graph Statistics:")
    print(f"- Nodes: {G.number_of_nodes()}")
    print(f"- Edges: {G.number_of_edges()}")
    
    # Subsampling to prevent crash (visualizing 200 nodes)
    # We will try to include a mix of normal and anomalous nodes if possible
    max_nodes = 200
    if G.number_of_nodes() > max_nodes:
        print(f"Sampling {max_nodes} nodes for visualization...")
        
        # Get nodes that actually exist in the graph (some might be disconnected and not in G.nodes())
        available_nodes = list(G.nodes())
        
        # Get anomalous and normal nodes from available nodes
        y_array = data.y.cpu().numpy()
        anomalous_nodes = [n for n in available_nodes if y_array[n] == 1]
        normal_nodes = [n for n in available_nodes if y_array[n] == 0]
        
        # Take up to 50 anomalous nodes to ensure they are visible
        sample_anomalous = random.sample(anomalous_nodes, min(50, len(anomalous_nodes)))
        remaining_slots = max_nodes - len(sample_anomalous)
        sample_normal = random.sample(normal_nodes, min(remaining_slots, len(normal_nodes)))
        
        sampled_nodes = set(sample_anomalous + sample_normal)
        
        # Create subgraph
        G_sub = G.subgraph(sampled_nodes)
        
        # To make the graph look better, we also include edges among the sampled nodes.
        # Connected components are better visually. Let's find nodes connected to anomalies.
        if len(sample_anomalous) > 0 and len(sample_normal) > 0:
            connected_nodes = set(sample_anomalous)
            for node in sample_anomalous:
                neighbors = list(G.neighbors(node))
                # Add a few neighbors
                connected_nodes.update(neighbors[:5])
                
            # If we exceeded max_nodes, truncate
            connected_nodes = list(connected_nodes)[:max_nodes]
            G_sub = G.subgraph(connected_nodes)
    else:
        G_sub = G

    print(f"\nVisualized Graph Statistics:")
    print(f"- Nodes: {G_sub.number_of_nodes()}")
    print(f"- Edges: {G_sub.number_of_edges()}")

    # Determine node colors
    node_colors = []
    y_array = data.y.cpu().numpy()
    
    for node in G_sub.nodes():
        if y_array[node] == 1:
            node_colors.append('red') # Anomalous
        else:
            node_colors.append('lightgreen') # Normal

    # Plot
    plt.figure(figsize=(12, 10))
    plt.title("Network Traffic Graph (Subset)\nRed: Anomalous, Green: Normal", fontsize=16)
    
    pos = nx.spring_layout(G_sub, seed=42) # Spring layout for better visualization
    
    # Draw nodes
    nx.draw_networkx_nodes(G_sub, pos, node_color=node_colors, node_size=100, edgecolors='black', linewidths=0.5)
    # Draw edges
    nx.draw_networkx_edges(G_sub, pos, alpha=0.3, edge_color='gray')
    
    plt.axis('off')
    plt.tight_layout()
    
    output_img = "data/network_graph.png"
    plt.savefig(output_img, dpi=300, bbox_inches='tight')
    print(f"Graph visualization saved to {output_img}")
    
    try:
        plt.show()
    except Exception as e:
        print("Could not display interactive plot (may be running headless). Saved image instead.")

if __name__ == "__main__":
    visualize()
