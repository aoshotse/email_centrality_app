# -*- coding: utf-8 -*-
"""
Created on Fri Mar 14 02:36:32 2025

@author: aosho

Strategic Email Network Analyzer
Enhanced version with improved email extraction
"""

# Import streamlit first, then set_page_config as the very first command
import streamlit as st
st.set_page_config(page_title="Strategic Network Analyzer", layout="wide")

# Now import all other libraries
import pandas as pd
import networkx as nx
import numpy as np
import re
import base64
import plotly.graph_objects as go
from io import BytesIO
from collections import defaultdict

# Add title and description
st.title("Email Network Analyzer")
st.markdown("""
This application analyzes email networks based on Outlook inbox data. Upload your email data to visualize connections, analyze centrality metrics,
and identify key players in your network.
""")

def extract_email_addresses(text):
    """
    Extract email addresses from a text string.
    Handles both standard email addresses and Exchange internal addresses.
    """
    if pd.isna(text) or not isinstance(text, str):
        return []
    
    email_addresses = []
    
    # First split by semicolons which often separate multiple addresses
    parts = text.split(';')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        # Standard email pattern
        std_email_pattern = r'[\w.+-]+@[\w-]+\.[\w.-]+'
        std_emails = re.findall(std_email_pattern, part)
        
        if std_emails:
            # If we found standard email format, add it
            email_addresses.extend(std_emails)
        elif '@' in part:
            # Might be a non-standard email format but contains @
            email_addresses.append(part)
        elif part.startswith('/o=ExchangeLabs') or 'cn=' in part:
            # This is an Exchange internal address
            # Extract the CN part which often contains a user identifier
            cn_match = re.search(r'cn=([^/]+)', part)
            if cn_match:
                identifier = cn_match.group(1).split('-')[0]  # Take part before first hyphen
                if identifier:
                    # Create a placeholder email for the Exchange address
                    email_addresses.append(f"exchange:{identifier}")
            else:
                # If we can't extract CN, use the whole Exchange address as a unique ID
                email_addresses.append(f"exchange:{part.replace('/', '_')}")
    
    return email_addresses

def parse_address_field(field, name_field=None):
    """
    Parse address field and match with names if available.
    Returns list of tuples (address, name)
    """
    addresses = extract_email_addresses(field)
    results = []
    
    if not name_field or pd.isna(name_field) or not isinstance(name_field, str):
        # If no name field, just return addresses with empty names
        return [(addr, "") for addr in addresses]
    
    # Try to match names with addresses
    name_parts = name_field.split(';')
    
    # If number of names matches number of addresses, direct mapping
    if len(name_parts) == len(addresses):
        return [(addr, name.strip()) for addr, name in zip(addresses, name_parts)]
    
    # Otherwise, try best-effort matching
    for i, addr in enumerate(addresses):
        if i < len(name_parts):
            results.append((addr, name_parts[i].strip()))
        else:
            results.append((addr, ""))
    
    return results

def extract_domain(email):
    """Extract domain from email address."""
    if pd.isna(email) or not isinstance(email, str):
        return ""
    
    if email.startswith('exchange:'):
        return "exchange"
    
    parts = email.split('@')
    if len(parts) > 1:
        return parts[1].lower()
    return ""

def build_network_from_emails(df, node_type='address', tie_type='shared_email', remove_isolated=False):
    """Build a network graph from email data based on selected node and tie types."""
    G = nx.Graph()
    
    # Expected columns
    expected_cols = [
        'From: (Address)', 'To: (Address)', 'CC: (Address)', 'BCC: (Address)',
        'From: (Name)', 'To: (Name)', 'CC: (Name)', 'BCC: (Name)',
        'Importance', 'Sensitivity'
    ]
    
    # Check if the necessary columns exist
    for col in expected_cols:
        if col not in df.columns:
            if 'Address' in col:
                # Try to construct email addresses from the data
                base_col = col.split(':')[0] + ': (Name)'
                if base_col in df.columns:
                    st.warning(f"Column {col} not found. Attempting to extract email addresses from {base_col}.")
                    df[col] = df[base_col].apply(lambda x: extract_email_addresses(x)[0] if extract_email_addresses(x) else "")
                else:
                    st.warning(f"Column {col} not found and cannot be constructed.")
            else:
                st.warning(f"Column {col} not found.")
                if 'Importance' in col or 'Sensitivity' in col:
                    df[col] = 'Normal'  # Default value
    
    # Create mappings between addresses and names
    email_to_name = {}
    name_to_email = {}
    
    # For shared institutional address (Op2)
    domain_participants = defaultdict(set)
    
    # Process all rows to collect necessary data
    for _, row in df.iterrows():
        all_participants = []
        high_importance = row.get('Importance') == 'High' or row.get('Sensitivity') == 'High'
        
        # Process From address
        from_addr = row.get('From: (Address)', '')
        from_name = row.get('From: (Name)', '')
        
        if from_addr and isinstance(from_addr, str):
            from_addresses = extract_email_addresses(from_addr)
            for addr in from_addresses:
                all_participants.append((addr, from_name, 'From'))
                if from_name and isinstance(from_name, str):
                    email_to_name[addr] = from_name
                    name_to_email[from_name] = addr
        
        # Process To addresses
        to_addrs = row.get('To: (Address)', '')
        to_names = row.get('To: (Name)', '')
        
        if to_addrs and isinstance(to_addrs, str):
            to_pairs = parse_address_field(to_addrs, to_names)
            for addr, name in to_pairs:
                all_participants.append((addr, name, 'To'))
                if name:
                    email_to_name[addr] = name
                    name_to_email[name] = addr
        
        # Process CC addresses
        cc_addrs = row.get('CC: (Address)', '')
        cc_names = row.get('CC: (Name)', '')
        
        if cc_addrs and isinstance(cc_addrs, str):
            cc_pairs = parse_address_field(cc_addrs, cc_names)
            for addr, name in cc_pairs:
                all_participants.append((addr, name, 'CC'))
                if name:
                    email_to_name[addr] = name
                    name_to_email[name] = addr
        
        # Process BCC addresses
        bcc_addrs = row.get('BCC: (Address)', '')
        bcc_names = row.get('BCC: (Name)', '')
        
        if bcc_addrs and isinstance(bcc_addrs, str):
            bcc_pairs = parse_address_field(bcc_addrs, bcc_names)
            for addr, name in bcc_pairs:
                all_participants.append((addr, name, 'BCC'))
                if name:
                    email_to_name[addr] = name
                    name_to_email[name] = addr
        
        # For Op2: Collect emails by domain
        if tie_type == 'shared_domain':
            for addr, name, _ in all_participants:
                # Extract domain from standard email addresses
                domain = extract_domain(addr)
                
                if domain:
                    if node_type == 'address':
                        domain_participants[domain].add(addr)
                    else:  # node_type == 'name'
                        if name:
                            domain_participants[domain].add(name)
                        else:
                            domain_participants[domain].add(addr)  # Fallback to address if name missing
        
        # For Op1: Create network based on shared emails
        if tie_type == 'shared_email':
            node_participants = []
            for addr, name, _ in all_participants:
                if node_type == 'address':
                    node_id = addr
                else:  # node_type == 'name'
                    node_id = name if name else addr  # Fallback to address if name missing
                
                if node_id not in G.nodes():
                    G.add_node(node_id, name=name if node_type == 'address' else addr)
                
                node_participants.append(node_id)
            
            # Create edges between all participants in this email
            for i in range(len(node_participants)):
                for j in range(i+1, len(node_participants)):
                    if G.has_edge(node_participants[i], node_participants[j]):
                        G[node_participants[i]][node_participants[j]]['weight'] += 1
                        if high_importance:
                            G[node_participants[i]][node_participants[j]]['high_importance'] = True
                    else:
                        G.add_edge(
                            node_participants[i],
                            node_participants[j],
                            weight=1,
                            high_importance=high_importance
                        )
    
    # If we're not using shared_email, build the network based on shared_domain
    if tie_type == 'shared_domain':
        for domain, participants in domain_participants.items():
            for participant in participants:
                if participant not in G.nodes():
                    if node_type == 'address':
                        G.add_node(participant, name=email_to_name.get(participant, participant))
                    else:  # node_type == 'name'
                        G.add_node(participant, name=name_to_email.get(participant, participant))
        
        # Create edges between participants with the same domain
        for domain, participants in domain_participants.items():
            participants_list = list(participants)
            for i in range(len(participants_list)):
                for j in range(i+1, len(participants_list)):
                    p1, p2 = participants_list[i], participants_list[j]
                    if G.has_edge(p1, p2):
                        G[p1][p2]['weight'] += 1
                    else:
                        G.add_edge(p1, p2, weight=1, high_importance=False)
    
    # Remove isolated nodes if requested
    if remove_isolated:
        isolated_nodes = list(nx.isolates(G))
        G.remove_nodes_from(isolated_nodes)
        if isolated_nodes:
            st.info(f"Removed {len(isolated_nodes)} isolated nodes with no connections.")
    
    return G, email_to_name, name_to_email

def calculate_centrality(G, measure='degree', alpha=0.1):
    """Calculate centrality measures for the network.
    If Bonacich fails for the entire graph, it attempts the top 3 largest
    connected components. If that also fails, we fall back to eigenvector."""
    
    centrality = {}
    
    if measure == 'degree':
        centrality = nx.degree_centrality(G)
    
    elif measure == 'betweenness':
        centrality = nx.betweenness_centrality(G)
    
    elif measure == 'closeness':
        centrality = nx.closeness_centrality(G)
    
    elif measure == 'eigenvector':
        try:
            centrality = nx.eigenvector_centrality_numpy(G)
        except:
            # Fallback if numpy-based method fails
            try:
                centrality = nx.eigenvector_centrality(G, max_iter=1000)
            except:
                st.warning("Could not calculate eigenvector centrality. Using degree centrality instead.")
                centrality = nx.degree_centrality(G)
    
    elif measure == 'bonacich':
        beta = 1.0
        try:
            # First try Bonacich (Katz) on the entire graph
            centrality = nx.katz_centrality(G, alpha=alpha, beta=beta)
        
        except:
            st.warning("Could not calculate Bonacich centrality on the full graph. "
                       "Trying the 3 largest connected components.")
            
            try:
                # Identify the 3 largest connected components
                comps = sorted(nx.connected_components(G), key=len, reverse=True)
                top_3 = comps[:3]
                
                # We'll store partial results here
                centrality = {}
                
                for cset in top_3:
                    sub_g = G.subgraph(cset).copy()
                    sub_cent = nx.katz_centrality(sub_g, alpha=alpha, beta=beta)
                    # Merge into main dictionary
                    for node, val in sub_cent.items():
                        centrality[node] = val
                
                # For nodes not in these 3 components, set 0
                all_in_top_3 = set().union(*top_3)
                for node in G.nodes():
                    if node not in all_in_top_3:
                        centrality[node] = 0.0
            
            except:
                # If computing for top 3 also fails, try eigenvector
                st.warning("Could not calculate Bonacich centrality on the 3 largest components. "
                           "Using eigenvector centrality instead.")
                try:
                    centrality = nx.eigenvector_centrality_numpy(G)
                except:
                    # Fallback if numpy-based eigenvector fails
                    try:
                        centrality = nx.eigenvector_centrality(G, max_iter=1000)
                    except:
                        st.warning("Could not calculate eigenvector centrality. Using degree centrality instead.")
                        centrality = nx.degree_centrality(G)
    
    return centrality

def visualize_network_plotly(G, id_to_label, centrality=None, highlight_top=25):
    """Create an interactive network visualization using Plotly."""
    # Get positions using spring layout from NetworkX
    pos = nx.spring_layout(G, seed=42)
    
    # Sort nodes by centrality if provided
    top_nodes = []
    if centrality:
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        top_nodes = [node[0] for node in sorted_nodes[:highlight_top]]
    
    # Prepare node traces
    node_x = []
    node_y = []
    node_text = []
    node_size = []
    node_color = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        # Node text for hover
        label = id_to_label.get(node, node)
        if label and isinstance(label, str) and len(label) > 30:
            label = label[:27] + "..."
        
        cent_val = centrality.get(node, 0) if centrality else 0
        node_text.append(f"ID: {node}<br>Label: {label}<br>Centrality: {cent_val:.4f}")
        
        # Node size based on centrality
        if centrality:
            size = 10 + 40 * cent_val
        else:
            size = 10
        
        node_size.append(size)
        
        # Node color based on top nodes
        if centrality and node in top_nodes:
            node_color.append("purple")     # Highlighted top nodes
        else:
            node_color.append("lightblue")  # Other nodes
    
    # Create node trace
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        text=node_text,
        marker=dict(
            showscale=True,
            colorscale='YlGnBu',
            color=node_color,
            size=node_size,
            line=dict(width=2, color='#FFFFFF')
        ),
        name='Nodes'
    )
    
    # Prepare edge traces
    edge_traces = []
    
    # Separate normal and high-importance edges
    normal_edges_x = []
    normal_edges_y = []
    high_edges_x = []
    high_edges_y = []
    normal_edge_text = []
    high_edge_text = []
    
    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        
        weight = data.get('weight', 1)
        edge_text = f"Connection between:<br>{u} and {v}<br>Weight: {weight}"
        
        if data.get('high_importance', False):
            high_edges_x.extend([x0, x1, None])
            high_edges_y.extend([y0, y1, None])
            high_edge_text.append(edge_text)
        else:
            normal_edges_x.extend([x0, x1, None])
            normal_edges_y.extend([y0, y1, None])
            normal_edge_text.append(edge_text)
    
    # Normal edges trace
    normal_edge_trace = go.Scatter(
        x=normal_edges_x, y=normal_edges_y,
        line=dict(width=0.5, color='#1f77b4'),
        hoverinfo='text',
        text=normal_edge_text,
        mode='lines',
        name='Regular Connection'
    )
    
    # High importance edges trace
    high_edge_trace = go.Scatter(
        x=high_edges_x, y=high_edges_y,
        line=dict(width=1.5, color='red'),
        hoverinfo='text',
        text=high_edge_text,
        mode='lines',
        name='High Importance'
    )
    
    # Add to edge traces
    if normal_edges_x:
        edge_traces.append(normal_edge_trace)
    if high_edges_x:
        edge_traces.append(high_edge_trace)
    
    # Create figure
    fig = go.Figure(
        data=edge_traces + [node_trace],
        layout=go.Layout(
            showlegend=True,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            title="Email Network Visualization",
            annotations=[
                dict(
                    text=(
                        "Node size represents centrality; Purple nodes are top central; "
                        "Red edges are high importance"
                    ),
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.5, y=0
                )
            ]
        )
    )
    
    return fig

def main():
    # File uploader
    uploaded_file = st.file_uploader("Upload your Outlook email data (Excel format)", type=["xlsx", "xls"])
    
    if uploaded_file is not None:
        # Show a loading message
        with st.spinner("Reading Excel file..."):
            try:
                # Read Excel file
                df = pd.read_excel(uploaded_file)
                st.success(f"Successfully loaded data with {len(df)} emails")
                
                # Show data sample
                with st.expander("Preview of the data"):
                    st.dataframe(df.head())
                
                # Node type selection
                st.subheader("Network Configuration")
                node_type = st.radio(
                    "Define nodes by:",
                    ["address", "name"],
                    format_func=lambda x: "Email Address" if x == "address" else "Person Name"
                )
                
                # Tie definition selection
                tie_type = st.selectbox(
                    "Define connections by:",
                    ["shared_email", "shared_domain"],
                    format_func=lambda x: {
                        "shared_email": "Shared Email (participants in same message, unweighted)",
                        "shared_domain": "Shared Domain (weighted by # of shared emails)"
                    }[x]
                )
                
                # Option to remove isolated nodes
                remove_isolated = st.checkbox("Remove isolated nodes (nodes with no connections)", value=True)
                
                # Build network
                with st.spinner("Building network..."):
                    G, email_to_name, name_to_email = build_network_from_emails(
                        df, 
                        node_type=node_type, 
                        tie_type=tie_type,
                        remove_isolated=remove_isolated
                    )
                
                # Display network statistics
                st.subheader("Network Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Number of Nodes", len(G.nodes()))
                with col2:
                    st.metric("Number of Connections", len(G.edges()))
                with col3:
                    density = nx.density(G)
                    st.metric("Network Density", f"{density:.4f}")
                
                # Centrality analysis
                st.subheader("Centrality Analysis")
                
                centrality_measure = st.selectbox(
                    "Select centrality measure",
                    ["degree", "betweenness", "closeness", "eigenvector", "bonacich"],
                    format_func=lambda x: {
                        'degree': 'Degree Centrality (number of direct connections)',
                        'betweenness': 'Betweenness Centrality (bridge connections)',
                        'closeness': 'Closeness Centrality (efficient information spread)',
                        'eigenvector': 'Eigenvector Centrality (connection to important nodes)',
                        'bonacich': 'Bonacich Power Centrality (influence through connections)'
                    }[x]
                )
                
                centrality_description = {
                    'degree': "Measures the number of direct connections each node has. Nodes with high degree centrality are the 'connectors' or 'hubs' in the network.",
                    'betweenness': "Measures how often a node lies on the shortest path between other nodes. Nodes with high betweenness are the 'bridges' in a network.",
                    'closeness': "Measures how close a node is to all other nodes in the network. Nodes with high closeness can efficiently spread information to all other nodes.",
                    'eigenvector': "Measures a node's influence based on the centrality of its neighbors. Nodes connected to many highly central nodes will have higher eigenvector centrality.",
                    'bonacich': "Considers both the number of connections and the centrality of those connections. It's useful for understanding power and influence in a network."
                }
                
                st.info(centrality_description[centrality_measure])
                
                # If user selects Bonacich, let them adjust alpha
                # Provide a reasonable range (e.g., 0.01 to 0.25) and default of 0.1
                alpha = 0.1
                if centrality_measure == 'bonacich':
                    alpha = st.slider(
                        "Bonacich alpha parameter",
                        min_value=0.01, max_value=0.25, value=0.1, step=0.01,
                        help="Adjusts the relative importance of neighbors in the Bonacich (Katz) centrality calculation."
                    )
                
                with st.spinner(f"Calculating {centrality_measure} centrality..."):
                    centrality = calculate_centrality(G, centrality_measure, alpha=alpha)
                
                # Display top central nodes
                st.subheader(f"Top 25 Most Central Nodes ({centrality_measure.capitalize()})")
                
                # Create a mapping from node ID to label for display
                id_to_label = {}
                for node in G.nodes():
                    if node_type == 'address':
                        id_to_label[node] = email_to_name.get(node, "")
                    else:  # node_type == 'name'
                        id_to_label[node] = name_to_email.get(node, "")
                
                centrality_df = pd.DataFrame({
                    'Node ID': list(centrality.keys()),
                    'Label': [id_to_label.get(n, "") for n in centrality.keys()],
                    f'{centrality_measure.capitalize()} Centrality': list(centrality.values())
                })
                
                # Sort by centrality value
                centrality_df = centrality_df.sort_values(
                    f'{centrality_measure.capitalize()} Centrality',
                    ascending=False
                )
                
                # Show top 25
                st.dataframe(centrality_df.head(25).reset_index(drop=True))
                
                # Visualize network
                st.subheader("Network Visualization")
                top_n = st.slider("Number of top central nodes to highlight", 1, 50, 25)
                
                with st.spinner("Generating network visualization..."):
                    fig = visualize_network_plotly(G, id_to_label, centrality, highlight_top=top_n)
                    st.plotly_chart(fig, use_container_width=True)
                
                # Add export options for network data
                st.subheader("Export Network Data")
                
                # Export node data
                node_data = pd.DataFrame({
                    'Node ID': list(G.nodes()),
                    'Label': [id_to_label.get(id, "") for id in G.nodes()],
                    f'{centrality_measure.capitalize()} Centrality': [
                        centrality.get(id, 0) for id in G.nodes()
                    ]
                })
                
                def get_csv_download_link(df, filename, link_text):
                    csv = df.to_csv(index=False).encode('utf-8')
                    b64 = base64.b64encode(csv).decode()
                    href = f'<a href="data:file/csv;base64,{b64}" download="{filename}">{link_text}</a>'
                    return href
                
                st.markdown(
                    get_csv_download_link(node_data, "network_nodes.csv", "Download Node Data (CSV)"),
                    unsafe_allow_html=True
                )
                
                # Export edge data
                edge_data = pd.DataFrame([
                    {
                        'Source': u,
                        'Source Label': id_to_label.get(u, ""),
                        'Target': v,
                        'Target Label': id_to_label.get(v, ""),
                        'Weight': data['weight'],
                        'High Importance': data.get('high_importance', False)
                    }
                    for u, v, data in G.edges(data=True)
                ])
                
                st.markdown(
                    get_csv_download_link(edge_data, "network_edges.csv", "Download Edge Data (CSV)"),
                    unsafe_allow_html=True
                )
                
                # Export the visualization as HTML
                buffer = BytesIO()
                fig.write_html(buffer)
                html_bytes = buffer.getvalue()  # Already bytes
                b64 = base64.b64encode(html_bytes).decode()
                href = f'<a href="data:text/html;base64,{b64}" download="network_visualization.html">Download Interactive Visualization (HTML)</a>'
                st.markdown(href, unsafe_allow_html=True)
            
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
                st.info("Please make sure your Excel file contains the required columns. The application expects columns like 'From: (Address)', 'To: (Address)', etc.")

if __name__ == "__main__":
    main()
