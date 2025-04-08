import sys
import os
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import re
import math
import numpy as np

# Detect stealthy port scanning behavior based on unique port access patterns
def detect_stealthy_port_scans(df, time_col='startDateTime', window='1h', port_threshold=10, min_total_ports=1000, top_n_visualize=10):
    print(f"\n🚨 Detecting Stealthy Port Scans (window: {window})...")

    # Prepare time window
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])
    df['time_window'] = df[time_col].dt.floor(window)

    # Group by source IP and time window, count unique destination ports
    port_counts = df.groupby(['time_window', 'source'])['destinationPort'].nunique().unstack(fill_value=0)

    print(f"Total unique source IPs analyzed: {len(port_counts.columns)}")

    # Filter IPs with total distinct ports > min_total_ports
    total_ports_per_ip = port_counts.sum()
    active_ips = total_ports_per_ip[total_ports_per_ip >= min_total_ports].index.tolist()
    port_counts = port_counts[active_ips]

    print(f"Source IPs after filtering (≥ {min_total_ports} unique ports total): {len(active_ips)}")

    # Detect IPs with high unique ports in any time window
    potential_scanners = (port_counts > port_threshold).sum(axis=0)
    scanners = potential_scanners[potential_scanners > 0]

    print(f"✅ Stealthy port scanners detected: {len(scanners)}")

    for ip, count in scanners.items():
        print(f" - {ip}: {count} windows with > {port_threshold} unique ports scanned")

    # --- Visualization: suspicious scanners ---
    if not scanners.empty:
        top_ips = scanners.sort_values(ascending=False).index.tolist()

        plt.figure(figsize=(12, 5))
        for ip in top_ips:
            plt.plot(port_counts.index, port_counts[ip], label=ip)

        plt.axhline(port_threshold, color='red', linestyle='--', label='Port Threshold')
        plt.title(f"Unique Destination Ports Over Time for Suspicious IPs")
        plt.xlabel("Time Window")
        plt.ylabel("Unique Destination Port Count")
        plt.legend(title="Source IP", bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.show()

    return scanners

# Detect slow DDoS attacks by analyzing flow counts and unique source spikes
def detect_slow_ddos(df, time_col='startDateTime', window='1h', z_thresh=2, top_n_visualize=10, min_score=60, weight_flow=1.0, weight_source=2.0):
    print(f"\n🚨 Detecting Slow DDoS Attacks (window: {window})...")

    # Prepare timestamps and time window
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])
    df['time_window'] = df[time_col].dt.floor(window)

    # Group by time window and destination IP
    flow_counts = df.groupby(['time_window', 'destination']).size().unstack(fill_value=0)
    unique_source_counts = df.groupby(['time_window', 'destination'])['source'].nunique().unstack(fill_value=0)

    # Calculate mean and std dev for flow counts
    flow_mean = flow_counts.mean()
    flow_std = flow_counts.std()

    # Calculate mean and std dev for unique sources
    source_mean = unique_source_counts.mean()
    source_std = unique_source_counts.std()

    # Detect spikes
    flow_spikes = (flow_counts > (flow_mean + z_thresh * flow_std)).sum(axis=0)
    source_spikes = (unique_source_counts > (source_mean + z_thresh * source_std)).sum(axis=0)

    # Combine suspicious scores
    combined_score = (weight_flow * flow_spikes) + (weight_source * source_spikes)

    # Filter by minimum score
    suspicious_destinations = combined_score[combined_score >= min_score].sort_values(ascending=False)

    print(f"\n✅ Potential slow DDoS targets (score ≥ {min_score}): {len(suspicious_destinations)}\n")

    for dst_ip, score in suspicious_destinations.items():
        print(f" - {dst_ip}: Suspicious Score = {score:.1f} (Flow spikes: {flow_spikes[dst_ip]}, Source spikes: {source_spikes[dst_ip]})")

    # --- Visualization: Combined Score for Top N suspicious destinations ---
    if not suspicious_destinations.empty:
        top_targets = suspicious_destinations.head(top_n_visualize)

        plt.figure(figsize=(12, 6))
        top_targets.plot(kind='bar', color='orange')

        plt.title(f"Combined Suspicious Score for Top {top_n_visualize} Potential DDoS Targets")
        plt.xlabel("Destination IP")
        plt.ylabel("Combined Suspicious Score")
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()

    return suspicious_destinations

# Detect IP hopping attacks by identifying source IP changes targeting same destination and port
def detect_ip_hopping(df, src_col='source', dst_col='destination', port_col='destinationPort', min_group_size=3, top_n_visualize=20):
    print("\n🔍 Detecting IP Hopping Behavior...")

    # Step 1: Group by dest, port, source and count occurrences
    counts = df.groupby([dst_col, port_col, src_col]).size().reset_index(name='flow_count')

    # Step 2: Group by dest:port pair and aggregate source IP counts as dict
    grouped = counts.groupby([dst_col, port_col])[[src_col, 'flow_count']].apply(
    lambda g: dict(zip(g[src_col], g['flow_count']))
    ).to_dict()

    # Step 3: Filter groups with enough unique source IPs
    filtered_groups = {group: counter for group, counter in grouped.items() if len(counter) >= min_group_size}

    if not filtered_groups:
        print("⚠️ No destination:port groups with sufficient unique source IPs found.")
        return None

    print(f"✅ Found {len(filtered_groups)} destination:port groups with potential IP hopping behavior.")

    # Step 4: Aggregate counts globally
    from collections import Counter
    global_counter = Counter()
    for counter in filtered_groups.values():
        global_counter.update(counter)

    # Step 5: Report top attackers globally
    print("\n🌐 Top source IPs globally across all destination:port groups:")
    for ip, count in global_counter.most_common(top_n_visualize):
        print(f" - {ip}: {count} flows")

    # Step 6: Global visualization
    if global_counter:
        top_ips, counts_vals = zip(*global_counter.most_common(top_n_visualize))
        plt.figure(figsize=(10, 5))
        plt.barh(top_ips, counts_vals)
        plt.title(f"Top {top_n_visualize} Source IPs Globally (Suspected IP Hopping)")
        plt.xlabel("Flow Count Across All Destination:Port Groups")
        plt.ylabel("Source IP")
        plt.tight_layout()
        plt.show()

    return global_counter

# Analyze payload contents for suspicious tokens and rare payload patterns
def detect_unusual_payload_patterns(df, payload_cols=['sourcePayloadAsUTF', 'destinationPayloadAsUTF'],
                                     suspicious_keywords=None, rare_token_threshold=2, top_n=10):
    print("\n🔍 Step 1: Analyzing Payloads for Unusual Patterns...")

    if suspicious_keywords is None:
        suspicious_keywords = [
            'sh', 'bash', 'cat', 'ls', 'sudo', 'passwd',
            'admin', 'root', 'login', 'drop', 'select', 'from', 'union', 'insert', 'delete', 'exec'
        ]

    # Step 1: Combine payloads
    payloads = df[payload_cols].fillna('').apply(lambda row: ' '.join(row), axis=1)
    payloads = payloads[payloads.str.strip() != '']  # Remove completely empty ones
    print(f"Total non-empty payloads: {len(payloads)}")

    # Step 2: Tokenize payloads
    tokenized = payloads.apply(lambda x: re.findall(r'\b[\w@./%-]+\b', x.lower()))
    flat_tokens = [token for sublist in tokenized for token in sublist]
    token_freq = Counter(flat_tokens)

    print(f"Total unique tokens: {len(token_freq)}")
    print("\n🔝 Top Common Tokens:")
    for token, count in token_freq.most_common(top_n):
        print(f" - {token}: {count} times")

    # Step 3: Find rare tokens
    rare_tokens = [token for token, count in token_freq.items() if count <= rare_token_threshold]
    print(f"\n🧪 Rare Tokens (≤ {rare_token_threshold} occurrences): {len(rare_tokens)}")

    # Step 4: Match suspicious keywords
    suspicious_payloads = payloads[tokenized.apply(lambda tokens: any(t in suspicious_keywords for t in tokens))]
    print(f"\n⚠️ Payloads with suspicious tokens: {len(suspicious_payloads)}")

    print("\n🚩 Sample Suspicious Payloads:")
    for i, payload in suspicious_payloads.head(top_n).items():
        print(f" - {payload[:100]}{'...' if len(payload) > 100 else ''}")

    # Step 5: Visualizations
    if token_freq:
        # Suspicious token match count
        susp_counts = [token_freq[t] for t in suspicious_keywords if t in token_freq]
        susp_tokens = [t for t in suspicious_keywords if t in token_freq]

        if susp_tokens:
            plt.figure(figsize=(10, 4))
            plt.barh(susp_tokens, susp_counts, color='red')
            plt.xlabel("Match Count")
            plt.title("Suspicious Token Matches in Payloads")
            plt.tight_layout()
            plt.show()

    return suspicious_payloads, token_freq, rare_tokens

# Calculate entropy of payload data for encrypted traffic detection
def calculate_entropy(data):
    if not data:
        return 0
    probability = [float(data.count(c)) / len(data) for c in set(data)]
    entropy = -sum(p * math.log2(p) for p in probability if p > 0)
    return entropy

# Detect suspicious encrypted-like traffic based on entropy and payload length analysis
def detect_suspicious_encrypted_traffic(df,
                                       payload_cols=['sourcePayloadAsBase64', 'destinationPayloadAsBase64'],
                                       entropy_z_thresh=1.25,
                                       length_z_thresh=2.5):
    print("\n🔍 Step 2: Detecting Anomalous Encrypted Traffic (Base64 Payloads)...")

    # Step 1: Extract payloads (Base64)
    payloads = df[payload_cols].fillna('').apply(lambda x: ''.join(x), axis=1)

    # Step 2: Calculate entropy and length
    entropies = payloads.apply(calculate_entropy)
    lengths = payloads.str.len()

    # Step 3: Calculate thresholds
    entropy_mean, entropy_std = entropies.mean(), entropies.std()
    entropy_threshold_high = entropy_mean + entropy_z_thresh * entropy_std

    length_mean, length_std = lengths.mean(), lengths.std()
    length_threshold_high = length_mean + length_z_thresh * length_std
    length_threshold_low = max(1, length_mean - length_z_thresh * length_std)

    print(f"\n📊 Entropy: mean={entropy_mean:.2f}, std={entropy_std:.2f}")
    print(f" - High threshold: > {entropy_threshold_high:.2f}")

    print(f"\n📊 Length: mean={length_mean:.2f}, std={length_std:.2f}")
    print(f" - High threshold: > {length_threshold_high:.2f}")
    print(f" - Low threshold: < {length_threshold_low:.2f}")

    # Step 4: Flag anomalous payloads
    is_entropy_high = entropies > entropy_threshold_high
    is_length_anomalous = (lengths > length_threshold_high) | (lengths < length_threshold_low)

    is_anomalous = is_entropy_high & is_length_anomalous
    anomalous_payloads = payloads[is_anomalous]

    print(f"\n🚩 Anomalous encrypted-like payloads detected: {len(anomalous_payloads)}")

    # Step 5: Visualization - Entropy distribution
    plt.figure(figsize=(10, 4))
    plt.hist(entropies, bins=50, color='steelblue', edgecolor='black')
    plt.axvline(entropy_threshold_high, color='red', linestyle='--', label='High Entropy Threshold')
    plt.title("Payload Entropy Distribution (Base64 Payloads)")
    plt.xlabel("Entropy")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.show()

    # Step 6: Visualization - Length distribution
    plt.figure(figsize=(10, 4))
    plt.hist(lengths, bins=50, color='orange', edgecolor='black')
    plt.axvline(length_threshold_high, color='red', linestyle='--', label='High Length Threshold')
    plt.axvline(length_threshold_low, color='green', linestyle='--', label='Low Length Threshold')
    plt.title("Payload Length Distribution (Base64 Payloads)")
    plt.xlabel("Payload Length (characters)")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    plt.show()

    # Step 7: Sample payloads
    print("\n🧪 Sample Anomalous Payloads:")
    for sample in anomalous_payloads.head(5):
        print(f" - {sample[:100]}...")

    return anomalous_payloads

# Detect command-and-control (C2) communication patterns using multiple heuristic indicators
def detect_command_control_patterns(df, suspicious_token_indices, encrypted_anomalous_indices,
                                    duration_z_thresh=2.0, bytes_z_thresh=2.0, top_n=10):
    print("\n🔍 Step 3: Detecting Command-and-Control Patterns...")

    df = df.copy()

    # Ensure proper datetime conversion
    df['startDateTime'] = pd.to_datetime(df['startDateTime'])
    df['stopDateTime'] = pd.to_datetime(df['stopDateTime'])

    # Calculate flow duration in milliseconds
    df['flowDuration'] = (df['stopDateTime'] - df['startDateTime']).dt.total_seconds() * 1000

    # Calculate total payload bytes
    df['sourcePayloadLength'] = df['sourcePayloadAsBase64'].fillna('').str.len()
    df['destinationPayloadLength'] = df['destinationPayloadAsBase64'].fillna('').str.len()
    df['totalPayloadBytes'] = df['sourcePayloadLength'] + df['destinationPayloadLength']


    # Step 2: Auto thresholds
    duration_mean, duration_std = df['flowDuration'].mean(), df['flowDuration'].std()
    duration_threshold = duration_mean + duration_z_thresh * duration_std
    print(f"Duration Mean: {duration_mean}, Duration Std: {duration_std}")

    bytes_mean, bytes_std = df['totalPayloadBytes'].mean(), df['totalPayloadBytes'].std()
    # bytes_threshold = max(0, bytes_mean - bytes_z_thresh * bytes_std)
    bytes_threshold = 100
    print(f"Bytes Mean: {bytes_mean}, Bytes Std: {bytes_std}")

    print(f"\n⏱️ Flow duration threshold: > {duration_threshold:.2f} ms")
    print(f"📦 Low total bytes threshold: < {bytes_threshold:.2f} bytes")

    # Step 3: Scoring system
    scores = pd.Series(0, index=df.index)

    # Payload token suspicious (Step 1)
    scores[df.index.isin(suspicious_token_indices)] += 1

    # Encrypted anomalies (Step 2)
    scores[df.index.isin(encrypted_anomalous_indices)] += 1

    # Asymmetric flows
    source_bytes = df['sourcePayloadLength'].fillna(0) + 1e-6
    dest_bytes = df['destinationPayloadLength'].fillna(0) + 1e-6
    asymmetry_ratio = np.maximum(source_bytes / dest_bytes, dest_bytes / source_bytes)
    asymmetric_hits = asymmetry_ratio > 10
    scores[asymmetric_hits] += 1

    # Persistent low-data flows
    persistent_hits = (df['flowDuration'] > duration_threshold) & (df['totalPayloadBytes'] < bytes_threshold)
    scores[persistent_hits] += 1

    # Step 4: Reporting
    df['C2_Score'] = scores
    suspicious_flows = df[df['C2_Score'] > 0].sort_values(by='C2_Score', ascending=False)

    print(f"\n🚩 Flows flagged with suspicious C2 patterns: {len(suspicious_flows)}")

    # Sample top flows
    print("\n🧪 Sample Top Suspicious Flows:")
    display_cols = ['source', 'destination', 'destinationPort', 'flowDuration', 'totalPayloadBytes', 'C2_Score']
    print(suspicious_flows[display_cols].head(top_n).to_string(index=False))

    # Optional: score distribution
    plt.figure(figsize=(8, 4))
    scores.value_counts().sort_index().plot(kind='bar', color='coral', edgecolor='black')
    plt.title("C2 Pattern Detection - Score Distribution")
    plt.xlabel("Suspicious Score")
    plt.ylabel("Flow Count")
    plt.tight_layout()
    plt.show()

    return suspicious_flows

# Perform threat attribution and categorize flows into risk levels
def risk_analysis(df, suspicious_payload, anomalous_payloads, c2_suspicious_flows):
    print("\n🚨 Step 4: Threat Attribution and Risk Analysis...")

    # Start by preparing risk DataFrame
    risk_df = c2_suspicious_flows.copy()
    risk_df['RiskLevel'] = 'Low'  # Default

    # Reasoning tracker
    risk_df['Reasoning'] = ''

    # Check payload injection
    is_payload_suspicious = risk_df.index.isin(suspicious_payload.index)
    risk_df.loc[is_payload_suspicious, 'RiskLevel'] = 'Medium'
    risk_df.loc[is_payload_suspicious, 'Reasoning'] += 'Payload injection detected. '

    # Check encrypted anomalies
    is_encrypted_anomalous = risk_df.index.isin(anomalous_payloads.index)
    risk_df.loc[is_encrypted_anomalous, 'RiskLevel'] = 'Medium'
    risk_df.loc[is_encrypted_anomalous, 'Reasoning'] += 'Encrypted anomaly detected. '

    # High C2 score: aggressive behavior
    high_score = risk_df['C2_Score'] >= 3
    risk_df.loc[high_score, 'RiskLevel'] = 'High'
    risk_df.loc[high_score, 'Reasoning'] = 'Multiple suspicious behaviors detected: Payload injection, Encrypted anomaly and C-2 pattern'

    # Clean up: if both Medium and High applied, keep High
    risk_df.loc[risk_df['RiskLevel'] == 'Medium', 'RiskLevel'] = risk_df.loc[risk_df['RiskLevel'] == 'Medium'].apply(
        lambda row: 'High' if row['C2_Score'] >= 3 else 'Medium', axis=1
    )

    # Summary
    print("\n🧾 Risk Summary:")
    risk_counts = risk_df['RiskLevel'].value_counts()
    for level, count in risk_counts.items():
        print(f" - {level} risk flows: {count}")

    # Sample risky flows
    print("\n🧪 Sample High Risk Flows:")
    high_risk_samples = risk_df[risk_df['RiskLevel'] == 'High'].head(5)
    if not high_risk_samples.empty:
        print(high_risk_samples[['source', 'destination', 'destinationPort', 'C2_Score', 'RiskLevel', 'Reasoning']].to_string(index=False))
    else:
        print("No high risk flows detected.")

    # Visualization
    import matplotlib.pyplot as plt
    plt.figure(figsize=(6, 4))
    risk_counts.plot(kind='bar', color=['green', 'orange', 'red'], edgecolor='black')
    plt.title("Risk Level Distribution")
    plt.xlabel("Risk Level")
    plt.ylabel("Flow Count")
    plt.tight_layout()
    plt.show()

    return risk_df

# Perform malicious payload identification pipeline (suspicious payloads, encrypted payloads, C2 patterns, risk analysis)
def malicious_payload_identification(df):
    suspicious_payload, _, _ = detect_unusual_payload_patterns(df)
    
    anomalous_payloads = detect_suspicious_encrypted_traffic(df)
    
    c2_suspicious_flows = detect_command_control_patterns(df, suspicious_payload.index, anomalous_payloads.index)
    
    risk_analysis(df, suspicious_payload, anomalous_payloads, c2_suspicious_flows)
    
    return

# Execute complex attack pattern detection (port scans, slow DDoS, IP hopping)
def detect_complex_attack_patterns(df):
    detect_stealthy_port_scans(df)
    
    detect_slow_ddos(df)

    detect_ip_hopping(df)
    
    return

# Main function to run deep security threat analysis from CSV input
def deep_security_threat_analysis(csv_path):
    if not os.path.isfile(csv_path):
        print(f"File not found: {csv_path}")
        return

    df = pd.read_csv(csv_path, low_memory=False)

    df.columns = df.columns.str.strip()
    
    # TASK 4A
    detect_complex_attack_patterns(df)
    
    # TASK 4B & 4C
    malicious_payload_identification(df)
    
    
    return

# Entry point for script execution
def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_traffic.py <path_to_csv_file>")
        return

    csv_file = sys.argv[1]
    
    deep_security_threat_analysis(csv_file)


if __name__ == "__main__":
    main()