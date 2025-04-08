import pandas as pd
import matplotlib.pyplot as plt
import sys
import os

# Function to identify IPs that consistently communicate across time windows
def get_consistently_communicating_ips(df, time_col='startDateTime', window='1h', threshold=0.98):
    # Convert timestamps to datetime objects, drop invalid entries
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])

    # Bucket flows into time windows (default: 1 hour)
    df['time_window'] = df[time_col].dt.floor(window)

    # For each time window, collect unique IPs that acted as source or destination
    window_ip_sets = df.groupby('time_window', group_keys=False)[['source', 'destination']].apply(
        lambda g: set(g['source']).union(set(g['destination']))
    )

    # Count the number of windows each IP appeared in
    ip_window_count = {}
    for window_ips in window_ip_sets:
        for ip in window_ips:
            ip_window_count[ip] = ip_window_count.get(ip, 0) + 1

    # Filter IPs that appear in a high percentage of windows (based on threshold)
    total_windows = len(window_ip_sets)
    consistent_ips = [ip for ip, count in ip_window_count.items()
                      if count / total_windows >= threshold]

    # Print results
    print(f"\nTotal time windows: {total_windows}")
    print(f"IPs appearing in ≥ {threshold*100:.0f}% of windows:")
    for ip in consistent_ips:
        print(f" - {ip} (seen in {ip_window_count[ip]} windows)")

    return consistent_ips


# Function to detect sudden spikes in network traffic volume
def detect_traffic_spikes(df, time_col='startDateTime', window='1h', z_thresh=2.0):
    # Convert timestamps to datetime objects, drop invalid entries
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])

    # Bucket flows into time windows
    df['time_window'] = df[time_col].dt.floor(window)

    # Count the number of flows per time window
    flow_counts = df.groupby('time_window').size()

    # Compute the spike threshold using z-score method
    mean = flow_counts.mean()
    std = flow_counts.std()
    spike_threshold = mean + z_thresh * std

    print(f"\nAverage Network Flows Per Window: {mean:.2f} flows")
    print(f"\nTraffic spike threshold: {spike_threshold:.2f} flows")

    # Identify time windows where flow count exceeds the threshold
    spikes = flow_counts[flow_counts > spike_threshold]
    print(f"\nDetected {len(spikes)} spike(s):")
    print(spikes)

    # Plot traffic volume over time with spike threshold line
    flow_counts.plot(title="Traffic Volume Over Time", figsize=(10, 4))
    plt.axhline(y=spike_threshold, color='r', linestyle='--', label='Spike Threshold')
    plt.xlabel("Time Window")
    plt.ylabel("Flow Count")
    plt.legend()
    plt.tight_layout()
    plt.show()

    return spikes


# Main analysis function for a given network traffic CSV file
def analyze_network_file(csv_path):
    if not os.path.isfile(csv_path):
        print(f"File not found: {csv_path}")
        return

    # Load the CSV data
    df = pd.read_csv(csv_path)
    print(f"\nAnalyzing file: {csv_path}")

    # Summary statistics
    total_flows = len(df)
    print(f"Total network flows: {total_flows}")

    # Top 5 protocols used in the traffic
    top_protocols = df['protocolName'].value_counts().head(5)
    print("\nTop 5 Protocols:\n", top_protocols)

    # Top 10 most active source IP addresses
    top_sources = df['source'].value_counts().head(10)
    print("\nTop 10 Source IPs:\n", top_sources)

    # Top 10 most active destination IP addresses
    top_destinations = df['destination'].value_counts().head(10)
    print("\nTop 10 Destination IPs:\n", top_destinations)

    # Calculate average packet size (bytes per packet) for valid flows
    total_bytes = df['totalSourceBytes'] + df['totalDestinationBytes']
    total_packets = df['totalSourcePackets'] + df['totalDestinationPackets']
    valid_flows = total_packets > 0
    avg_packet_sizes_per_flow = total_bytes[valid_flows] / total_packets[valid_flows]
    avg_packet_size = avg_packet_sizes_per_flow.mean()
    print(f"\nAverage Packet Size (bytes per packet): {avg_packet_size:.2f}")

    # Calculate variance in packet sizes
    variance = avg_packet_sizes_per_flow.var()
    print(f"\nPacket Size Variance: {variance:.2f}")

    # Identify the most common source-destination pair
    df['pair'] = df['source'] + " -> " + df['destination']
    common_pair = df['pair'].value_counts().idxmax()
    print(f"\nMost common source-destination pair: {common_pair}")

    # Identify consistently communicating IP addresses
    get_consistently_communicating_ips(df)

    # Detect unusual spikes in network traffic volume
    detect_traffic_spikes(df)

    # Optional: plot top protocols (currently commented out)
    # top_protocols.plot(kind='bar', title='Top 5 Protocols Used')
    # plt.xlabel("Protocol")
    # plt.ylabel("Frequency")
    # plt.tight_layout()
    # plt.show()


# Entry point for the script
def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_traffic.py <path_to_csv_file>")
        return

    csv_file = sys.argv[1]
    analyze_network_file(csv_file)


# Execute main function if script is run directly
if __name__ == "__main__":
    main()
