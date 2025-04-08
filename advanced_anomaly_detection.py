import sys
import os
import random
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

def calculate_baselines(df, time_col='startDateTime'):
    print("\n📊 Step 1: Calculating global baselines...")

    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])

    # ✅ Packet size
    total_bytes = df['totalSourceBytes'] + df['totalDestinationBytes']
    total_packets = df['totalSourcePackets'] + df['totalDestinationPackets']
    valid_flows = total_packets > 0
    packet_sizes = total_bytes[valid_flows] / total_packets[valid_flows]
    packet_size_mean = packet_sizes.mean()
    packet_size_std = packet_sizes.std()

    # ✅ Flow counts (hourly and daily)
    df['hour_window'] = df[time_col].dt.floor('1h')
    df['day_window'] = df[time_col].dt.floor('1d')

    hourly_flows = df.groupby('hour_window').size()
    daily_flows = df.groupby('day_window').size()

    flow_count_hourly_mean = hourly_flows.mean()
    flow_count_hourly_std = hourly_flows.std()

    flow_count_daily_mean = daily_flows.mean()
    flow_count_daily_std = daily_flows.std()

    # ✅ Protocol distribution
    protocol_distribution = df['protocolName'].value_counts(normalize=True)

    print(f"\n✅ Baselines computed:")
    print(f" - Packet Size Mean: {packet_size_mean:.2f}, Std Dev: {packet_size_std:.2f}")
    print(f" - Hourly Flow Count Mean: {flow_count_hourly_mean:.2f}, Std Dev: {flow_count_hourly_std:.2f}")
    print(f" - Daily Flow Count Mean: {flow_count_daily_mean:.2f}, Std Dev: {flow_count_daily_std:.2f}")
    print(f" - Protocol Distribution:\n{protocol_distribution}\n")

    baselines = {
        'packet_size_mean': packet_size_mean,
        'packet_size_std': packet_size_std,
        'hourly_flow_mean': flow_count_hourly_mean,
        'hourly_flow_std': flow_count_hourly_std,
        'daily_flow_mean': flow_count_daily_mean,
        'daily_flow_std': flow_count_daily_std,
        'protocol_distribution': protocol_distribution,
    }

    return baselines, df  # return df as well since we added time windows

def analyze_time_windows(df, baselines, window='hourly', z_thresh=2):
    print(f"\n🔍 Step 2: Analyzing {window} time windows for anomalies...")

    if window == 'hourly':
        time_window_col = 'hour_window'
        flow_mean = baselines['hourly_flow_mean']
        flow_std = baselines['hourly_flow_std']
        window_label = 'Hour'
    elif window == 'daily':
        time_window_col = 'day_window'
        flow_mean = baselines['daily_flow_mean']
        flow_std = baselines['daily_flow_std']
        window_label = 'Day'
    else:
        raise ValueError("Invalid window type. Use 'hourly' or 'daily'.")

    packet_mean = baselines['packet_size_mean']
    packet_std = baselines['packet_size_std']
    protocol_distribution = baselines['protocol_distribution']

    anomalies = []

    # Prepare data for visualization
    flow_counts = df.groupby(time_window_col).size()
    packet_sizes_over_time = {}
    time_windows = []

    for window_time, group in df.groupby(time_window_col):
        if group.empty:
            continue

        time_windows.append(window_time)

        # --- Packet Size ---
        total_bytes = group['totalSourceBytes'] + group['totalDestinationBytes']
        total_packets = group['totalSourcePackets'] + group['totalDestinationPackets']
        valid_flows = total_packets > 0
        packet_sizes = (total_bytes[valid_flows] / total_packets[valid_flows]) if valid_flows.sum() > 0 else pd.Series([0])
        packet_size_mean_window = packet_sizes.mean()
        packet_sizes_over_time[window_time] = packet_size_mean_window

        packet_anomaly = (
            packet_size_mean_window > (packet_mean + z_thresh * packet_std)
            or packet_size_mean_window < (packet_mean - z_thresh * packet_std)
        )

        # --- Flow Count ---
        flow_count = len(group)
        flow_anomaly = flow_count > (flow_mean + z_thresh * flow_std)

        # --- Protocol Distribution ---
        window_protocol_counts = group['protocolName'].value_counts(normalize=True)
        protocol_anomaly = False
        for protocol, global_prop in protocol_distribution.items():
            window_prop = window_protocol_counts.get(protocol, 0)
            deviation = abs(window_prop - global_prop)
            if deviation > global_prop:
                protocol_anomaly = True
                break

        # --- Record anomalies ---
        if packet_anomaly or flow_anomaly or protocol_anomaly:
            anomalies.append({
                'time_window': window_time,
                'packet_size_mean': packet_size_mean_window,
                'flow_count': flow_count,
                'packet_anomaly': packet_anomaly,
                'flow_anomaly': flow_anomaly,
                'protocol_anomaly': protocol_anomaly,
            })

    print(f"\n✅ Anomalous {window} windows detected: {len(anomalies)}")

    # --- Visualization ---

    # Convert packet size dict to Series for plotting
    packet_sizes_series = pd.Series(packet_sizes_over_time)

    # Flow count plot
    plt.figure(figsize=(12, 4))
    flow_counts.plot(label='Flow Count', color='blue')
    anomaly_times = [entry['time_window'] for entry in anomalies if entry['flow_anomaly']]
    print(f"{window_label}ly Flow Anomalies: {len(anomaly_times)}\n")
    if anomaly_times:
        plt.scatter(anomaly_times, flow_counts[anomaly_times], color='red', label='Anomaly')
    plt.title(f'{window_label}ly Flow Count with Anomalies')
    plt.xlabel(f'{window_label} Window')
    plt.ylabel('Flow Count')
    plt.legend()
    plt.tight_layout()
    plt.show()

    # Packet size plot
    plt.figure(figsize=(12, 4))
    packet_sizes_series.plot(label='Avg Packet Size', color='green')
    anomaly_times_packet = [entry['time_window'] for entry in anomalies if entry['packet_anomaly']]
    print(f"{window_label}ly Packet Anomalies: {len(anomaly_times_packet)}\n")
    if anomaly_times_packet:
        plt.scatter(anomaly_times_packet, packet_sizes_series[anomaly_times_packet], color='red', label='Anomaly')
    plt.title(f'{window_label}ly Avg Packet Size with Anomalies')
    plt.xlabel(f'{window_label} Window')
    plt.ylabel('Avg Packet Size (bytes)')
    plt.legend()
    plt.tight_layout()
    plt.show()

    # Protocol distribution over time (stacked area chart for top protocols)
    protocol_over_time = df.groupby([time_window_col, 'protocolName']).size().unstack(fill_value=0)
    protocol_over_time_percent = protocol_over_time.div(protocol_over_time.sum(axis=1), axis=0)

    protocol_over_time_percent.plot.area(figsize=(12, 4), cmap='tab20')
    plt.title(f'{window_label}ly Protocol Distribution Over Time')
    plt.xlabel(f'{window_label} Window')
    plt.ylabel('Proportion')
    plt.legend(title='Protocol')
    plt.tight_layout()
    plt.show()

    return anomalies

def flag_outlier_ips(df, anomalies, time_col='startDateTime', window='hourly', z_thresh=2):
    print(f"\n🕵️ Step 3: Flagging Outlier IPs for {window} windows...")

    if window == 'hourly':
        time_window_col = 'hour_window'
    elif window == 'daily':
        time_window_col = 'day_window'
    else:
        raise ValueError("Invalid window type. Use 'hourly' or 'daily'.")

    # Prepare list of anomaly windows
    anomaly_windows = [entry['time_window'] for entry in anomalies]

    # Filter DataFrame to only anomaly windows
    df_anomalies = df[df[time_window_col].isin(anomaly_windows)]

    flagged_ips = {}

    for window_time, group in df_anomalies.groupby(time_window_col):
        # Analyze source IPs
        source_traffic = group.groupby('source').agg({
            'totalSourcePackets': 'sum',
            'source': 'count'  # number of flows
        }).rename(columns={'source': 'flow_count'})

        if source_traffic.empty:
            continue

        # Calculate statistics
        packet_mean = source_traffic['totalSourcePackets'].mean()
        packet_std = source_traffic['totalSourcePackets'].std()
        flow_mean = source_traffic['flow_count'].mean()
        flow_std = source_traffic['flow_count'].std()

        # Handle zero std deviation to avoid division by zero
        if pd.isna(packet_std) or packet_std == 0:
            packet_std = 1
        if pd.isna(flow_std) or flow_std == 0:
            flow_std = 1

        # Identify outlier IPs (using Z-score threshold)
        packet_outliers = source_traffic[source_traffic['totalSourcePackets'] > (packet_mean + z_thresh * packet_std)]
        flow_outliers = source_traffic[source_traffic['flow_count'] > (flow_mean + z_thresh * flow_std)]

        # Combine all outliers
        outlier_ips = set(packet_outliers.index).union(flow_outliers.index)

        if outlier_ips:
            flagged_ips[window_time] = list(outlier_ips)

    print(f"\n✅ Outlier IPs detected in {len(flagged_ips)} {window} windows.")

    return flagged_ips

def summarize_top_outlier_ips(outliers_hourly, outliers_daily, top_n=10):
    print("\n📊 Summary of Top Outlier IPs:")

    # Flatten and count occurrences
    hourly_ips_flat = [ip for ips in outliers_hourly.values() for ip in ips]
    daily_ips_flat = [ip for ips in outliers_daily.values() for ip in ips]

    hourly_counts = Counter(hourly_ips_flat)
    daily_counts = Counter(daily_ips_flat)

    # Get top N from hourly and daily
    top_hourly = hourly_counts.most_common(top_n)
    top_daily = daily_counts.most_common(top_n)

    # Intersection of both sets
    hourly_set = set(hourly_counts.keys())
    daily_set = set(daily_counts.keys())
    intersection_ips = hourly_set.intersection(daily_set)

    # Count occurrences only for intersection IPs
    intersection_counts = Counter()
    for ip in intersection_ips:
        total_count = hourly_counts.get(ip, 0) + daily_counts.get(ip, 0)
        intersection_counts[ip] = total_count

    top_intersection = intersection_counts.most_common(top_n)

    # Display results
    print(f"\n🔹 Top {top_n} IPs in short-term (hourly) anomalies:")
    for ip, count in top_hourly:
        print(f" - {ip}: {count} appearances")

    print(f"\n🔸 Top {top_n} IPs in long-term (daily) anomalies:")
    for ip, count in top_daily:
        print(f" - {ip}: {count} appearances")

    print(f"\n🟢 Top {top_n} IPs in BOTH short-term and long-term anomalies:")
    for ip, count in top_intersection:
        print(f" - {ip}: {count} appearances")

    # Optional: visualize
    def plot_top_ips(counter, title):
        if not counter:
            return
        pd.Series(dict(counter)).sort_values(ascending=False).head(top_n).plot(kind='bar', figsize=(8, 4))
        plt.title(title)
        plt.xlabel('IP Address')
        plt.ylabel('Number of Appearances')
        plt.tight_layout()
        plt.show()

    plot_top_ips(hourly_counts, f'Top {top_n} IPs in Short-Term (Hourly) Anomalies')
    plot_top_ips(daily_counts, f'Top {top_n} IPs in Long-Term (Daily) Anomalies')
    plot_top_ips(intersection_counts, f'Top {top_n} IPs in BOTH Hourly and Daily Anomalies')

    return {
        'top_hourly': top_hourly,
        'top_daily': top_daily,
        'top_intersection': top_intersection
    }
    
def detect_behavior_change(df, time_col='startDateTime', window='1h', z_thresh=2, min_total_flows=5, top_n_visualize=10):
    print(f"\n🔍 Detecting IPs with Sudden Behavior Change (window: {window})...")

    # Prepare time window
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])
    df['time_window'] = df[time_col].dt.floor(window)

    # Group by time window and source IP, count flows
    activity = df.groupby(['time_window', 'source']).size().unstack(fill_value=0)

    # Filter IPs with total activity below threshold
    total_flows_per_ip = activity.sum()
    active_ips = total_flows_per_ip[total_flows_per_ip >= min_total_flows].index.tolist()
    activity = activity[active_ips]

    print(f"Total unique source IPs after flow threshold filter (≥ {min_total_flows} flows): {len(active_ips)}")

    # Calculate per-IP change across time windows (difference between consecutive windows)
    activity_diff = activity.diff().fillna(0)

    # Detect sudden spikes: where diff > z_thresh * std deviation
    spikes = {}

    for ip in activity_diff.columns:
        ip_diffs = activity_diff[ip]
        std_dev = ip_diffs.std()

        if std_dev == 0:
            continue  # Skip IPs with no variance

        threshold = z_thresh * std_dev
        spike_times = ip_diffs[ip_diffs > threshold].index.tolist()

        if spike_times:
            spikes[ip] = spike_times

    print(f"\n✅ IPs with sudden behavior change detected: {len(spikes)}")

    if not spikes:
        print("No IPs found with significant behavior change.")
        return spikes

    # --- Identify Top N most spiking IPs ---
    spike_counts = Counter({ip: len(times) for ip, times in spikes.items()})
    top_ips = [ip for ip, _ in spike_counts.most_common(top_n_visualize)]

    print(f"\n📊 Top {top_n_visualize} IPs with most spikes:")
    for ip in top_ips:
        print(f" - {ip}: {spike_counts[ip]} spikes")

    # --- Visualization: plot Top N IPs in single graph ---
    plt.figure(figsize=(12, 5))
    for ip in top_ips:
        plt.plot(activity.index, activity[ip], label=ip)

    plt.title(f"Activity Over Time for Top {top_n_visualize} Outlier IPs")
    plt.xlabel("Time Window")
    plt.ylabel("Flow Count")
    plt.legend(title="Source IP", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.show()

    return spikes 

def detect_common_target_spikes(
    df,
    time_col='startDateTime',
    window='1h',
    absolute_min_sources=5,
    relative_increase_threshold=2,
    min_total_sources=5,
    top_n_visualize=5
):
    print(f"\n🔍 Detecting Destinations with Sudden Surge of Unique Sources (window: {window})...")

    # Prepare time window
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df = df.dropna(subset=[time_col])
    df['time_window'] = df[time_col].dt.floor(window)

    # Group by time window and destination IP, count unique sources
    unique_sources_per_dest = df.groupby(['time_window', 'destination'])['source'].nunique().unstack(fill_value=0)

    # Filter destinations with total unique sources below threshold
    total_unique_sources = unique_sources_per_dest.sum()
    active_dests = total_unique_sources[total_unique_sources >= min_total_sources].index.tolist()
    unique_sources_per_dest = unique_sources_per_dest[active_dests]

    print(f"Total unique destination IPs after source count filter (≥ {min_total_sources} total sources): {len(active_dests)}")

    spikes = {}

    for dest_ip in unique_sources_per_dest.columns:
        source_counts = unique_sources_per_dest[dest_ip]

        # Skip destinations with no meaningful activity
        if source_counts.sum() < min_total_sources:
            continue

        mean_sources = source_counts.mean()
        if mean_sources == 0:
            continue  # Avoid division by zero

        # Detect spike windows: absolute + relative threshold
        spike_times = source_counts[
            (source_counts >= absolute_min_sources) &
            ((source_counts / mean_sources) >= relative_increase_threshold)
        ].index.tolist()

        if spike_times:
            spikes[dest_ip] = spike_times

    print(f"\n✅ Destination IPs with sudden spike in unique sources detected: {len(spikes)}")

    if not spikes:
        print("No destination IPs found with significant source surge.")
        return spikes

    # --- Identify Top N most spiking destination IPs ---
    spike_counts = Counter({ip: len(times) for ip, times in spikes.items()})
    top_dest_ips = [ip for ip, _ in spike_counts.most_common(top_n_visualize)]

    print(f"\n📊 Top {top_n_visualize} Destination IPs with most spikes in unique sources:")
    for ip in top_dest_ips:
        print(f" - {ip}: {spike_counts[ip]} spikes")

    # --- Visualization: plot Top N destination IPs in single graph ---
    plt.figure(figsize=(12, 5))
    for ip in top_dest_ips:
        plt.plot(unique_sources_per_dest.index, unique_sources_per_dest[ip], label=ip)

    plt.title(f"Unique Source Count Over Time for Top {top_n_visualize} Destination IPs")
    plt.xlabel("Time Window")
    plt.ylabel("Unique Source Count")
    plt.legend(title="Destination IP", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.show()

    return spikes

def detect_suspicious_communication_patterns(
    df,
    time_col='startDateTime',
    window='1h',
    duration_threshold='2h',
    multi_protocol_threshold=2,
    top_n_visualize=10
):
    print(f"\n🚨 Detecting Suspicious Communication Patterns (window: {window})...")

    # Prepare timestamps
    df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
    df['stopDateTime'] = pd.to_datetime(df['stopDateTime'], errors='coerce')
    df = df.dropna(subset=[time_col, 'stopDateTime'])

    # Convert duration threshold to pandas Timedelta and seconds
    duration_threshold_timedelta = pd.to_timedelta(duration_threshold)
    duration_threshold_seconds = duration_threshold_timedelta.total_seconds()

    # --- Part 1: Long-Duration Connections ---
    print(f"\n🔍 Part 1: Identifying long-duration connections (> {duration_threshold})...")

    df['duration'] = df['stopDateTime'] - df[time_col]
    df['duration_seconds'] = df['duration'].dt.total_seconds()

    # Group by connection (source, destination, protocol)
    connection_durations = df.groupby(['source', 'destination', 'protocolName'])['duration_seconds'].max()

    # Flag long-duration connections
    long_connections = connection_durations[connection_durations > duration_threshold_seconds]

    # Print total count of long connections
    print(f"✅ Total long-duration connections detected: {len(long_connections)}")

    # Take top N longest connections for printing and visualization
    top_long_connections = long_connections.sort_values(ascending=False).head(top_n_visualize)

    print(f"\nTop {top_n_visualize} Long-duration connections (in minutes):")
    for (src, dst, proto), duration_sec in top_long_connections.items():
        duration_minutes = duration_sec / 60
        print(f" - {src} -> {dst} [{proto}] Duration: {duration_minutes:.2f} minutes")

    # --- Visualization: Connection durations (Top N only) ---
    if not top_long_connections.empty:
        top_long_connections_minutes = top_long_connections / 60  # Convert seconds to minutes

        plt.figure(figsize=(10, 4))
        top_long_connections_minutes.sort_values().plot(kind='barh')

        plt.axvline(duration_threshold_seconds / 60, color='red', linestyle='--', label='Threshold')

        plt.title(f"Top {top_n_visualize} Long-Duration Connections")
        plt.xlabel("Duration (minutes)")
        plt.ylabel("Connection (Source → Destination → Protocol)")
        plt.legend()
        plt.tight_layout()
        plt.show()

    # --- Part 2: Multi-Protocol Communication ---
    print(f"\n🔍 Part 2: Identifying IPs using multiple protocols in short time (> {multi_protocol_threshold} protocols)...")

    df['time_window'] = df[time_col].dt.floor(window)

    # Count distinct protocols per source IP per time window
    protocol_counts = df.groupby(['time_window', 'source'])['protocolName'].nunique().unstack(fill_value=0)

    # Filter IPs with multiple protocols in any window
    multi_protocol_ips = (protocol_counts > multi_protocol_threshold).sum(axis=0)
    suspicious_ips = multi_protocol_ips[multi_protocol_ips > 0]

    print(f"✅ IPs communicating over > {multi_protocol_threshold} protocols in short time detected: {len(suspicious_ips)}")
    for ip, count in suspicious_ips.items():
        print(f" - {ip}: {count} windows with multi-protocol communication")

    # --- Visualization: Top N multi-protocol IPs over time ---
    if not suspicious_ips.empty:
        top_ips = suspicious_ips.sort_values(ascending=False).head(top_n_visualize).index.tolist()

        plt.figure(figsize=(12, 5))
        for ip in top_ips:
            plt.plot(protocol_counts.index, protocol_counts[ip], label=ip)

        plt.axhline(y=multi_protocol_threshold, color='red', linestyle='--', label='Threshold')

        plt.title(f"Protocol Count Over Time for Top {top_n_visualize} Multi-Protocol IPs")
        plt.xlabel("Time Window")
        plt.ylabel("Distinct Protocol Count")
        plt.legend(title="Source IP", bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.show()

    return {
        "long_duration_connections": long_connections,  # ✅ Full data
        "multi_protocol_ips": suspicious_ips  # ✅ Full data
    }

def stastical_traffic_analysis(df):
    baselines, df = calculate_baselines(df)
    
    anomalies_hourly = analyze_time_windows(df, baselines, window='hourly')
    anomalies_daily = analyze_time_windows(df, baselines, window='daily')
    
    outliers_hourly = flag_outlier_ips(df, anomalies_hourly, window='hourly')
    outliers_daily = flag_outlier_ips(df, anomalies_daily, window='daily')
    
    summary_results = summarize_top_outlier_ips(outliers_hourly, outliers_daily, top_n=10)
    
    return

def behavioural_analysis(df):
    detect_behavior_change(df)
    
    detect_common_target_spikes(df)
    
    detect_suspicious_communication_patterns(df)
    
    return

def advanced_anomaly_detection(csv_path):
    if not os.path.isfile(csv_path):
        print(f"File not found: {csv_path}")
        return

    df = pd.read_csv(csv_path, low_memory=False)

    df.columns = df.columns.str.strip()
    
    # TASK 3A
    stastical_traffic_analysis(df)

    # TASK 3B & 3C
    behavioural_analysis(df)

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_traffic.py <path_to_csv_file>")
        return

    csv_file = sys.argv[1]
    
    advanced_anomaly_detection(csv_file)


if __name__ == "__main__":
    main()