# Network-Traffic-Analysis

This project framework can be used to carry out comprehensive network traffic analysis and threat detection.
Using real network capture data, it performs:
- Descriptive traffic statistics
- Sublinear-space traffic estimation
- Advanced anomaly detection
- Deep security threat analysis

The toolkit is designed to help analysts and security engineers **quickly process large-scale traffic datasets**, detect hidden patterns, and uncover stealthy attacks.

## Prerequisities

Before running any of the scripts in this framework, ensure you have the necessary dependencies installed. Install then using the following command:

```bash
pip install -r requirements.txt
```

## Overview of Tools

1. ```network_traffic_statistics.py```: <br>Analyzes raw traffic to extract the following information:
    - Top protocols, source/destination IPs
    - Average packet size and variance
    - Consistently communicating IPs
    - Traffic spikes over time

    Useful for initial traffic profiling.

2. ```traffic_estimation_using_sublinear_space.py```: <br>Uses compact data structures to estimate metrics at scale:
    - Unique IP estimation via HyperLogLog
    - Frequent destination IPs using Count-Min Sketch
    - Membership testing with Bloom Filters

    Efficient when dealing with memory/storage constraints.

3. ```advanced_anomaly_detection.py```: <br>Detects behavioral anomalies in traffic patterns by:
    - Establishing baselines and finding hourly/daily outliers
    - Monitoring IPs with sudden behavioral spikes
    - Detecting coordinated attacks via set overlap and entropy metrics

    Enables detection of stealthy or distributed attacks.

4. ```deep_security_threat_analysis.py```: <br>Performs payload-level analysis to detect malicious activity:
    - Finds suspicious token injection or rare command strings
    - Flags encrypted traffic with anomalous entropy/length
    - Detects C2 (Command & Control) behaviors via multiple scoring rules
    - Performs risk categorization of all flows

    Backed by strong heuristics and multiple-layer scoring.

## Usage

Run the scripts using the following command format, specifying the tool-type by the respective python filename and path to traffic-capture file stored in csv format:

```bash
python <tool_name>.py <path_to_traffic_csv_file>
```

### Example

```bash
python advanced_anomaly_detection.py ./data/demo_traffic_capture.csv
```

## Output

Depending upon the tool used, the script outputs a detailed analysis on the console. It also helps visualize the metrics using graphs where required. Each tool is self-contained for modular use.
