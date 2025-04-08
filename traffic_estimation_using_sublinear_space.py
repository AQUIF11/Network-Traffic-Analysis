import sys
import os
import pandas as pd
from datasketch import HyperLogLog
from countminsketch import CountMinSketch
from bloom_filter2 import BloomFilter
import math
import time

# Function to test membership detection of destination IPs using Bloom Filter
def test_membership_bloom(df, false_positive_rate=0.05):
    dest_ips = df['destination']
    total_flows = len(dest_ips)
    unique_ips = dest_ips.nunique()

    print(f"\nTesting Bloom Filter for membership detection...")
    print(f"Total flows: {total_flows}")
    print(f"Unique destination IPs: {unique_ips}")
    print(f"Target false positive rate: {false_positive_rate:.2%}")

    # --- Ground truth set ---
    seen_exact = set()  # Exact set of seen IPs
    false_positives = 0
    true_negatives = 0

    # --- Initialize Bloom Filter ---
    bloom = BloomFilter(max_elements=unique_ips, error_rate=false_positive_rate)

    start = time.time()
    for ip in dest_ips:
        # If Bloom filter says "yes", but exact set says "no", it's a false positive
        if ip in bloom:
            if ip not in seen_exact:
                false_positives += 1
        else:
            true_negatives += 1
        # Add to both structures
        bloom.add(ip)
        seen_exact.add(ip)
    end = time.time()

    total_checks = false_positives + true_negatives
    fpr = false_positives / total_checks * 100 if total_checks > 0 else 0

    # Estimate memory usage
    bloom_bytes = bloom.num_bits_m / 8
    bloom_kb = bloom_bytes / 1024

    # Approximate size of Python set in memory
    exact_bytes = unique_ips * 100  
    exact_kb = exact_bytes / 1024

    # Print evaluation results
    print(f"\nFalse Positives: {false_positives}")
    print(f"True Negatives:  {true_negatives}")
    print(f"False Positive Rate: {fpr:.2f}%")
    print(f"Time Taken: {end - start:.4f} seconds")

    print(f"\n📦 Memory Usage:")
    print(f"  Bloom Filter (approx): {bloom_kb:.2f} KB")
    print(f"  Exact Set (approx):    {exact_kb:.2f} KB")

    return {
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_positive_rate": fpr,
        "bloom_memory_kb": bloom_kb,
        "exact_memory_kb": exact_kb
    }


# Function to estimate top-k frequent destination IPs using Count-Min Sketch
def estimate_topk_frequent_destinations(df, k=10, error=0.001, confidence=0.99):
    dest_ips = df['destination']

    print(f"\nEstimating top-{k} frequent destination IPs...\n")

    # --- Exact method for ground truth ---
    start_exact = time.time()
    exact_counts = dest_ips.value_counts()
    topk_exact = set(exact_counts.head(k).index)
    end_exact = time.time()
    exact_time = end_exact - start_exact

    print(f"[Exact] Top-{k} Destination IPs:")
    print(exact_counts.head(k))

    # --- Count-Min Sketch initialization ---
    width = math.ceil(math.e / error)
    depth = math.ceil(math.log(1 / (1 - confidence)))
    cms = CountMinSketch(width=width, depth=depth)

    start_cms = time.time()
    for ip in dest_ips:
        cms.update(ip.encode('utf-8'))
    end_cms = time.time()
    cms_time = end_cms - start_cms

    # Estimate counts for all unique destination IPs
    all_dest_ips = dest_ips.unique()
    estimated_counts = {
        ip: cms.estimate(ip.encode('utf-8')) for ip in all_dest_ips
    }

    # Select top-k estimates
    topk_cms = sorted(estimated_counts.items(), key=lambda x: x[1], reverse=True)[:k]
    topk_cms_set = set(ip for ip, _ in topk_cms)

    print(f"\n[CMS] Top-{k} Estimated Destination IPs:")
    for ip, est in topk_cms:
        print(f"{ip:<20} Estimated Count: {est}")

    # --- Evaluate overlap with exact method ---
    overlap = topk_exact.intersection(topk_cms_set)
    overlap_count = len(overlap)
    accuracy_pct = overlap_count / k * 100

    print(f"\n✅ Overlap in Top-{k}: {overlap_count}/{k}")
    print(f"🎯 Accuracy (Top-k match): {accuracy_pct:.2f}%")

    # Estimate memory usage for CMS
    cms_memory_bytes = width * depth * 4  # assuming 4 bytes per counter
    cms_memory_kb = cms_memory_bytes / 1024

    print(f"\n📊 Summary:")
    print(f"  Exact method time        : {exact_time:.4f} s")
    print(f"  Count-Min Sketch time    : {cms_time:.4f} s")
    print(f"  CMS memory usage         : {cms_memory_kb:.2f} KB")
    print(f"  Width × Depth            : {width} × {depth}")

    return {
        "topk_exact": topk_exact,
        "topk_cms": topk_cms_set,
        "overlap_count": overlap_count,
        "accuracy_pct": accuracy_pct
    }

# Helper function to calculate HyperLogLog precision parameter (p)
def get_hll_precision_from_error(error_rate):
    """Calculate HyperLogLog precision (p) for desired error rate."""
    return math.ceil(math.log2((1.04 / error_rate) ** 2))

# Function to estimate total unique IP addresses using HyperLogLog
def estimate_unique_ips(df, error_rate=0.05):
    all_ips = pd.concat([df['source'], df['destination']])

    print("\nEstimating number of unique IP addresses...\n")

    # --- Exact method (ground truth) ---
    start_exact = time.time()
    unique_ip_set = set(all_ips)
    exact_unique_ips = len(unique_ip_set)
    end_exact = time.time()
    exact_time = end_exact - start_exact

    # Estimate memory usage for exact set
    linear_space_bytes = exact_unique_ips * 100
    linear_space_kb = linear_space_bytes / 1024

    print(f"[Exact] Unique IPs: {exact_unique_ips}")
    print(f"[Exact] Computation Time: {exact_time:.4f} seconds")
    print(f"[Exact] Estimated Space Usage: {linear_space_kb:.2f} KB")

    # --- Approximate method: HyperLogLog ---
    p = get_hll_precision_from_error(error_rate)
    hll = HyperLogLog(p)

    start_hll = time.time()
    for ip in all_ips:
        hll.update(ip.encode('utf8'))
    estimated_unique_ips = int(hll.count())
    end_hll = time.time()
    hll_time = end_hll - start_hll

    # Estimate memory usage for HLL
    hll_registers = 2 ** p
    hll_bits = hll_registers * 6
    hll_bytes = hll_bits / 8
    hll_kb = hll_bytes / 1024

    print(f"\n[HLL] Estimated Unique IPs: {estimated_unique_ips}")
    print(f"[HLL] Computation Time: {hll_time:.4f} seconds")
    print(f"[HLL] Memory Usage: {hll_kb:.2f} KB (p={p}, {hll_registers} registers)")

    # Compare accuracy
    error_pct = abs(estimated_unique_ips - exact_unique_ips) / exact_unique_ips * 100
    print(f"\nEstimation Error: {error_pct:.2f}%")

    if error_pct <= 10:
        print("✅ Error is within acceptable bounds (≤ 10%)")
    else:
        print("⚠️ Error exceeds acceptable bounds")

    print("\n📊 Comparative Summary:")
    print(f"  Exact method time           : {exact_time:.4f} s")
    print(f"  HyperLogLog time            : {hll_time:.4f} s")
    print(f"  Exact method memory         : {linear_space_kb:.2f} KB")
    print(f"  HyperLogLog memory          : {hll_kb:.2f} KB")
    print(f"  Accuracy difference         : {error_pct:.2f}%")

    return estimated_unique_ips

# Orchestrator function to run all estimations
def estimate_network_traffic(csv_path):
    if not os.path.isfile(csv_path):
        print(f"File not found: {csv_path}")
        return

    df = pd.read_csv(csv_path, low_memory=False)

    # Clean column names (strip whitespace)
    df.columns = df.columns.str.strip()

    # Estimate unique IPs
    estimate_unique_ips(df)

    # Estimate top-k destination IPs
    estimate_topk_frequent_destinations(df)

    # Test membership detection with Bloom Filter
    test_membership_bloom(df)

    return

# Main function: entry point of script
def main():
    if len(sys.argv) != 2:
        print("Usage: python analyze_traffic.py <path_to_csv_file>")
        return

    csv_file = sys.argv[1]
    estimate_network_traffic(csv_file)

# Run main if this script is executed
if __name__ == "__main__":
    main()
