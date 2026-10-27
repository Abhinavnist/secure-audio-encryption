#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Milestone 6: Empirical Performance Benchmark Runner
==============================================================================
Runs multi-trial benchmarks, saves JSON telemetry, and plots comparative graphs.
==============================================================================
"""

import sys
import os

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from benchmarks.benchmark_engine import BenchmarkEngine
from benchmarks.plot_benchmarks import generate_benchmark_charts

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def main():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*85}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} [M.TECH EVALUATION] MILESTONE 6: EMPIRICAL PERFORMANCE BENCHMARK SUITE {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*85}{Colors.RESET}")
    print(" Running real multi-trial benchmarks across 250 KB, 1.0 MB, and 5.0 MB audio files...")
    print(" (Measuring: Encryption time, Decryption time, Throughput MB/s, and Storage expansion)\n")

    json_path = os.path.abspath("benchmarks/benchmark_results.json")
    results = BenchmarkEngine.run_suite(trials=3, output_json=json_path)

    # Print Table
    print(f"{Colors.BOLD}{Colors.YELLOW}{'-'*85}{Colors.RESET}")
    print(f"{Colors.BOLD}{'Size':<10} | {'Enc Time':<12} | {'Dec Time':<12} | {'Enc MB/s':<12} | {'Dec MB/s':<12} | {'Overhead':<10} | {'Lossless'}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}{'-'*85}{Colors.RESET}")

    for b in results["benchmarks"]:
        lossless_str = f"{Colors.GREEN}YES (100%){Colors.RESET}" if b["lossless_match"] else f"{Colors.RED}NO{Colors.RESET}"
        print(f"{b['file_label']:<10} | {b['mean_encryption_time_sec']*1000.0:>8.1f} ms | {b['mean_decryption_time_sec']*1000.0:>8.1f} ms | {b['encryption_throughput_mb_s']:>8.1f} MB/s | {b['decryption_throughput_mb_s']:>8.1f} MB/s | {b['storage_overhead_bytes']:>6} B   | {lossless_str}")

    print(f"{Colors.BOLD}{Colors.YELLOW}{'-'*85}{Colors.RESET}\n")

    # Generate Publication Plots
    plot_path = os.path.abspath("docs/performance_benchmark_charts.png")
    generate_benchmark_charts(results, plot_path)

    print(f" {Colors.GREEN}[PASS]{Colors.RESET} {Colors.BOLD}Benchmark Telemetry JSON:{Colors.RESET} {os.path.basename(json_path)}")
    print(f" {Colors.GREEN}[PASS]{Colors.RESET} {Colors.BOLD}Benchmark Research Plot:{Colors.RESET}  {plot_path} ({os.path.getsize(plot_path)//1024} KB)")

    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*85}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN} [+] ALL MILESTONE 6 BENCHMARKS COMPLETE WITH REAL EMPIRICAL MEASUREMENTS! {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*85}{Colors.RESET}\n")

if __name__ == "__main__":
    main()
