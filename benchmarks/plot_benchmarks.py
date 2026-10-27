"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: benchmarks.plot_benchmarks
==============================================================================
Generates publication-quality empirical benchmark graphs from benchmark results.
==============================================================================
"""

import os
import json
from typing import Dict, Any

# Configure Matplotlib non-interactive backend
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib_cache"
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

def generate_benchmark_charts(
    benchmark_data: Dict[str, Any],
    output_image_path: str = "docs/performance_benchmark_charts.png"
) -> str:
    """
    Renders 4-panel publication-ready empirical performance charts.
    """
    items = benchmark_data["benchmarks"]
    labels = [b["file_label"] for b in items]
    sizes_mb = [b["original_size_mb"] for b in items]
    enc_times = [b["mean_encryption_time_sec"] * 1000.0 for b in items]  # in ms
    dec_times = [b["mean_decryption_time_sec"] * 1000.0 for b in items]  # in ms
    enc_tput = [b["encryption_throughput_mb_s"] for b in items]
    dec_tput = [b["decryption_throughput_mb_s"] for b in items]
    overheads_pct = [b["storage_overhead_percent"] for b in items]

    fig, axs = plt.subplots(2, 2, figsize=(14, 10))
    fig.patch.set_facecolor('#0F172A')

    for ax_row in axs:
        for ax in ax_row:
            ax.set_facecolor('#1E293B')
            ax.tick_params(colors='#94A3B8')
            ax.xaxis.label.set_color('#E2E8F0')
            ax.yaxis.label.set_color('#E2E8F0')
            ax.title.set_color('#38BDF8')
            for spine in ax.spines.values():
                spine.set_color('#334155')

    # Subplot 1: Processing Latency (ms)
    x = np.arange(len(labels))
    width = 0.35
    axs[0, 0].bar(x - width/2, enc_times, width, label='Encryption Time', color='#38BDF8')
    axs[0, 0].bar(x + width/2, dec_times, width, label='Decryption Time', color='#10B981')
    axs[0, 0].set_title("Processing Latency vs Audio File Size")
    axs[0, 0].set_ylabel("Execution Time (milliseconds)")
    axs[0, 0].set_xticks(x)
    axs[0, 0].set_xticklabels(labels)
    axs[0, 0].legend(facecolor='#1E293B', edgecolor='#334155', labelcolor='#E2E8F0')
    axs[0, 0].grid(True, linestyle='--', alpha=0.3, color='#475569')

    # Subplot 2: Throughput (MB/s)
    axs[0, 1].plot(labels, enc_tput, marker='o', lw=2.5, color='#38BDF8', label='Encryption MB/s')
    axs[0, 1].plot(labels, dec_tput, marker='s', lw=2.5, color='#10B981', label='Decryption MB/s')
    axs[0, 1].set_title("Processing Throughput Scaling (Amortized KDF)")
    axs[0, 1].set_ylabel("Throughput (MB / second)")
    axs[0, 1].legend(facecolor='#1E293B', edgecolor='#334155', labelcolor='#E2E8F0')
    axs[0, 1].grid(True, linestyle='--', alpha=0.3, color='#475569')

    # Subplot 3: Storage Overhead Percentage (%)
    axs[1, 0].plot(labels, overheads_pct, marker='^', lw=2.5, color='#F59E0B')
    axs[1, 0].set_title("Storage Overhead Decay (% Container Expansion)")
    axs[1, 0].set_ylabel("Overhead Percentage (%)")
    axs[1, 0].set_xlabel("Audio File Size Category")
    axs[1, 0].grid(True, linestyle='--', alpha=0.3, color='#475569')

    # Subplot 4: Summary Telemetry Table
    axs[1, 1].axis('off')
    col_labels = ["Audio Size", "Enc (ms)", "Dec (ms)", "Enc (MB/s)", "Dec (MB/s)", "Overhead"]
    table_data = []
    for b in items:
        table_data.append([
            b["file_label"],
            f"{b['mean_encryption_time_sec']*1000.0:.1f}",
            f"{b['mean_decryption_time_sec']*1000.0:.1f}",
            f"{b['encryption_throughput_mb_s']:.1f}",
            f"{b['decryption_throughput_mb_s']:.1f}",
            f"{b['storage_overhead_bytes']} B"
        ])

    table = axs[1, 1].table(
        cellText=table_data,
        colLabels=col_labels,
        loc='center',
        cellLoc='center'
    )
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.1, 2.2)

    for key, cell in table.get_celld().items():
        cell.set_edgecolor('#334155')
        if key[0] == 0:
            cell.set_facecolor('#0284C7')
            cell.set_text_props(color='white', weight='bold')
        else:
            cell.set_facecolor('#1E293B')
            cell.set_text_props(color='#E2E8F0')

    plt.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(output_image_path)), exist_ok=True)
    plt.savefig(output_image_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close(fig)

    return output_image_path
