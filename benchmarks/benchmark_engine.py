"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: benchmarks.benchmark_engine
==============================================================================
Automated empirical performance benchmarking suite:
  - Measures Encryption & Decryption latency (ms)
  - Evaluates Throughput (MB/s)
  - Calculates Storage Overhead (Container Expansion)
  - Tests multiple formats (WAV, MP3) across scalable file sizes
==============================================================================
"""

import os
import time
import json
import tempfile
import shutil
from typing import Dict, Any, List
import numpy as np

from src.audio.audio_handler import AudioHandler
from src.core.cipher import AudioCipher

class BenchmarkEngine:
    """
    Executes empirical cryptographic benchmarks across audio formats and sizes.
    """

    BENCHMARK_SIZES = [
        {"name": "250 KB", "duration_sec": 2.8, "target_bytes": 250_000},
        {"name": "1.0 MB", "duration_sec": 11.6, "target_bytes": 1_024_000},
        {"name": "5.0 MB", "duration_sec": 58.0, "target_bytes": 5_120_000},
    ]

    @staticmethod
    def run_suite(
        trials: int = 3, 
        passphrase: str = "BenchmarkAuditSecret#2026",
        output_json: str = "benchmarks/benchmark_results.json"
    ) -> Dict[str, Any]:
        """
        Executes multi-run empirical benchmarks and records metrics.
        """
        temp_dir = tempfile.mkdtemp(prefix="audio_bench_")
        results: Dict[str, Any] = {
            "system_info": {
                "cipher": "AES-256-GCM",
                "kdf": "PBKDF2-HMAC-SHA256 (100k iterations)",
                "trials_per_size": trials
            },
            "benchmarks": []
        }

        try:
            for item in BenchmarkEngine.BENCHMARK_SIZES:
                label = item["name"]
                duration = item["duration_sec"]
                
                # 1. Generate synthetic WAV audio for benchmark
                wav_path = os.path.join(temp_dir, f"bench_{label.replace(' ', '_')}.wav")
                AudioHandler.generate_synthetic_wav(
                    output_path=wav_path,
                    frequency_hz=440.0,
                    duration_seconds=duration,
                    sample_rate=44100,
                    channels=1
                )
                actual_size_bytes = os.path.getsize(wav_path)
                actual_size_mb = actual_size_bytes / (1024 * 1024)

                enc_times: List[float] = []
                dec_times: List[float] = []
                enc_sizes: List[int] = []

                safeaudio_path = os.path.join(temp_dir, f"bench_{label.replace(' ', '_')}.safeaudio")
                rec_path = os.path.join(temp_dir, f"bench_{label.replace(' ', '_')}_rec.wav")

                for _ in range(trials):
                    # Measure Encryption
                    t0 = time.perf_counter()
                    enc_meta = AudioCipher.encrypt_file(
                        input_audio_path=wav_path,
                        output_container_path=safeaudio_path,
                        key_or_password=passphrase,
                        is_password=True,
                        iterations=100_000
                    )
                    t1 = time.perf_counter()
                    enc_times.append(t1 - t0)
                    enc_sizes.append(enc_meta["encrypted_size_bytes"])

                    # Measure Decryption
                    t2 = time.perf_counter()
                    dec_meta = AudioCipher.decrypt_file(
                        input_container_path=safeaudio_path,
                        output_audio_path=rec_path,
                        key_or_password=passphrase,
                        is_password=True
                    )
                    t3 = time.perf_counter()
                    dec_times.append(t3 - t2)

                mean_enc_time = float(np.mean(enc_times))
                mean_dec_time = float(np.mean(dec_times))
                std_enc_time = float(np.std(enc_times))
                std_dec_time = float(np.std(dec_times))

                mean_enc_throughput = actual_size_mb / mean_enc_time if mean_enc_time > 0 else 0.0
                mean_dec_throughput = actual_size_mb / mean_dec_time if mean_dec_time > 0 else 0.0

                encrypted_size = enc_sizes[0]
                expansion_bytes = encrypted_size - actual_size_bytes
                expansion_percent = (expansion_bytes / actual_size_bytes) * 100.0

                record = {
                    "file_label": label,
                    "original_size_bytes": actual_size_bytes,
                    "original_size_mb": round(actual_size_mb, 3),
                    "encrypted_size_bytes": encrypted_size,
                    "storage_overhead_bytes": expansion_bytes,
                    "storage_overhead_percent": round(expansion_percent, 4),
                    "mean_encryption_time_sec": round(mean_enc_time, 4),
                    "mean_decryption_time_sec": round(mean_dec_time, 4),
                    "encryption_throughput_mb_s": round(mean_enc_throughput, 2),
                    "decryption_throughput_mb_s": round(mean_dec_throughput, 2),
                    "std_enc_sec": round(std_enc_time, 5),
                    "std_dec_sec": round(std_dec_time, 5),
                    "lossless_match": dec_meta["lossless_integrity_verified"]
                }
                results["benchmarks"].append(record)

            os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
            with open(output_json, 'w') as f:
                json.dump(results, f, indent=2)

            return results

        finally:
            shutil.rmtree(temp_dir)
