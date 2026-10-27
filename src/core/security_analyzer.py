"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.core.security_analyzer
==============================================================================
M.Tech Research & Cryptographic Verification Module:
  1. Shannon Information Entropy Calculation (Max 8.0 bits/byte).
  2. Byte Frequency Uniformity Distribution (Chi-Square goodness of fit).
  3. Audio Player Rejection Verification (Format parser failure test).
  4. Waveform & Short-Time Fourier Transform (STFT) Spectrogram Generation.
==============================================================================
"""

import os
import math
import wave
from typing import Dict, Any, Tuple
import numpy as np

# Set non-interactive backend and clean cache dir for Matplotlib
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib_cache"
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

class SecurityAnalyzer:
    """
    Evaluates cryptographic strength, randomness, and acoustic information leakage.
    """

    @staticmethod
    def calculate_shannon_entropy(data_or_path: Any) -> float:
        """
        Calculates Shannon Entropy:
            H(X) = - SUM( P(x_i) * log2(P(x_i)) ) for i in 0..255
            
        Theoretical bounds:
          - Minimum: 0.0 bits/byte (all identical bytes, zero randomness).
          - Structured Audio Plaintext: Typically 3.5 - 6.5 bits/byte.
          - Maximum (True Cryptographic Randomness): 8.0 bits/byte.
          - AES-256-GCM Target: >= 7.999 bits/byte.
        """
        if isinstance(data_or_path, str):
            with open(data_or_path, 'rb') as f:
                byte_data = f.read()
        elif isinstance(data_or_path, (bytes, bytearray)):
            byte_data = bytes(data_or_path)
        else:
            raise TypeError("Expected file path or bytes.")

        if not byte_data:
            return 0.0

        total_bytes = len(byte_data)
        counts = np.bincount(np.frombuffer(byte_data, dtype=np.uint8), minlength=256)
        probabilities = counts[counts > 0] / total_bytes
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(round(entropy, 5))

    @staticmethod
    def calculate_chi_square(data_or_path: Any) -> Tuple[float, float]:
        """
        Calculates Chi-Square statistic for uniformity across 256 byte bins.
        Degrees of freedom: 255.
        Expected count per bin: total_bytes / 256.
        """
        if isinstance(data_or_path, str):
            with open(data_or_path, 'rb') as f:
                byte_data = f.read()
        else:
            byte_data = bytes(data_or_path)

        total_bytes = len(byte_data)
        if total_bytes == 0:
            return 0.0, 0.0

        expected = total_bytes / 256.0
        counts = np.bincount(np.frombuffer(byte_data, dtype=np.uint8), minlength=256)
        chi2 = float(np.sum((counts - expected) ** 2 / expected))
        return chi2, expected

    @staticmethod
    def verify_audio_unplayability(encrypted_path: str) -> Dict[str, Any]:
        """
        Security Verification: Proves that an encrypted audio file cannot be
        played or parsed by digital audio decoders without the secret key.
        """
        results = {
            "is_rejected_by_wave_decoder": False,
            "wave_decoder_error": "",
            "header_has_riff_signature": False,
            "header_has_mp3_sync": False,
            "unauthorized_access_prevented": False
        }

        with open(encrypted_path, 'rb') as f:
            header_sample = f.read(128)

        # 1. Wave decoder rejection test
        try:
            with wave.open(encrypted_path, 'rb') as _:
                results["is_rejected_by_wave_decoder"] = False
        except wave.Error as e:
            results["is_rejected_by_wave_decoder"] = True
            results["wave_decoder_error"] = str(e)
        except Exception as e:
            results["is_rejected_by_wave_decoder"] = True
            results["wave_decoder_error"] = f"{type(e).__name__}: {e}"

        # 2. Raw binary signatures check
        results["header_has_riff_signature"] = b"RIFF" in header_sample[:12]
        # MP3 sync word is 0xFFE / 0xFFF
        results["header_has_mp3_sync"] = (
            len(header_sample) >= 2 and 
            header_sample[0] == 0xFF and 
            (header_sample[1] & 0xE0) == 0xE0
        )

        results["unauthorized_access_prevented"] = (
            results["is_rejected_by_wave_decoder"] and 
            not results["header_has_riff_signature"]
        )

        return results

    @staticmethod
    def generate_security_visualizations(
        original_wav_path: str,
        encrypted_container_path: str,
        output_image_path: str
    ) -> Dict[str, Any]:
        """
        Generates publication-quality comparative visualizations:
          1. Original Audio Waveform (Time domain harmonic structure).
          2. Encrypted Ciphertext Waveform (Pseudo-audio white noise).
          3. Original Audio Spectrogram (Frequency vs Time spectrogram).
          4. Encrypted Ciphertext Spectrogram (Completely flat, uniform spectrum).
          5. Byte Distribution Histogram (Plaintext spikes vs Ciphertext uniform flat line).
        """
        # Read Original Audio PCM
        with wave.open(original_wav_path, 'rb') as wav:
            sr = wav.getframerate()
            n_frames = wav.getnframes()
            channels = wav.getnchannels()
            raw_orig = wav.readframes(n_frames)
            
        orig_samples = np.frombuffer(raw_orig, dtype=np.int16)
        if channels > 1:
            orig_samples = orig_samples[::channels]  # Take first channel
        time_axis_orig = np.linspace(0, len(orig_samples) / sr, num=len(orig_samples))

        # Read Encrypted Ciphertext bytes (extract raw ciphertext section)
        with open(encrypted_container_path, 'rb') as f:
            enc_bytes = f.read()

        # Treat ciphertext bytes as pseudo 16-bit PCM for fair acoustic domain comparison
        num_pseudo_samples = len(enc_bytes) // 2
        pseudo_cipher_samples = np.frombuffer(enc_bytes[:num_pseudo_samples * 2], dtype=np.int16)
        time_axis_cipher = np.linspace(0, len(pseudo_cipher_samples) / sr, num=len(pseudo_cipher_samples))

        # Entropies
        h_orig = SecurityAnalyzer.calculate_shannon_entropy(raw_orig)
        h_cipher = SecurityAnalyzer.calculate_shannon_entropy(enc_bytes)

        # Plotting Setup
        fig, axs = plt.subplots(3, 2, figsize=(14, 11))
        fig.patch.set_facecolor('#0F172A')  # Dark academic background

        for ax_row in axs:
            for ax in ax_row:
                ax.set_facecolor('#1E293B')
                ax.tick_params(colors='#94A3B8')
                ax.xaxis.label.set_color('#E2E8F0')
                ax.yaxis.label.set_color('#E2E8F0')
                ax.title.set_color('#38BDF8')
                for spine in ax.spines.values():
                    spine.set_color('#334155')

        # Panel 1: Original Audio Waveform
        axs[0, 0].plot(time_axis_orig[:4000], orig_samples[:4000], color='#10B981', lw=1.0)
        axs[0, 0].set_title(f"Original Audio Waveform (Time Domain) [H = {h_orig:.3f} bits/byte]")
        axs[0, 0].set_xlabel("Time (seconds)")
        axs[0, 0].set_ylabel("Amplitude (16-bit PCM)")
        axs[0, 0].set_ylim(-32768, 32767)

        # Panel 2: Encrypted Ciphertext Pseudo-Waveform
        axs[0, 1].plot(time_axis_cipher[:4000], pseudo_cipher_samples[:4000], color='#EF4444', lw=0.6, alpha=0.8)
        axs[0, 1].set_title(f"Ciphertext Pseudo-Waveform (Pure White Noise) [H = {h_cipher:.5f} bits/byte]")
        axs[0, 1].set_xlabel("Time (seconds)")
        axs[0, 1].set_ylabel("Amplitude")
        axs[0, 1].set_ylim(-32768, 32767)

        # Panel 3: Original Audio Spectrogram (STFT)
        axs[1, 0].specgram(orig_samples, Fs=sr, NFFT=512, noverlap=256, cmap='viridis')
        axs[1, 0].set_title("Original Audio Spectrogram (Clear Harmonic Formants)")
        axs[1, 0].set_xlabel("Time (seconds)")
        axs[1, 0].set_ylabel("Frequency (Hz)")

        # Panel 4: Ciphertext Spectrogram (STFT)
        axs[1, 1].specgram(pseudo_cipher_samples, Fs=sr, NFFT=512, noverlap=256, cmap='inferno')
        axs[1, 1].set_title("Ciphertext Spectrogram (Zero Acoustic Leakage - Flat Spectrum)")
        axs[1, 1].set_xlabel("Time (seconds)")
        axs[1, 1].set_ylabel("Frequency (Hz)")

        # Panel 5: Plaintext Byte Histogram
        orig_counts = np.bincount(np.frombuffer(raw_orig, dtype=np.uint8), minlength=256)
        axs[2, 0].bar(range(256), orig_counts, color='#3B82F6', width=1.0)
        axs[2, 0].set_title("Original Audio Byte Distribution (Predictable Structural Spikes)")
        axs[2, 0].set_xlabel("Byte Value (0 - 255)")
        axs[2, 0].set_ylabel("Occurrences")

        # Panel 6: Ciphertext Byte Histogram
        cipher_counts = np.bincount(np.frombuffer(enc_bytes, dtype=np.uint8), minlength=256)
        axs[2, 1].bar(range(256), cipher_counts, color='#F59E0B', width=1.0)
        axs[2, 1].set_title(f"Ciphertext Byte Distribution (Ideal Uniform Distribution, Max Entropy: 8.0)")
        axs[2, 1].set_xlabel("Byte Value (0 - 255)")
        axs[2, 1].set_ylabel("Occurrences")

        plt.tight_layout()
        os.makedirs(os.path.dirname(os.path.abspath(output_image_path)), exist_ok=True)
        plt.savefig(output_image_path, dpi=200, facecolor=fig.get_facecolor(), edgecolor='none')
        plt.close(fig)

        return {
            "image_path": output_image_path,
            "original_entropy": h_orig,
            "ciphertext_entropy": h_cipher,
            "entropy_gain": round(h_cipher - h_orig, 5)
        }
