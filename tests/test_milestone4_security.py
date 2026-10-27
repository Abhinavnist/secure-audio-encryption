#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Milestone 4 Test Suite: Adversarial Security Verification, Shannon Entropy & Spectrograms
==============================================================================
Tests:
  1. Shannon Information Entropy (Plaintext vs AES-256-GCM Ciphertext).
  2. Audio Player Rejection Test (Verification that encrypted file cannot be played).
  3. Chi-Square Uniform Randomness Distribution Test.
  4. Publication-Quality Waveform & Spectrogram Analysis Plot Generation.
==============================================================================
"""

import sys
import os
import shutil

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.audio.audio_handler import AudioHandler
from src.core.cipher import AudioCipher
from src.core.security_analyzer import SecurityAnalyzer

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def assert_test(condition: bool, test_name: str, details: str = ""):
    if condition:
        print(f" {Colors.GREEN}[PASS]{Colors.RESET} {Colors.BOLD}{test_name:<48}{Colors.RESET} {details}")
    else:
        print(f" {Colors.RED}[FAIL]{Colors.RESET} {Colors.BOLD}{test_name:<48}{Colors.RESET} {details}")
        raise AssertionError(f"Test failed: {test_name} - {details}")

def run_milestone4_tests():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} [M.TECH TEST] MILESTONE 4: ADVERSARIAL SECURITY & SPECTROGRAM ANALYSIS {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")

    test_dir = os.path.join(os.path.dirname(__file__), "sandbox_security_data")
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, exist_ok=True)

    try:
        # 1. Generate test audio file (1.0 second, 440 Hz tone)
        sample_wav = os.path.join(test_dir, "test_audio_sample.wav")
        AudioHandler.generate_synthetic_wav(
            output_path=sample_wav,
            frequency_hz=440.0,
            duration_seconds=1.0,
            sample_rate=44100,
            channels=1
        )
        assert_test(os.path.exists(sample_wav), "Test Audio Preparation", f"Created {os.path.getsize(sample_wav)} bytes WAV")

        # 2. Encrypt audio using AES-256-GCM
        enc_file = os.path.join(test_dir, "test_audio_sample.safeaudio")
        passphrase = "MTechCryptographicEvaluation#2026"
        AudioCipher.encrypt_file(
            input_audio_path=sample_wav,
            output_container_path=enc_file,
            key_or_password=passphrase,
            is_password=True,
            iterations=100_000
        )
        assert_test(os.path.exists(enc_file), "AES-256-GCM Encryption", f"Generated .safeaudio container ({os.path.getsize(enc_file)} bytes)")

        # 3. Shannon Entropy Verification
        h_plain = SecurityAnalyzer.calculate_shannon_entropy(sample_wav)
        h_cipher = SecurityAnalyzer.calculate_shannon_entropy(enc_file)
        
        assert_test(
            h_cipher >= 7.995, 
            "Shannon Entropy Maxima (Max = 8.0)", 
            f"Plaintext: {h_plain:.4f} bits/byte | Ciphertext: {h_cipher:.5f} bits/byte"
        )

        # 4. Audio Player / Decoder Rejection Test
        unplayability = SecurityAnalyzer.verify_audio_unplayability(enc_file)
        assert_test(
            unplayability["is_rejected_by_wave_decoder"], 
            "Audio Decoder Rejection Test", 
            f"Wave parser rejected: '{unplayability['wave_decoder_error']}'"
        )
        assert_test(
            unplayability["unauthorized_access_prevented"], 
            "Unauthorized Playback Blocked", 
            "Zero RIFF/MPEG framing signatures found in ciphertext."
        )

        # 5. Chi-Square Uniformity Test
        chi2, expected_freq = SecurityAnalyzer.calculate_chi_square(enc_file)
        # For 255 degrees of freedom, typical critical values at p=0.01 is ~310
        # A chi2 around 200-300 indicates exceptional uniform randomness
        assert_test(
            chi2 < 400.0, 
            "Chi-Square Byte Distribution Uniformity", 
            f"Chi2: {chi2:.2f} (Expected per bin: {expected_freq:.1f}, DOF: 255)"
        )

        # 6. Generate Publication-Quality Spectrogram and Waveform Visualizations
        output_image = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "security_analysis_spectrogram.png"))
        vis_result = SecurityAnalyzer.generate_security_visualizations(
            original_wav_path=sample_wav,
            encrypted_container_path=enc_file,
            output_image_path=output_image
        )
        assert_test(
            os.path.exists(output_image) and os.path.getsize(output_image) > 50_000, 
            "Comparative Spectrogram Plot Generated", 
            f"Saved 6-panel figure to: {os.path.basename(output_image)} ({os.path.getsize(output_image) // 1024} KB)"
        )

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN} [+] ALL MILESTONE 4 SECURITY & ENTROPY VERIFICATIONS PASSED! {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN} [+] Visual Analysis Chart saved to docs/security_analysis_spectrogram.png {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}\n")

    finally:
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)

if __name__ == "__main__":
    run_milestone4_tests()
