#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Milestone 3 Test Suite: End-to-End AEAD Audio Encryption, Decryption, & Lossless Recovery
==============================================================================
Tests:
  1. Synthetic Audio Generation (WAV PCM 440 Hz).
  2. Passphrase-based authenticated encryption (.safeaudio generation).
  3. Correct passphrase decryption & bit-for-bit SHA-256 lossless verification.
  4. Raw 256-bit master key encryption & decryption.
  5. Negative Security Test: Wrong passphrase rejection (AuthenticationError).
  6. RUP (Release of Unverified Plaintext) Protection Check.
  7. Adversarial Test: Ciphertext bit-flipping detection.
  8. Adversarial Test: Header metadata tampering detection via AAD.
==============================================================================
"""

import sys
import os
import shutil
import wave

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.cipher import AudioCipher, AuthenticationError
from src.core.key_manager import KeyManager
from src.audio.audio_handler import AudioHandler

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def assert_test(condition: bool, test_name: str, details: str = ""):
    if condition:
        print(f" {Colors.GREEN}[PASS]{Colors.RESET} {Colors.BOLD}{test_name:<45}{Colors.RESET} {details}")
    else:
        print(f" {Colors.RED}[FAIL]{Colors.RESET} {Colors.BOLD}{test_name:<45}{Colors.RESET} {details}")
        raise AssertionError(f"Test failed: {test_name} - {details}")

def run_milestone3_tests():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} [M.TECH TEST] MILESTONE 3: CORE AES-256-GCM AUDIO ENCRYPTION ENGINE {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")

    test_dir = os.path.join(os.path.dirname(__file__), "sandbox_test_data")
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, exist_ok=True)

    try:
        # -------------------------------------------------------------
        # 1. Generate Synthetic Audio File
        # -------------------------------------------------------------
        orig_wav = os.path.join(test_dir, "original_speech.wav")
        AudioHandler.generate_synthetic_wav(
            output_path=orig_wav, 
            frequency_hz=440.0, 
            duration_seconds=0.5, 
            sample_rate=44100
        )
        assert_test(os.path.exists(orig_wav), "Synthetic Audio Generation", f"Created {os.path.getsize(orig_wav)} bytes WAV")
        orig_hash = AudioHandler.calculate_sha256(orig_wav)

        # -------------------------------------------------------------
        # 2. Passphrase-based Encryption
        # -------------------------------------------------------------
        enc_file = os.path.join(test_dir, "encrypted_audio.safeaudio")
        passphrase = "MasterStudentSecureAudio2026!#"
        
        enc_result = AudioCipher.encrypt_file(
            input_audio_path=orig_wav,
            output_container_path=enc_file,
            key_or_password=passphrase,
            is_password=True,
            iterations=100_000  # Fast iteration for unit testing
        )
        assert_test(os.path.exists(enc_file), "Passphrase Encryption (.safeaudio)", f"Throughput: {enc_result['throughput_mb_s']} MB/s")
        assert_test(enc_result["header_overhead_bytes"] > 0, "Header Overhead Check", f"Header+Tag size: {enc_result['header_overhead_bytes']} bytes")

        # -------------------------------------------------------------
        # 3. Legitimate Decryption & Lossless SHA-256 Verification
        # -------------------------------------------------------------
        rec_wav = os.path.join(test_dir, "recovered_speech.wav")
        dec_result = AudioCipher.decrypt_file(
            input_container_path=enc_file,
            output_audio_path=rec_wav,
            key_or_password=passphrase,
            is_password=True
        )
        assert_test(dec_result["lossless_integrity_verified"], "Lossless SHA-256 Checksum Match", f"Hash: {dec_result['decrypted_sha256'][:16]}...")
        assert_test(orig_hash == dec_result["decrypted_sha256"], "Bit-for-Bit Identity", "Decrypted audio is 100% identical to original.")

        # Verify decrypted WAV header is playable
        with wave.open(rec_wav, 'rb') as w:
            assert_test(w.getframerate() == 44100 and w.getnchannels() == 1, "Audio Header Integrity", "Recovered valid PCM WAV format.")

        # -------------------------------------------------------------
        # 4. Raw 256-bit Key Encryption & Decryption
        # -------------------------------------------------------------
        raw_key = KeyManager.generate_master_key()
        raw_enc_file = os.path.join(test_dir, "raw_key_encrypted.safeaudio")
        raw_rec_file = os.path.join(test_dir, "raw_key_recovered.wav")

        AudioCipher.encrypt_file(
            input_audio_path=orig_wav,
            output_container_path=raw_enc_file,
            key_or_password=raw_key,
            is_password=False
        )
        raw_dec = AudioCipher.decrypt_file(
            input_container_path=raw_enc_file,
            output_audio_path=raw_rec_file,
            key_or_password=raw_key,
            is_password=False
        )
        assert_test(raw_dec["lossless_integrity_verified"], "Raw 256-bit Key Encryption/Decryption", "Lossless recovery via 256-bit CSPRNG key.")

        # -------------------------------------------------------------
        # 5. Security Test: Wrong Passphrase Rejection
        # -------------------------------------------------------------
        wrong_pass_failed = False
        leak_file = os.path.join(test_dir, "leaked.wav")
        try:
            AudioCipher.decrypt_file(
                input_container_path=enc_file,
                output_audio_path=leak_file,
                key_or_password="WrongPasswordAttempt#999",
                is_password=True
            )
        except AuthenticationError:
            wrong_pass_failed = True

        assert_test(wrong_pass_failed, "Wrong Passphrase Rejection", "AuthenticationError raised; MAC verification failed.")
        assert_test(not os.path.exists(leak_file), "RUP Protection (No Leaked Plaintext)", "Zero unverified bytes written to disk.")

        # -------------------------------------------------------------
        # 6. Adversarial Security: Ciphertext Bit-Flipping Attack
        # -------------------------------------------------------------
        tampered_cipher_file = os.path.join(test_dir, "tampered_ciphertext.safeaudio")
        with open(enc_file, 'rb') as f:
            data = bytearray(f.read())
        # Flip a bit near the middle of ciphertext
        data[-50] ^= 0x01
        with open(tampered_cipher_file, 'wb') as f:
            f.write(data)

        tamper_detected = False
        try:
            AudioCipher.decrypt_file(
                input_container_path=tampered_cipher_file,
                output_audio_path=os.path.join(test_dir, "tampered_recovered.wav"),
                key_or_password=passphrase,
                is_password=True
            )
        except AuthenticationError:
            tamper_detected = True

        assert_test(tamper_detected, "Ciphertext Bit-Flip Tamper Detection", "Single-bit flip in ciphertext caused instant rejection.")

        # -------------------------------------------------------------
        # 7. Adversarial Security: Header Metadata Tampering (AAD Defense)
        # -------------------------------------------------------------
        tampered_header_file = os.path.join(test_dir, "tampered_header.safeaudio")
        with open(enc_file, 'rb') as f:
            h_data = bytearray(f.read())
        # Tamper with an ASCII character in the metadata JSON area (e.g. change filename char)
        for idx in range(40, len(h_data) - 16):
            if chr(h_data[idx]) == 's':  # find 'speech'
                h_data[idx] = ord('x')
                break

        with open(tampered_header_file, 'wb') as f:
            f.write(h_data)

        header_tamper_detected = False
        try:
            AudioCipher.decrypt_file(
                input_container_path=tampered_header_file,
                output_audio_path=os.path.join(test_dir, "tampered_header_rec.wav"),
                key_or_password=passphrase,
                is_password=True
            )
        except AuthenticationError:
            header_tamper_detected = True

        assert_test(header_tamper_detected, "Header Metadata AAD Tamper Detection", "Modified metadata triggered AAD MAC mismatch rejection.")

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN} [+] ALL MILESTONE 3 TESTS & SECURITY CHECKS PASSED WITH 100% SUCCESS! {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}\n")

    finally:
        # Clean up test artifacts
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)

if __name__ == "__main__":
    run_milestone3_tests()
