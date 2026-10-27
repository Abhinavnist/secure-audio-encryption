#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Milestone 2 Verification & Test Suite
==============================================================================
Tests:
  1. KeyManager: 256-bit CSPRNG key generation & Hex export/import.
  2. KeyManager: PBKDF2-HMAC-SHA256 derivation correctness & collision resistance.
  3. KeyManager: 96-bit Nonce generation uniqueness.
  4. AudioContainer: Header binary packing, serialization, and deserialization.
  5. AudioContainer: Magic signature & truncation tamper resistance.
==============================================================================
"""

import sys
import os
import time

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.key_manager import (
    KeyManager, 
    AES_256_KEY_SIZE_BYTES, 
    GCM_NONCE_SIZE_BYTES, 
    SALT_SIZE_BYTES
)
from src.core.container import (
    AudioContainer, 
    MAGIC_BYTES, 
    CURRENT_VERSION, 
    KDF_TYPE_PBKDF2, 
    InvalidContainerError
)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def assert_test(condition: bool, test_name: str, details: str = ""):
    if condition:
        print(f" {Colors.GREEN}[PASS]{Colors.RESET} {Colors.BOLD}{test_name:<40}{Colors.RESET} {details}")
    else:
        print(f" {Colors.RED}[FAIL]{Colors.RESET} {Colors.BOLD}{test_name:<40}{Colors.RESET} {details}")
        raise AssertionError(f"Test failed: {test_name} - {details}")

def run_milestone2_tests():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*75}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} [M.TECH TEST] MILESTONE 2: KEY MANAGEMENT & CONTAINER SPEC {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*75}{Colors.RESET}")

    # ---------------------------------------------------------
    # 1. Master Key CSPRNG Generation & Hex Encoding
    # ---------------------------------------------------------
    key1 = KeyManager.generate_master_key()
    key2 = KeyManager.generate_master_key()
    assert_test(len(key1) == AES_256_KEY_SIZE_BYTES, "Master Key Length Check", f"Size: {len(key1)} bytes (256 bits)")
    assert_test(key1 != key2, "CSPRNG Uniqueness Check", "Consecutive 256-bit keys are distinct.")
    
    key_hex = KeyManager.key_to_hex(key1)
    recovered_key = KeyManager.hex_to_key(key_hex)
    assert_test(recovered_key == key1, "Key Hex Serialization", f"Hex: {key_hex[:16]}... len={len(key_hex)} chars")

    # ---------------------------------------------------------
    # 2. Nonce Strict 96-bit Length & Uniqueness
    # ---------------------------------------------------------
    nonce1 = KeyManager.generate_nonce()
    nonce2 = KeyManager.generate_nonce()
    assert_test(len(nonce1) == GCM_NONCE_SIZE_BYTES, "GCM Nonce Length Check", f"Size: {len(nonce1)} bytes (96 bits)")
    assert_test(nonce1 != nonce2, "GCM Nonce Entropy Check", "Consecutive nonces are distinct.")

    # ---------------------------------------------------------
    # 3. PBKDF2 Key Derivation
    # ---------------------------------------------------------
    password = "SuperSecretMTechAudioPassword#2026"
    t0 = time.perf_counter()
    # Using 100,000 for unit test speed; production default is 600,000
    derived_k1, salt1 = KeyManager.derive_key_from_password(password, iterations=100_000)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert_test(len(derived_k1) == AES_256_KEY_SIZE_BYTES, "PBKDF2 Output Size", f"Derived 256-bit key in {elapsed_ms:.1f}ms")
    assert_test(len(salt1) == SALT_SIZE_BYTES, "PBKDF2 Salt Generation", f"Salt size: {len(salt1)} bytes")

    # Determinism test with identical salt
    derived_k2, _ = KeyManager.derive_key_from_password(password, salt=salt1, iterations=100_000)
    assert_test(derived_k1 == derived_k2, "PBKDF2 Determinism", "Same password & salt produce identical key.")

    # Avalanche test with different password
    derived_k3, _ = KeyManager.derive_key_from_password("WrongPassword#2026", salt=salt1, iterations=100_000)
    assert_test(derived_k1 != derived_k3, "PBKDF2 Avalanche Effect", "Different passwords produce distinct keys.")

    # ---------------------------------------------------------
    # 4. AudioContainer Packing & Unpacking
    # ---------------------------------------------------------
    sample_metadata = {
        "original_filename": "voice_recording_01.wav",
        "audio_format": "WAV",
        "sample_rate": 44100,
        "channels": 2,
        "sample_width": 2,
        "file_size_bytes": 1048576,
        "timestamp": 1729641600
    }
    dummy_tag = b"\xaa" * 16
    dummy_ciphertext = b"ENCRYPTED-AUDIO-STREAM-DATA" * 10

    # Pack Header (AAD)
    aad_header = AudioContainer.pack_header(
        kdf_type=KDF_TYPE_PBKDF2,
        iterations=600_000,
        salt=salt1,
        nonce=nonce1,
        metadata=sample_metadata
    )
    assert_test(aad_header.startswith(MAGIC_BYTES), "Container Magic Bytes", f"Magic header: {MAGIC_BYTES.decode('ascii')}")

    # Build Complete Container Stream: Header + Tag + Ciphertext
    container_bytes = aad_header + dummy_tag + dummy_ciphertext

    # Unpack
    header_info, parsed_aad, extracted_ciphertext = AudioContainer.unpack_header(container_bytes)
    assert_test(parsed_aad == aad_header, "AAD Integrity Match", f"AAD Header length: {len(parsed_aad)} bytes")
    assert_test(header_info["metadata"]["original_filename"] == "voice_recording_01.wav", "Metadata Extraction", "Filename matches.")
    assert_test(header_info["metadata"]["sample_rate"] == 44100, "Metadata Audio Spec", "Sample rate: 44.1 kHz")
    assert_test(header_info["tag"] == dummy_tag, "Tag Extraction", "16-byte GHASH tag matches.")
    assert_test(extracted_ciphertext == dummy_ciphertext, "Ciphertext Extraction", f"{len(extracted_ciphertext)} bytes extracted.")

    # ---------------------------------------------------------
    # 5. Tamper Resistance on Container
    # ---------------------------------------------------------
    # Corrupt Magic bytes
    corrupt_magic_bytes = b"BAD!" + container_bytes[4:]
    magic_rejected = False
    try:
        AudioContainer.unpack_header(corrupt_magic_bytes)
    except InvalidContainerError:
        magic_rejected = True
    assert_test(magic_rejected, "Invalid Magic Rejection", "Altered magic header immediately rejected.")

    # Truncated container
    truncated_rejected = False
    try:
        AudioContainer.unpack_header(container_bytes[:20])
    except InvalidContainerError:
        truncated_rejected = True
    assert_test(truncated_rejected, "Truncated Container Rejection", "Truncated file rejected cleanly.")

    print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*75}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN} [+] ALL MILESTONE 2 SPECIFICATIONS & TESTS PASSED! {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}{'='*75}{Colors.RESET}\n")

if __name__ == "__main__":
    run_milestone2_tests()
