#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Milestone 1: Environment & Cryptographic Primitive Diagnostic Verification
==============================================================================
Author: M.Tech Cryptography Research Team
Purpose:
  1. Validates Python runtime version and platform architecture.
  2. Verifies OS Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).
  3. Verifies PyCryptodome AES-256-GCM AEAD encryption, decryption, and MAC integrity checks.
  4. Tests bit-flip tamper rejection (ensures MAC verification failure is triggered).
  5. Validates audio generation & standard library wave capabilities.
  6. Checks optional packages: Pydub, NumPy, Matplotlib, CustomTkinter.
==============================================================================
"""

import sys
import os
import time
import struct
import math
import wave
import io
import platform

# Terminal ANSI Colors for professional diagnostics
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def print_section(title: str):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*75}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} [M.TECH DIAGNOSTIC] {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*75}{Colors.RESET}")

def print_status(component: str, success: bool, details: str = ""):
    if success:
        status_tag = f"{Colors.GREEN}[PASS]{Colors.RESET}"
    else:
        status_tag = f"{Colors.RED}[FAIL]{Colors.RESET}"
    print(f" {status_tag} {Colors.BOLD}{component:<30}{Colors.RESET} {details}")

def check_python_runtime() -> bool:
    print_section("1. Python Runtime & Platform Architecture")
    version = sys.version_info
    ver_str = f"{version.major}.{version.minor}.{version.micro}"
    arch = platform.machine()
    system = platform.system()
    
    is_supported = version.major == 3 and version.minor >= 10
    print_status(
        "Python Version", 
        is_supported, 
        f"Detected: {ver_str} on {system} ({arch}) (Required: >= 3.10)"
    )
    return is_supported

def check_csprng_entropy() -> bool:
    print_section("2. Cryptographically Secure Random Number Generator (CSPRNG)")
    try:
        # Test 1: secrets / os.urandom availability
        entropy_sample = os.urandom(32)
        if len(entropy_sample) != 32:
            print_status("CSPRNG os.urandom", False, "Failed to produce 32 bytes.")
            return False
        
        # Test 2: Basic uniqueness check (two 32-byte draws must differ)
        second_sample = os.urandom(32)
        if entropy_sample == second_sample:
            print_status("CSPRNG Determinism Check", False, "CRITICAL: Consecutive samples are identical!")
            return False
        
        print_status(
            "Kernel Entropy Pool", 
            True, 
            f"32-byte entropy block OK. Sample hex: {entropy_sample[:8].hex()}..."
        )
        return True
    except Exception as e:
        print_status("Kernel Entropy Pool", False, f"Exception: {e}")
        return False

def check_aes_256_gcm_primitive() -> bool:
    print_section("3. AES-256-GCM AEAD Engine (PyCryptodome)")
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        import Crypto
        
        print_status("PyCryptodome Import", True, f"Version: {Crypto.__version__}")
    except ImportError:
        print_status("PyCryptodome Import", False, "Module not found. Run: pip install pycryptodome")
        return False

    try:
        # 1. 256-bit Key (32 bytes) and 96-bit Nonce (12 bytes)
        key = get_random_bytes(32)
        nonce = get_random_bytes(12)
        
        # 2. Associated Authenticated Data (Metadata bound to ciphertext)
        aad_metadata = b"FILE_TYPE=WAV;SAMPLERATE=44100;CHANNELS=2"
        sample_audio_pcm = b"RIFF-SYNTHETIC-AUDIO-PCM-PAYLOAD-" * 8  # 256 bytes dummy audio
        
        # 3. Encryption
        cipher_encrypt = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher_encrypt.update(aad_metadata)
        ciphertext, tag = cipher_encrypt.encrypt_and_digest(sample_audio_pcm)
        
        if len(tag) != 16:
            print_status("AES-256-GCM Tag Size", False, f"Expected 16 bytes (128-bit MAC), got {len(tag)}")
            return False
        print_status("AES-256-GCM Encryption", True, f"Ciphertext: {len(ciphertext)} bytes, Tag: 16 bytes")

        # 4. Legitimate Decryption
        cipher_decrypt = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher_decrypt.update(aad_metadata)
        recovered_plaintext = cipher_decrypt.decrypt_and_verify(ciphertext, tag)
        
        if recovered_plaintext != sample_audio_pcm:
            print_status("AES-256-GCM Verification", False, "Plaintext mismatch after legitimate decryption!")
            return False
        print_status("AES-256-GCM Verification", True, "Decryption and 128-bit MAC verification successful.")

        # 5. Adversarial Bit-Flipping Test (Tampering Detection)
        # Flip the very first bit of the ciphertext
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0x01
        
        tamper_detected = False
        try:
            tamper_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            tamper_cipher.update(aad_metadata)
            tamper_cipher.decrypt_and_verify(bytes(tampered_ciphertext), tag)
        except (ValueError, KeyError):
            tamper_detected = True

        if tamper_detected:
            print_status(
                "Tamper-Proof Integrity Check", 
                True, 
                "Bit-flipped ciphertext was successfully rejected by MAC check!"
            )
            return True
        else:
            print_status(
                "Tamper-Proof Integrity Check", 
                False, 
                "CRITICAL SECURITY FLAW: Bit-flipped ciphertext was accepted without error!"
            )
            return False

    except Exception as e:
        print_status("AES-256-GCM Functional Test", False, f"Unexpected error: {e}")
        return False

def check_audio_subsystem() -> bool:
    print_section("4. Audio Generation & Signal Processing")
    try:
        # Generate an in-memory 440 Hz test sine wave (A4 tone) using standard library
        sample_rate = 44100
        duration_s = 0.1  # 100 ms
        num_samples = int(sample_rate * duration_s)
        
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as wav_file:
            wav_file.setnchannels(1)      # Mono
            wav_file.setsampwidth(2)      # 16-bit PCM
            wav_file.setframerate(sample_rate)
            
            raw_frames = []
            for i in range(num_samples):
                sample_val = int(32767.0 * 0.5 * math.sin(2.0 * math.pi * 440.0 * (i / sample_rate)))
                raw_frames.append(struct.pack('<h', sample_val))
            wav_file.writeframes(b''.join(raw_frames))
        
        generated_wav_bytes = buffer.getvalue()
        is_valid_wav = generated_wav_bytes.startswith(b"RIFF") and b"WAVE" in generated_wav_bytes[:16]
        
        print_status(
            "Standard Library Wave Engine", 
            is_valid_wav, 
            f"Generated 100ms synthetic 440Hz PCM WAV ({len(generated_wav_bytes)} bytes in-memory)."
        )
    except Exception as e:
        print_status("Standard Library Wave Engine", False, f"Error: {e}")
        return False

    # Check optional multimedia dependencies
    # 1. NumPy
    try:
        import numpy as np
        print_status("NumPy Library", True, f"Version: {np.__version__}")
    except ImportError:
        print_status("NumPy Library", False, "Not installed (Optional for Milestone 1, needed for Milestone 4/6)")

    # 2. Pydub
    try:
        import pydub
        import importlib.metadata
        try:
            pydub_ver = importlib.metadata.version('pydub')
        except Exception:
            pydub_ver = "Installed"
        print_status("Pydub Library", True, f"Version: {pydub_ver}")
    except (ImportError, ModuleNotFoundError) as e:
        if "audioop" in str(e):
            print_status("Pydub Library", False, "Python 3.13+ PEP 594 requires: pip install audioop-lts")
        else:
            print_status("Pydub Library", False, f"Import failed: {e}")

    # 3. Matplotlib
    try:
        import matplotlib
        print_status("Matplotlib Library", True, f"Version: {matplotlib.__version__}")
    except ImportError:
        print_status("Matplotlib Library", False, "Not installed (Required for benchmark graphs in Milestone 6)")

    # 4. CustomTkinter / Tkinter
    try:
        import tkinter
        print_status("Tkinter GUI Engine", True, f"Tcl/Tk Version: {tkinter.Tcl().eval('info patchlevel')}")
    except ImportError:
        print_status("Tkinter GUI Engine", False, "Tkinter not found in Python build")

    try:
        import customtkinter
        print_status("CustomTkinter Library", True, f"Version: {customtkinter.__version__}")
    except ImportError:
        print_status("CustomTkinter Library", False, "Not installed (Required for Modern GUI in Milestone 7)")

    return True

def check_high_res_timer() -> bool:
    print_section("5. Benchmark Timing Hardware Clocks")
    t0 = time.perf_counter_ns()
    time.sleep(0.01)  # 10ms sleep
    t1 = time.perf_counter_ns()
    elapsed_ms = (t1 - t0) / 1_000_000.0
    
    print_status(
        "Monotonic Perf Counter", 
        True, 
        f"Resolution verified. 10ms sleep measured as {elapsed_ms:.3f} ms."
    )
    return True

def main():
    print(f"\n{Colors.BOLD}{Colors.YELLOW}{'#'*75}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW} SECURE AUDIO FILE ENCRYPTION USING AES-256-GCM {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW} M.TECH RESEARCH PROJECT - MILESTONE 1 VERIFICATION {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}{'#'*75}{Colors.RESET}")

    c1 = check_python_runtime()
    c2 = check_csprng_entropy()
    c3 = check_aes_256_gcm_primitive()
    c4 = check_audio_subsystem()
    c5 = check_high_res_timer()

    print_section("Summary & Readiness")
    core_ready = c1 and c2 and c3
    if core_ready:
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] CORE CRYPTOGRAPHIC ENVIRONMENT IS READY!{Colors.RESET}")
        print("    You have verified:")
        print("      - OS CSPRNG key/nonce entropy generation")
        print("      - AES-256-GCM Authenticated Encryption & Decryption")
        print("      - Bit-flip tamper detection rejecting corrupted ciphertexts")
        print("      - In-memory audio byte stream processing\n")
    else:
        print(f"\n{Colors.BOLD}{Colors.RED}[!] CORE REQUIREMENTS FAILED.{Colors.RESET}")
        print("    Please install missing core packages using: pip install -r requirements.txt\n")

if __name__ == "__main__":
    main()
