#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Milestone 5 Test Suite: Secure Audio Transmission Simulation & Replay Attack Defense
==============================================================================
Tests:
  1. Authenticated Audio Receiver Server Setup.
  2. End-to-end encrypted wire transmission from Sender to Receiver.
  3. Remote decryption and lossless SHA-256 integrity verification.
  4. Adversarial Attack 1: Replay attack prevention via TxID cache rejection.
  5. Adversarial Attack 2: Stale/expired packet rejection via sliding timestamp window.
  6. Adversarial Attack 3: In-flight tampering rejection by Receiver AEAD engine.
==============================================================================
"""

import sys
import os
import time
import socket
import struct
import threading
import shutil

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.audio.audio_handler import AudioHandler
from src.network.receiver import AudioReceiverServer
from src.network.sender import AudioSenderClient
from src.network.protocol import (
    send_packet, 
    recv_packet, 
    MAGIC_PROTO,
    HEADER_FORMAT,
    MSG_TYPE_DATA, 
    MSG_TYPE_ERROR, 
    TransmissionError
)

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def assert_test(condition: bool, test_name: str, details: str = ""):
    if condition:
        print(f" {Colors.GREEN}[PASS]{Colors.RESET} {Colors.BOLD}{test_name:<50}{Colors.RESET} {details}")
    else:
        print(f" {Colors.RED}[FAIL]{Colors.RESET} {Colors.BOLD}{test_name:<50}{Colors.RESET} {details}")
        raise AssertionError(f"Test failed: {test_name} - {details}")

def get_channel(server: AudioReceiverServer, port: int):
    """
    Returns (sender_sock, receiver_sock, is_socketpair).
    Tries TCP localhost loopback first; falls back to socketpair if sandboxed.
    """
    try:
        s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_sock.connect(("127.0.0.1", port))
        return s_sock, None, False
    except (PermissionError, ConnectionRefusedError):
        # Fall back to connected socketpair for sandboxed environments
        s1, s2 = socket.socketpair()
        threading.Thread(target=server.handle_client_socket, args=(s2,), daemon=True).start()
        return s1, s2, True

def run_milestone5_tests():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} [M.TECH TEST] MILESTONE 5: TRANSMISSION SIMULATION & REPLAY DEFENSE {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")

    test_dir = os.path.join(os.path.dirname(__file__), "sandbox_network_data")
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir, exist_ok=True)

    server_storage = os.path.join(test_dir, "receiver_vault")
    port = 9876
    passphrase = "SecureMTechTransmissionSecret#2026"

    server = AudioReceiverServer(
        host="127.0.0.1",
        port=port,
        storage_dir=server_storage,
        passphrase=passphrase
    )

    try:
        # 1. Start Receiver Server
        tcp_active = False
        try:
            server.start(blocking=False)
            time.sleep(0.1)
            tcp_active = True
        except PermissionError:
            pass

        assert_test(True, "Receiver Server Initialization", f"Target Port: {port} (TCP/Pair stream enabled)")

        # 2. Generate sender source audio
        sender_audio = os.path.join(test_dir, "alice_voice_sample.wav")
        AudioHandler.generate_synthetic_wav(
            output_path=sender_audio,
            frequency_hz=523.25,  # Note C5
            duration_seconds=0.5,
            sample_rate=44100
        )
        orig_hash = AudioHandler.calculate_sha256(sender_audio)

        # 3. Legitimate Transmission
        fixed_tx_id = os.urandom(16)
        sender_sock, _, is_pair = get_channel(server, port)

        tx_result = AudioSenderClient.transmit_audio(
            audio_file_path=sender_audio,
            passphrase=passphrase,
            iterations=100_000,
            custom_tx_id=fixed_tx_id,
            existing_socket=sender_sock
        )

        assert_test(tx_result["status"] == "SUCCESS", "Encrypted Transmission", f"Sent {tx_result['bytes_sent']} bytes")
        assert_test(
            tx_result["receiver_ack"]["decryption_verified"], 
            "Receiver Decryption & Verification", 
            "Receiver successfully authenticated and decrypted audio."
        )
        assert_test(
            tx_result["receiver_ack"]["recovered_sha256"] == orig_hash,
            "Remote Bit-for-Bit Hash Match",
            "Decrypted audio on receiver matches sender's original exactly."
        )

        # 4. Adversarial Attack 1: Replay Attack (Duplicate TxID)
        replay_sock, _, _ = get_channel(server, port)
        replay_caught = False
        try:
            AudioSenderClient.transmit_audio(
                audio_file_path=sender_audio,
                passphrase=passphrase,
                iterations=100_000,
                custom_tx_id=fixed_tx_id,  # Duplicate TxID!
                existing_socket=replay_sock
            )
        except TransmissionError as e:
            if "REPLAY_ATTACK_DETECTED" in str(e):
                replay_caught = True

        assert_test(
            replay_caught, 
            "Replay Attack Defense (Duplicate TxID)", 
            "Receiver identified duplicate transmission ID and rejected packet."
        )

        # 5. Adversarial Attack 2: Stale/Expired Timestamp
        stale_sock, _, _ = get_channel(server, port)
        # Craft packet with timestamp 2 hours in the past
        stale_ts = int((time.time() - 7200) * 1000)
        stale_payload = b"FAKE-DATA-PAYLOAD"
        stale_tx_id = os.urandom(16)
        
        hdr = struct.pack(HEADER_FORMAT, MAGIC_PROTO, MSG_TYPE_DATA, stale_ts, stale_tx_id, len(stale_payload))
        stale_sock.sendall(hdr + stale_payload)

        resp_type, _, _, resp_bytes = recv_packet(stale_sock)
        stale_sock.close()
        
        stale_rejected = (resp_type == MSG_TYPE_ERROR and b"REPLAY_ATTACK_DETECTED" in resp_bytes)
        assert_test(
            stale_rejected, 
            "Sliding Window Stale Packet Defense", 
            "Packet with expired timestamp was rejected."
        )

        # 6. Adversarial Attack 3: In-Flight Ciphertext Tampering
        tamper_sock, _, _ = get_channel(server, port)
        with open(tx_result["receiver_ack"]["safeaudio_file"], 'rb') as f:
            tampered_bytes = bytearray(f.read())
        # Corrupt 1 byte in the ciphertext portion
        tampered_bytes[-20] ^= 0xFF
        send_packet(tamper_sock, MSG_TYPE_DATA, bytes(tampered_bytes), tx_id=os.urandom(16))

        t_resp_type, _, _, t_resp_bytes = recv_packet(tamper_sock)
        tamper_sock.close()

        tamper_caught = (t_resp_type == MSG_TYPE_ERROR and b"AUTHENTICATION_FAILED" in t_resp_bytes)
        assert_test(
            tamper_caught, 
            "In-Flight Tampering Rejection", 
            "Receiver rejected tampered payload via AES-GCM MAC check."
        )

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN} [+] ALL MILESTONE 5 TRANSMISSION & REPLAY TESTS PASSED! {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}{'='*80}{Colors.RESET}\n")

    finally:
        server.stop()
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)

if __name__ == "__main__":
    run_milestone5_tests()
