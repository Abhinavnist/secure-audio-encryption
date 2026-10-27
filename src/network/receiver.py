"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.network.receiver
==============================================================================
Server endpoint that listens for encrypted audio transmissions,
validates freshness, enforces replay prevention, and decrypts the audio.
==============================================================================
"""

import os
import socket
import json
import threading
from typing import Optional, Dict, Any, Callable
from src.network.protocol import (
    recv_packet, 
    send_packet, 
    MSG_TYPE_DATA, 
    MSG_TYPE_ACK, 
    MSG_TYPE_ERROR,
    ReplayGuard, 
    ReplayAttackError
)
from src.core.cipher import AudioCipher, AuthenticationError

class AudioReceiverServer:
    """
    Authenticated Audio Receiver Service.
    """
    def __init__(
        self, 
        host: str = "127.0.0.1", 
        port: int = 9099, 
        storage_dir: str = "storage/received",
        passphrase: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.storage_dir = storage_dir
        self.passphrase = passphrase
        self.replay_guard = ReplayGuard()
        self.is_running = False
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        os.makedirs(self.storage_dir, exist_ok=True)

    def start(self, blocking: bool = False):
        """Starts TCP listener."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(5)
        self.is_running = True

        if blocking:
            self._serve()
        else:
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

    def stop(self):
        """Stops TCP listener."""
        self.is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def handle_client_socket(self, client_sock: socket.socket, client_addr: Any = "connected_stream"):
        """Directly handles an established client socket (works for TCP and socketpair)."""
        self._handle_client(client_sock, client_addr)

    def _serve(self):
        while self.is_running:
            try:
                client_sock, client_addr = self._server_sock.accept()
                client_handler = threading.Thread(
                    target=self._handle_client, 
                    args=(client_sock, client_addr), 
                    daemon=True
                )
                client_handler.start()
            except Exception:
                if not self.is_running:
                    break

    def _handle_client(self, client_sock: socket.socket, client_addr: Any):
        try:
            # 1. Receive framed transmission packet
            msg_type, tx_id, timestamp_ms, payload = recv_packet(client_sock)

            if msg_type != MSG_TYPE_DATA:
                err_resp = json.dumps({"error": f"Unexpected message type: {msg_type}"}).encode('utf-8')
                send_packet(client_sock, MSG_TYPE_ERROR, err_resp, tx_id)
                return

            # 2. Check Replay Attack Prevention Guard
            self.replay_guard.validate_packet(tx_id, timestamp_ms)

            # 3. Store encrypted container payload to disk
            safeaudio_path = os.path.join(self.storage_dir, f"received_{tx_id.hex()[:8]}.safeaudio")
            with open(safeaudio_path, 'wb') as f:
                f.write(payload)

            # 4. Decrypt received audio if passphrase configured
            dec_result = None
            if self.passphrase:
                decrypted_dest_path = os.path.join(
                    self.storage_dir, 
                    f"decrypted_{tx_id.hex()[:8]}.wav"
                )
                dec_result = AudioCipher.decrypt_file(
                    input_container_path=safeaudio_path,
                    output_audio_path=decrypted_dest_path,
                    key_or_password=self.passphrase,
                    is_password=True
                )

            # 5. Send ACK confirmation with telemetry
            ack_data = {
                "status": "ACCEPTED",
                "tx_id": tx_id.hex(),
                "bytes_received": len(payload),
                "safeaudio_file": safeaudio_path,
                "decryption_verified": dec_result["lossless_integrity_verified"] if dec_result else False,
                "recovered_sha256": dec_result["decrypted_sha256"] if dec_result else None
            }
            send_packet(client_sock, MSG_TYPE_ACK, json.dumps(ack_data).encode('utf-8'), tx_id)

        except ReplayAttackError as e:
            err_resp = json.dumps({"error": "REPLAY_ATTACK_DETECTED", "details": str(e)}).encode('utf-8')
            send_packet(client_sock, MSG_TYPE_ERROR, err_resp)
        except AuthenticationError as e:
            err_resp = json.dumps({"error": "AUTHENTICATION_FAILED", "details": str(e)}).encode('utf-8')
            send_packet(client_sock, MSG_TYPE_ERROR, err_resp)
        except Exception as e:
            err_resp = json.dumps({"error": "SERVER_ERROR", "details": str(e)}).encode('utf-8')
            try:
                send_packet(client_sock, MSG_TYPE_ERROR, err_resp)
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure Audio Receiver Server")
    parser.add_argument("--port", type=int, default=9099, help="Listening port")
    parser.add_argument("--passphrase", type=str, required=True, help="Decryption passphrase")
    args = parser.parse_args()

    server = AudioReceiverServer(port=args.port, passphrase=args.passphrase)
    print(f"[*] Secure Audio Receiver listening on port {args.port}...")
    server.start(blocking=True)
