"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.network.sender
==============================================================================
Client endpoint that encrypts audio files and securely transmits the
.safeaudio container over TCP to an authenticated receiver.
==============================================================================
"""

import os
import socket
import json
import tempfile
from typing import Dict, Any, Optional
from src.core.cipher import AudioCipher
from src.network.protocol import (
    send_packet, 
    recv_packet, 
    MSG_TYPE_DATA, 
    MSG_TYPE_ACK, 
    MSG_TYPE_ERROR,
    TransmissionError
)

class AudioSenderClient:
    """
    Authenticated Audio Sender Service.
    """
    @staticmethod
    def transmit_audio(
        audio_file_path: str,
        host: str = "127.0.0.1",
        port: int = 9099,
        passphrase: str = "",
        iterations: int = 100_000,
        custom_tx_id: Optional[bytes] = None,
        existing_socket: Optional[socket.socket] = None
    ) -> Dict[str, Any]:
        """
        Encrypts audio with AES-256-GCM and transmits over TCP/stream socket to receiver.
        """
        if not os.path.exists(audio_file_path):
            raise FileNotFoundError(f"Source audio not found: {audio_file_path}")

        # Step 1: Encrypt audio file into temporary .safeaudio container
        with tempfile.NamedTemporaryFile(suffix=".safeaudio", delete=False) as temp_safeaudio:
            temp_container_path = temp_safeaudio.name

        try:
            enc_metrics = AudioCipher.encrypt_file(
                input_audio_path=audio_file_path,
                output_container_path=temp_container_path,
                key_or_password=passphrase,
                is_password=True,
                iterations=iterations
            )

            with open(temp_container_path, 'rb') as f:
                container_bytes = f.read()

            # Step 2: Use existing connected socket or connect to Receiver via TCP
            created_socket = False
            if existing_socket is not None:
                sock = existing_socket
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.connect((host, port))
                created_socket = True

            try:
                # Step 3: Transmit protocol framed packet
                tx_id = send_packet(
                    sock=sock,
                    msg_type=MSG_TYPE_DATA,
                    payload=container_bytes,
                    tx_id=custom_tx_id
                )

                # Step 4: Await Receiver ACK or ERROR response
                resp_type, resp_tx_id, resp_ts, resp_payload = recv_packet(sock)

                if resp_type == MSG_TYPE_ERROR:
                    err_info = json.loads(resp_payload.decode('utf-8'))
                    raise TransmissionError(f"Receiver error: {err_info}")

                if resp_type != MSG_TYPE_ACK:
                    raise TransmissionError(f"Unexpected response code: {resp_type}")

                ack_data = json.loads(resp_payload.decode('utf-8'))

                return {
                    "status": "SUCCESS",
                    "tx_id": tx_id.hex(),
                    "bytes_sent": len(container_bytes),
                    "receiver_ack": ack_data,
                    "encryption_metrics": enc_metrics
                }

            finally:
                if created_socket:
                    sock.close()

        finally:
            if os.path.exists(temp_container_path):
                os.remove(temp_container_path)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure Audio Sender Client")
    parser.add_argument("--file", type=str, required=True, help="Audio file to encrypt and transmit")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Receiver IP")
    parser.add_argument("--port", type=int, default=9099, help="Receiver port")
    parser.add_argument("--passphrase", type=str, required=True, help="Encryption passphrase")
    args = parser.parse_args()

    result = AudioSenderClient.transmit_audio(
        audio_file_path=args.file,
        host=args.host,
        port=args.port,
        passphrase=args.passphrase
    )
    print(f"[+] Transmission Successful: {json.dumps(result, indent=2)}")
