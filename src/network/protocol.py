"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.network.protocol
==============================================================================
M.Tech Specification: Secure Transport Framing & Replay Attack Defense
Features:
  1. Fixed 33-byte Binary Wire Framing (Magic, MsgType, Timestamp, TxID, Length).
  2. Cryptographic Replay Attack Mitigation (Sliding Timestamp Window + CSPRNG TxID Cache).
  3. Safe chunked socket stream transport.
==============================================================================
"""

import time
import struct
import socket
import os
from typing import Tuple, Dict, Any, Optional

MAGIC_PROTO = b"STXP"  # Secure Transmission Protocol
MSG_TYPE_DATA = 1
MSG_TYPE_ACK = 2
MSG_TYPE_ERROR = 3

# Header Layout: Magic(4s) + Type(B) + Timestamp_ms(Q) + TxID(16s) + PayloadLen(I)
# Total size: 4 + 1 + 8 + 16 + 4 = 33 bytes
HEADER_FORMAT = ">4sB Q 16s I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_CLOCK_SKEW_MS = 60_000  # 60 seconds allowable clock skew window

class TransmissionError(Exception):
    """Raised on socket framing or network protocol failure."""
    pass

class ReplayAttackError(Exception):
    """Raised when an attacker attempts to retransmit a previously captured audio payload."""
    pass

class ReplayGuard:
    """
    Maintains a sliding timestamp window and seen transaction ID cache to thwart replay attacks.
    """
    def __init__(self, window_ms: int = MAX_CLOCK_SKEW_MS):
        self.window_ms = window_ms
        self.seen_tx_ids: Dict[bytes, int] = {}

    def validate_packet(self, tx_id: bytes, timestamp_ms: int):
        now_ms = int(time.time() * 1000)

        # 1. Freshness check: reject packets outside the sliding window
        if abs(now_ms - timestamp_ms) > self.window_ms:
            raise ReplayAttackError(
                f"Packet timestamp rejected! Clock skew: {abs(now_ms - timestamp_ms)}ms "
                f"exceeds tolerance of {self.window_ms}ms."
            )

        # 2. Duplicate TxID check
        if tx_id in self.seen_tx_ids:
            raise ReplayAttackError(
                f"CRITICAL SECURITY ALERT: Replay Attack detected! Duplicate TxID: {tx_id.hex()}"
            )

        # 3. Purge expired TxIDs to prevent memory bloat
        cutoff = now_ms - self.window_ms
        self.seen_tx_ids = {tid: ts for tid, ts in self.seen_tx_ids.items() if ts > cutoff}

        # 4. Record new transaction ID
        self.seen_tx_ids[tx_id] = timestamp_ms

def send_all(sock: socket.socket, data: bytes):
    """Sends all bytes reliably over socket."""
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise TransmissionError("Socket connection severed during send.")
        total_sent += sent

def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Reads exactly num_bytes from socket."""
    chunks = []
    bytes_recd = 0
    while bytes_recd < num_bytes:
        chunk = sock.recv(min(num_bytes - bytes_recd, 65536))
        if not chunk:
            raise TransmissionError("Socket connection closed prematurely during receive.")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b"".join(chunks)

def send_packet(
    sock: socket.socket, 
    msg_type: int, 
    payload: bytes, 
    tx_id: Optional[bytes] = None
) -> bytes:
    """Serializes and sends a protocol packet. Returns tx_id."""
    if tx_id is None:
        tx_id = os.urandom(16)
    timestamp_ms = int(time.time() * 1000)
    payload_len = len(payload)

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC_PROTO,
        msg_type,
        timestamp_ms,
        tx_id,
        payload_len
    )

    send_all(sock, header + payload)
    return tx_id

def recv_packet(sock: socket.socket) -> Tuple[int, bytes, int, bytes]:
    """
    Receives and unpacks a protocol packet.
    Returns: Tuple[msg_type, tx_id, timestamp_ms, payload_bytes]
    """
    header_bytes = recv_exact(sock, HEADER_SIZE)
    magic, msg_type, timestamp_ms, tx_id, payload_len = struct.unpack(
        HEADER_FORMAT, header_bytes
    )

    if magic != MAGIC_PROTO:
        raise TransmissionError(f"Invalid protocol magic: {magic!r}")

    payload = recv_exact(sock, payload_len)
    return msg_type, tx_id, timestamp_ms, payload
