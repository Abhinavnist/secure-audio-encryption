"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.core.container
==============================================================================
Specification: Custom Binary Container Format (.safeaudio)
Container Binary Layout:
  +--------------------------------------------------------------------------+
  | FIELD               | SIZE (Bytes) | TYPE         | DESCRIPTION          |
  +--------------------------------------------------------------------------+
  | MAGIC               | 4            | Raw Bytes    | ASCII 'SAUD'         |
  | VERSION             | 1            | uint8        | Container Version (1)|
  | KDF_TYPE            | 1            | uint8        | 0=RawKey, 1=PBKDF2   |
  | ITERATIONS          | 4            | uint32 (BE)  | PBKDF2 Iteration count|
  | SALT                | 16           | Raw Bytes    | CSPRNG Salt (128-bit)|
  | NONCE               | 12           | Raw Bytes    | GCM Nonce (96-bit)   |
  | METADATA_LEN        | 2            | uint16 (BE)  | Length of JSON Meta  |
  | METADATA            | N            | UTF-8 JSON   | Dynamic Audio Meta   |
  +--------------------------------------------------------------------------+
  | TAG (GHASH MAC)     | 16           | Raw Bytes    | 128-bit GCM Auth Tag |
  +--------------------------------------------------------------------------+
  | CIPHERTEXT          | L            | Raw Bytes    | AES-256-GCM Payload  |
  +--------------------------------------------------------------------------+

Cryptographic Security Binding:
  The entire HEADER block (Magic to Metadata inclusive, total 40 + N bytes)
  serves as the Associated Authenticated Data (AAD) for AES-GCM.
  Any modification to the header or metadata will cause MAC verification failure!
==============================================================================
"""

import json
import struct
from typing import Dict, Any, Tuple

# Container Constants
MAGIC_BYTES = b"SAUD"
CURRENT_VERSION = 1
KDF_TYPE_RAW_KEY = 0
KDF_TYPE_PBKDF2 = 1

# Fixed-size header layout prefix:
# Magic(4) + Version(1) + KDF_Type(1) + Iterations(4) + Salt(16) + Nonce(12) + MetaLen(2)
# Format: >4s B B I 16s 12s H  (Total = 40 bytes)
FIXED_HEADER_FORMAT = ">4sBBI16s12sH"
FIXED_HEADER_SIZE = struct.calcsize(FIXED_HEADER_FORMAT)  # 40 bytes
TAG_SIZE = 16  # 128 bits GHASH tag

class InvalidContainerError(Exception):
    """Raised when file does not adhere to .safeaudio container specification."""
    pass

class AudioContainer:
    """
    Handles serialization and deserialization of the secure .safeaudio binary format.
    """

    @staticmethod
    def pack_header(
        kdf_type: int,
        iterations: int,
        salt: bytes,
        nonce: bytes,
        metadata: Dict[str, Any]
    ) -> bytes:
        """
        Serializes header fields into a binary byte string.
        This byte string is used as Associated Authenticated Data (AAD) in AES-GCM.
        """
        if len(salt) != 16:
            raise ValueError(f"Salt must be 16 bytes, got {len(salt)}")
        if len(nonce) != 12:
            raise ValueError(f"Nonce must be 12 bytes, got {len(nonce)}")

        meta_json_bytes = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
        meta_len = len(meta_json_bytes)
        if meta_len > 65535:
            raise ValueError(f"Metadata exceeds maximum allowed size (65535 bytes): {meta_len}")

        fixed_prefix = struct.pack(
            FIXED_HEADER_FORMAT,
            MAGIC_BYTES,
            CURRENT_VERSION,
            kdf_type,
            iterations,
            salt,
            nonce,
            meta_len
        )

        return fixed_prefix + meta_json_bytes

    @staticmethod
    def unpack_header(stream_or_bytes: bytes) -> Tuple[Dict[str, Any], bytes, bytes]:
        """
        Parses header from bytes.
        
        Returns:
            Tuple[header_info_dict, aad_header_bytes, remaining_bytes]
        """
        if len(stream_or_bytes) < FIXED_HEADER_SIZE:
            raise InvalidContainerError("File is too small to contain a valid .safeaudio header.")

        magic, version, kdf_type, iterations, salt, nonce, meta_len = struct.unpack_from(
            FIXED_HEADER_FORMAT, stream_or_bytes, 0
        )

        if magic != MAGIC_BYTES:
            raise InvalidContainerError(f"Invalid magic signature: expected {MAGIC_BYTES!r}, got {magic!r}")
        if version != CURRENT_VERSION:
            raise InvalidContainerError(f"Unsupported container version: {version}")

        total_header_size = FIXED_HEADER_SIZE + meta_len
        if len(stream_or_bytes) < total_header_size + TAG_SIZE:
            raise InvalidContainerError("File truncated: insufficient data for metadata and auth tag.")

        meta_raw = stream_or_bytes[FIXED_HEADER_SIZE:total_header_size]
        try:
            metadata = json.loads(meta_raw.decode('utf-8'))
        except Exception as e:
            raise InvalidContainerError(f"Corrupted metadata JSON: {e}")

        aad_header_bytes = stream_or_bytes[:total_header_size]
        tag = stream_or_bytes[total_header_size:total_header_size + TAG_SIZE]
        ciphertext = stream_or_bytes[total_header_size + TAG_SIZE:]

        header_info = {
            "version": version,
            "kdf_type": kdf_type,
            "iterations": iterations,
            "salt": salt,
            "nonce": nonce,
            "metadata": metadata,
            "tag": tag,
            "header_size": total_header_size
        }

        return header_info, aad_header_bytes, ciphertext
