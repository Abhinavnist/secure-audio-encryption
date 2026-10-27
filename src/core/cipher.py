"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.core.cipher
==============================================================================
Cryptographic Specifications:
  - NIST SP 800-38D (Galois/Counter Mode)
  - RFC 5116 (AEAD)
  - Constant memory streaming architecture (handles multi-GB audio files)
  - Release of Unverified Plaintext (RUP) protection on tamper detection
==============================================================================
"""

import os
import time
import struct
import json
from typing import Dict, Any, Optional, Union
from Crypto.Cipher import AES

from src.core.key_manager import (
    KeyManager, 
    AES_256_KEY_SIZE_BYTES, 
    GCM_NONCE_SIZE_BYTES, 
    DEFAULT_PBKDF2_ITERATIONS
)
from src.core.container import (
    AudioContainer, 
    MAGIC_BYTES, 
    CURRENT_VERSION, 
    KDF_TYPE_RAW_KEY, 
    KDF_TYPE_PBKDF2, 
    FIXED_HEADER_FORMAT, 
    FIXED_HEADER_SIZE, 
    TAG_SIZE, 
    InvalidContainerError
)
from src.audio.audio_handler import AudioHandler

class AuthenticationError(Exception):
    """Raised when AES-GCM 128-bit MAC tag check fails (wrong key or tampering)."""
    pass

class AudioCipher:
    """
    High-performance, authenticated streaming AES-256-GCM encryption/decryption engine.
    """

    DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB buffer: optimal for L1/L2 cache

    @classmethod
    def encrypt_file(
        cls,
        input_audio_path: str,
        output_container_path: str,
        key_or_password: Union[str, bytes],
        is_password: bool = True,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> Dict[str, Any]:
        """
        Encrypts a digital audio file (WAV, MP3, FLAC) into a .safeaudio container.
        
        Args:
            input_audio_path: Path to original audio file.
            output_container_path: Destination path (.safeaudio).
            key_or_password: Human passphrase (str) or 256-bit raw key (bytes/hex str).
            is_password: True if passphrase derivation (PBKDF2) is to be used.
            iterations: PBKDF2 iteration count (default: 600,000).
            chunk_size: Streaming buffer size in bytes.
            
        Returns:
            Dict containing performance metrics and encryption metadata.
        """
        if not os.path.exists(input_audio_path):
            raise FileNotFoundError(f"Input audio file not found: {input_audio_path}")

        # 1. Extract audio metadata & original SHA-256
        metadata = AudioHandler.extract_metadata(input_audio_path)
        original_size = metadata["file_size_bytes"]

        # 2. Key Acquisition & KDF
        t_start = time.perf_counter()
        if is_password:
            if not isinstance(key_or_password, str):
                raise TypeError("When is_password=True, passphrase must be a string.")
            kdf_type = KDF_TYPE_PBKDF2
            key, salt = KeyManager.derive_key_from_password(
                password=key_or_password, 
                iterations=iterations
            )
        else:
            kdf_type = KDF_TYPE_RAW_KEY
            iterations = 0
            salt = b"\x00" * 16  # Null salt for raw key
            if isinstance(key_or_password, str):
                key = KeyManager.hex_to_key(key_or_password)
            elif isinstance(key_or_password, bytes):
                if len(key_or_password) != AES_256_KEY_SIZE_BYTES:
                    raise ValueError(f"Raw key must be exactly {AES_256_KEY_SIZE_BYTES} bytes.")
                key = key_or_password
            else:
                raise TypeError("Raw key must be 32 bytes or 64-char hex string.")

        # 3. Fresh CSPRNG Nonce (CRITICAL: 96-bit unique per encryption)
        nonce = KeyManager.generate_nonce()

        # 4. Pack Container Header (This entire header is the AAD)
        aad_header = AudioContainer.pack_header(
            kdf_type=kdf_type,
            iterations=iterations,
            salt=salt,
            nonce=nonce,
            metadata=metadata
        )

        # 5. Initialize AES-256-GCM Cipher & Feed AAD
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad_header)

        # 6. Stream Plaintext -> Ciphertext directly to file
        os.makedirs(os.path.dirname(os.path.abspath(output_container_path)), exist_ok=True)
        aad_header_len = len(aad_header)

        with open(output_container_path, 'wb') as out_f, open(input_audio_path, 'rb') as in_f:
            # Step A: Write AAD Header
            out_f.write(aad_header)
            # Step B: Write 16-byte placeholder for Tag
            out_f.write(b"\x00" * TAG_SIZE)

            # Step C: Stream chunks
            while chunk := in_f.read(chunk_size):
                ciphertext_chunk = cipher.encrypt(chunk)
                out_f.write(ciphertext_chunk)

            # Step D: Compute 128-bit GHASH Tag over AAD and Ciphertext
            tag = cipher.digest()

            # Step E: Seek back to tag slot and write authentic tag
            out_f.seek(aad_header_len)
            out_f.write(tag)

        t_end = time.perf_counter()
        elapsed_sec = t_end - t_start
        encrypted_size = os.path.getsize(output_container_path)
        throughput_mb_s = (original_size / (1024 * 1024)) / elapsed_sec if elapsed_sec > 0 else 0.0

        return {
            "status": "SUCCESS",
            "operation": "ENCRYPTION",
            "original_file": input_audio_path,
            "encrypted_file": output_container_path,
            "original_size_bytes": original_size,
            "encrypted_size_bytes": encrypted_size,
            "header_overhead_bytes": encrypted_size - original_size,
            "elapsed_seconds": round(elapsed_sec, 4),
            "throughput_mb_s": round(throughput_mb_s, 2),
            "nonce_hex": KeyManager.key_to_hex(nonce),
            "salt_hex": KeyManager.key_to_hex(salt),
            "tag_hex": KeyManager.key_to_hex(tag),
            "sha256": metadata["sha256_checksum"]
        }

    @classmethod
    def decrypt_file(
        cls,
        input_container_path: str,
        output_audio_path: Optional[str] = None,
        key_or_password: Union[str, bytes] = "",
        is_password: bool = True,
        chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> Dict[str, Any]:
        """
        Decrypts a .safeaudio container and verifies 128-bit GHASH authentication tag.
        Enforces Release of Unverified Plaintext (RUP) security: if tag fails,
        any decrypted bytes are instantly purged and never released.
        """
        if not os.path.exists(input_container_path):
            raise FileNotFoundError(f"Container file not found: {input_container_path}")

        t_start = time.perf_counter()

        with open(input_container_path, 'rb') as in_f:
            # 1. Read fixed header prefix
            fixed_bytes = in_f.read(FIXED_HEADER_SIZE)
            if len(fixed_bytes) < FIXED_HEADER_SIZE:
                raise InvalidContainerError("File is too small to contain a valid .safeaudio header.")

            magic, version, kdf_type, iterations, salt, nonce, meta_len = struct.unpack(
                FIXED_HEADER_FORMAT, fixed_bytes
            )

            if magic != MAGIC_BYTES:
                raise InvalidContainerError(f"Invalid magic signature: {magic!r}")
            if version != CURRENT_VERSION:
                raise InvalidContainerError(f"Unsupported container version: {version}")

            # 2. Read dynamic JSON metadata
            meta_bytes = in_f.read(meta_len)
            if len(meta_bytes) != meta_len:
                raise InvalidContainerError("Container corrupted: incomplete metadata payload.")

            try:
                metadata = json.loads(meta_bytes.decode('utf-8'))
            except Exception as e:
                raise InvalidContainerError(f"Failed to parse container metadata: {e}")

            # 3. Read 16-byte GHASH Authentication Tag
            tag = in_f.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise InvalidContainerError("Container corrupted: missing authentication tag.")

            # Reconstruct exact AAD header bytes (Fixed + Metadata)
            aad_header = fixed_bytes + meta_bytes

            # 4. Key Derivation / Resolution
            if is_password:
                if not isinstance(key_or_password, str):
                    raise TypeError("When is_password=True, passphrase must be a string.")
                if kdf_type != KDF_TYPE_PBKDF2:
                    raise ValueError("Container was encrypted with a raw key, not a passphrase.")
                key, _ = KeyManager.derive_key_from_password(
                    password=key_or_password, 
                    salt=salt, 
                    iterations=iterations
                )
            else:
                if kdf_type != KDF_TYPE_RAW_KEY:
                    raise ValueError("Container was encrypted with a passphrase, not a raw key.")
                if isinstance(key_or_password, str):
                    key = KeyManager.hex_to_key(key_or_password)
                elif isinstance(key_or_password, bytes):
                    key = key_or_password
                else:
                    raise TypeError("Raw key must be bytes or hex string.")

            # 5. Initialize AES-256-GCM Cipher & Feed AAD
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(aad_header)

            # Determine destination output path
            if output_audio_path is None:
                parent_dir = os.path.dirname(os.path.abspath(input_container_path))
                output_audio_path = os.path.join(parent_dir, f"decrypted_{metadata.get('original_filename', 'audio.wav')}")

            temp_output_path = output_audio_path + ".tmp_decrypted"
            os.makedirs(os.path.dirname(os.path.abspath(output_audio_path)), exist_ok=True)

            # 6. Stream Ciphertext -> Decrypt into temporary file (RUP Protection)
            try:
                with open(temp_output_path, 'wb') as temp_f:
                    while chunk := in_f.read(chunk_size):
                        plaintext_chunk = cipher.decrypt(chunk)
                        temp_f.write(plaintext_chunk)

                # 7. CRITICAL VERIFICATION: Check 128-bit GHASH Tag
                cipher.verify(tag)

            except (ValueError, KeyError) as e:
                # MAC verification failed! Wipe temporary file immediately!
                if os.path.exists(temp_output_path):
                    try:
                        os.remove(temp_output_path)
                    except OSError:
                        pass
                raise AuthenticationError(
                    "CRITICAL SECURITY ALERT: MAC check failed! "
                    "The audio file has been tampered with, or an invalid key/passphrase was provided."
                ) from e
            except Exception:
                if os.path.exists(temp_output_path):
                    try:
                        os.remove(temp_output_path)
                    except OSError:
                        pass
                raise

        # 8. Post-Verification: Commit atomic file replacement
        if os.path.exists(output_audio_path):
            os.remove(output_audio_path)
        os.replace(temp_output_path, output_audio_path)

        t_end = time.perf_counter()
        elapsed_sec = t_end - t_start
        decrypted_size = os.path.getsize(output_audio_path)
        throughput_mb_s = (decrypted_size / (1024 * 1024)) / elapsed_sec if elapsed_sec > 0 else 0.0

        # 9. Verify bit-for-bit lossless SHA-256 match
        decrypted_sha256 = AudioHandler.calculate_sha256(output_audio_path)
        expected_sha256 = metadata.get("sha256_checksum")
        integrity_verified = (decrypted_sha256 == expected_sha256)

        return {
            "status": "SUCCESS",
            "operation": "DECRYPTION",
            "container_file": input_container_path,
            "recovered_file": output_audio_path,
            "decrypted_size_bytes": decrypted_size,
            "elapsed_seconds": round(elapsed_sec, 4),
            "throughput_mb_s": round(throughput_mb_s, 2),
            "lossless_integrity_verified": integrity_verified,
            "original_sha256": expected_sha256,
            "decrypted_sha256": decrypted_sha256,
            "metadata": metadata
        }
