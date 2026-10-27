"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.core.key_manager
==============================================================================
M.Tech Cryptography & Information Security Specification:
  - NIST SP 800-132: Recommendation for Password-Based Key Derivation
  - OWASP Password Storage Guidelines (PBKDF2-HMAC-SHA256 >= 600,000 iterations)
  - CSPRNG (Cryptographically Secure Pseudo-Random Number Generation)
==============================================================================
"""

import os
import binascii
from typing import Tuple, Optional
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Standard Cryptographic Constants
AES_256_KEY_SIZE_BYTES = 32      # 256 bits
GCM_NONCE_SIZE_BYTES = 12         # 96 bits (Standard NIST SP 800-38D recommendation)
SALT_SIZE_BYTES = 16              # 128 bits
DEFAULT_PBKDF2_ITERATIONS = 600_000  # OWASP minimum standard for PBKDF2-SHA256

class KeyManager:
    """
    Manages cryptographic key lifecycle, entropy generation, and derivation.
    Supports:
      1. Direct 256-bit CSPRNG Master Key generation (Machine-to-Machine / Pre-shared).
      2. Human Password-Based Key Derivation (PBKDF2-HMAC-SHA256) with unique salt.
      3. Nonce generation with strict 96-bit length enforcement.
    """

    @staticmethod
    def generate_master_key() -> bytes:
        """
        Generates a 256-bit (32 bytes) cryptographically random master key
        sourced directly from the operating system's kernel entropy pool.
        """
        return get_random_bytes(AES_256_KEY_SIZE_BYTES)

    @staticmethod
    def generate_salt() -> bytes:
        """
        Generates a 128-bit (16 bytes) random salt for key derivation.
        Salt prevents rainbow table and precomputed dictionary attacks.
        """
        return get_random_bytes(SALT_SIZE_BYTES)

    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generates a fresh 96-bit (12 bytes) nonce for AES-GCM.
        
        CRITICAL SECURITY INVARIANT:
        A (Key, Nonce) pair must NEVER be reused for encrypting multiple files.
        96 bits from CSPRNG guarantees collision resistance across practical operational lifetimes.
        """
        return get_random_bytes(GCM_NONCE_SIZE_BYTES)

    @staticmethod
    def derive_key_from_password(
        password: str, 
        salt: Optional[bytes] = None, 
        iterations: int = DEFAULT_PBKDF2_ITERATIONS
    ) -> Tuple[bytes, bytes]:
        """
        Derives a 256-bit AES key from a human passphrase using PBKDF2-HMAC-SHA256.
        
        Args:
            password: User-provided passphrase.
            salt: Optional 16-byte salt. If None, a fresh CSPRNG salt is generated.
            iterations: Iteration count (work factor) to slow down GPU/ASIC brute forcing.
            
        Returns:
            Tuple[bytes, bytes]: (derived_key_32_bytes, salt_16_bytes)
        """
        if not password or len(password) < 6:
            raise ValueError("Passphrase must be at least 6 characters for sufficient entropy.")

        if salt is None:
            salt = KeyManager.generate_salt()
        elif len(salt) != SALT_SIZE_BYTES:
            raise ValueError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes, got {len(salt)}.")

        if iterations < 100_000:
            raise ValueError("Iteration count below 100,000 violates security threshold.")

        derived_key = PBKDF2(
            password=password.encode('utf-8'),
            salt=salt,
            dkLen=AES_256_KEY_SIZE_BYTES,
            count=iterations,
            hmac_hash_module=SHA256
        )

        return derived_key, salt

    @staticmethod
    def key_to_hex(key_bytes: bytes) -> str:
        """Encodes raw key bytes to hexadecimal string for secure display/logging."""
        return binascii.hexlify(key_bytes).decode('ascii')

    @staticmethod
    def hex_to_key(key_hex: str) -> bytes:
        """Decodes hexadecimal string back to raw 32-byte key."""
        clean_hex = key_hex.strip()
        raw = binascii.unhexlify(clean_hex)
        if len(raw) != AES_256_KEY_SIZE_BYTES:
            raise ValueError(f"Key must be exactly {AES_256_KEY_SIZE_BYTES} bytes (64 hex characters).")
        return raw
