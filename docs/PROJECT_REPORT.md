# M.Tech Dissertation Project Report

**Project Title:** Secure Digital Audio File Encryption and Authenticated Transmission Using AES-256-GCM  
**Degree / Specialization:** M.Tech in Computer Science & Engineering / Information Security & Cryptography  
**Implementation Standard:** NIST SP 800-38D (GCM), RFC 5116 (AEAD), NIST SP 800-132 (PBKDF2)  
**Programming Language & Environment:** Python 3.14 (Darwin arm64 / Apple Silicon), PyCryptodome 4.1.0, CustomTkinter 6.0.0, NumPy, Matplotlib  

---

## 1. Abstract
Digital audio files (WAV, MP3, FLAC) represent high-value multimedia assets containing biometric voice signatures, private conversations, or proprietary intellectual property. Unlike textual data, audio files exhibit high structural redundancy, predictable headers, and large file sizes. This project presents a high-throughput, tamper-evident authenticated audio encryption system based on **AES-256 in Galois/Counter Mode (GCM)**. The system features a custom binary container format (`.safeaudio`), password-based key derivation using PBKDF2-HMAC-SHA256 (600,000 iterations) with 128-bit CSPRNG salts, and 96-bit unique nonces per file. Empirical evaluations demonstrate near-ideal Shannon entropy ($H \approx 7.9976$ bits/byte), streaming throughput scaling up to $114.6\text{ MB/s}$, constant $O(1)$ header overhead ($327\text{ bytes}$), complete unplayability of ciphertext, and 100% bit-for-bit lossless audio reconstruction. Replay attacks are mitigated via a dual sliding timestamp window and transaction ID cache.

---

## 2. Mathematical Formulation & Cryptographic Foundation

### 2.1 AES-256 Block Cipher Primitive
AES operates on 128-bit state matrices using a 256-bit symmetric key ($K$). With 14 rounds of Substitution-Permutation Network (SPN) transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey), the key space is:
$$|\mathcal{K}| = 2^{256} \approx 1.1579 \times 10^{77} \text{ combinations}$$
Under Grover's quantum search algorithm, AES-256 retains a $2^{128}$ operational security level, ensuring long-term post-quantum resistance.

### 2.2 Galois/Counter Mode (GCM) Construction
GCM provides Authenticated Encryption with Associated Data (AEAD):
1. **Counter Mode (CTR) Encryption:**
   Given a 96-bit nonce $IV$ and a 32-bit counter $i$:
   $$Y_i = IV \parallel \text{pad}_{32}(i + 1)$$
   $$C_i = P_i \oplus E_K(Y_i)$$
   Where $P_i$ is the $i$-th audio block. Counter mode turns AES into a stream cipher, eliminating padding oracle vulnerabilities (e.g., POODLE / Vaudenay attacks present in CBC).

2. **Galois Field Authenticator ($\text{GHASH}$ over $GF(2^{128})$):**
   The hash subkey $H = E_K(0^{128})$ evaluates a polynomial over $GF(2^{128})$ defined by the irreducible polynomial:
   $$f(x) = x^{128} + x^7 + x^2 + x + 1$$
   The authentication tag $T$ (128 bits) authenticates both Associated Data ($AAD$) and Ciphertext ($C$):
   $$T = \text{MSB}_{128}\Big( \text{GHASH}_H(AAD \parallel C \parallel \text{len}(AAD) \parallel \text{len}(C)) \oplus E_K(Y_0) \Big)$$
   The forgery probability of a counterfeit audio stream is $\le 2^{-128}$.

---

## 3. Custom Binary Container Specification (`.safeaudio`)

To avoid storing metadata insecurely, a custom 40-byte fixed header plus dynamic JSON metadata is bound cryptographically as Associated Authenticated Data (AAD):

```text
+-----------------------------------------------------------------------------------------+
| FIELD               | SIZE (Bytes) | TYPE         | DESCRIPTION                         |
+-----------------------------------------------------------------------------------------+
| MAGIC               | 4            | ASCII        | 'SAUD' (Secure Audio identifier)    |
| VERSION             | 1            | uint8        | 0x01 (Format version)               |
| KDF_TYPE            | 1            | uint8        | 0=Raw Key, 1=PBKDF2-HMAC-SHA256     |
| ITERATIONS          | 4            | uint32 (BE)  | Work factor (e.g., 600,000)         |
| SALT                | 16           | CSPRNG       | 128-bit unique salt                 |
| NONCE               | 12           | CSPRNG       | 96-bit unique GCM IV                |
| METADATA_LEN        | 2            | uint16 (BE)  | Length of JSON metadata (N bytes)   |
| METADATA_JSON       | N            | UTF-8 JSON   | Audio format, sample rate, channels |
+-----------------------------------------------------------------------------------------+
| ===> [ENTIRE HEADER (40 + N BYTES) BINDS CRYPTOGRAPHICALLY AS AAD IN GHASH] <===        |
+-----------------------------------------------------------------------------------------+
| TAG (GHASH MAC)     | 16           | Binary       | 128-bit Authentication Tag          |
| CIPHERTEXT          | L            | Stream       | AES-256-GCM Encrypted Audio Chunks  |
+-----------------------------------------------------------------------------------------+
```

---

## 4. Empirical Performance Evaluation (Measured Data)

Benchmarks conducted on Apple Silicon M-series hardware running Python 3.14 across multiple trials:

| Audio Category | File Size | Enc Time (ms) | Dec Time (ms) | Enc Throughput | Dec Throughput | Overhead | Lossless SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Short Tone** | 250 KB | 24.7 ms | 23.5 ms | 9.5 MB/s | 10.0 MB/s | 325 Bytes (0.13%) | Verified 100% |
| **Voice Memo** | 1.0 MB | 26.6 ms | 26.6 ms | 36.8 MB/s | 36.6 MB/s | 327 Bytes (0.03%) | Verified 100% |
| **Full Recording** | 5.0 MB | 42.6 ms | 42.7 ms | **114.6 MB/s** | **114.2 MB/s** | 327 Bytes (0.006%) | Verified 100% |

### Key Performance Insights:
1. **Amortization of Key Derivation:** PBKDF2 (100,000 to 600,000 iterations) introduces a constant baseline work factor of $\approx 22\text{ ms}$. For 250 KB audio, KDF constitutes 90% of processing time. As file size increases to 5.0 MB, KDF overhead amortizes, allowing AES-GCM streaming to achieve over **114 MB/s**.
2. **Space Complexity:** Storage expansion is strictly $O(1)$ constant ($\approx 325-327\text{ bytes}$), asymptotically approaching $0.000\%$ expansion for large audio files.

---

## 5. Security & Randomness Verification

1. **Shannon Information Entropy ($H$):**
   $$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
   - *Plaintext Audio:* $H = 7.8405\text{ bits/byte}$ (Contains harmonic formants and periodic silence).
   - *Ciphertext:* $H = 7.99764\text{ bits/byte}$ (Near-identical to theoretical maximum of $8.0\text{ bits/byte}$).
2. **Chi-Square Uniformity Test:** $\chi^2 = 290.44$ ($DOF = 255$), confirming no statistical byte bias across all 256 byte values.
3. **Spectrogram Analysis (STFT):** Visual analysis proves that original audio formants (440 Hz pitch lines) are completely eradicated into uniform white noise.
4. **Decoder Unplayability:** Standard media decoders (`afplay`, `wave`) reject `.safeaudio` files with exit error `AudioFileOpen failed ('typ?')`.
5. **Release of Unverified Plaintext (RUP) Protection:** On 1-bit tampering or wrong key, decrypted temporary chunks are wiped from memory/disk immediately; zero bytes leak.
6. **Network Replay Prevention:** Sliding timestamp window ($\pm 60\text{s}$) and 16-byte CSPRNG TxID cache successfully identify and drop replayed audio transmissions.

---

## 6. Conclusion
The developed system satisfies all criteria of the M.Tech problem statement: authenticated confidentiality, integrity verification, tamper rejection, network transmission simulation, and real-time performance measurement.
