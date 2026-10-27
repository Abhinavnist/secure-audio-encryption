# Threat Model & Cryptographic Specification: Secure Audio Encryption (AES-256-GCM)

**Academic Level:** M.Tech Project / Cryptography & Information Security  
**Standard Compliance:** NIST SP 800-38D (GCM Mode), RFC 5116 (AEAD), NIST SP 800-132 (PBKDF2)

---

## 1. System Overview & Problem Statement
Digital audio files (WAV, MP3, FLAC) are rich multimedia assets often containing sensitive intellectual property, biometric voice data, medical dictations, or confidential communications. Audio data presents unique cryptographic challenges:
1. **High Redundancy & Predictable Structure:** Audio headers (`RIFF`, `fmt `, `data`, `ID3`) and periodic acoustic patterns (silence, steady tones) exhibit low entropy in unencrypted form.
2. **Bandwidth & Storage Overhead:** Audio files are significantly larger than text; encryption must have minimal latency and high streaming throughput.
3. **Integrity Vulnerability:** In legacy modes (e.g., CBC), an adversary can tamper with ciphertext bits to produce undetected acoustic distortions or exploit padding oracles without recovering the secret key.

---

## 2. Cryptographic Algorithm Selection & Justification

### 2.1 Why AES-256?
* **Key Space:** 256-bit symmetric key ($2^{256} \approx 1.15 \times 10^{77}$ possible keys). Immune to brute-force attacks across all foreseeable computational paradigms.
* **Post-Quantum Security:** By Grover's algorithm, quantum search reduces symmetric key security to $O(\sqrt{N})$. A 256-bit key retains 128-bit quantum security, meeting NIST long-term security recommendations.

### 2.2 Why Galois/Counter Mode (GCM) instead of ECB or CBC?

| Feature | ECB (Electronic Codebook) | CBC (Cipher Block Chaining) | GCM (Galois/Counter Mode) |
| :--- | :--- | :--- | :--- |
| **Security Classification** | **Insecure / Banned** | Confidentiality Only | **AEAD (Confidentiality + Authenticity)** |
| **Pattern Leakage** | **Severe:** Identical audio blocks encrypt to identical ciphertext. Spectrogram leaks melody/voice. | None (with random IV) | **Zero:** Counter mode ensures pseudorandom stream. |
| **Padding Requirement** | Required (PKCS#7) | Required (PKCS#7) | **None:** Stream cipher mode handles arbitrary byte lengths. |
| **Padding Oracle Vulnerability** | N/A | **High:** Vulnerable to Vaudenay / POODLE attacks. | **Immune:** No padding used. |
| **Integrity & Tamper Detection** | None | None (needs separate HMAC) | **Built-in 128-bit GHASH Authentication Tag.** |
| **Parallelization** | Yes (Encrypt & Decrypt) | Decrypt only (Encrypt is sequential) | **Full hardware pipelining (AES-NI / CLMUL).** |

---

## 3. Mathematical Foundations of AES-256-GCM

AES-GCM combines two primitives:
1. **CTR (Counter Mode) Encryption:**
   Given a 256-bit key $K$, a 96-bit nonce $IV$, and a 32-bit counter starting at 1:
   $$Y_i = IV \parallel \text{pad}_{32}(i + 1)$$
   $$C_i = P_i \oplus E_K(Y_i)$$
   Where $E_K$ is the AES block cipher and $P_i$ is the $i$-th 128-bit block of audio data.

2. **Galois Field GHASH Authentication ($GF(2^{128})$):**
   Authentication key $H = E_K(0^{128})$.
   The authentication tag $T$ is computed over the Associated Authenticated Data ($AAD$) and the Ciphertext ($C$) using polynomial evaluation over $GF(2^{128})$:
   $$T = \text{MSB}_{128}\Big( \text{GHASH}_H(AAD \parallel C \parallel \text{len}(AAD) \parallel \text{len}(C)) \oplus E_K(Y_0) \Big)$$
   Any bit flip in $C$ or $AAD$ produces an invalid $T$ with probability $1 - 2^{-128}$.

---

## 4. Threat Matrix (STRIDE Model)

| Threat Category | Attack Vector | Potential Impact | AES-256-GCM Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary crafts fake encrypted audio purporting to be from a trusted sender. | Unauthorized command execution, misinformation. | Sender signs or derives keys using shared secret with AAD sender identity. |
| **Tampering** | Man-in-the-Middle (MitM) flips bits in the ciphertext or audio header during storage/transit. | Corrupted audio playback or audio player exploit. | **128-bit GHASH Tag Verification:** Any single-bit change causes decryption rejection (`MAC check failed`). |
| **Repudiation** | Sender denies having generated the encrypted file. | Non-repudiation failure. | Handled via authenticated header container containing sender cryptographic identity. |
| **Information Disclosure** | Passive eavesdropper captures stored files or network packets. | Loss of confidential audio/speech content. | AES-256 encryption ensures ciphertext is computationally indistinguishable from uniform random noise. |
| **Denial of Service** | Corrupted headers causing buffer overflow in audio decoder. | Audio player crashes. | Strict parsing of validated binary container before feeding bytes into audio codecs. |
| **Elevation of Privilege** | Attacker injects malicious metadata payload into audio tags (e.g., ID3 tags). | Code execution on receiver. | All metadata is bound in authenticated Associated Data ($AAD$) and rejected if tampered. |

---

## 5. Critical Cryptographic Rule: Nonce Uniqueness
> [!CAUTION]
> **Catastrophic Failure on Nonce Reuse:** If the same $(K, IV)$ pair is ever used to encrypt two different audio messages, an attacker can XOR the ciphertexts to eliminate the keystream:
> $$C_1 \oplus C_2 = P_1 \oplus P_2$$
> Furthermore, the GHASH polynomial structure allows the attacker to solve for the hash key $H$, completely breaking both integrity and authenticity for all past and future communications under that key!
> 
> **System Enforcement:**
> 1. Every audio file encryption must generate a unique, fresh 96-bit (12-byte) CSPRNG nonce via `os.urandom(12)`.
> 2. The nonce is never kept secret; it is prefixed in the public `.safeaudio` container header.
