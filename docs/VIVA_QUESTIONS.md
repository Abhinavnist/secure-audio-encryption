# M.Tech Viva Voce Defense Question Bank: Secure Audio Encryption (AES-256-GCM)

This comprehensive guide prepares you for any question external examiners, professors, or security reviewers may ask during your M.Tech project defense.

---

## Category 1: Cryptographic Primitives & Mode Selection

### Q1: Why did you choose AES-256 over AES-128 or DES/3DES?
**Answer:**
- **Key Space:** AES-256 has a key space of $2^{256} \approx 1.15 \times 10^{77}$ combinations, making brute-force attacks computationally impossible.
- **Quantum Resistance:** Under Grover's quantum search algorithm, symmetric key search efficiency is square-rooted ($O(\sqrt{N})$). Therefore, AES-128 is reduced to 64 bits of security (which is vulnerable), whereas AES-256 retains 128 bits of post-quantum security, satisfying NIST long-term security recommendations.
- **DES/3DES:** DES has a 56-bit key (cracked in hours), and 3DES suffers from Sweet32 collision attacks due to its small 64-bit block size.

### Q2: Why did you use Galois/Counter Mode (GCM) instead of ECB or CBC?
**Answer:**
- **ECB (Electronic Codebook):** It is completely insecure for audio. Identical 16-byte blocks of audio (such as silence or repeating acoustic beats) encrypt to identical ciphertext blocks. In an audio spectrogram, melody and voice patterns leak clearly (known as the *ECB Penguin effect*).
- **CBC (Cipher Block Chaining):** CBC only provides *confidentiality*, NOT *integrity or authenticity*. It requires PKCS#7 padding, making it vulnerable to Padding Oracle attacks (Vaudenay attack). If an attacker flips bits in CBC ciphertext, it decrypts into corrupted audio without warning.
- **GCM (Galois/Counter Mode):** It is an **Authenticated Encryption with Associated Data (AEAD)** mode. It runs in Counter (CTR) mode (no padding needed, stream-friendly) and simultaneously computes a 128-bit GHASH authentication tag over $GF(2^{128})$. Any modification of even 1 bit in ciphertext causes immediate rejection (`MAC check failed`).

### Q3: What is the Catastrophic Nonce-Reuse Failure in AES-GCM? How did you prevent it?
**Answer:**
- In AES-GCM, if the same key $K$ and nonce $IV$ are reused to encrypt two different audio messages ($P_1, P_2$):
  $$C_1 \oplus C_2 = (P_1 \oplus S) \oplus (P_2 \oplus S) = P_1 \oplus P_2$$
  The keystream $S$ cancels out, exposing the XOR of the plaintexts!
- Even worse, because GHASH is a polynomial over a Galois field, an attacker can solve for the hash subkey $H$, which completely destroys both integrity and confidentiality for all past and future communications under that key!
- **Prevention in our project:** We enforce that a fresh 96-bit (12-byte) nonce is generated via operating system kernel CSPRNG (`os.urandom(12)`) for every single encryption. The nonce is never reused.

### Q4: What is Associated Authenticated Data (AAD), and what did you include in it?
**Answer:**
- AAD is data that is authenticated (tamper-proof) by the GHASH tag but is NOT encrypted (it remains readable in plaintext).
- In our project, the entire `.safeaudio` container header (Magic signature `SAUD`, Version, KDF iterations, Salt, Nonce, and audio metadata JSON containing original filename, format, sample rate, and channels) is fed into the cipher as AAD!
- If an attacker tampers with the filename or changes the sampling rate in a hex editor, AES-GCM tag verification fails immediately.

---

## Category 2: Key Management & Password Derivation

### Q5: Why can't we use a user's password directly as an AES key?
**Answer:**
- AES-256 requires exactly 32 bytes (256 bits) of uniformly distributed, high-entropy cryptographic material.
- Human passwords have low entropy (typically 30–40 bits) and contain predictable ASCII character distributions. An attacker can use GPU-accelerated dictionary attacks to crack passwords in seconds if used directly.

### Q6: How does PBKDF2-HMAC-SHA256 protect against attacks? Why did you use a Salt?
**Answer:**
- **Salt (128-bit CSPRNG):** Without salt, if two users have the same password, their derived keys are identical. Attackers can compute lookup tables (Rainbow Tables) to crack passwords offline. A unique random salt ensures that identical passwords produce completely different keys.
- **Iterations (Work Factor):** We use 100,000 to 600,000 iterations (OWASP standard). Each iteration computes HMAC-SHA256 repeatedly. This slows down brute-force attempts from billions of guesses per second to only a few dozen guesses per second, making brute forcing infeasible.

---

## Category 3: Audio Signal Processing & Security Verification

### Q7: What is Shannon Entropy, and what value did your ciphertext achieve?
**Answer:**
- Shannon Entropy measures the average information density and uncertainty per byte:
  $$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- The theoretical maximum entropy for an 8-bit byte is $\log_2(256) = 8.0\text{ bits/byte}$.
- Plaintext audio has structural patterns (silence, formants), yielding $H \approx 7.84\text{ bits/byte}$.
- Our AES-256-GCM ciphertext achieved **$7.99764\text{ bits/byte}$**, proving near-perfect cryptographic randomness and no information leakage.

### Q8: What does the STFT Spectrogram prove in your report?
**Answer:**
- A Short-Time Fourier Transform (STFT) spectrogram displays audio frequency components over time.
- The original audio spectrogram clearly reveals vocal formants, pitch lines, and harmonics (e.g., 440 Hz).
- The ciphertext spectrogram is a completely flat, uniform white-noise spectrum across all frequency bands. This proves that an adversary performing frequency or Fourier analysis cannot extract any acoustic or melody pattern.

### Q9: Why did media players (like QuickTime or afplay) reject your encrypted audio?
**Answer:**
- Media players require standard container headers (e.g., `RIFF....WAVE` or MPEG frame sync `0xFFE`).
- In `.safeaudio`, the raw audio bytes (including headers) are encrypted into pseudorandom ciphertext. Audio players attempting to parse the file fail with `AudioFileOpen failed ('typ?')` because the file lacks recognizable audio codecs.

---

## Category 4: Software Architecture & Tampering Defense

### Q10: What is Release of Unverified Plaintext (RUP), and how does your code enforce RUP protection?
**Answer:**
- **NIST SP 800-38D Vulnerability:** In streaming decryption, if plaintext bytes are written directly to disk or played through speakers *before* the authentication tag is checked at the end, an attacker could tamper with the file and still receive partial unverified plaintext audio.
- **Our Solution:** Our `AudioCipher.decrypt_file` streams into a temporary file (`.tmp_decrypted`). Only after `cipher.verify(tag)` succeeds does it atomically rename the file to the destination. If the tag check fails, the temporary file is purged instantly from disk.

### Q11: How does your streaming architecture handle large 500MB WAV files without memory exhaustion?
**Answer:**
- Instead of loading the entire file into memory (`file.read()`), we process the audio in **64 KB chunks**.
- Counter Mode (CTR) generates keystream blocks independently, and GHASH accumulates polynomial products iteratively block-by-block.
- This ensures constant memory usage ($< 1\text{ MB}$ RAM) regardless of whether the audio file is 1 MB or 2 GB.

---

## Category 5: Network Transmission & Replay Protection

### Q12: What is a Replay Attack, and how does your `ReplayGuard` prevent it?
**Answer:**
- In a replay attack, an eavesdropper captures an encrypted voice transmission over the network and retransmits it later. Even though the eavesdropper cannot decrypt it, the receiver might execute the retransmitted voice command twice.
- **Our Defense:**
  1. **Sliding Timestamp Window ($\pm 60\text{ seconds}$):** Packets outside the 60-second tolerance are rejected immediately.
  2. **Transaction ID (TxID) Cache:** Every transmission packet has a 16-byte unique CSPRNG token. The receiver caches seen IDs within the sliding window. Any duplicate TxID raises `REPLAY_ATTACK_DETECTED` and drops the connection.

---

## Category 6: Performance & Benchmarking

### Q13: Why did encryption throughput increase from 9.5 MB/s on small files to 114.6 MB/s on 5 MB files?
**Answer:**
- PBKDF2 key derivation takes a constant baseline computation time of $\approx 22\text{ ms}$ regardless of file size.
- For a 250 KB file, the 22 ms KDF represents 90% of the total execution time, yielding 9.5 MB/s.
- For a 5 MB file, the 22 ms initial setup is amortized across a much larger payload, allowing hardware-accelerated AES-NI streaming to achieve **$114.6\text{ MB/s}$**.

### Q14: How did you verify lossless audio recovery?
**Answer:**
- We compute the SHA-256 hash of the original audio file prior to encryption and store it inside the container metadata.
- After decryption, we recompute the SHA-256 hash of the recovered audio file and verify that `hash(original) == hash(decrypted)` bit-for-bit.
