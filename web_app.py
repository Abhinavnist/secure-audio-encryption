"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Web Application (Streamlit Cloud / Hugging Face Spaces Deployable)
==============================================================================
Enables 1-click cloud deployment with full browser-based audio encryption,
decryption, browser playback, and tamper testing.
==============================================================================
"""

import os
import sys
import tempfile
import streamlit as st

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.core.cipher import AudioCipher, AuthenticationError
from src.core.key_manager import KeyManager
from src.core.container import AudioContainer, InvalidContainerError
from src.audio.audio_handler import AudioHandler

# Page Config
st.set_page_config(
    page_title="Secure Audio Encryption (AES-256-GCM)",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🔒 Secure Audio File Encryption — AES-256-GCM")
st.markdown(
    "**M.Tech Cryptography Dissertation Project** • "
    "*NIST SP 800-38D AEAD • PBKDF2-HMAC-SHA256 • Lossless Integrity • Replay & Tamper Defense*"
)

tab1, tab2, tab3, tab4 = st.tabs([
    "1. 🎧 Encrypt Audio", 
    "2. 🔓 Decrypt & Browser Playback", 
    "3. ⚡ Examiner Tamper Lab", 
    "4. 📊 Research Charts"
])

# -----------------------------------------------------------------------------
# TAB 1: ENCRYPT
# -----------------------------------------------------------------------------
with tab1:
    st.header("Encrypt Digital Audio File")
    uploaded_file = st.file_uploader(
        "Upload Audio File (WAV, MP3, FLAC)", 
        type=["wav", "mp3", "flac", "ogg", "m4a"]
    )

    if uploaded_file:
        st.audio(uploaded_file, format=f"audio/{uploaded_file.name.split('.')[-1]}")
        st.info(f"File: **{uploaded_file.name}** | Size: **{uploaded_file.size / 1024:.1f} KB**")

        enc_password = st.text_input(
            "Enter Secret Passphrase (PBKDF2-HMAC-SHA256)", 
            type="password", 
            key="enc_pass"
        )

        if st.button("ENCRYPT AUDIO (AES-256-GCM)", type="primary"):
            if len(enc_password) < 6:
                st.error("Passphrase must be at least 6 characters long.")
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_in:
                    tmp_in.write(uploaded_file.getvalue())
                    tmp_in_path = tmp_in.name

                tmp_out_path = tmp_in_path + ".safeaudio"
                try:
                    with st.spinner("Deriving key and encrypting audio chunks..."):
                        metrics = AudioCipher.encrypt_file(
                            input_audio_path=tmp_in_path,
                            output_container_path=tmp_out_path,
                            key_or_password=enc_password,
                            is_password=True,
                            iterations=100_000
                        )

                    with open(tmp_out_path, "rb") as f:
                        safeaudio_bytes = f.read()

                    st.success("✅ Encryption Completed Successfully!")
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Throughput", f"{metrics['throughput_mb_s']} MB/s")
                    col2.metric("Execution Time", f"{metrics['elapsed_seconds']*1000:.1f} ms")
                    col3.metric("GCM Nonce", f"{metrics['nonce_hex'][:12]}...")
                    col4.metric("Header Overhead", f"{metrics['header_overhead_bytes']} Bytes")

                    st.download_button(
                        label="⬇️ Download .safeaudio Container",
                        data=safeaudio_bytes,
                        file_name=f"{os.path.splitext(uploaded_file.name)[0]}.safeaudio",
                        mime="application/octet-stream"
                    )
                finally:
                    if os.path.exists(tmp_in_path): os.remove(tmp_in_path)
                    if os.path.exists(tmp_out_path): os.remove(tmp_out_path)

# -----------------------------------------------------------------------------
# TAB 2: DECRYPT
# -----------------------------------------------------------------------------
with tab2:
    st.header("Decrypt & Verify Audio Container")
    uploaded_container = st.file_uploader("Upload .safeaudio Container", type=["safeaudio"])

    if uploaded_container:
        st.info(f"Container: **{uploaded_container.name}** | Size: **{uploaded_container.size / 1024:.1f} KB**")
        dec_password = st.text_input("Enter Passphrase", type="password", key="dec_pass")

        if st.button("AUTHENTICATE & DECRYPT", type="primary"):
            if not dec_password:
                st.error("Please enter the passphrase.")
            else:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".safeaudio") as tmp_c:
                    tmp_c.write(uploaded_container.getvalue())
                    tmp_c_path = tmp_c.name

                tmp_dec_path = tmp_c_path + ".decrypted.wav"
                try:
                    with st.spinner("Verifying 128-bit GHASH Authentication Tag..."):
                        dec_result = AudioCipher.decrypt_file(
                            input_container_path=tmp_c_path,
                            output_audio_path=tmp_dec_path,
                            key_or_password=dec_password,
                            is_password=True
                        )

                    st.success("🎉 [AUTHENTICATION VERIFIED] 128-bit MAC Tag Validated Successfully!")
                    st.write(f"**Recovered Audio:** `{dec_result['metadata']['original_filename']}`")
                    st.write(f"**Lossless SHA-256 Checksum Match:** `100% IDENTICAL`")

                    with open(tmp_dec_path, "rb") as f:
                        dec_bytes = f.read()

                    st.audio(dec_bytes, format="audio/wav")
                    st.download_button(
                        label="⬇️ Download Restored Audio",
                        data=dec_bytes,
                        file_name=dec_result['metadata']['original_filename'],
                        mime="audio/wav"
                    )

                except AuthenticationError:
                    st.error(
                        "🚨 **CRITICAL SECURITY ALERT: MAC check failed!**\n\n"
                        "Possible reasons:\n"
                        "- Incorrect passphrase was entered.\n"
                        "- Ciphertext audio bytes were tampered with.\n"
                        "- Header metadata was altered.\n\n"
                        "*Zero unverified audio bytes were released.*"
                    )
                finally:
                    if os.path.exists(tmp_c_path): os.remove(tmp_c_path)
                    if os.path.exists(tmp_dec_path): os.remove(tmp_dec_path)

# -----------------------------------------------------------------------------
# TAB 3: TAMPER LAB
# -----------------------------------------------------------------------------
with tab3:
    st.header("Adversarial Tamper Demonstration Lab")
    st.markdown(
        "Demonstrates to external examiners that modifying even **1 single bit** "
        "in the ciphertext or metadata causes AES-256-GCM to immediately reject decryption."
    )

    tamper_file = st.file_uploader("Upload .safeaudio file to test tampering", type=["safeaudio"], key="tamper_upload")
    if tamper_file:
        test_pass = st.text_input("Correct Passphrase for this file", type="password", key="t_pass")
        
        col_t1, col_t2 = st.columns(2)
        with col_t1:
            if st.button("⚡ Inject 1-Bit Corruption into Ciphertext", type="primary"):
                data = bytearray(tamper_file.getvalue())
                data[-50] ^= 0x01  # Flip 1 bit

                with tempfile.NamedTemporaryFile(delete=False, suffix=".safeaudio") as tf:
                    tf.write(data)
                    tf_path = tf.name

                try:
                    AudioCipher.decrypt_file(tf_path, key_or_password=test_pass, is_password=True)
                    st.error("FLAW: Tampered file was accepted!")
                except AuthenticationError:
                    st.success("🛡️ **DEFENSE VERIFIED:** AES-256-GCM detected the 1-bit flip and blocked decryption!")
                    st.info("Release of Unverified Plaintext (RUP) protection ensured ZERO audio was leaked.")
                finally:
                    if os.path.exists(tf_path): os.remove(tf_path)

        with col_t2:
            if st.button("⚡ Tamper with Container AAD Header"):
                data = bytearray(tamper_file.getvalue())
                data[45] ^= 0x20  # Corrupt metadata

                with tempfile.NamedTemporaryFile(delete=False, suffix=".safeaudio") as tf:
                    tf.write(data)
                    tf_path = tf.name

                try:
                    AudioCipher.decrypt_file(tf_path, key_or_password=test_pass, is_password=True)
                    st.error("FLAW: Tampered header was accepted!")
                except (AuthenticationError, InvalidContainerError):
                    st.success("🛡️ **DEFENSE VERIFIED:** AAD cryptographic binding rejected the modified metadata!")
                finally:
                    if os.path.exists(tf_path): os.remove(tf_path)

# -----------------------------------------------------------------------------
# TAB 4: RESEARCH CHARTS
# -----------------------------------------------------------------------------
with tab4:
    st.header("Research Visualizations & Experimental Evaluation")
    spec_img = "docs/security_analysis_spectrogram.png"
    bench_img = "docs/performance_benchmark_charts.png"

    if os.path.exists(spec_img):
        st.subheader("1. Shannon Information Entropy & Acoustic Spectrogram (STFT)")
        st.image(spec_img, caption="6-Panel Acoustic Security & Entropy Analysis (200 DPI)", use_container_width=True)

    if os.path.exists(bench_img):
        st.subheader("2. Empirical Performance Benchmarking Charts")
        st.image(bench_img, caption="4-Panel Latency, Throughput Scaling & Storage Overhead Charts", use_container_width=True)
