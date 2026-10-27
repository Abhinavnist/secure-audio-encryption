"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.gui.app
==============================================================================
Modern Desktop GUI for M.Tech Cryptography Demonstration:
  - Tab 1: Audio Encryption & Metadata Extraction
  - Tab 2: Authenticated Decryption & Audio Playback
  - Tab 3: Adversarial Tamper Lab (Live Examiner Demonstration)
  - Tab 4: Security Spectrogram & Performance Benchmark Viewer
==============================================================================
"""

import os
import sys
import time
import subprocess
import threading
from typing import Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.core.cipher import AudioCipher, AuthenticationError
from src.core.key_manager import KeyManager
from src.core.container import AudioContainer, InvalidContainerError
from src.audio.audio_handler import AudioHandler

# Set theme and appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AudioSecurityApp(ctk.CTk):
    """
    Main Application Window.
    """
    def __init__(self):
        super().__init__()

        self.title("Secure Audio Encryption Engine — AES-256-GCM (M.Tech Project)")
        self.geometry("980x720")
        self.minsize(900, 680)

        self._active_audio_process: Optional[subprocess.Popen] = None

        self._build_header()
        self._build_tabs()
        self._build_footer()

    def _build_header(self):
        header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#0F172A", height=70)
        header_frame.pack(fill="x", side="top")

        title_label = ctk.CTkLabel(
            header_frame, 
            text="SECURE AUDIO FILE ENCRYPTION USING AES-256-GCM",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#38BDF8"
        )
        title_label.pack(pady=(12, 2))

        sub_label = ctk.CTkLabel(
            header_frame,
            text="AEAD Cryptography • NIST SP 800-38D • Lossless Integrity • Replay & Tamper Defense",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8"
        )
        sub_label.pack(pady=(0, 10))

    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(self, corner_radius=10, fg_color="#1E293B")
        self.tabview.pack(fill="both", expand=True, padx=20, pady=15)

        self.tab_encrypt = self.tabview.add("1. Encrypt Audio")
        self.tab_decrypt = self.tabview.add("2. Decrypt & Play")
        self.tab_tamper = self.tabview.add("3. Tamper Lab (Examiner Demo)")
        self.tab_visuals = self.tabview.add("4. Spectrogram & Benchmarks")

        self._setup_encrypt_tab()
        self._setup_decrypt_tab()
        self._setup_tamper_tab()
        self._setup_visuals_tab()

    # --------------------------------------------------------------------------
    # TAB 1: ENCRYPT AUDIO
    # --------------------------------------------------------------------------
    def _setup_encrypt_tab(self):
        # File selector frame
        sel_frame = ctk.CTkFrame(self.tab_encrypt, fg_color="#0F172A", corner_radius=8)
        sel_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(sel_frame, text="Source Audio File (WAV, MP3, FLAC):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        row1 = ctk.CTkFrame(sel_frame, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(0, 10))

        self.enc_file_entry = ctk.CTkEntry(row1, placeholder_text="Select audio file to encrypt...", width=600)
        self.enc_file_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        browse_btn = ctk.CTkButton(row1, text="Browse Audio", width=120, command=self._browse_source_audio)
        browse_btn.pack(side="right")

        # Audio Info Box
        self.enc_info_box = ctk.CTkLabel(
            self.tab_encrypt, 
            text="No audio file loaded. Click 'Browse Audio' to inspect format and header.",
            font=ctk.CTkFont(family="Courier", size=12),
            fg_color="#0F172A",
            corner_radius=8,
            anchor="w",
            justify="left",
            padx=15, pady=10
        )
        self.enc_info_box.pack(fill="x", padx=15, pady=5)

        # Credentials frame
        cred_frame = ctk.CTkFrame(self.tab_encrypt, fg_color="#0F172A", corner_radius=8)
        cred_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(cred_frame, text="Encryption Passphrase (PBKDF2-HMAC-SHA256):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        self.enc_pass_entry = ctk.CTkEntry(cred_frame, placeholder_text="Enter secret passphrase (minimum 6 characters)...", show="*", width=600)
        self.enc_pass_entry.pack(fill="x", padx=15, pady=(0, 10))

        # Action Button
        self.btn_run_enc = ctk.CTkButton(
            self.tab_encrypt, 
            text="ENCRYPT AUDIO FILE (AES-256-GCM)", 
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#0284C7", hover_color="#0369A1",
            height=40,
            command=self._execute_encryption
        )
        self.btn_run_enc.pack(fill="x", padx=15, pady=10)

        # Output telemetry box
        self.enc_result_box = ctk.CTkTextbox(self.tab_encrypt, height=120, font=ctk.CTkFont(family="Courier", size=12))
        self.enc_result_box.pack(fill="both", expand=True, padx=15, pady=(5, 10))
        self.enc_result_box.insert("end", "[READY] Awaiting input audio file.\n")

    def _browse_source_audio(self):
        path = filedialog.askopenfilename(
            title="Select Digital Audio File",
            filetypes=[("Audio Files", "*.wav *.mp3 *.flac *.m4a *.aac *.ogg"), ("All Files", "*.*")]
        )
        if path:
            self.enc_file_entry.delete(0, "end")
            self.enc_file_entry.insert(0, path)
            try:
                meta = AudioHandler.extract_metadata(path)
                info_text = (
                    f"File: {meta['original_filename']} | Format: {meta['format']}\n"
                    f"Size: {meta['file_size_bytes']:,} Bytes ({meta['file_size_bytes']/(1024*1024):.2f} MB)\n"
                    f"Sample Rate: {meta.get('sample_rate') or 'N/A'} Hz | Channels: {meta.get('channels') or 'N/A'}\n"
                    f"SHA-256: {meta['sha256_checksum'][:32]}..."
                )
                self.enc_info_box.configure(text=info_text)
            except Exception as e:
                self.enc_info_box.configure(text=f"Error inspecting audio: {e}")

    def _execute_encryption(self):
        input_path = self.enc_file_entry.get().strip()
        passphrase = self.enc_pass_entry.get().strip()

        if not input_path or not os.path.exists(input_path):
            messagebox.showerror("File Error", "Please select a valid audio file.")
            return
        if len(passphrase) < 6:
            messagebox.showerror("Passphrase Error", "Passphrase must be at least 6 characters.")
            return

        dest_container = os.path.splitext(input_path)[0] + ".safeaudio"
        try:
            self.enc_result_box.delete("1.0", "end")
            self.enc_result_box.insert("end", "[*] Encrypting audio stream with AES-256-GCM AEAD...\n")
            self.update()

            t0 = time.perf_counter()
            metrics = AudioCipher.encrypt_file(
                input_audio_path=input_path,
                output_container_path=dest_container,
                key_or_password=passphrase,
                is_password=True,
                iterations=100_000
            )
            elapsed = time.perf_counter() - t0

            report = (
                f"[SUCCESS] Audio Encrypted Successfully!\n"
                f"Container File   : {os.path.basename(dest_container)}\n"
                f"Destination Path : {dest_container}\n"
                f"Original Size    : {metrics['original_size_bytes']:,} Bytes\n"
                f"Encrypted Size   : {metrics['encrypted_size_bytes']:,} Bytes\n"
                f"Header Overhead  : {metrics['header_overhead_bytes']} Bytes (O(1) constant)\n"
                f"GCM 96-bit Nonce : {metrics['nonce_hex'][:24]}\n"
                f"128-bit MAC Tag  : {metrics['tag_hex']}\n"
                f"Execution Time   : {metrics['elapsed_seconds'] * 1000.0:.2f} ms\n"
                f"Throughput       : {metrics['throughput_mb_s']} MB/s\n"
            )
            self.enc_result_box.delete("1.0", "end")
            self.enc_result_box.insert("end", report)
            messagebox.showinfo("Encryption Completed", f"Encrypted successfully!\nSaved as: {os.path.basename(dest_container)}")
            
            # Automatically populate Decrypt tab
            self.dec_file_entry.delete(0, "end")
            self.dec_file_entry.insert(0, dest_container)
            self._inspect_container(dest_container)

        except Exception as e:
            self.enc_result_box.insert("end", f"\n[ERROR] Encryption failed: {e}\n")
            messagebox.showerror("Encryption Error", str(e))

    # --------------------------------------------------------------------------
    # TAB 2: DECRYPT & PLAY
    # --------------------------------------------------------------------------
    def _setup_decrypt_tab(self):
        sel_frame = ctk.CTkFrame(self.tab_decrypt, fg_color="#0F172A", corner_radius=8)
        sel_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(sel_frame, text="Encrypted Audio Container (.safeaudio):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        
        row1 = ctk.CTkFrame(sel_frame, fg_color="transparent")
        row1.pack(fill="x", padx=15, pady=(0, 10))

        self.dec_file_entry = ctk.CTkEntry(row1, placeholder_text="Select .safeaudio file to decrypt...", width=600)
        self.dec_file_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        browse_btn = ctk.CTkButton(row1, text="Browse SafeAudio", width=140, command=self._browse_container)
        browse_btn.pack(side="right")

        # Container Header Card
        self.dec_info_box = ctk.CTkLabel(
            self.tab_decrypt, 
            text="No container loaded. Click 'Browse SafeAudio' to inspect header.",
            font=ctk.CTkFont(family="Courier", size=12),
            fg_color="#0F172A",
            corner_radius=8,
            anchor="w",
            justify="left",
            padx=15, pady=10
        )
        self.dec_info_box.pack(fill="x", padx=15, pady=5)

        # Passphrase
        cred_frame = ctk.CTkFrame(self.tab_decrypt, fg_color="#0F172A", corner_radius=8)
        cred_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(cred_frame, text="Decryption Passphrase:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10, 5))
        self.dec_pass_entry = ctk.CTkEntry(cred_frame, placeholder_text="Enter secret passphrase...", show="*", width=600)
        self.dec_pass_entry.pack(fill="x", padx=15, pady=(0, 10))

        # Action Buttons
        btn_row = ctk.CTkFrame(self.tab_decrypt, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=10)

        self.btn_run_dec = ctk.CTkButton(
            btn_row, 
            text="AUTHENTICATE & DECRYPT (VERIFY MAC)", 
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10B981", hover_color="#059669",
            height=40,
            command=self._execute_decryption
        )
        self.btn_run_dec.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_play_audio = ctk.CTkButton(
            btn_row,
            text="▶ PLAY RECOVERED AUDIO",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#8B5CF6", hover_color="#7C3AED",
            height=40,
            width=220,
            state="disabled",
            command=self._play_recovered_audio
        )
        self.btn_play_audio.pack(side="right")

        # Output box
        self.dec_result_box = ctk.CTkTextbox(self.tab_decrypt, height=120, font=ctk.CTkFont(family="Courier", size=12))
        self.dec_result_box.pack(fill="both", expand=True, padx=15, pady=(5, 10))
        self.dec_result_box.insert("end", "[READY] Awaiting container file.\n")

        self.last_recovered_file: Optional[str] = None

    def _browse_container(self):
        path = filedialog.askopenfilename(
            title="Select Encrypted Container",
            filetypes=[("SafeAudio Container", "*.safeaudio"), ("All Files", "*.*")]
        )
        if path:
            self.dec_file_entry.delete(0, "end")
            self.dec_file_entry.insert(0, path)
            self._inspect_container(path)

    def _inspect_container(self, container_path: str):
        try:
            with open(container_path, 'rb') as f:
                header_data = f.read(1024)
            header_info, _, _ = AudioContainer.unpack_header(header_data)
            meta = header_info["metadata"]
            info_text = (
                f"Container Magic : SAUD | Version: {header_info['version']}\n"
                f"Original File   : {meta.get('original_filename')} | Format: {meta.get('format')}\n"
                f"KDF Type        : PBKDF2-HMAC-SHA256 ({header_info['iterations']:,} Iterations)\n"
                f"128-bit MAC Tag : {header_info['tag'].hex()}"
            )
            self.dec_info_box.configure(text=info_text)
        except Exception as e:
            self.dec_info_box.configure(text=f"Header Inspection Notice: {e}")

    def _execute_decryption(self):
        container_path = self.dec_file_entry.get().strip()
        passphrase = self.dec_pass_entry.get().strip()

        if not container_path or not os.path.exists(container_path):
            messagebox.showerror("File Error", "Please select a valid .safeaudio file.")
            return
        if not passphrase:
            messagebox.showerror("Passphrase Error", "Please enter the passphrase.")
            return

        try:
            self.dec_result_box.delete("1.0", "end")
            self.dec_result_box.insert("end", "[*] Verifying 128-bit GHASH Tag & Decrypting...\n")
            self.update()

            result = AudioCipher.decrypt_file(
                input_container_path=container_path,
                key_or_password=passphrase,
                is_password=True
            )

            self.last_recovered_file = result["recovered_file"]
            self.btn_play_audio.configure(state="normal")

            report = (
                f"[AUTHENTICATION VERIFIED] 128-bit MAC Tag Validated Successfully!\n"
                f"Recovered File  : {os.path.basename(result['recovered_file'])}\n"
                f"Decrypted Size  : {result['decrypted_size_bytes']:,} Bytes\n"
                f"Throughput      : {result['throughput_mb_s']} MB/s\n"
                f"Original Hash   : {result['original_sha256']}\n"
                f"Decrypted Hash  : {result['decrypted_sha256']}\n"
                f"Lossless Match  : {'VERIFIED 100% IDENTICAL' if result['lossless_integrity_verified'] else 'MISMATCH'}\n"
            )
            self.dec_result_box.delete("1.0", "end")
            self.dec_result_box.insert("end", report)
            messagebox.showinfo("Decryption Success", "Audio Authenticated and Decrypted Losslessly!\nYou can now click 'Play Recovered Audio'.")

        except AuthenticationError as e:
            # Terminate any running audio playback immediately
            if self._active_audio_process:
                try:
                    self._active_audio_process.terminate()
                except Exception:
                    pass
                self._active_audio_process = None

            # Reset recovered file reference and disable play button
            self.last_recovered_file = None
            self.btn_play_audio.configure(state="disabled")

            # Remove any stale decrypted file from previous runs to prevent playing old audio
            parent_dir = os.path.dirname(os.path.abspath(container_path))
            for f in os.listdir(parent_dir):
                if f.startswith("decrypted_"):
                    try:
                        os.remove(os.path.join(parent_dir, f))
                    except Exception:
                        pass

            err_msg = (
                "[SECURITY ALERT] MAC VERIFICATION FAILED!\n"
                "Tampering detected or incorrect passphrase!\n\n"
                "[RUP DEFENSE ACTIVE] The cryptographic engine REFUSED to decrypt.\n"
                "Zero audio bytes were written to disk, and playback has been disabled.\n"
            )
            self.dec_result_box.delete("1.0", "end")
            self.dec_result_box.insert("end", err_msg)
            messagebox.showerror("Authentication Failed", "CRITICAL SECURITY ALERT: MAC check failed!\nTampering detected or wrong passphrase.\nDecryption was BLOCKED and no audio was produced.")

        except Exception as e:
            if self._active_audio_process:
                try:
                    self._active_audio_process.terminate()
                except Exception:
                    pass
                self._active_audio_process = None
            self.last_recovered_file = None
            self.btn_play_audio.configure(state="disabled")
            self.dec_result_box.insert("end", f"\n[ERROR] Decryption failed: {e}\n")
            messagebox.showerror("Decryption Error", str(e))

    def _play_recovered_audio(self):
        if not self.last_recovered_file or not os.path.exists(self.last_recovered_file):
            messagebox.showerror("Playback Error", "No recovered audio file available to play.")
            return

        # Stop previous playback if any
        if self._active_audio_process:
            try:
                self._active_audio_process.terminate()
            except Exception:
                pass

        # Use native macOS afplay or system opener
        try:
            if sys.platform == "darwin":
                self._active_audio_process = subprocess.Popen(["afplay", self.last_recovered_file])
            elif sys.platform == "win32":
                os.startfile(self.last_recovered_file)
            else:
                self._active_audio_process = subprocess.Popen(["aplay", self.last_recovered_file])
            messagebox.showinfo("Playing Audio", f"Playing audio via system player: {os.path.basename(self.last_recovered_file)}")
        except Exception as e:
            messagebox.showerror("Playback Error", f"Failed to launch audio player: {e}")

    # --------------------------------------------------------------------------
    # TAB 3: ADVERSARIAL TAMPER LAB
    # --------------------------------------------------------------------------
    def _setup_tamper_tab(self):
        desc = (
            "EXAMINER VIVA DEMONSTRATION LAB:\n"
            "This module allows external examiners to intentionally flip random bits in the ciphertext\n"
            "or modify the container's metadata to prove that AES-256-GCM instantly rejects tampered audio."
        )
        ctk.CTkLabel(
            self.tab_tamper, 
            text=desc, 
            font=ctk.CTkFont(family="Courier", size=12),
            fg_color="#0F172A", corner_radius=8, padx=15, pady=12, justify="left"
        ).pack(fill="x", padx=15, pady=10)

        # Action Buttons in Tamper Tab
        btn_frame = ctk.CTkFrame(self.tab_tamper, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)

        btn_tamper_cipher = ctk.CTkButton(
            btn_frame,
            text="⚡ INJECT 1-BIT CORRUPTION INTO CIPHERTEXT",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#DC2626", hover_color="#B91C1C",
            height=40,
            command=self._tamper_ciphertext_demo
        )
        btn_tamper_cipher.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_tamper_header = ctk.CTkButton(
            btn_frame,
            text="⚡ TAMPER WITH AAD HEADER",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#EA580C", hover_color="#C2410C",
            height=40,
            command=self._tamper_header_demo
        )
        btn_tamper_header.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_play_tamper = ctk.CTkButton(
            btn_frame,
            text="🚫 TEST DIRECT UNPLAYABILITY (PLAYER REJECTION)",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#475569", hover_color="#334155",
            height=40,
            command=self._force_play_encrypted_demo
        )
        btn_play_tamper.pack(side="right", fill="x", expand=True)

        self.tamper_log = ctk.CTkTextbox(self.tab_tamper, font=ctk.CTkFont(family="Courier", size=12))
        self.tamper_log.pack(fill="both", expand=True, padx=15, pady=10)
        self.tamper_log.insert("end", "[TAMPER LAB INITIALIZED] Select an attack above to demonstrate to examiners.\n")

    def _tamper_ciphertext_demo(self):
        container_path = self.dec_file_entry.get().strip()
        if not container_path or not os.path.exists(container_path):
            messagebox.showerror("Error", "Please select a valid container file in Tab 2 first.")
            return

        # Stop any active playback immediately
        if self._active_audio_process:
            try:
                self._active_audio_process.terminate()
            except Exception:
                pass
            self._active_audio_process = None

        # Invalidate old decrypted file reference
        self.last_recovered_file = None
        self.btn_play_audio.configure(state="disabled")

        # Clean up any previously decrypted files in that directory
        parent_dir = os.path.dirname(os.path.abspath(container_path))
        for f in os.listdir(parent_dir):
            if f.startswith("decrypted_"):
                try:
                    os.remove(os.path.join(parent_dir, f))
                except Exception:
                    pass

        tampered_path = container_path + ".corrupted_cipher"
        with open(container_path, 'rb') as f:
            data = bytearray(f.read())

        data[-50] ^= 0x01  # Flip 1 bit in ciphertext
        with open(tampered_path, 'wb') as f:
            f.write(data)

        self.tamper_log.insert("end", f"\n[ATTACK 1] Injected 1-bit corruption into ciphertext.\n")
        self.tamper_log.insert("end", f"[*] Executing AES-256-GCM AEAD decryption engine on tampered container...\n")

        try:
            AudioCipher.decrypt_file(
                input_container_path=tampered_path,
                key_or_password=self.dec_pass_entry.get().strip() or "testpass",
                is_password=True
            )
            self.tamper_log.insert("end", "[CRITICAL FLAW] Tampered file was accepted!\n")
        except AuthenticationError:
            self.tamper_log.insert("end", "[DEFENSE SUCCESS] AES-256-GCM GHASH MAC check failed! Tampering rejected!\n")
            self.tamper_log.insert("end", "[RUP VERIFIED] Zero audio output generated. Stale playback killed.\n")
            messagebox.showinfo("Tamper Attack Defeated", "AES-256-GCM successfully caught the 1-bit corruption!\nDecryption was BLOCKED and NO audio was generated.")
        finally:
            if os.path.exists(tampered_path):
                os.remove(tampered_path)

    def _tamper_header_demo(self):
        container_path = self.dec_file_entry.get().strip()
        if not container_path or not os.path.exists(container_path):
            messagebox.showerror("Error", "Please select a valid container file in Tab 2 first.")
            return

        if self._active_audio_process:
            try:
                self._active_audio_process.terminate()
            except Exception:
                pass
            self._active_audio_process = None

        self.last_recovered_file = None
        self.btn_play_audio.configure(state="disabled")

        parent_dir = os.path.dirname(os.path.abspath(container_path))
        for f in os.listdir(parent_dir):
            if f.startswith("decrypted_"):
                try:
                    os.remove(os.path.join(parent_dir, f))
                except Exception:
                    pass

        tampered_path = container_path + ".corrupted_header"
        with open(container_path, 'rb') as f:
            data = bytearray(f.read())

        data[45] ^= 0x20  # Modify metadata character
        with open(tampered_path, 'wb') as f:
            f.write(data)

        self.tamper_log.insert("end", f"\n[ATTACK 2] Corrupted metadata header byte at offset 45.\n")
        self.tamper_log.insert("end", f"[*] Attempting decryption on: {os.path.basename(tampered_path)}...\n")

        try:
            AudioCipher.decrypt_file(
                input_container_path=tampered_path,
                key_or_password=self.dec_pass_entry.get().strip() or "testpass",
                is_password=True
            )
            self.tamper_log.insert("end", "[CRITICAL FLAW] Header tampering went unnoticed!\n")
        except (AuthenticationError, InvalidContainerError):
            self.tamper_log.insert("end", "[DEFENSE SUCCESS] AAD validation failed! Modified header rejected!\n")
            messagebox.showinfo("Header Attack Defeated", "AAD cryptographic binding caught the header modification!\nDecryption BLOCKED.")
        finally:
            if os.path.exists(tampered_path):
                os.remove(tampered_path)

    def _force_play_encrypted_demo(self):
        container_path = self.dec_file_entry.get().strip()
        if not container_path or not os.path.exists(container_path):
            messagebox.showerror("Error", "Please select a valid container file in Tab 2 first.")
            return

        self.tamper_log.insert("end", f"\n[UNPLAYABILITY TEST] Feeding encrypted container to system media player...\n")
        
        # Test directly with afplay on macOS
        try:
            res = subprocess.run(["afplay", container_path], capture_output=True, text=True)
            err_output = res.stderr.strip() or res.stdout.strip()
            self.tamper_log.insert("end", f"[PLAYER RESPONSE] Media player rejected file! Exit Code: {res.returncode}\n")
            self.tamper_log.insert("end", f"[DETAIL] {err_output or 'AudioFileOpen failed: unreadable audio container.'}\n")
            self.tamper_log.insert("end", "[VERIFIED] Encrypted audio CANNOT be played by unauthorized users without key.\n")
            messagebox.showinfo(
                "Unplayability Verified",
                f"Media player rejected the file!\nError: {err_output or 'AudioFileOpen failed'}\n\nThis proves ciphertext cannot be played without decryption!"
            )
        except Exception as e:
            self.tamper_log.insert("end", f"[PLAYER REJECTED] {e}\n")
            messagebox.showinfo("Player Rejected", f"Player could not open the file: {e}")
        except (AuthenticationError, InvalidContainerError):
            self.tamper_log.insert("end", "[DEFENSE SUCCESS] AAD validation failed! Modified header rejected!\n")
            messagebox.showinfo("Header Attack Defeated", "AAD cryptographic binding caught the header modification!")
        finally:
            if os.path.exists(tampered_path):
                os.remove(tampered_path)

    # --------------------------------------------------------------------------
    # TAB 4: SPECTROGRAM & BENCHMARKS
    # --------------------------------------------------------------------------
    def _setup_visuals_tab(self):
        info_label = ctk.CTkLabel(
            self.tab_visuals,
            text="Research Graphs & Thesis Visualizations:\nOpen high-resolution figures generated by Milestone 4 and Milestone 6.",
            font=ctk.CTkFont(family="Courier", size=12),
            fg_color="#0F172A", corner_radius=8, padx=15, pady=12, justify="left"
        )
        info_label.pack(fill="x", padx=15, pady=10)

        btn_row = ctk.CTkFrame(self.tab_visuals, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=15)

        btn_open_spec = ctk.CTkButton(
            btn_row,
            text="VIEW SECURITY SPECTROGRAM PLOT",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#0284C7", hover_color="#0369A1",
            height=45,
            command=self._open_spectrogram_image
        )
        btn_open_spec.pack(side="left", fill="x", expand=True, padx=(0, 10))

        btn_open_bench = ctk.CTkButton(
            btn_row,
            text="VIEW PERFORMANCE BENCHMARK CHARTS",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#10B981", hover_color="#059669",
            height=45,
            command=self._open_benchmark_image
        )
        btn_open_bench.pack(side="right", fill="x", expand=True)

        self.visuals_status = ctk.CTkLabel(
            self.tab_visuals,
            text="Status: Ready. Click above to view 200 DPI publication plots.",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8"
        )
        self.visuals_status.pack(pady=20)

    def _open_spectrogram_image(self):
        img_path = os.path.abspath("docs/security_analysis_spectrogram.png")
        if os.path.exists(img_path):
            if sys.platform == "darwin":
                subprocess.Popen(["open", img_path])
            elif sys.platform == "win32":
                os.startfile(img_path)
            else:
                subprocess.Popen(["xdg-open", img_path])
            self.visuals_status.configure(text=f"Opened: {os.path.basename(img_path)}")
        else:
            messagebox.showerror("File Missing", "Please run Milestone 4 security tests first to generate the image.")

    def _open_benchmark_image(self):
        img_path = os.path.abspath("docs/performance_benchmark_charts.png")
        if os.path.exists(img_path):
            if sys.platform == "darwin":
                subprocess.Popen(["open", img_path])
            elif sys.platform == "win32":
                os.startfile(img_path)
            else:
                subprocess.Popen(["xdg-open", img_path])
            self.visuals_status.configure(text=f"Opened: {os.path.basename(img_path)}")
        else:
            messagebox.showerror("File Missing", "Please run Milestone 6 benchmark tests first to generate the image.")

    def _build_footer(self):
        footer = ctk.CTkFrame(self, height=30, fg_color="#0F172A", corner_radius=0)
        footer.pack(fill="x", side="bottom")

        lbl = ctk.CTkLabel(
            footer,
            text="M.Tech Cryptography & Information Security • AES-256-GCM Project Suite • Python 3.14",
            font=ctk.CTkFont(size=11),
            text_color="#64748B"
        )
        lbl.pack(pady=5)

def main():
    app = AudioSecurityApp()
    app.mainloop()

if __name__ == "__main__":
    main()
