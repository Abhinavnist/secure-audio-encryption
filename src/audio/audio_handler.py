"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Module: src.audio.audio_handler
==============================================================================
Provides robust audio metadata extraction, synthetic audio generation for tests,
and audio integrity checksum calculation.
Compatible with standard library (no external system binary dependencies required for WAV).
==============================================================================
"""

import os
import wave
import struct
import math
import hashlib
from typing import Dict, Any, Optional

class AudioHandler:
    """
    Handles audio format identification, header metadata extraction,
    and synthetic test audio generation (WAV/PCM).
    """

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """
        Computes the cryptographic SHA-256 checksum of an audio file.
        This provides proof of bit-for-bit lossless integrity post-decryption.
        """
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def extract_metadata(file_path: str) -> Dict[str, Any]:
        """
        Extracts structural audio metadata and integrity hash.
        Supports WAV, MP3, FLAC, and generic digital audio containers.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Audio file not found: {file_path}")

        file_size = os.path.getsize(file_path)
        base_name = os.path.basename(file_path)
        ext = os.path.splitext(base_name)[1].lower().replace('.', '')

        metadata: Dict[str, Any] = {
            "original_filename": base_name,
            "file_size_bytes": file_size,
            "extension": ext or "bin",
            "sha256_checksum": AudioHandler.calculate_sha256(file_path),
            "sample_rate": None,
            "channels": None,
            "sample_width": None,
            "duration_seconds": None,
            "format": ext.upper()
        }

        # Attempt native WAV header extraction
        if ext == "wav":
            try:
                with wave.open(file_path, 'rb') as wav:
                    channels = wav.getnchannels()
                    sample_rate = wav.getframerate()
                    sample_width = wav.getsampwidth()
                    n_frames = wav.getnframes()
                    duration = n_frames / float(sample_rate) if sample_rate > 0 else 0.0

                    metadata.update({
                        "sample_rate": sample_rate,
                        "channels": channels,
                        "sample_width": sample_width,
                        "duration_seconds": round(duration, 3),
                        "format": "WAV (Linear PCM)"
                    })
            except Exception:
                # File has .wav extension but may be non-standard
                pass

        # Attempt generic MP3 frame header inspection
        elif ext == "mp3":
            metadata.update({
                "format": "MPEG-1/2 Audio Layer III (MP3)"
            })
            # Try pydub if available
            try:
                from pydub import AudioSegment
                seg = AudioSegment.from_file(file_path, format="mp3")
                metadata.update({
                    "sample_rate": seg.frame_rate,
                    "channels": seg.channels,
                    "sample_width": seg.sample_width,
                    "duration_seconds": round(len(seg) / 1000.0, 3)
                })
            except Exception:
                # Graceful fallback if ffmpeg is not installed
                pass

        return metadata

    @staticmethod
    def generate_synthetic_wav(
        output_path: str,
        frequency_hz: float = 440.0,
        duration_seconds: float = 1.0,
        sample_rate: int = 44100,
        channels: int = 1
    ) -> str:
        """
        Generates a valid, playable PCM WAV tone file without any external dependencies.
        Crucial for automated testing, benchmarks, and laboratory experiments.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        num_samples = int(sample_rate * duration_seconds)
        
        with wave.open(output_path, 'wb') as wav:
            wav.setnchannels(channels)
            wav.setsampwidth(2)  # 16-bit signed PCM
            wav.setframerate(sample_rate)

            # Generate sine wave with soft fade-in/fade-out to avoid audio click
            frames = []
            for i in range(num_samples):
                t = i / sample_rate
                # Envelope
                envelope = 1.0
                fade_samples = int(sample_rate * 0.05)
                if i < fade_samples:
                    envelope = i / fade_samples
                elif i > num_samples - fade_samples:
                    envelope = (num_samples - i) / fade_samples

                val = int(32767.0 * 0.7 * envelope * math.sin(2.0 * math.pi * frequency_hz * t))
                packed_sample = struct.pack('<h', val)
                # Duplicate for all channels
                frames.append(packed_sample * channels)

            wav.writeframes(b''.join(frames))

        return output_path
