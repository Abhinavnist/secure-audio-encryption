#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Utility: generate_test_audio.py
==============================================================================
Generates pristine, playable WAV audio files for testing and GUI demonstrations:
  1. sample_audio/tone_440hz.wav      (Standard A4 Concert Pitch Tone)
  2. sample_audio/major_chord.wav     (C-Major Triad Musical Chord - 3 frequencies)
  3. sample_audio/speech_sweep.wav    (Human Voice Range Frequency Sweep 200Hz - 3kHz)
==============================================================================
"""

import os
import wave
import struct
import math

def generate_tone(filepath: str, freq: float = 440.0, duration: float = 2.0, sr: int = 44100):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    num_samples = int(sr * duration)
    with wave.open(filepath, 'wb') as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sr)
        frames = []
        fade_len = int(sr * 0.05)
        for i in range(num_samples):
            # Soft envelope to prevent speaker pop
            env = 1.0
            if i < fade_len:
                env = i / fade_len
            elif i > num_samples - fade_len:
                env = (num_samples - i) / fade_len
            val = int(32767.0 * 0.6 * env * math.sin(2.0 * math.pi * freq * (i / sr)))
            frames.append(struct.pack('<h', val))
        wav.writeframes(b''.join(frames))

def generate_chord(filepath: str, freqs=(261.63, 329.63, 392.00), duration: float = 2.5, sr: int = 44100):
    # C-Major Chord (C4 + E4 + G4)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    num_samples = int(sr * duration)
    with wave.open(filepath, 'wb') as wav:
        wav.setnchannels(2)  # Stereo
        wav.setsampwidth(2)
        wav.setframerate(sr)
        frames = []
        fade_len = int(sr * 0.1)
        for i in range(num_samples):
            env = 1.0
            if i < fade_len:
                env = i / fade_len
            elif i > num_samples - fade_len:
                env = (num_samples - i) / fade_len
            
            # Sum 3 frequencies with normalization
            combined = 0.0
            for f in freqs:
                combined += math.sin(2.0 * math.pi * f * (i / sr))
            combined = (combined / len(freqs)) * 0.7 * env
            sample_val = int(32767.0 * combined)
            packed = struct.pack('<h', sample_val)
            frames.append(packed * 2)  # Left + Right channels
        wav.writeframes(b''.join(frames))

def generate_sweep(filepath: str, f_start: float = 200.0, f_end: float = 3000.0, duration: float = 2.5, sr: int = 44100):
    # Simulates human speech formant range (200 Hz to 3000 Hz)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    num_samples = int(sr * duration)
    with wave.open(filepath, 'wb') as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sr)
        frames = []
        fade_len = int(sr * 0.05)
        for i in range(num_samples):
            t = i / sr
            # Instantaneous frequency linearly increases
            freq = f_start + (f_end - f_start) * (t / duration)
            env = 1.0
            if i < fade_len:
                env = i / fade_len
            elif i > num_samples - fade_len:
                env = (num_samples - i) / fade_len
            val = int(32767.0 * 0.6 * env * math.sin(2.0 * math.pi * freq * t))
            frames.append(struct.pack('<h', val))
        wav.writeframes(b''.join(frames))

def main():
    print("\n" + "="*70)
    print(" [*] GENERATING SAMPLE AUDIO TEST FILES")
    print("="*70)

    f1 = "sample_audio/tone_440hz.wav"
    f2 = "sample_audio/major_chord.wav"
    f3 = "sample_audio/speech_sweep.wav"

    generate_tone(f1, freq=440.0, duration=2.0)
    print(f" [+] Generated: {f1:<35} (Single Musical Note A4 - 440 Hz)")

    generate_chord(f2, freqs=(261.63, 329.63, 392.00), duration=2.5)
    print(f" [+] Generated: {f2:<35} (C-Major Musical Chord - Stereo)")

    generate_sweep(f3, f_start=200.0, f_end=3000.0, duration=2.5)
    print(f" [+] Generated: {f3:<35} (Human Voice Formant Frequency Sweep)")

    print("="*70)
    print(" [✓] Done! You can now select any of these files in the GUI or CLI.\n")

if __name__ == "__main__":
    main()
