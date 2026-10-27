#!/usr/bin/env python3
"""
==============================================================================
Secure Audio File Encryption using AES-256-GCM
Application Launcher (GUI)
==============================================================================
Launches the modern CustomTkinter graphical desktop interface.
==============================================================================
"""

import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from src.gui.app import main

if __name__ == "__main__":
    main()
