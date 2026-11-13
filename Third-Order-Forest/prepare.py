#!/usr/bin/env python3
"""Align traces (Step 1) and export the binary files that tri.c reads.
Usage: python3 prepare.py <challenge_dir>   ->  writes traces_cm.bin and pt.bin in the current folder
"""
import sys
import numpy as np
from solve import align

d = sys.argv[1] if len(sys.argv) > 1 else "."
data = np.load(f"{d}/capture.npz")
align(data["traces"]).T.copy().tofile("traces_cm.bin")   # column-major int8 (195 x 60000)
data["plaintext"].tofile("pt.bin")                        # 60000 x 16 uint8
print("wrote traces_cm.bin and pt.bin")