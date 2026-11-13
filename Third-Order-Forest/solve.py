#!/usr/bin/env python3
"""Third-Order Forest solver: recover AES-128 key from masked traces, decrypt capsule.json.

Usage: python3 solve.py <challenge_dir>
  <challenge_dir> must contain capture.npz and capsule.json
Sites below were found with tri.c (see README, Step 2).
"""
import sys, json
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Sites per key byte, in phase-aligned column numbers (found with tri.c)
SITES = [(7,9,11),(22,23,24),(29,31,33),(40,42,45),(54,56,60),(65,67,68),(82,83,84),(92,93,95),
         (102,103,104),(112,114,115),(125,126,132),(135,143,144),(147,149,151),(159,164,167),
         (171,176,179),(184,185,188)]

def make_sbox():
    """AES S-box generated from GF(2^8) inverse + affine transform."""
    sbox = [0]*256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)       # p *= 3
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF             # q /= 3
        if q & 0x80: q ^= 0x09
        x = q ^ (q<<1 | q>>7) & 0xFF ^ (q<<2 | q>>6) & 0xFF ^ (q<<3 | q>>5) & 0xFF ^ (q<<4 | q>>4) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1: break
    sbox[0] = 0x63
    return np.array(sbox, dtype=np.uint8)

def align(traces):
    """Step 1: one of columns 0-2 equals 110 (phase marker). Roll so marker sits at column 0."""
    marker = np.argmax(traces[:, :3] == 110, axis=1)
    out = np.empty_like(traces)
    for m in range(3):
        idx = marker == m
        out[idx] = np.roll(traces[idx], -m, axis=1)
    return out

def parity_table():
    """H[m][x] = (-1)^{<m,x>} for all m,x in 0..255 (Walsh characters)."""
    par = np.array([bin(v).count("1") & 1 for v in range(256)])
    mx = np.bitwise_and.outer(np.arange(256), np.arange(256))
    return 1 - 2*par[mx]

def recover_key(pt, tr, sbox):
    H = parity_table()
    key = []
    for b, (i, j, k) in enumerate(SITES):
        w = tr[:, i].astype(np.float64) * tr[:, j] * tr[:, k]
        w -= w.mean()
        sums = np.bincount(pt[:, b], weights=w, minlength=256)
        cnt = np.bincount(pt[:, b], minlength=256)
        mu = sums / np.maximum(cnt, 1)              # mean product per plaintext byte
        scores = np.empty(256)
        p = np.arange(256)
        for kg in range(256):
            r = H[:, sbox[p ^ kg]] @ mu / 256.0     # r(k, m) for all m
            r2 = np.sort(r[1:]**2)                  # ignore m = 0
            scores[kg] = r2[-8:].sum()              # top-8 Walsh characters
        order = np.argsort(scores)[::-1]
        print(f"byte {b:2d}: key={order[0]:02x}  best={scores[order[0]]:.0f}  runner-up={scores[order[1]]:.0f}")
        key.append(int(order[0]))
    return bytes(key)

def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    data = np.load(f"{d}/capture.npz")
    pt, tr = data["plaintext"], align(data["traces"])
    key = recover_key(pt, tr, make_sbox())
    print("key:", key.hex())
    c = json.load(open(f"{d}/capsule.json"))
    print(AESGCM(key).decrypt(bytes.fromhex(c["nonce"]), bytes.fromhex(c["ct"]), None).decode())

if __name__ == "__main__":
    main()