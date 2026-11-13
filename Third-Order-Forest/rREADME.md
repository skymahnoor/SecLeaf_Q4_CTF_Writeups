# Third-Order Forest

**CTF:** SecLeaf Q4 CTF · **Category:** Crypto / Side-channel · **Points:** 500 · **Author:** 5h1kh4r

**Flag:** `SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}`

**Tools:** Python (numpy, cryptography), C (gcc)

## 1. Challenge Overview

The challenge gives `Third_Order_Forest.zip` containing:

- `acquisition.py` — public leakage equations (device wiring and secrets are missing)
- `capture.npz` — plaintext (60000×16, uint8) and traces (60000×195, int8)
- `capsule.json` — AES-128-GCM ciphertext, with nonce

**Goal:** recover the AES-128 key from the traces, then decrypt `capsule.json`.

Per key byte, the leakage model in `acquisition.py` is:

- `z = M(Sbox[p ^ k])`, where `M` is an unknown invertible linear map over GF(2) (eight secret 8-bit rows)
- Three shares leak, each as Hamming weight minus 4: `hw(a)-4`, `hw(b)-4`, `hw(z^a^b)-4`
- `a` and `b` are fresh random masks per trace

The comments also hint at a trace phase, three site locations, and decoy background samples that look like shares.

## 2. Why Normal Attacks Fail

Because `a`, `b` are uniform and independent, any one or two of the three shares are independent of `z`.
So plain CPA and second-order CPA see nothing. Only the **product of all three shares** depends on the
secret, which makes this a **third-order attack**.

Why the product leaks: write `hw(x)-4 = -1/2 · Σ_i (-1)^{x_i}`. Then `E[s1·s2·s3 | z]` is a sum over
bit indices `i,j,k` of `E[(-1)^{a_i + b_j + (z^a^b)_k}]`, and only the `i=j=k` terms survive:

```
E[s1·s2·s3 | p]  ∝  Σ_i (-1)^{z_i},   with z_i = <row_i, Sbox[p^k]>
```

So the third-order product is a sum of 8 Walsh characters of the S-box output, where the unknown masks
are the secret rows.

## 3. Step 1 — Trace Alignment (Phase)

Columns 0–2 look different from the rest: mean ≈ 36.6 and std ≈ 53, because exactly one of them equals
110 in every trace. The marker is at column 0, 1 or 2 with roughly equal frequency (20098 / 19960 / 19942).

This is the **phase**. `np.roll(trace, -marker_pos)` puts the marker at column 0, so the data sits at
the same columns in every trace.

## 4. Step 2 — Finding the Three Sites per Byte

All columns have the same std (≈ 13.4), so variance cannot reveal the sites. The only signal is the
conditional mean of the product given the plaintext byte.

For a candidate triple `(i, j, k)` and plaintext byte index `b`:

1. Compute `w = x_i · x_j · x_k` for every trace
2. Group `w` by the value of `plaintext[:, b]` (256 groups)
3. Statistic: `Σ_g (Σ w in group g)² / n_g` (ANOVA / chi-square-like)

For the true triple the 256 group means are non-constant, so the statistic is clearly high.
[`tri.c`](tri.c) brute-forces all C(194,3) ≈ 1.2M triples per byte in about 1 minute.

Best triple per byte (statistic ≈ 3.1–3.9e9 vs ≈ 2.2–2.3e9 for the best wrong triples):

| Byte | Sites | Byte | Sites |
|------|-------|------|-------|
| 0 | 7, 9, 11 | 8 | 102, 103, 104 |
| 1 | 22, 23, 24 | 9 | 112, 114, 115 |
| 2 | 29, 31, 33 | 10 | 125, 126, 132 |
| 3 | 40, 42, 45 | 11 | 135, 143, 144 |
| 4 | 54, 56, 60 | 12 | 147, 149, 151 |
| 5 | 65, 67, 68 | 13 | 159, 164, 167 |
| 6 | 82, 83, 84 | 14 | 171, 176, 179 |
| 7 | 92, 93, 95 | 15 | 184, 185, 188 |

The sites are not evenly spaced. Decoy columns are statistically identical to shares, so only the
plaintext-conditioned test can find the real ones.

```bash
python3 prepare.py <challenge_dir>       # aligns traces, writes traces_cm.bin + pt.bin
gcc -O3 -march=native -o tri tri.c
./tri traces_cm.bin pt.bin 0             # byte 0 -> sites 7,9,11
```

## 5. Step 3 — Key Recovery with Walsh Correlation

For each byte, let `mu[p]` be the mean of the product `w` over traces with plaintext byte `p`
(after centering `w`).

For each key guess `k` (0–255) and each non-zero mask `m` (1–255):

```
r(k, m) = (1/256) · Σ_p (-1)^{<m, Sbox[p^k]>} · mu[p]
```

The true `k` produces 8 large values, one per secret row, because the product leaks a sum of 8
characters. So the score for `k` is the sum of the 8 largest `r(k, m)²`. This needs **no knowledge of
the secret rows**.

The winning key byte scored ≈ 30000–38000, the runner-up ≈ 13000–17000 — a clear gap for all 16 bytes.

**Recovered key:** `2f1aa90f9774de5a29ef06a881d5ee68`

## 6. Step 4 — Decryption

`capsule.json` is AES-128-GCM with nonce `24cadc05b99ee53f82921a29`. Decrypting with the recovered key
(no AAD) succeeds, and GCM authentication passing confirms the key is correct. [`solve.py`](solve.py)
does steps 1, 3 and 4 end to end:

```bash
python3 solve.py <challenge_dir>      # folder containing capture.npz and capsule.json
```

Output: `SecLeaf{wal5h_sp3ctra_outgr0w_th3_m4sked_f0r3st}`

## 7. Takeaways

- Boolean masking with 2 shares plus a third share leaks at third order, and the leakage is a sum of
  Walsh characters, which matches the flag's "Walsh spectra" hint
- An unknown linear wiring does not stop the attack. Scoring over all masks `m` makes the correlation
  independent of the rows
- Decoy columns cannot be removed by variance or pairwise tests. Use the plaintext-conditioned
  product statistic
- A brute-force triple search is cheap in C (≈ 1.2M triples × 60000 traces per byte), and plaintext
  grouping by byte value gives more power than a single linear model