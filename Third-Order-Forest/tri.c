/* tri.c - brute-force the 3 leakage sites of one key byte (Third-Order Forest)
 *
 * For every column triple (i<j<k) it computes w = x_i * x_j * x_k per trace, groups w by the
 * plaintext byte, and scores the triple with  sum_g (sum_{w in g})^2 / n_g  (ANOVA-like).
 * The true triple has non-constant group means, so its score stands out.
 *
 * Input: aligned traces, column-major int8 (NCOL x NTR), plaintext (NTR x 16, uint8).
 * Build: gcc -O3 -march=native -o tri tri.c
 * Run:   ./tri traces_cm.bin pt.bin <byte_index>      (prints the 5 best triples)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NTR 60000
#define NCOL 195
#define FIRST 1   /* column 0 is the constant phase marker (110) after alignment: skip it */

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s traces_cm.bin pt.bin byte\n", argv[0]); return 1; }
    int b = atoi(argv[3]);
    int8_t *x = malloc((size_t)NCOL * NTR);
    uint8_t *pt = malloc((size_t)NTR * 16);
    FILE *f = fopen(argv[1], "rb"); if (!f || fread(x, 1, (size_t)NCOL * NTR, f) != (size_t)NCOL * NTR) return 2; fclose(f);
    f = fopen(argv[2], "rb");       if (!f || fread(pt, 1, (size_t)NTR * 16, f) != (size_t)NTR * 16) return 2; fclose(f);

    /* plaintext byte of every trace, and group sizes n_g */
    uint8_t *g = malloc(NTR); double n[256] = {0};
    for (int t = 0; t < NTR; t++) { g[t] = pt[t * 16 + b]; n[g[t]]++; }

    int16_t *w2 = malloc(NTR * sizeof(int16_t));      /* x_i * x_j  (|v| <= 16) */
    double best[5] = {0}; int bi[5][3] = {{0}};

    for (int i = FIRST; i < NCOL; i++)
        for (int j = i + 1; j < NCOL; j++) {
            for (int t = 0; t < NTR; t++) w2[t] = (int16_t)x[(size_t)i * NTR + t] * x[(size_t)j * NTR + t];
            for (int k = j + 1; k < NCOL; k++) {
                const int8_t *xk = x + (size_t)k * NTR;
                int32_t s[256] = {0};
                for (int t = 0; t < NTR; t++) s[g[t]] += w2[t] * xk[t];
                double score = 0;
                for (int v = 0; v < 256; v++) score += (double)s[v] * s[v] / n[v];
                /* keep top 5 */
                int pos = -1;
                for (int q = 0; q < 5; q++) if (score > best[q]) { pos = q; break; }
                if (pos >= 0) {
                    for (int q = 4; q > pos; q--) { best[q] = best[q-1]; memcpy(bi[q], bi[q-1], sizeof bi[q]); }
                    best[pos] = score; bi[pos][0] = i; bi[pos][1] = j; bi[pos][2] = k;
                }
            }
        }
    for (int q = 0; q < 5; q++) printf("byte %d  sites %d,%d,%d  score %.3e\n", b, bi[q][0], bi[q][1], bi[q][2], best[q]);
    return 0;
}