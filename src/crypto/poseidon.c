/* NEW (quorum-lang S11 H2, O155): the Grain LFSR, the Poseidon parameters
   and the permutation. The steps follow the Grain class, poseidon_params and
   poseidon_perm of quorum-lang-work/s11-h2-vectors.py, which follow
   generate_params_poseidon.sage. test/ivccrypto.c compares the results with
   the vectors of that script. */
#include "crypto/poseidon.h"

#include <string.h>

#define GRAIN_BITS 80u

/* The 80-bit LFSR in a ring: logical bit K is s[(head + K) % 80]. */
typedef struct {
  unsigned char s[GRAIN_BITS];
  uint32_t head;
} Grain;

/* Shift once: the new bit is s62 ^ s51 ^ s38 ^ s23 ^ s13 ^ s0. */
static unsigned char grain_step(Grain *g) {
  unsigned char b = (unsigned char)(g->s[(g->head + 62u) % GRAIN_BITS] ^ g->s[(g->head + 51u) % GRAIN_BITS] ^
                                    g->s[(g->head + 38u) % GRAIN_BITS] ^ g->s[(g->head + 23u) % GRAIN_BITS] ^
                                    g->s[(g->head + 13u) % GRAIN_BITS] ^ g->s[g->head]);
  g->s[g->head] = b;
  g->head = (g->head + 1u) % GRAIN_BITS;
  return b;
}

/* Put the WIDTH low bits of VALUE at bit AT, the most significant first. */
static uint32_t put_bits(Grain *g, uint32_t at, uint32_t value, uint32_t width) {
  uint32_t i;
  for (i = 0; i < width; i++)
    g->s[at + i] = (unsigned char)((value >> (width - 1u - i)) & 1u);
  return at + width;
}

/* The seed for a prime field of N bits, then 160 discarded steps. */
static void grain_init(Grain *g, uint32_t n) {
  uint32_t at = 0;
  uint32_t i;
  g->head = 0;
  at = put_bits(g, at, 1u, 2u);
  at = put_bits(g, at, 0u, 4u);
  at = put_bits(g, at, n, 12u);
  at = put_bits(g, at, POSEIDON_WIDTH, 12u);
  at = put_bits(g, at, POSEIDON_RF, 10u);
  at = put_bits(g, at, POSEIDON_RP, 10u);
  for (i = at; i < GRAIN_BITS; i++)
    g->s[i] = 1u;
  for (i = 0; i < 160u; i++)
    (void)grain_step(g);
}

/* One output bit: a pair (b, x) gives x when b is 1, and nothing when b is
   0. */
static unsigned char grain_bit(Grain *g) {
  unsigned char b = grain_step(g);
  while (b == 0u) {
    (void)grain_step(g);
    b = grain_step(g);
  }
  return grain_step(g);
}

/* OUT = the next N output bits as a number, the first bit the most
   significant. */
static void grain_bits(U256 *out, Grain *g, uint32_t n) {
  uint32_t i;
  uint32_t at;
  memset(out, 0, sizeof *out);
  for (i = 0; i < n; i++) {
    at = n - 1u - i;
    out->limb[at / 64u] |= (uint64_t)grain_bit(g) << (at % 64u);
  }
}

static uint32_t bit_length(const Modulus *f) {
  uint32_t i = BN_LIMBS * 32u;
  while (i > 0u && ((f->w[(i - 1u) / 32u] >> ((i - 1u) % 32u)) & 1u) == 0u)
    i--;
  return i;
}

/* OUT = V mod F, for a V of at most the bit length of F (so V < 2 F). */
static void reduce_once(Fe *out, const U256 *v, const Modulus *f) {
  U256 q;
  U256 d;
  uint32_t i;
  if (fe_from_u256(out, v, f))
    return;
  for (i = 0; i < 4u; i++)
    q.limb[i] = (uint64_t)f->w[2u * i] | ((uint64_t)f->w[2u * i + 1u] << 32);
  (void)u256_sub(&d, v, &q);
  fe_from_u256(out, &d, f);
}

/* VALS = the next 6 field elements, drawn again until all are different. */
static void draw_distinct(Fe vals[2u * POSEIDON_WIDTH], Grain *g, uint32_t n, const Modulus *f) {
  U256 v;
  uint32_t i;
  uint32_t j;
  int same = 1;
  while (same) {
    for (i = 0; i < 2u * POSEIDON_WIDTH; i++) {
      grain_bits(&v, g, n);
      reduce_once(&vals[i], &v, f);
    }
    same = 0;
    for (i = 0; i < 2u * POSEIDON_WIDTH; i++)
      for (j = i + 1u; j < 2u * POSEIDON_WIDTH; j++)
        same = same || fe_eq(&vals[i], &vals[j]);
  }
}

void poseidon_params(PoseidonParams *out, const Modulus *f) {
  Grain g;
  U256 v;
  Fe vals[2u * POSEIDON_WIDTH];
  Fe sum;
  Fe zero;
  uint32_t n = bit_length(f);
  uint32_t i;
  uint32_t j;
  int pole = 1;
  out->f = *f;
  grain_init(&g, n);
  for (i = 0; i < POSEIDON_CONSTANTS; i++) {
    grain_bits(&v, &g, n);
    while (!fe_from_u256(&out->rc[i], &v, f))
      grain_bits(&v, &g, n);
  }
  /* The Cauchy matrix 1 / (x_i + y_j) of xs = vals[0..3) and ys =
     vals[3..6); a sample with an x_i + y_j of 0 is discarded. */
  memset(&zero, 0, sizeof zero);
  while (pole) {
    draw_distinct(vals, &g, n, f);
    pole = 0;
    for (i = 0; i < POSEIDON_WIDTH; i++)
      for (j = 0; j < POSEIDON_WIDTH; j++) {
        fe_add(&sum, &vals[i], &vals[POSEIDON_WIDTH + j], f);
        pole = pole || fe_eq(&sum, &zero);
      }
  }
  for (i = 0; i < POSEIDON_WIDTH; i++)
    for (j = 0; j < POSEIDON_WIDTH; j++) {
      fe_add(&sum, &vals[i], &vals[POSEIDON_WIDTH + j], f);
      fe_inv(&out->mds[i][j], &sum, f);
    }
}

/* X = X^5. */
static void sbox(Fe *x, const Modulus *f) {
  Fe sq;
  Fe quad;
  fe_mul(&sq, x, x, f);
  fe_mul(&quad, &sq, &sq, f);
  fe_mul(x, &quad, x, f);
}

void poseidon_perm(Fe state[POSEIDON_WIDTH], const PoseidonParams *p) {
  Fe next[POSEIDON_WIDTH];
  Fe term;
  uint32_t half = POSEIDON_RF / 2u;
  uint32_t r;
  uint32_t i;
  uint32_t j;
  int full;
  for (r = 0; r < POSEIDON_ROUNDS; r++) {
    full = r < half || r >= half + POSEIDON_RP;
    for (i = 0; i < POSEIDON_WIDTH; i++) {
      fe_add(&state[i], &state[i], &p->rc[r * POSEIDON_WIDTH + i], &p->f);
      if (full || i == 0u)
        sbox(&state[i], &p->f);
    }
    for (i = 0; i < POSEIDON_WIDTH; i++) {
      memset(&next[i], 0, sizeof next[i]);
      for (j = 0; j < POSEIDON_WIDTH; j++) {
        fe_mul(&term, &p->mds[i][j], &state[j], &p->f);
        fe_add(&next[i], &next[i], &term, &p->f);
      }
    }
    memcpy(state, next, sizeof next);
  }
}
