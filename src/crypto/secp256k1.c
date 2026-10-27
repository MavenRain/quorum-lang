/* Source: intent-lang 79e1898 src/front/secp256k1.c :6 to :49 (secp_recover
   and keccak cut; scalar_of and N_WORD cut, FROST does not use them;
   SECP_P and SECP_N renamed SECP_FP and SECP_FN): the moduli, the
   generator words, the parity lift_x and put_word.
   NEW (quorum-lang S7, O93): get_word, the group operations on the ec0_*
   of crypto/bn254.h, the SEC1 compressed points and the scalar bytes. */
#include "crypto/secp256k1.h"

#include <string.h>

const Modulus SECP_FP = {{0xfffffc2fu, 0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu}};
const Modulus SECP_FN = {{0xd0364141u, 0xbfd25e8cu, 0xaf48a03bu, 0xbaaedce6u, 0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu}};

/* (p + 1) / 4: p = 3 mod 4, so A^((p + 1) / 4) is a square root of a square A. */
static const U256 SQRT_EXP = {{0xffffffffbfffff0cull, 0xffffffffffffffffull, 0xffffffffffffffffull, 0x3fffffffffffffffull}};
static const U256 GX = {{0x59f2815b16f81798ull, 0x029bfcdb2dce28d9ull, 0x55a06295ce870b07ull, 0x79be667ef9dcbbacull}};
static const U256 GY = {{0x9c47d08ffb10d4b8ull, 0xfd17b448a6855419ull, 0x5da4fbfc0e1108a8ull, 0x483ada7726a3c465ull}};

/* The point with x = X and a y of parity ODD, or 0 when X is no x on the
   curve y^2 = x^3 + 7. */
static int lift_x(G1 *out, const Fe *x, uint32_t odd) {
  Fe rhs;
  Fe y;
  Fe sq;
  Fe seven;
  U256 w;
  fe_from_u64(&seven, 7);
  fe_mul(&rhs, x, x, &SECP_FP);
  fe_mul(&rhs, &rhs, x, &SECP_FP);
  fe_add(&rhs, &rhs, &seven, &SECP_FP);
  fe_pow(&y, &rhs, &SQRT_EXP, &SECP_FP);
  fe_mul(&sq, &y, &y, &SECP_FP);
  if (!fe_eq(&sq, &rhs))
    return 0;
  fe_to_u256(&w, &y);
  if ((uint32_t)(w.limb[0] & 1u) != odd)
    fe_neg(&y, &y, &SECP_FP);
  out->x = *x;
  out->y = y;
  return 1;
}

/* The 32 big-endian bytes of X at OUT. */
static void put_word(unsigned char *out, const U256 *x) {
  uint32_t i;
  for (i = 0; i < 32u; i++)
    out[i] = (unsigned char)(x->limb[3u - i / 8u] >> (56u - 8u * (i % 8u)));
}

/* NEW (quorum-lang S7, O93) from here. */

/* The word of the 32 big-endian bytes at IN. */
static void get_word(U256 *out, const unsigned char *in) {
  uint32_t i;
  memset(out, 0, sizeof *out);
  for (i = 0; i < 32u; i++)
    out->limb[3u - i / 8u] |= (uint64_t)in[i] << (56u - 8u * (i % 8u));
}

static int is_identity(const G1 *p) {
  G1 zero;
  memset(&zero, 0, sizeof zero);
  return secp_eq(p, &zero);
}

void secp_gen(G1 *out) {
  fe_from_u256(&out->x, &GX, &SECP_FP);
  fe_from_u256(&out->y, &GY, &SECP_FP);
}

int secp_on_curve(const G1 *p) {
  Fe lhs;
  Fe rhs;
  Fe seven;
  if (is_identity(p))
    return 1;
  fe_from_u64(&seven, 7);
  fe_mul(&lhs, &p->y, &p->y, &SECP_FP);
  fe_mul(&rhs, &p->x, &p->x, &SECP_FP);
  fe_mul(&rhs, &rhs, &p->x, &SECP_FP);
  fe_add(&rhs, &rhs, &seven, &SECP_FP);
  return fe_eq(&lhs, &rhs);
}

void secp_add(G1 *out, const G1 *a, const G1 *b) {
  ec0_add(out, a, b, &SECP_FP);
}

void secp_mul(G1 *out, const G1 *p, const U256 *k) {
  ec0_mul(out, p, k, &SECP_FP);
}

void secp_neg(G1 *out, const G1 *a) {
  G1 t;
  t.x = a->x;
  fe_neg(&t.y, &a->y, &SECP_FP);
  *out = t;
}

int secp_eq(const G1 *a, const G1 *b) {
  return fe_eq(&a->x, &b->x) && fe_eq(&a->y, &b->y);
}

int secp_encode(unsigned char out[33], const G1 *p) {
  U256 w;
  if (is_identity(p) || !secp_on_curve(p))
    return 0;
  fe_to_u256(&w, &p->y);
  out[0] = (unsigned char)(2u + (uint32_t)(w.limb[0] & 1u));
  fe_to_u256(&w, &p->x);
  put_word(out + 1, &w);
  return 1;
}

int secp_decode(G1 *out, const unsigned char in[33]) {
  U256 w;
  Fe x;
  if (in[0] != 2 && in[0] != 3)
    return 0;
  get_word(&w, in + 1);
  if (!fe_from_u256(&x, &w, &SECP_FP))
    return 0;
  return lift_x(out, &x, (uint32_t)(in[0] & 1u));
}

int scalar_decode(Fe *out, const unsigned char in[32]) {
  U256 w;
  get_word(&w, in);
  return fe_from_u256(out, &w, &SECP_FN);
}

void scalar_encode(unsigned char out[32], const Fe *k) {
  U256 w;
  fe_to_u256(&w, k);
  put_word(out, &w);
}
