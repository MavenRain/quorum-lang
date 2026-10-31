/* Source: intent-lang 79e1898 src/front/bn254.c, plus scalar_reduce from src/front/blsag.c. */
/* Ported from glue-lang src/front/fr.c at cded21d (the field part, with the
   modulus as a parameter). The G1 part is new (slice S8 B1). See
   crypto/bn254.h. */
#include <string.h>

#include "crypto/bn254.h"

const Modulus BN254_FP = {{
  0xd87cfd47u, 0x3c208c16u, 0x6871ca8du, 0x97816a91u,
  0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u,
}};

const Modulus BN254_FR = {{
  0xf0000001u, 0x43e1f593u, 0x79b97091u, 0x2833e848u,
  0x8181585du, 0xb85045b6u, 0xe131a029u, 0x30644e72u,
}};

/* -1, 0 or 1 as A is less than, equal to or more than B. */
static int cmp_limbs(const uint32_t *a, const uint32_t *b) {
  unsigned i;
  for (i = BN_LIMBS; i > 0; i--) {
    if (a[i - 1] != b[i - 1])
      return a[i - 1] < b[i - 1] ? -1 : 1;
  }
  return 0;
}

/* A = A - B modulo 2^256. Returns the borrow. */
static uint32_t sub_limbs(uint32_t *a, const uint32_t *b) {
  uint64_t borrow = 0;
  unsigned i;
  for (i = 0; i < BN_LIMBS; i++) {
    uint64_t d = (uint64_t)a[i] - b[i] - borrow;
    a[i] = (uint32_t)d;
    borrow = d >> 63;
  }
  return (uint32_t)borrow;
}

/* A = A + B modulo 2^256. Returns the carry. */
static uint32_t add_limbs(uint32_t *a, const uint32_t *b) {
  uint64_t carry = 0;
  unsigned i;
  for (i = 0; i < BN_LIMBS; i++) {
    uint64_t s = (uint64_t)a[i] + b[i] + carry;
    a[i] = (uint32_t)s;
    carry = s >> 32;
  }
  return (uint32_t)carry;
}

static int is_zero(const Fe *x) {
  unsigned i;
  for (i = 0; i < BN_LIMBS; i++) {
    if (x->w[i] != 0)
      return 0;
  }
  return 1;
}

static void u256_limbs(uint32_t *out, const U256 *x) {
  unsigned i;
  for (i = 0; i < BN_LIMBS; i++)
    out[i] = (uint32_t)(x->limb[i / 2u] >> (32u * (i % 2u)));
}

int fe_from_u256(Fe *out, const U256 *x, const Modulus *f) {
  Fe t;
  u256_limbs(t.w, x);
  if (cmp_limbs(t.w, f->w) >= 0)
    return 0;
  *out = t;
  return 1;
}

void fe_to_u256(U256 *out, const Fe *x) {
  unsigned i;
  for (i = 0; i < 4u; i++)
    out->limb[i] = (uint64_t)x->w[2u * i] | ((uint64_t)x->w[2u * i + 1u] << 32);
}

void fe_from_u64(Fe *out, uint64_t n) {
  memset(out, 0, sizeof *out);
  out->w[0] = (uint32_t)n;
  out->w[1] = (uint32_t)(n >> 32);
}

void fe_add(Fe *out, const Fe *a, const Fe *b, const Modulus *f) {
  /* a + b < 2m. A carry out of the top limb (a modulus near 2^256, as the
     secp256k1 p of S7 b4) means the sum is m or more; the wrapping
     subtraction is then exact. */
  Fe t = *a;
  uint32_t carry = add_limbs(t.w, b->w);
  if (carry != 0 || cmp_limbs(t.w, f->w) >= 0)
    sub_limbs(t.w, f->w);
  *out = t;
}

void fe_sub(Fe *out, const Fe *a, const Fe *b, const Modulus *f) {
  Fe t = *a;
  if (sub_limbs(t.w, b->w) != 0)
    add_limbs(t.w, f->w);
  *out = t;
}

void fe_neg(Fe *out, const Fe *a, const Modulus *f) {
  Fe zero;
  memset(&zero, 0, sizeof zero);
  fe_sub(out, &zero, a, f);
}

/* The number of zero bits above the top 1 bit of X (X is not 0). */
static unsigned top_zeros(uint32_t x) {
  unsigned n;
  for (n = 0; n < 32u && (x & 0x80000000u) == 0; n++)
    x <<= 1;
  return n;
}

/* OUT = U modulo F for the 512-bit U (2 BN_LIMBS limbs, least significant
   first), by Knuth algorithm D (TAOCP vol. 2, 4.3.1; divmnu of Hacker's
   Delight) on 32-bit limbs with uint64_t intermediates. F has N limbs below
   its top zero limbs; F is not 0. D1 shifts F and U left by S bits, so that
   the top bit of F is 1. For each quotient limb from the top, D3 estimates
   the limb from the top 2 limbs of the partial remainder and corrects it
   with the third limb; the estimate is then the true limb or 1 more. D4
   subtracts the estimate times F. On a borrow (the estimate is 1 more), D6
   adds F back. The quotient is not kept. D8 shifts the remainder right by S
   bits. For N = 1 a short division by 64-bit words does the work. */
static void rem_words(Fe *out, const uint32_t *u, const Modulus *f) {
  uint32_t vn[BN_LIMBS];
  uint32_t un[2u * BN_LIMBS + 1u];
  unsigned n = BN_LIMBS;
  unsigned s;
  unsigned i;
  unsigned j;
  memset(out, 0, sizeof *out);
  while (n > 0 && f->w[n - 1u] == 0)
    n--;
  if (n == 0)
    return;
  if (n == 1u) {
    uint64_t r = 0;
    for (i = 2u * BN_LIMBS; i > 0; i--)
      r = ((r << 32) | u[i - 1u]) % f->w[0];
    out->w[0] = (uint32_t)r;
    return;
  }
  s = top_zeros(f->w[n - 1u]);
  for (i = n - 1u; i > 0; i--)
    vn[i] = (uint32_t)(((uint64_t)f->w[i] << s) | ((uint64_t)f->w[i - 1u] >> (32u - s)));
  vn[0] = f->w[0] << s;
  un[2u * BN_LIMBS] = (uint32_t)((uint64_t)u[2u * BN_LIMBS - 1u] >> (32u - s));
  for (i = 2u * BN_LIMBS - 1u; i > 0; i--)
    un[i] = (uint32_t)(((uint64_t)u[i] << s) | ((uint64_t)u[i - 1u] >> (32u - s)));
  un[0] = u[0] << s;
  for (j = 2u * BN_LIMBS - n + 1u; j > 0; j--) {
    unsigned k = j - 1u;
    uint64_t num = ((uint64_t)un[k + n] << 32) | un[k + n - 1u];
    uint64_t qhat = num / vn[n - 1u];
    uint64_t rhat = num % vn[n - 1u];
    uint64_t borrow = 0;
    while (qhat > 0xffffffffu || qhat * vn[n - 2u] > ((rhat << 32) | un[k + n - 2u])) {
      qhat--;
      rhat += vn[n - 1u];
      if (rhat > 0xffffffffu)
        break;
    }
    for (i = 0; i < n; i++) {
      uint64_t p = qhat * vn[i] + borrow;
      uint32_t lo = (uint32_t)p;
      borrow = (p >> 32) + (un[i + k] < lo ? 1u : 0u);
      un[i + k] -= lo;
    }
    if ((uint64_t)un[k + n] < borrow) {
      uint64_t carry = 0;
      un[k + n] = (uint32_t)((uint64_t)un[k + n] - borrow);
      for (i = 0; i < n; i++) {
        uint64_t t = (uint64_t)un[i + k] + vn[i] + carry;
        un[i + k] = (uint32_t)t;
        carry = t >> 32;
      }
      un[k + n] += (uint32_t)carry;
    } else {
      un[k + n] -= (uint32_t)borrow;
    }
  }
  for (i = 0; i < n; i++)
    out->w[i] = (uint32_t)(((uint64_t)un[i] >> s) | ((uint64_t)un[i + 1u] << (32u - s)));
}

/* The product of A and B (schoolbook), then the remainder by rem_words. Up
   to S10 the remainder was bit-serial (512 shift and subtract steps). S11 H2
   (Q-S11-6 ruling (a), O157) put the word-wise remainder in its place. Both
   give the exact remainder, so each result is the same. test/ivccrypto.c
   keeps the old code (ref_mul) and compares the two. */
void fe_mul(Fe *out, const Fe *a, const Fe *b, const Modulus *f) {
  uint32_t p[2u * BN_LIMBS];
  unsigned i;
  unsigned j;
  memset(p, 0, sizeof p);
  for (i = 0; i < BN_LIMBS; i++) {
    uint64_t carry = 0;
    for (j = 0; j < BN_LIMBS; j++) {
      uint64_t t = (uint64_t)a->w[i] * b->w[j] + p[i + j] + carry;
      p[i + j] = (uint32_t)t;
      carry = t >> 32;
    }
    p[i + BN_LIMBS] = (uint32_t)carry;
  }
  rem_words(out, p, f);
}

/* Square and multiply over fe_mul, from the top bit of E. */
static void pow_limbs(Fe *out, const Fe *a, const uint32_t *e, const Modulus *f) {
  Fe acc;
  unsigned i;
  fe_from_u64(&acc, 1);
  for (i = BN_LIMBS * 32u; i > 0; i--) {
    fe_mul(&acc, &acc, &acc, f);
    if ((e[(i - 1) / 32u] >> ((i - 1) % 32u)) & 1u)
      fe_mul(&acc, &acc, a, f);
  }
  *out = acc;
}

void fe_pow(Fe *out, const Fe *a, const U256 *e, const Modulus *f) {
  uint32_t w[BN_LIMBS];
  u256_limbs(w, e);
  pow_limbs(out, a, w, f);
}

/* At 0 the power is 0, because m minus 2 is not 0. The low limb of p and of
   r is 2 or more, so the subtract has no borrow. */
void fe_inv(Fe *out, const Fe *a, const Modulus *f) {
  uint32_t e[BN_LIMBS];
  memcpy(e, f->w, sizeof e);
  e[0] -= 2u;
  pow_limbs(out, a, e, f);
}

int fe_eq(const Fe *a, const Fe *b) {
  return cmp_limbs(a->w, b->w) == 0;
}

int fe_lt(const Fe *a, const Fe *b) {
  return cmp_limbs(a->w, b->w) < 0;
}

/* G1. Each coordinate is in Fp. */

static int is_infinity(const G1 *p) {
  return is_zero(&p->x) && is_zero(&p->y);
}

static void infinity(G1 *out) {
  memset(out, 0, sizeof *out);
}

int g1_on_curve(const G1 *p) {
  Fe lhs;
  Fe rhs;
  Fe three;
  if (is_infinity(p))
    return 1;
  fe_from_u64(&three, 3);
  fe_mul(&lhs, &p->y, &p->y, &BN254_FP);
  fe_mul(&rhs, &p->x, &p->x, &BN254_FP);
  fe_mul(&rhs, &rhs, &p->x, &BN254_FP);
  fe_add(&rhs, &rhs, &three, &BN254_FP);
  return fe_eq(&lhs, &rhs);
}

int g1_from_words(G1 *out, const U256 *x, const U256 *y) {
  G1 t;
  if (!fe_from_u256(&t.x, x, &BN254_FP) || !fe_from_u256(&t.y, y, &BN254_FP) || !g1_on_curve(&t))
    return 0;
  *out = t;
  return 1;
}

void g1_to_words(U256 *x, U256 *y, const G1 *p) {
  fe_to_u256(x, &p->x);
  fe_to_u256(y, &p->y);
}

/* The point with the slope L through A: x3 = L^2 minus a.x minus b.x,
   y3 = L (a.x minus x3) minus a.y. */
static void chord(G1 *out, const Fe *l, const G1 *a, const Fe *bx, const Modulus *f) {
  G1 t;
  fe_mul(&t.x, l, l, f);
  fe_sub(&t.x, &t.x, &a->x, f);
  fe_sub(&t.x, &t.x, bx, f);
  fe_sub(&t.y, &a->x, &t.x, f);
  fe_mul(&t.y, l, &t.y, f);
  fe_sub(&t.y, &t.y, &a->y, f);
  *out = t;
}

/* L = 3 x^2 / 2 y. A point with y = 0 has order 2, so its double is the
   point at infinity (G1 has none). */
void ec0_double(G1 *out, const G1 *a, const Modulus *f) {
  Fe num;
  Fe den;
  Fe three;
  if (is_zero(&a->y)) {
    infinity(out);
    return;
  }
  fe_from_u64(&three, 3);
  fe_mul(&num, &a->x, &a->x, f);
  fe_mul(&num, &num, &three, f);
  fe_add(&den, &a->y, &a->y, f);
  fe_inv(&den, &den, f);
  fe_mul(&num, &num, &den, f);
  chord(out, &num, a, &a->x, f);
}

/* L = (b.y minus a.y) / (b.x minus a.x). Equal x gives the double, or the
   point at infinity for B = minus A. */
void ec0_add(G1 *out, const G1 *a, const G1 *b, const Modulus *f) {
  Fe num;
  Fe den;
  if (is_infinity(a)) {
    *out = *b;
    return;
  }
  if (is_infinity(b)) {
    *out = *a;
    return;
  }
  if (fe_eq(&a->x, &b->x)) {
    if (fe_eq(&a->y, &b->y))
      ec0_double(out, a, f);
    else
      infinity(out);
    return;
  }
  fe_sub(&num, &b->y, &a->y, f);
  fe_sub(&den, &b->x, &a->x, f);
  fe_inv(&den, &den, f);
  fe_mul(&num, &num, &den, f);
  chord(out, &num, a, &b->x, f);
}

/* The Jacobian operations (EcJac, crypto/bn254.h; public from S11 H2). */

/* S = 4 X Y^2, M = 3 X^2, X3 = M^2 minus 2 S, Y3 = M (S minus X3) minus
   8 Y^4, Z3 = 2 Y Z. */
void ec0_jac_double(EcJac *out, const EcJac *a, const Modulus *f) {
  Fe yy;
  Fe s;
  Fe mm;
  Fe t;
  EcJac r;
  if (is_zero(&a->z) || is_zero(&a->y)) {
    memset(out, 0, sizeof *out);
    return;
  }
  fe_mul(&yy, &a->y, &a->y, f);
  fe_mul(&s, &a->x, &yy, f);
  fe_add(&s, &s, &s, f);
  fe_add(&s, &s, &s, f);
  fe_mul(&mm, &a->x, &a->x, f);
  fe_add(&t, &mm, &mm, f);
  fe_add(&mm, &t, &mm, f);
  fe_mul(&r.x, &mm, &mm, f);
  fe_sub(&r.x, &r.x, &s, f);
  fe_sub(&r.x, &r.x, &s, f);
  fe_mul(&yy, &yy, &yy, f);
  fe_add(&yy, &yy, &yy, f);
  fe_add(&yy, &yy, &yy, f);
  fe_add(&yy, &yy, &yy, f);
  fe_sub(&t, &s, &r.x, f);
  fe_mul(&r.y, &mm, &t, f);
  fe_sub(&r.y, &r.y, &yy, f);
  fe_mul(&r.z, &a->y, &a->z, f);
  fe_add(&r.z, &r.z, &r.z, f);
  *out = r;
}

/* A plus the affine point B. U = b.x Z^2, S = b.y Z^3, H = U minus X,
   R = S minus Y; X3 = R^2 minus H^3 minus 2 X H^2,
   Y3 = R (X H^2 minus X3) minus Y H^3, Z3 = Z H. */
void ec0_jac_add_affine(EcJac *out, const EcJac *a, const G1 *b, const Modulus *f) {
  Fe zz;
  Fe u;
  Fe s;
  Fe h;
  Fe hh;
  Fe hhh;
  Fe v;
  Fe t;
  EcJac r;
  if (is_infinity(b)) {
    *out = *a;
    return;
  }
  if (is_zero(&a->z)) {
    out->x = b->x;
    out->y = b->y;
    fe_from_u64(&out->z, 1);
    return;
  }
  fe_mul(&zz, &a->z, &a->z, f);
  fe_mul(&u, &b->x, &zz, f);
  fe_mul(&s, &b->y, &zz, f);
  fe_mul(&s, &s, &a->z, f);
  fe_sub(&h, &u, &a->x, f);
  fe_sub(&s, &s, &a->y, f);
  if (is_zero(&h)) {
    if (is_zero(&s))
      ec0_jac_double(out, a, f);
    else
      memset(out, 0, sizeof *out);
    return;
  }
  fe_mul(&hh, &h, &h, f);
  fe_mul(&hhh, &h, &hh, f);
  fe_mul(&v, &a->x, &hh, f);
  fe_mul(&r.x, &s, &s, f);
  fe_sub(&r.x, &r.x, &hhh, f);
  fe_sub(&r.x, &r.x, &v, f);
  fe_sub(&r.x, &r.x, &v, f);
  fe_sub(&t, &v, &r.x, f);
  fe_mul(&r.y, &s, &t, f);
  fe_mul(&t, &a->y, &hhh, f);
  fe_sub(&r.y, &r.y, &t, f);
  fe_mul(&r.z, &a->z, &h, f);
  *out = r;
}

/* A plus B, both in Jacobian form (S11 H2, for crypto/msm.c).
   U1 = X1 Z2^2, U2 = X2 Z1^2, S1 = Y1 Z2^3, S2 = Y2 Z1^3, H = U2 minus U1,
   R = S2 minus S1; X3 = R^2 minus H^3 minus 2 U1 H^2,
   Y3 = R (U1 H^2 minus X3) minus S1 H^3, Z3 = Z1 Z2 H. */
void ec0_jac_add(EcJac *out, const EcJac *a, const EcJac *b, const Modulus *f) {
  Fe z1z1;
  Fe z2z2;
  Fe u1;
  Fe u2;
  Fe s1;
  Fe s2;
  Fe h;
  Fe hh;
  Fe hhh;
  Fe v;
  Fe t;
  EcJac r;
  if (is_zero(&b->z)) {
    *out = *a;
    return;
  }
  if (is_zero(&a->z)) {
    *out = *b;
    return;
  }
  fe_mul(&z1z1, &a->z, &a->z, f);
  fe_mul(&z2z2, &b->z, &b->z, f);
  fe_mul(&u1, &a->x, &z2z2, f);
  fe_mul(&u2, &b->x, &z1z1, f);
  fe_mul(&s1, &a->y, &z2z2, f);
  fe_mul(&s1, &s1, &b->z, f);
  fe_mul(&s2, &b->y, &z1z1, f);
  fe_mul(&s2, &s2, &a->z, f);
  fe_sub(&h, &u2, &u1, f);
  fe_sub(&s2, &s2, &s1, f);
  if (is_zero(&h)) {
    if (is_zero(&s2))
      ec0_jac_double(out, a, f);
    else
      memset(out, 0, sizeof *out);
    return;
  }
  fe_mul(&hh, &h, &h, f);
  fe_mul(&hhh, &h, &hh, f);
  fe_mul(&v, &u1, &hh, f);
  fe_mul(&r.x, &s2, &s2, f);
  fe_sub(&r.x, &r.x, &hhh, f);
  fe_sub(&r.x, &r.x, &v, f);
  fe_sub(&r.x, &r.x, &v, f);
  fe_sub(&t, &v, &r.x, f);
  fe_mul(&r.y, &s2, &t, f);
  fe_mul(&t, &s1, &hhh, f);
  fe_sub(&r.y, &r.y, &t, f);
  fe_mul(&r.z, &a->z, &b->z, f);
  fe_mul(&r.z, &r.z, &h, f);
  *out = r;
}

/* X / Z^2 and Y / Z^3 with one inverse; (0, 0) for Z = 0. */
void ec0_jac_affine(G1 *out, const EcJac *a, const Modulus *f) {
  Fe zi;
  Fe zi2;
  if (is_zero(&a->z)) {
    infinity(out);
    return;
  }
  fe_inv(&zi, &a->z, f);
  fe_mul(&zi2, &zi, &zi, f);
  fe_mul(&out->x, &a->x, &zi2, f);
  fe_mul(&zi2, &zi2, &zi, f);
  fe_mul(&out->y, &a->y, &zi2, f);
}

void ec0_mul(G1 *out, const G1 *p, const U256 *k, const Modulus *f) {
  uint32_t e[BN_LIMBS];
  EcJac acc;
  unsigned i;
  u256_limbs(e, k);
  memset(&acc, 0, sizeof acc);
  for (i = BN_LIMBS * 32u; i > 0; i--) {
    ec0_jac_double(&acc, &acc, f);
    if ((e[(i - 1) / 32u] >> ((i - 1) % 32u)) & 1u)
      ec0_jac_add_affine(&acc, &acc, p, f);
  }
  ec0_jac_affine(out, &acc, f);
}

void g1_double(G1 *out, const G1 *a) {
  ec0_double(out, a, &BN254_FP);
}

void g1_add(G1 *out, const G1 *a, const G1 *b) {
  ec0_add(out, a, b, &BN254_FP);
}

void g1_mul(G1 *out, const G1 *p, const U256 *k) {
  ec0_mul(out, p, k, &BN254_FP);
}

/* The modulus F as a word. */
static void modulus_word(U256 *out, const Modulus *f) {
  uint32_t i;
  for (i = 0; i < 4u; i++)
    out->limb[i] = (uint64_t)f->w[2u * i] | ((uint64_t)f->w[2u * i + 1u] << 32);
}

void scalar_reduce(U256 *out, const U256 *x) {
  U256 r;
  modulus_word(&r, &BN254_FR);
  *out = *x;
  while (u256_cmp(out, &r) >= 0)
    u256_sub(out, out, &r);
}

int g1_from_be(G1 *out, const unsigned char *be) {
  U256 x;
  U256 y;
  u256_from_be(&x, be);
  u256_from_be(&y, be + 32);
  return g1_from_words(out, &x, &y);
}

void g1_to_be(unsigned char *be, const G1 *p) {
  U256 x;
  U256 y;
  g1_to_words(&x, &y, p);
  u256_to_be(be, &x);
  u256_to_be(be + 32, &y);
}
