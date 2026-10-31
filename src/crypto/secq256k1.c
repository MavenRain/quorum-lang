/* NEW (quorum-lang S11 H2, O156): secq256k1 on the ec0_* of crypto/bn254.h,
   and fe_sqrt (Tonelli-Shanks). n = 1 mod 4 and n - 1 = 2^6 times an odd
   number, so the p = 3 mod 4 root of crypto/secp256k1.c (lift_x) does not
   work in F_n. */
#include "crypto/secq256k1.h"

#include <string.h>

/* The y of the generator (O156); x = 1. */
static const U256 QGY = {{0xc1b800d1ffc278c0ull, 0x48916189041f2af0ull, 0x4909abdf82c9bd02ull, 0x0c7c97045a207463ull}};

/* The word of the modulus F. */
static void modulus_word(U256 *out, const Modulus *f) {
  uint32_t i;
  for (i = 0; i < 4u; i++)
    out->limb[i] = (uint64_t)f->w[2u * i] | ((uint64_t)f->w[2u * i + 1u] << 32);
}

/* X = X / 2, the floor. */
static void halve(U256 *x) {
  uint32_t i;
  for (i = 0; i < 4u; i++)
    x->limb[i] = (x->limb[i] >> 1) | (i < 3u ? x->limb[i + 1u] << 63 : 0u);
}

/* The steps follow the sqrt_mod of quorum-lang-work/s11-h2-vectors.py: q - 1
   = 2^s odd; z is the least non-square from 2; then c = z^odd, t = a^odd,
   r = a^((odd + 1) / 2), and each step makes the order of t less. */
int fe_sqrt(Fe *out, const Fe *a, const Modulus *f) {
  U256 q;
  U256 one;
  U256 euler;
  U256 odd;
  U256 odd_up;
  Fe zero;
  Fe e_one;
  Fe minus_one;
  Fe z;
  Fe c;
  Fe t;
  Fe r;
  Fe b;
  Fe tt;
  Fe check;
  uint32_t s = 0;
  uint32_t m;
  uint32_t i;
  uint32_t k;
  memset(&zero, 0, sizeof zero);
  if (fe_eq(a, &zero)) {
    *out = zero;
    return 1;
  }
  modulus_word(&q, f);
  u256_from_u64(&one, 1);
  (void)u256_sub(&euler, &q, &one);
  odd = euler;
  halve(&euler);
  fe_from_u64(&e_one, 1);
  fe_pow(&check, a, &euler, f);
  if (!fe_eq(&check, &e_one))
    return 0;
  while ((odd.limb[0] & 1u) == 0u) {
    halve(&odd);
    s++;
  }
  fe_neg(&minus_one, &e_one, f);
  fe_from_u64(&z, 2);
  fe_pow(&check, &z, &euler, f);
  while (!fe_eq(&check, &minus_one)) {
    fe_add(&z, &z, &e_one, f);
    fe_pow(&check, &z, &euler, f);
  }
  (void)u256_add(&odd_up, &odd, &one);
  halve(&odd_up);
  m = s;
  fe_pow(&c, &z, &odd, f);
  fe_pow(&t, a, &odd, f);
  fe_pow(&r, a, &odd_up, f);
  while (!fe_eq(&t, &e_one)) {
    i = 0;
    tt = t;
    while (!fe_eq(&tt, &e_one)) {
      fe_mul(&tt, &tt, &tt, f);
      i++;
    }
    b = c;
    for (k = 0; k + i + 1u < m; k++)
      fe_mul(&b, &b, &b, f);
    m = i;
    fe_mul(&c, &b, &b, f);
    fe_mul(&t, &t, &c, f);
    fe_mul(&r, &r, &b, f);
  }
  *out = r;
  return 1;
}

static int is_identity(const G1 *p) {
  G1 zero;
  memset(&zero, 0, sizeof zero);
  return secq_eq(p, &zero);
}

void secq_gen(G1 *out) {
  fe_from_u64(&out->x, 1);
  fe_from_u256(&out->y, &QGY, &SECQ_FB);
}

int secq_on_curve(const G1 *p) {
  Fe lhs;
  Fe rhs;
  Fe seven;
  if (is_identity(p))
    return 1;
  fe_from_u64(&seven, 7);
  fe_mul(&lhs, &p->y, &p->y, &SECQ_FB);
  fe_mul(&rhs, &p->x, &p->x, &SECQ_FB);
  fe_mul(&rhs, &rhs, &p->x, &SECQ_FB);
  fe_add(&rhs, &rhs, &seven, &SECQ_FB);
  return fe_eq(&lhs, &rhs);
}

void secq_add(G1 *out, const G1 *a, const G1 *b) {
  ec0_add(out, a, b, &SECQ_FB);
}

void secq_double(G1 *out, const G1 *a) {
  ec0_double(out, a, &SECQ_FB);
}

void secq_mul(G1 *out, const G1 *p, const U256 *k) {
  ec0_mul(out, p, k, &SECQ_FB);
}

void secq_neg(G1 *out, const G1 *a) {
  G1 t;
  t.x = a->x;
  fe_neg(&t.y, &a->y, &SECQ_FB);
  *out = t;
}

int secq_eq(const G1 *a, const G1 *b) {
  return fe_eq(&a->x, &b->x) && fe_eq(&a->y, &b->y);
}
