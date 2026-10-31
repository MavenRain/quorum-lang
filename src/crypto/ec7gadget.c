/* NEW (quorum-lang S11 H3a P4, O159): the gadgets of crypto/ec7gadget.h.
   Each gadget reads its input values with r1cs_value, so the sizing run
   (all capacities 0) gives the same rows. */
#include "crypto/ec7gadget.h"

#include "crypto/secq256k1.h"

/* The offset point Q of the mul gadgets: the first x = 1, 2, ... with
   x^3 + 7 a square in the field F, and y = the root of fe_sqrt. No small
   multiple of P gives Q, so ACC + 2^i P never has ACC = 2^i P or
   ACC = -2^i P for a usual P (O159). */
static void offset_point(Fe *qx, Fe *qy, const Modulus *f) {
  Fe one;
  Fe seven;
  Fe rhs;
  fe_from_u64(&one, 1);
  fe_from_u64(&seven, 7);
  fe_from_u64(qx, 0);
  do {
    fe_add(qx, qx, &one, f);
    fe_mul(&rhs, qx, qx, f);
    fe_mul(&rhs, &rhs, qx, f);
    fe_add(&rhs, &rhs, &seven, f);
  } while (!fe_sqrt(qy, &rhs, f));
}

/* A new variable with the constant value C: one row V * 1 = C. */
static uint32_t constant(R1cs *cs, const Fe *c) {
  uint32_t v = r1cs_var(cs, c);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, v, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term(cs, R1CS_C, 0, c);
  return v;
}

void ec7_const_gadget(R1cs *cs, uint32_t out[2], const Fe *x, const Fe *y) {
  out[0] = constant(cs, x);
  out[1] = constant(cs, y);
}

void ec7_curve_gadget(R1cs *cs, const uint32_t p[2]) {
  uint32_t xx = r1cs_mul(cs, p[0], p[0]);
  uint32_t xxx = r1cs_mul(cs, xx, p[0]);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, p[1], 1);
  r1cs_term_int(cs, R1CS_B, p[1], 1);
  r1cs_term_int(cs, R1CS_C, xxx, 1);
  r1cs_term_int(cs, R1CS_C, 0, 7);
}

void ec7_add_gadget(R1cs *cs, uint32_t out[2], const uint32_t a[2], const uint32_t b[2]) {
  const Modulus *f = cs->f;
  uint32_t x1 = a[0];
  uint32_t y1 = a[1];
  uint32_t x2 = b[0];
  uint32_t y2 = b[1];
  uint32_t inv;
  uint32_t lam;
  Fe vx1;
  Fe vy1;
  Fe vx2;
  Fe vy2;
  Fe d;
  Fe v;
  Fe lambda;
  Fe x3;
  Fe y3;
  r1cs_value(&vx1, cs, x1);
  r1cs_value(&vy1, cs, y1);
  r1cs_value(&vx2, cs, x2);
  r1cs_value(&vy2, cs, y2);
  fe_sub(&d, &vx2, &vx1, f);
  fe_inv(&v, &d, f);
  inv = r1cs_var(cs, &v);
  fe_sub(&d, &vy2, &vy1, f);
  fe_mul(&lambda, &d, &v, f);
  lam = r1cs_var(cs, &lambda);
  fe_mul(&x3, &lambda, &lambda, f);
  fe_sub(&x3, &x3, &vx1, f);
  fe_sub(&x3, &x3, &vx2, f);
  out[0] = r1cs_var(cs, &x3);
  fe_sub(&d, &vx1, &x3, f);
  fe_mul(&y3, &lambda, &d, f);
  fe_sub(&y3, &y3, &vy1, f);
  out[1] = r1cs_var(cs, &y3);
  /* (x2 - x1) inv = 1: x2 is not x1. */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, x2, 1);
  r1cs_term_int(cs, R1CS_A, x1, -1);
  r1cs_term_int(cs, R1CS_B, inv, 1);
  r1cs_term_int(cs, R1CS_C, 0, 1);
  /* lambda (x2 - x1) = y2 - y1 */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, lam, 1);
  r1cs_term_int(cs, R1CS_B, x2, 1);
  r1cs_term_int(cs, R1CS_B, x1, -1);
  r1cs_term_int(cs, R1CS_C, y2, 1);
  r1cs_term_int(cs, R1CS_C, y1, -1);
  /* lambda lambda = x3 + x1 + x2 */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, lam, 1);
  r1cs_term_int(cs, R1CS_B, lam, 1);
  r1cs_term_int(cs, R1CS_C, out[0], 1);
  r1cs_term_int(cs, R1CS_C, x1, 1);
  r1cs_term_int(cs, R1CS_C, x2, 1);
  /* lambda (x1 - x3) = y3 + y1 */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, lam, 1);
  r1cs_term_int(cs, R1CS_B, x1, 1);
  r1cs_term_int(cs, R1CS_B, out[0], -1);
  r1cs_term_int(cs, R1CS_C, out[1], 1);
  r1cs_term_int(cs, R1CS_C, y1, 1);
}

void ec7_double_gadget(R1cs *cs, uint32_t out[2], const uint32_t a[2]) {
  const Modulus *f = cs->f;
  uint32_t x = a[0];
  uint32_t y = a[1];
  uint32_t xx;
  uint32_t lam;
  Fe vx;
  Fe vy;
  Fe t;
  Fe d;
  Fe e;
  Fe lambda;
  Fe x3;
  Fe y3;
  r1cs_value(&vx, cs, x);
  r1cs_value(&vy, cs, y);
  xx = r1cs_mul(cs, x, x);
  r1cs_value(&t, cs, xx);
  fe_add(&d, &t, &t, f);
  fe_add(&d, &d, &t, f);
  fe_add(&t, &vy, &vy, f);
  fe_inv(&e, &t, f);
  fe_mul(&lambda, &d, &e, f);
  lam = r1cs_var(cs, &lambda);
  fe_mul(&x3, &lambda, &lambda, f);
  fe_sub(&x3, &x3, &vx, f);
  fe_sub(&x3, &x3, &vx, f);
  out[0] = r1cs_var(cs, &x3);
  fe_sub(&d, &vx, &x3, f);
  fe_mul(&y3, &lambda, &d, f);
  fe_sub(&y3, &y3, &vy, f);
  out[1] = r1cs_var(cs, &y3);
  /* lambda (2 y) = 3 x x */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, lam, 1);
  r1cs_term_int(cs, R1CS_B, y, 2);
  r1cs_term_int(cs, R1CS_C, xx, 3);
  /* lambda lambda = x3 + 2 x */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, lam, 1);
  r1cs_term_int(cs, R1CS_B, lam, 1);
  r1cs_term_int(cs, R1CS_C, out[0], 1);
  r1cs_term_int(cs, R1CS_C, x, 2);
  /* lambda (x - x3) = y3 + y */
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, lam, 1);
  r1cs_term_int(cs, R1CS_B, x, 1);
  r1cs_term_int(cs, R1CS_B, out[0], -1);
  r1cs_term_int(cs, R1CS_C, out[1], 1);
  r1cs_term_int(cs, R1CS_C, y, 1);
}

/* OUT = K P for K = sum 2^i BIT[i] (i < N), after the curve check of P:
   the constant Q, then for each bit (least significant first) SUM = ACC +
   BASE, 2 selects and BASE = 2 BASE (not after the last bit), then -Q and
   OUT = ACC + (-Q). ACC starts at Q, so it is never the identity. */
static void mul_bits(R1cs *cs, uint32_t out[2], const uint32_t p[2], const uint32_t *bit,
                     size_t n) {
  const Modulus *f = cs->f;
  uint32_t q[2];
  uint32_t acc[2];
  uint32_t base[2];
  uint32_t sum[2];
  size_t i;
  Fe c;
  Fe qx;
  Fe qy;
  offset_point(&qx, &qy, f);
  q[0] = constant(cs, &qx);
  q[1] = constant(cs, &qy);
  acc[0] = q[0];
  acc[1] = q[1];
  base[0] = p[0];
  base[1] = p[1];
  for (i = 0; i < n; i++) {
    ec7_add_gadget(cs, sum, acc, base);
    acc[0] = r1cs_select(cs, bit[i], sum[0], acc[0]);
    acc[1] = r1cs_select(cs, bit[i], sum[1], acc[1]);
    if (i + 1u < n)
      ec7_double_gadget(cs, base, base);
  }
  fe_neg(&c, &qy, f);
  q[1] = constant(cs, &c);
  ec7_add_gadget(cs, out, acc, q);
}

void ec7_mul_gadget(R1cs *cs, uint32_t out[2], const uint32_t p[2], const uint32_t k[2]) {
  const Modulus *f = cs->f;
  uint32_t bit[EC7_GADGET_BITS];
  unsigned char be[32];
  unsigned i;
  unsigned j;
  Fe v;
  Fe c;
  U256 limb;
  ec7_curve_gadget(cs, p);
  for (j = 0; j < 2; j++) {
    r1cs_value(&v, cs, k[j]);
    fe_to_u256(&limb, &v);
    u256_to_be(be, &limb);
    for (i = 0; i < 128; i++) {
      fe_from_u64(&v, ((unsigned)be[31u - (i >> 3)] >> (i & 7u)) & 1u);
      bit[128u * j + i] = r1cs_bool(cs, &v);
    }
  }
  /* (sum 2^i bit[128 j + i]) * 1 = K[j]: each limb is below 2^128, so
     its bits are the only ones. */
  for (j = 0; j < 2; j++) {
    fe_from_u64(&c, 1);
    r1cs_row(cs);
    for (i = 0; i < 128; i++) {
      r1cs_term(cs, R1CS_A, bit[128u * j + i], &c);
      fe_add(&c, &c, &c, f);
    }
    r1cs_term_int(cs, R1CS_B, 0, 1);
    r1cs_term_int(cs, R1CS_C, k[j], 1);
  }
  mul_bits(cs, out, p, bit, EC7_GADGET_BITS);
}

void ec7_mul_bits_gadget(R1cs *cs, uint32_t out[2], const uint32_t p[2], const uint32_t *bit,
                         size_t n) {
  ec7_curve_gadget(cs, p);
  mul_bits(cs, out, p, bit, n);
}

void ec7_add_id_gadget(R1cs *cs, uint32_t out[2], const uint32_t a[2], uint32_t a_id,
                       const uint32_t b[2]) {
  uint32_t q[2];
  uint32_t left[2];
  uint32_t sum[2];
  Fe qx;
  Fe qy;
  r1cs_assert_bool(cs, a_id);
  offset_point(&qx, &qy, cs->f);
  q[0] = constant(cs, &qx);
  q[1] = constant(cs, &qy);
  left[0] = r1cs_select(cs, a_id, q[0], a[0]);
  left[1] = r1cs_select(cs, a_id, q[1], a[1]);
  ec7_add_gadget(cs, sum, left, b);
  out[0] = r1cs_select(cs, a_id, b[0], sum[0]);
  out[1] = r1cs_select(cs, a_id, b[1], sum[1]);
}
