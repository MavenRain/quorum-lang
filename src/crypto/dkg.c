/* New C (S6 H2b): Pedersen DKG, FROST paper Figure 1. See crypto/dkg.h. */
#include <string.h>

#include "crypto/dkg.h"

#include "crypto/elgamal.h"

const U256 DKG_TAG = {{0x646b67u, 0u, 0u, 0u}};

/* The bit set of the dealers 1 to N. */
static uint32_t all_dealers(uint32_t n) {
  return (1u << (n + 1u)) - 2u;
}

/* 1 when N is THR_N_MAX or less and T is 1 to N. */
static int sizes_ok(uint32_t t, uint32_t n) {
  return n <= THR_N_MAX && t >= 1u && t <= n;
}

void dkg_challenge(U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r) {
  U256 x;
  U256 y;
  thr_hash(c, &DKG_TAG, ctx);
  u256_from_u64(&x, i);
  thr_hash(c, c, &x);
  g1_to_words(&x, &y, c0);
  thr_hash(c, c, &x);
  thr_hash(c, c, &y);
  g1_to_words(&x, &y, r);
  thr_hash(c, c, &x);
  thr_hash(c, c, &y);
}

DkgResult dkg_deal(DkgDealing *out, U256 *shares, const U256 *seed, uint32_t i, uint32_t t, uint32_t n, const U256 *ctx) {
  Fe a[THR_N_MAX];
  Fe x;
  Fe acc;
  Fe tmp;
  Fe fw;
  Fe fc;
  U256 w;
  U256 c;
  G1 g;
  uint32_t k;
  uint32_t j;
  if (!sizes_ok(t, n) || i == 0u || i > n)
    return DKG_BAD_INDEX;
  memset(out, 0, sizeof *out);
  elg_generator(&g);
  for (k = 0; k < t; k++) {
    thr_nonce(&w, seed, k);
    fe_from_u256(&a[k], &w, &BN254_FR);
    g1_mul(&out->c[k], &g, &w);
  }
  /* The Schnorr proof of a_0 (round 1, step 2): the nonce w = a_t. */
  thr_nonce(&w, seed, t);
  g1_mul(&out->r, &g, &w);
  dkg_challenge(&c, ctx, i, &out->c[0], &out->r);
  scalar_reduce(&c, &c);
  fe_from_u256(&fw, &w, &BN254_FR);
  fe_from_u256(&fc, &c, &BN254_FR);
  fe_mul(&tmp, &fc, &a[0], &BN254_FR);
  fe_add(&acc, &fw, &tmp, &BN254_FR);
  fe_to_u256(&out->z, &acc);
  /* f(j) by Horner, as the deal loop of intent-lang src/front/threshold.c. */
  for (j = 1u; j <= n; j++) {
    fe_from_u64(&x, j);
    fe_from_u64(&acc, 0u);
    for (k = t; k > 0u; k--) {
      fe_mul(&tmp, &acc, &x, &BN254_FR);
      fe_add(&acc, &tmp, &a[k - 1u], &BN254_FR);
    }
    fe_to_u256(&shares[j - 1u], &acc);
  }
  return DKG_OK;
}

int dkg_check_proof(const DkgDealing *d, uint32_t i, uint32_t t, const U256 *ctx) {
  U256 c;
  G1 g;
  G1 lhs;
  G1 rhs;
  uint32_t k;
  if (!g1_on_curve(&d->r))
    return 0;
  for (k = 0; k < t; k++)
    if (!g1_on_curve(&d->c[k]))
      return 0;
  dkg_challenge(&c, ctx, i, &d->c[0], &d->r);
  elg_generator(&g);
  g1_mul(&lhs, &g, &d->z);
  g1_mul(&rhs, &d->c[0], &c);
  g1_add(&rhs, &d->r, &rhs);
  return g1_eq(&lhs, &rhs);
}

void dkg_eval(G1 *out, const DkgDealing *d, uint32_t t, uint32_t j) {
  U256 x;
  G1 acc;
  G1 term;
  uint32_t k;
  u256_from_u64(&x, j);
  acc = d->c[t - 1u];
  for (k = t - 1u; k > 0u; k--) {
    g1_mul(&term, &acc, &x);
    g1_add(&acc, &term, &d->c[k - 1u]);
  }
  *out = acc;
}

int dkg_check_share(const DkgDealing *d, uint32_t t, uint32_t j, const U256 *s) {
  G1 g;
  G1 lhs;
  G1 rhs;
  elg_generator(&g);
  g1_mul(&lhs, &g, s);
  dkg_eval(&rhs, d, t, j);
  return g1_eq(&lhs, &rhs);
}

/* 1 when each share in the row ROW of the dealing D passes its check. */
static int row_ok(const DkgDealing *d, const U256 *row, uint32_t t, uint32_t n) {
  uint32_t j;
  for (j = 1u; j <= n; j++)
    if (!dkg_check_share(d, t, j, &row[j - 1u]))
      return 0;
  return 1;
}

DkgResult dkg_qual(uint32_t *qual, const DkgDealing *dealings, const U256 *shares, uint32_t t, uint32_t n, const U256 *ctx) {
  uint32_t bad_proof = 0;
  uint32_t bad_share = 0;
  uint32_t set = 0;
  uint32_t i;
  if (!sizes_ok(t, n))
    return DKG_BAD_INDEX;
  for (i = 1u; i <= n; i++) {
    uint32_t bit = 1u << i;
    int proof = dkg_check_proof(&dealings[i - 1u], i, t, ctx);
    int share = proof && row_ok(&dealings[i - 1u], &shares[(i - 1u) * n], t, n);
    bad_proof |= proof ? 0u : bit;
    bad_share |= (proof && !share) ? bit : 0u;
    set |= share ? bit : 0u;
  }
  *qual = set;
  if (set == 0u)
    return DKG_TOO_FEW;
  if (bad_proof != 0u)
    return DKG_BAD_PROOF;
  return bad_share != 0u ? DKG_BAD_SHARE : DKG_OK;
}

DkgResult dkg_share(ThrShare *out, uint32_t qual, const U256 *shares, uint32_t j, uint32_t n) {
  Fe sum;
  Fe s;
  Fe tmp;
  U256 w;
  G1 g;
  uint32_t i;
  if (n > THR_N_MAX || j == 0u || j > n)
    return DKG_BAD_INDEX;
  if ((qual & all_dealers(n)) == 0u)
    return DKG_TOO_FEW;
  fe_from_u64(&sum, 0u);
  for (i = 1u; i <= n; i++) {
    if (((qual >> i) & 1u) != 0u) {
      scalar_reduce(&w, &shares[(i - 1u) * n + (j - 1u)]);
      fe_from_u256(&s, &w, &BN254_FR);
      fe_add(&tmp, &sum, &s, &BN254_FR);
      sum = tmp;
    }
  }
  out->x = j;
  fe_to_u256(&out->s, &sum);
  elg_generator(&g);
  g1_mul(&out->key, &g, &out->s);
  return DKG_OK;
}

DkgResult dkg_key(G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t t, uint32_t j, uint32_t n) {
  G1 sum;
  G1 term;
  uint32_t i;
  if (!sizes_ok(t, n) || j == 0u || j > n)
    return DKG_BAD_INDEX;
  if ((qual & all_dealers(n)) == 0u)
    return DKG_TOO_FEW;
  /* (0, 0) is the point at infinity. */
  memset(&sum, 0, sizeof sum);
  for (i = 1u; i <= n; i++) {
    if (((qual >> i) & 1u) != 0u) {
      dkg_eval(&term, &dealings[i - 1u], t, j);
      g1_add(&sum, &sum, &term);
    }
  }
  *out = sum;
  return DKG_OK;
}

void dkg_public(G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t n) {
  G1 sum;
  uint32_t i;
  /* (0, 0) is the point at infinity. */
  memset(&sum, 0, sizeof sum);
  for (i = 1u; i <= n && i <= THR_N_MAX; i++)
    if (((qual >> i) & 1u) != 0u)
      g1_add(&sum, &sum, &dealings[i - 1u].c[0]);
  *out = sum;
}
