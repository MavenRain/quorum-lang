/* New C (S6 H2b): Pedersen DKG, FROST paper Figure 1. S7 H3b (O96): the
   curve descriptor, DKG_BN254 and DKG_SECP256K1. S7 H4a (O97): the
   reshare. See crypto/dkg.h. */
#include <string.h>

#include "crypto/dkg.h"

#include "crypto/elgamal.h"
#include "crypto/secp256k1.h"
#include "crypto/xmd.h"

const U256 DKG_TAG = {{0x646b67u, 0u, 0u, 0u}};

/* The secp256k1 order n as a word (SEC 2 section 2.4.1). */
static const U256 SECP_N_WORD = {{0xbfd25e8cd0364141ull, 0xbaaedce6af48a03bull, 0xfffffffffffffffeull,
                                  0xffffffffffffffffull}};

/* The DST of the DKG_SECP256K1 nonce. */
static const unsigned char NONCE_DST[] = "dkg nonce";

/* The bit set of the dealers 1 to N. */
static uint32_t all_dealers(uint32_t n) {
  return (1u << (n + 1u)) - 2u;
}

/* 1 when N is THR_N_MAX or less and T is 1 to N. */
static int sizes_ok(uint32_t t, uint32_t n) {
  return n <= THR_N_MAX && t >= 1u && t <= n;
}

/* The S6 challenge: the thr_hash chain, not reduced. */
static int bn_challenge(U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r) {
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
  return 1;
}

/* The 32 big endian bytes of X (as put_word of crypto/secp256k1.c). */
static void put_word(unsigned char *out, const U256 *x) {
  uint32_t i;
  for (i = 0; i < 32u; i++)
    out[i] = (unsigned char)(x->limb[3u - i / 8u] >> (56u - 8u * (i % 8u)));
}

/* X mod n: n is above 2^255, so one subtraction is enough. */
static void secp_reduce(U256 *out, const U256 *x) {
  Fe f;
  U256 y = *x;
  if (!fe_from_u256(&f, x, &SECP_FN))
    u256_sub(&y, x, &SECP_N_WORD);
  *out = y;
}

static void secp_nonce(U256 *out, const U256 *seed, uint64_t k) {
  unsigned char msg[40];
  Fe a;
  uint32_t b;
  put_word(msg, seed);
  for (b = 0; b < 8u; b++)
    msg[32u + b] = (unsigned char)(k >> (56u - 8u * b));
  fe_from_u64(&a, 0u);
  xmd_to_scalar(&a, msg, sizeof msg, NONCE_DST, sizeof NONCE_DST - 1u, &SECP_FN);
  fe_to_u256(out, &a);
}

static int secp_challenge(U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r) {
  unsigned char dst[35];
  unsigned char msg[98];
  U256 w;
  Fe x;
  memset(c, 0, sizeof *c);
  put_word(dst, ctx);
  memcpy(dst + 32, "dkg", 3);
  u256_from_u64(&w, i);
  put_word(msg, &w);
  if (!secp_encode(msg + 32, c0) || !secp_encode(msg + 65, r) ||
      !xmd_to_scalar(&x, msg, sizeof msg, dst, sizeof dst, &SECP_FN))
    return 0;
  fe_to_u256(c, &x);
  return 1;
}

const DkgCurve DKG_BN254 = {&BN254_FR, elg_generator, g1_on_curve, g1_add, g1_mul,
                            g1_eq, scalar_reduce, thr_nonce, bn_challenge};

const DkgCurve DKG_SECP256K1 = {&SECP_FN, secp_gen, secp_on_curve, secp_add, secp_mul,
                                secp_eq, secp_reduce, secp_nonce, secp_challenge};

int dkg_challenge(const DkgCurve *curve, U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r) {
  return curve->challenge(c, ctx, i, c0, r);
}

/* The dealing of the dealer I for T of N and CTX (dkg_deal), with a_0 =
   *A0 when A0 is not NULL (dkg_reshare_deal). */
static void deal_with(const DkgCurve *curve, DkgDealing *out, U256 *shares, const U256 *seed, const Fe *a0,
                      uint32_t i, uint32_t t, uint32_t n, const U256 *ctx) {
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
  memset(out, 0, sizeof *out);
  curve->gen(&g);
  for (k = 0; k < t; k++) {
    curve->nonce(&w, seed, k);
    if (k == 0u && a0 != NULL)
      fe_to_u256(&w, a0);
    fe_from_u256(&a[k], &w, curve->order);
    curve->mul(&out->c[k], &g, &w);
  }
  /* The Schnorr proof of a_0 (round 1, step 2): the nonce w = a_t. A point
     with no encoding gives c = 0, and dkg_check_proof refuses it. */
  curve->nonce(&w, seed, t);
  curve->mul(&out->r, &g, &w);
  dkg_challenge(curve, &c, ctx, i, &out->c[0], &out->r);
  curve->reduce(&c, &c);
  fe_from_u256(&fw, &w, curve->order);
  fe_from_u256(&fc, &c, curve->order);
  fe_mul(&tmp, &fc, &a[0], curve->order);
  fe_add(&acc, &fw, &tmp, curve->order);
  fe_to_u256(&out->z, &acc);
  /* f(j) by Horner, as the deal loop of intent-lang src/front/threshold.c. */
  for (j = 1u; j <= n; j++) {
    fe_from_u64(&x, j);
    fe_from_u64(&acc, 0u);
    for (k = t; k > 0u; k--) {
      fe_mul(&tmp, &acc, &x, curve->order);
      fe_add(&acc, &tmp, &a[k - 1u], curve->order);
    }
    fe_to_u256(&shares[j - 1u], &acc);
  }
}

DkgResult dkg_deal(const DkgCurve *curve, DkgDealing *out, U256 *shares, const U256 *seed, uint32_t i, uint32_t t,
                   uint32_t n, const U256 *ctx) {
  if (!sizes_ok(t, n) || i == 0u || i > n)
    return DKG_BAD_INDEX;
  deal_with(curve, out, shares, seed, NULL, i, t, n, ctx);
  return DKG_OK;
}

int dkg_check_proof(const DkgCurve *curve, const DkgDealing *d, uint32_t i, uint32_t t, const U256 *ctx) {
  U256 c;
  G1 g;
  G1 lhs;
  G1 rhs;
  uint32_t k;
  if (!curve->on_curve(&d->r))
    return 0;
  for (k = 0; k < t; k++)
    if (!curve->on_curve(&d->c[k]))
      return 0;
  if (!dkg_challenge(curve, &c, ctx, i, &d->c[0], &d->r))
    return 0;
  curve->gen(&g);
  curve->mul(&lhs, &g, &d->z);
  curve->mul(&rhs, &d->c[0], &c);
  curve->add(&rhs, &d->r, &rhs);
  return curve->eq(&lhs, &rhs);
}

void dkg_eval(const DkgCurve *curve, G1 *out, const DkgDealing *d, uint32_t t, uint32_t j) {
  U256 x;
  G1 acc;
  G1 term;
  uint32_t k;
  u256_from_u64(&x, j);
  acc = d->c[t - 1u];
  for (k = t - 1u; k > 0u; k--) {
    curve->mul(&term, &acc, &x);
    curve->add(&acc, &term, &d->c[k - 1u]);
  }
  *out = acc;
}

int dkg_check_share(const DkgCurve *curve, const DkgDealing *d, uint32_t t, uint32_t j, const U256 *s) {
  G1 g;
  G1 lhs;
  G1 rhs;
  curve->gen(&g);
  curve->mul(&lhs, &g, s);
  dkg_eval(curve, &rhs, d, t, j);
  return curve->eq(&lhs, &rhs);
}

/* 1 when each share in the row ROW of the dealing D passes its check. */
static int row_ok(const DkgCurve *curve, const DkgDealing *d, const U256 *row, uint32_t t, uint32_t n) {
  uint32_t j;
  for (j = 1u; j <= n; j++)
    if (!dkg_check_share(curve, d, t, j, &row[j - 1u]))
      return 0;
  return 1;
}

DkgResult dkg_qual(const DkgCurve *curve, uint32_t *qual, const DkgDealing *dealings, const U256 *shares, uint32_t t,
                   uint32_t n, const U256 *ctx) {
  uint32_t bad_proof = 0;
  uint32_t bad_share = 0;
  uint32_t set = 0;
  uint32_t i;
  if (!sizes_ok(t, n))
    return DKG_BAD_INDEX;
  for (i = 1u; i <= n; i++) {
    uint32_t bit = 1u << i;
    int proof = dkg_check_proof(curve, &dealings[i - 1u], i, t, ctx);
    int share = proof && row_ok(curve, &dealings[i - 1u], &shares[(i - 1u) * n], t, n);
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

DkgResult dkg_share(const DkgCurve *curve, ThrShare *out, uint32_t qual, const U256 *shares, uint32_t j, uint32_t n) {
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
      curve->reduce(&w, &shares[(i - 1u) * n + (j - 1u)]);
      fe_from_u256(&s, &w, curve->order);
      fe_add(&tmp, &sum, &s, curve->order);
      sum = tmp;
    }
  }
  out->x = j;
  fe_to_u256(&out->s, &sum);
  curve->gen(&g);
  curve->mul(&out->key, &g, &out->s);
  return DKG_OK;
}

DkgResult dkg_key(const DkgCurve *curve, G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t t, uint32_t j,
                  uint32_t n) {
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
      dkg_eval(curve, &term, &dealings[i - 1u], t, j);
      curve->add(&sum, &sum, &term);
    }
  }
  *out = sum;
  return DKG_OK;
}

void dkg_public(const DkgCurve *curve, G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t n) {
  G1 sum;
  uint32_t i;
  /* (0, 0) is the point at infinity. */
  memset(&sum, 0, sizeof sum);
  for (i = 1u; i <= n && i <= THR_N_MAX; i++)
    if (((qual >> i) & 1u) != 0u)
      curve->add(&sum, &sum, &dealings[i - 1u].c[0]);
  *out = sum;
}

/* 1 when Q is COUNT indices 1 to THR_N_MAX in rising order (so each one
   time). */
static int quorum_ok(const uint32_t *quorum, uint32_t count) {
  uint32_t k;
  if (count == 0u || count > THR_N_MAX)
    return 0;
  for (k = 0; k < count; k++)
    if (quorum[k] == 0u || quorum[k] > THR_N_MAX || (k > 0u && quorum[k] <= quorum[k - 1u]))
      return 0;
  return 1;
}

/* The bit set of Q (bit i for the dealer i). */
static uint32_t quorum_set(const uint32_t *quorum, uint32_t count) {
  uint32_t set = 0;
  uint32_t k;
  for (k = 0; k < count; k++)
    set |= 1u << quorum[k];
  return set;
}

/* OUT = lambda_{I,Q}: the product over the other j of Q of j / (j - I) mod
   r (the frost_lagrange rule over CURVE). Q must pass quorum_ok. */
static void lambda_of(const DkgCurve *curve, Fe *out, uint32_t i, const uint32_t *quorum, uint32_t count) {
  Fe num;
  Fe den;
  Fe xi;
  Fe xj;
  Fe diff;
  Fe tmp;
  Fe inv;
  uint32_t k;
  fe_from_u64(&num, 1u);
  fe_from_u64(&den, 1u);
  fe_from_u64(&xi, i);
  for (k = 0; k < count; k++)
    if (quorum[k] != i) {
      fe_from_u64(&xj, quorum[k]);
      fe_mul(&tmp, &num, &xj, curve->order);
      num = tmp;
      fe_sub(&diff, &xj, &xi, curve->order);
      fe_mul(&tmp, &den, &diff, curve->order);
      den = tmp;
    }
  fe_inv(&inv, &den, curve->order);
  fe_mul(out, &num, &inv, curve->order);
}

/* 1 when C[0] of D = lambda_{I,Q} KEY (O97). */
static int reshare_ok(const DkgCurve *curve, const DkgDealing *d, const G1 *key, uint32_t i, const uint32_t *quorum,
                      uint32_t count) {
  Fe lam;
  U256 w;
  G1 want;
  lambda_of(curve, &lam, i, quorum, count);
  fe_to_u256(&w, &lam);
  curve->mul(&want, key, &w);
  return curve->eq(&d->c[0], &want);
}

DkgResult dkg_reshare_deal(const DkgCurve *curve, DkgDealing *out, U256 *shares, const U256 *seed, const ThrShare *old,
                           const uint32_t *quorum, uint32_t count, uint32_t t, uint32_t n, const U256 *ctx) {
  Fe lam;
  Fe s;
  Fe a0;
  U256 reduced;
  if (!sizes_ok(t, n) || !quorum_ok(quorum, count) || old->x > THR_N_MAX ||
      (quorum_set(quorum, count) & (1u << old->x)) == 0u)
    return DKG_BAD_INDEX;
  lambda_of(curve, &lam, old->x, quorum, count);
  curve->reduce(&reduced, &old->s);
  fe_from_u256(&s, &reduced, curve->order);
  fe_mul(&a0, &lam, &s, curve->order);
  deal_with(curve, out, shares, seed, &a0, old->x, t, n, ctx);
  return DKG_OK;
}

DkgResult dkg_reshare_qual(const DkgCurve *curve, uint32_t *qual, const DkgDealing *dealings, const U256 *shares,
                           const G1 *keys, const uint32_t *quorum, uint32_t count, uint32_t old_t, uint32_t t,
                           uint32_t n, const U256 *ctx) {
  uint32_t bad_proof = 0;
  uint32_t bad_reshare = 0;
  uint32_t bad_share = 0;
  uint32_t set = 0;
  uint32_t k;
  if (!sizes_ok(t, n) || old_t == 0u || !quorum_ok(quorum, count))
    return DKG_BAD_INDEX;
  if (count < old_t) {
    *qual = 0u;
    return DKG_TOO_FEW;
  }
  for (k = 0; k < count; k++) {
    uint32_t i = quorum[k];
    uint32_t bit = 1u << i;
    int proof = dkg_check_proof(curve, &dealings[k], i, t, ctx);
    int reshare = proof && reshare_ok(curve, &dealings[k], &keys[k], i, quorum, count);
    int share = reshare && row_ok(curve, &dealings[k], &shares[k * n], t, n);
    bad_proof |= proof ? 0u : bit;
    bad_reshare |= (proof && !reshare) ? bit : 0u;
    bad_share |= (reshare && !share) ? bit : 0u;
    set |= share ? bit : 0u;
  }
  *qual = set;
  if (set == 0u)
    return DKG_TOO_FEW;
  if (bad_proof != 0u)
    return DKG_BAD_PROOF;
  if (bad_reshare != 0u)
    return DKG_BAD_RESHARE;
  return bad_share != 0u ? DKG_BAD_SHARE : DKG_OK;
}

DkgResult dkg_reshare_share(const DkgCurve *curve, ThrShare *out, uint32_t qual, const U256 *shares,
                            const uint32_t *quorum, uint32_t count, uint32_t j, uint32_t n) {
  Fe acc;
  Fe s;
  Fe tmp;
  U256 reduced;
  G1 g;
  uint32_t k;
  if (n > THR_N_MAX || j == 0u || j > n || !quorum_ok(quorum, count))
    return DKG_BAD_INDEX;
  if (qual != quorum_set(quorum, count))
    return DKG_TOO_FEW;
  fe_from_u64(&acc, 0u);
  for (k = 0; k < count; k++) {
    curve->reduce(&reduced, &shares[k * n + j - 1u]);
    fe_from_u256(&s, &reduced, curve->order);
    fe_add(&tmp, &acc, &s, curve->order);
    acc = tmp;
  }
  out->x = j;
  fe_to_u256(&out->s, &acc);
  curve->gen(&g);
  curve->mul(&out->key, &g, &out->s);
  return DKG_OK;
}

DkgResult dkg_reshare_key(const DkgCurve *curve, G1 *out, uint32_t qual, const DkgDealing *dealings,
                          const uint32_t *quorum, uint32_t count, uint32_t t, uint32_t j, uint32_t n) {
  G1 acc;
  G1 part;
  G1 tmp;
  uint32_t k;
  if (!sizes_ok(t, n) || j == 0u || j > n || !quorum_ok(quorum, count))
    return DKG_BAD_INDEX;
  if (qual != quorum_set(quorum, count))
    return DKG_TOO_FEW;
  dkg_eval(curve, &acc, &dealings[0], t, j);
  for (k = 1u; k < count; k++) {
    dkg_eval(curve, &part, &dealings[k], t, j);
    curve->add(&tmp, &acc, &part);
    acc = tmp;
  }
  *out = acc;
  return DKG_OK;
}
