/* NEW (quorum-lang S11 H4a C2): the IPA, the MLE helpers and the
   transcript of the compressed Nova proof (see crypto/ipa.h). */
#include "crypto/ipa.h"

#include "crypto/msm.h"

/* The work space of the last MSM of ipa_verify: 2 IPA_C_MAX + 3 points
   need msm_buckets = 3 buckets. */
#define IPA_SMALL_POINTS (2u * IPA_C_MAX + 3u)
#define IPA_SMALL_BUCKETS 16u

static void ipa_identity(G1 *out) {
  fe_from_u64(&out->x, 0);
  fe_from_u64(&out->y, 0);
}

static int ipa_is_identity(const G1 *p) {
  Fe zero;
  fe_from_u64(&zero, 0);
  return fe_eq(&p->x, &zero) && fe_eq(&p->y, &zero);
}

static int ipa_is_zero(const Fe *x) {
  Fe zero;
  fe_from_u64(&zero, 0);
  return fe_eq(x, &zero);
}

/* The scalar field of CURVE: F_n for secp256k1, F_p for secq256k1. */
static const Modulus *ipa_field(GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return nova_base(GENS_SECQ256K1);
  case GENS_SECQ256K1:
    return nova_base(GENS_SECP256K1);
  }
  return nova_base(GENS_SECP256K1);
}

int ipa_key(IpaKey *out, const NovaKey *nova, unsigned c, G1 *g, U256 *k, EcJac *bucket,
            size_t buckets) {
  size_t n;
  size_t i;
  if (c > IPA_C_MAX)
    return 0;
  n = (size_t)1 << c;
  if (buckets < msm_buckets(n))
    return 0;
  for (i = 0; i < n; i++) {
    if (i < nova->n)
      g[i] = nova->g[i];
    else
      gens_point(&g[i], nova->curve, (uint32_t)i);
  }
  gens_point(&out->q, nova->curve, (uint32_t)n);
  out->curve = nova->curve;
  out->f = ipa_field(nova->curve);
  out->c = c;
  out->g = g;
  out->k = k;
  out->bucket = bucket;
  out->buckets = buckets;
  return 1;
}

int ipa_com(G1 *out, const IpaKey *key, const Fe *v, size_t len) {
  size_t i;
  if (len > ((size_t)1 << key->c))
    return 0;
  if (len == 0) {
    ipa_identity(out);
    return 1;
  }
  for (i = 0; i < len; i++)
    fe_to_u256(&key->k[i], &v[i]);
  return msm(out, key->g, key->k, len, key->bucket, key->buckets, nova_base(key->curve));
}

/* OUT[j] = the product over i below C of (LO[i] for j_i = 0, HI[i] for
   j_i = 1), with j_i the bit C - 1 - i of j. */
static void ipa_table(Fe *out, const Fe *lo, const Fe *hi, unsigned c, const Modulus *f) {
  size_t len = 1;
  size_t t;
  unsigned i;
  Fe v;
  fe_from_u64(&out[0], 1);
  for (i = 0; i < c; i++) {
    for (t = len; t-- > 0;) {
      v = out[t];
      fe_mul(&out[2 * t + 1], &v, &hi[i], f);
      fe_mul(&out[2 * t], &v, &lo[i], f);
    }
    len *= 2;
  }
}

int ipa_eq(Fe *out, const Fe *r, unsigned c, const Modulus *f) {
  Fe lo[IPA_C_MAX];
  Fe one;
  unsigned i;
  if (c > IPA_C_MAX)
    return 0;
  fe_from_u64(&one, 1);
  for (i = 0; i < c; i++)
    fe_sub(&lo[i], &one, &r[i], f);
  ipa_table(out, lo, r, c, f);
  return 1;
}

void ipa_eq_at(Fe *out, const Fe *a, const Fe *b, unsigned c, const Modulus *f) {
  Fe one;
  Fe acc;
  Fe ab;
  Fe na;
  Fe nb;
  Fe t;
  unsigned i;
  fe_from_u64(&one, 1);
  acc = one;
  for (i = 0; i < c; i++) {
    fe_mul(&ab, &a[i], &b[i], f);
    fe_sub(&na, &one, &a[i], f);
    fe_sub(&nb, &one, &b[i], f);
    fe_mul(&t, &na, &nb, f);
    fe_add(&t, &t, &ab, f);
    fe_mul(&ab, &acc, &t, f);
    acc = ab;
  }
  *out = acc;
}

/* OUT = the sum of A[i] B[i] for i below N. */
static void ipa_dot(Fe *out, const Fe *a, const Fe *b, size_t n, const Modulus *f) {
  Fe s;
  Fe sum;
  size_t i;
  fe_from_u64(&sum, 0);
  for (i = 0; i < n; i++) {
    fe_mul(&s, &a[i], &b[i], f);
    fe_add(&sum, &sum, &s, f);
  }
  *out = sum;
}

int ipa_mle(Fe *out, const Fe *v, size_t len, const Fe *r, unsigned c, Fe *w, const Modulus *f) {
  if (c > IPA_C_MAX || len > ((size_t)1 << c))
    return 0;
  (void)ipa_eq(w, r, c, f);
  ipa_dot(out, v, w, len, f);
  return 1;
}

void ipa_ts_domain(Fe *out) {
  fe_from_u64(out, IPA_TS_DOMAIN);
}

void ipa_ts_start(IpaTranscript *ts, const PoseidonParams *params, const Fe *domain) {
  unsigned i;
  ts->params = params;
  for (i = 0; i < POSEIDON_WIDTH; i++)
    fe_from_u64(&ts->state[i], 0);
  ts->state[0] = *domain;
  fe_from_u64(&ts->pend, 0);
  ts->has = 0;
}

void ipa_ts_fe(IpaTranscript *ts, const Fe *x) {
  const Modulus *f = &ts->params->f;
  if (!ts->has) {
    ts->pend = *x;
    ts->has = 1;
    return;
  }
  fe_add(&ts->state[1], &ts->state[1], &ts->pend, f);
  fe_add(&ts->state[2], &ts->state[2], x, f);
  poseidon_perm(ts->state, ts->params);
  ts->has = 0;
}

/* TS adds X as 2 limbs of 128 bits, the low limb first (X can be a value
   of the other field). */
static void ipa_ts_limbs(IpaTranscript *ts, const Fe *x) {
  U256 v;
  U256 lo;
  U256 hi;
  Fe in;
  fe_to_u256(&v, x);
  u256_from_u64(&lo, 0);
  u256_from_u64(&hi, 0);
  lo.limb[0] = v.limb[0];
  lo.limb[1] = v.limb[1];
  hi.limb[0] = v.limb[2];
  hi.limb[1] = v.limb[3];
  (void)fe_from_u256(&in, &lo, &ts->params->f);
  ipa_ts_fe(ts, &in);
  (void)fe_from_u256(&in, &hi, &ts->params->f);
  ipa_ts_fe(ts, &in);
}

void ipa_ts_point(IpaTranscript *ts, const G1 *p) {
  ipa_ts_limbs(ts, &p->x);
  ipa_ts_limbs(ts, &p->y);
}

void ipa_ts_challenge(IpaTranscript *ts, Fe *out) {
  if (ts->has)
    fe_add(&ts->state[1], &ts->state[1], &ts->pend, &ts->params->f);
  poseidon_perm(ts->state, ts->params);
  ts->has = 0;
  *out = ts->state[1];
}

void ipa_ts_challenge128(IpaTranscript *ts, Fe *out) {
  Fe full;
  U256 h;
  ipa_ts_challenge(ts, &full);
  fe_to_u256(&h, &full);
  h.limb[2] = 0;
  h.limb[3] = 0;
  (void)fe_from_u256(out, &h, &ts->params->f);
}

/* OUT = P in Jacobian form (Z = 1). */
static void ipa_lift(EcJac *out, const G1 *p) {
  out->x = p->x;
  out->y = p->y;
  fe_from_u64(&out->z, 1);
}

/* OUT = LO + X HI over BASE, X below 2^128: the bits of X from the top,
   in Jacobian form, one inverse at the end. OUT can be LO. */
static void ipa_fold_point(G1 *out, const G1 *lo, const G1 *hi, const Fe *x, const Modulus *base) {
  EcJac acc;
  EcJac tmp;
  U256 k;
  G1 low = *lo;
  unsigned bit;
  int set;
  int started = 0;
  if (ipa_is_identity(hi)) {
    *out = low;
    return;
  }
  fe_to_u256(&k, x);
  fe_from_u64(&acc.x, 1);
  fe_from_u64(&acc.y, 1);
  fe_from_u64(&acc.z, 0);
  for (bit = NOVA_R_BITS; bit-- > 0;) {
    set = (int)((k.limb[bit / 64u] >> (bit % 64u)) & 1u);
    if (started) {
      ec0_jac_double(&tmp, &acc, base);
      acc = tmp;
    }
    if (started && set) {
      ec0_jac_add_affine(&tmp, &acc, hi, base);
      acc = tmp;
    }
    if (!started && set)
      ipa_lift(&acc, hi);
    started = started || set;
  }
  if (started && !ipa_is_identity(&low)) {
    ec0_jac_add_affine(&tmp, &acc, &low, base);
    acc = tmp;
  }
  if (started) {
    ec0_jac_affine(out, &acc, base);
    return;
  }
  *out = low;
}

/* OUT = <A, G> + CROSS QH for LEN values. */
static int ipa_side(G1 *out, const IpaKey *key, const G1 *g, const Fe *a, size_t len,
                    const Fe *cross, const G1 *qh) {
  G1 sum;
  G1 t;
  size_t i;
  for (i = 0; i < len; i++)
    fe_to_u256(&key->k[i], &a[i]);
  if (!msm(&sum, g, key->k, len, key->bucket, key->buckets, nova_base(key->curve)))
    return 0;
  nova_mul(&t, qh, cross, key->curve);
  nova_add(out, &sum, &t, key->curve);
  return 1;
}

int ipa_prove(IpaProof *out, const IpaKey *key, IpaTranscript *ts, const G1 *com, Fe *a, Fe *b,
              const Fe *rho, const Fe *v, G1 *gw) {
  const Modulus *f = key->f;
  const Modulus *base = nova_base(key->curve);
  const G1 *src = key->g;
  size_t n = (size_t)1 << key->c;
  size_t half;
  size_t t;
  unsigned i;
  Fe h;
  Fe cl;
  Fe cr;
  Fe x;
  Fe xi;
  Fe s;
  G1 qh;
  if (!ipa_eq(b, rho, key->c, f))
    return 0;
  ipa_ts_point(ts, com);
  ipa_ts_fe(ts, v);
  ipa_ts_challenge(ts, &h);
  nova_mul(&qh, &key->q, &h, key->curve);
  out->c = key->c;
  for (i = 0; i < key->c; i++) {
    half = n / 2;
    ipa_dot(&cl, a, b + half, half, f);
    ipa_dot(&cr, a + half, b, half, f);
    if (!ipa_side(&out->l[i], key, src + half, a, half, &cl, &qh) ||
        !ipa_side(&out->r[i], key, src, a + half, half, &cr, &qh))
      return 0;
    ipa_ts_point(ts, &out->l[i]);
    ipa_ts_point(ts, &out->r[i]);
    ipa_ts_challenge128(ts, &x);
    if (ipa_is_zero(&x))
      return 0;
    fe_inv(&xi, &x, f);
    for (t = 0; t < half; t++) {
      fe_mul(&s, &xi, &a[half + t], f);
      fe_add(&a[t], &a[t], &s, f);
      fe_mul(&s, &x, &b[half + t], f);
      fe_add(&b[t], &b[t], &s, f);
      ipa_fold_point(&gw[t], &src[t], &src[half + t], &x, base);
    }
    src = gw;
    n = half;
  }
  out->a = a[0];
  return 1;
}

/* PTS[*M] = P and KS[*M] = K when P is not the identity (the identity
   adds nothing, and to skip it keeps the point count small). */
static void ipa_term(G1 *pts, U256 *ks, size_t *m, const G1 *p, const Fe *k) {
  if (ipa_is_identity(p))
    return;
  pts[*m] = *p;
  fe_to_u256(&ks[*m], k);
  *m += 1;
}

int ipa_verify(const IpaKey *key, IpaTranscript *ts, const G1 *com, const Fe *rho, const Fe *v,
               const IpaProof *pf, Fe *w) {
  const Modulus *f = key->f;
  const Modulus *base = nova_base(key->curve);
  size_t n = (size_t)1 << key->c;
  size_t j;
  size_t m = 0;
  unsigned i;
  Fe h;
  Fe one;
  Fe bf;
  Fe s;
  Fe u;
  Fe x[IPA_C_MAX];
  Fe xi[IPA_C_MAX];
  Fe ones[IPA_C_MAX];
  G1 gf;
  G1 sum;
  G1 pts[IPA_SMALL_POINTS];
  U256 ks[IPA_SMALL_POINTS];
  EcJac bk[IPA_SMALL_BUCKETS];
  if (pf->c != key->c)
    return 1;
  fe_from_u64(&one, 1);
  bf = one;
  ipa_ts_point(ts, com);
  ipa_ts_fe(ts, v);
  ipa_ts_challenge(ts, &h);
  for (i = 0; i < key->c; i++) {
    ipa_ts_point(ts, &pf->l[i]);
    ipa_ts_point(ts, &pf->r[i]);
    ipa_ts_challenge128(ts, &x[i]);
    if (ipa_is_zero(&x[i]))
      return 2;
    fe_inv(&xi[i], &x[i], f);
    ones[i] = one;
    fe_sub(&s, &one, &rho[i], f);
    fe_mul(&u, &x[i], &rho[i], f);
    fe_add(&s, &s, &u, f);
    fe_mul(&u, &bf, &s, f);
    bf = u;
  }
  ipa_table(w, ones, x, key->c, f);
  for (j = 0; j < n; j++)
    fe_to_u256(&key->k[j], &w[j]);
  if (!msm(&gf, key->g, key->k, n, key->bucket, key->buckets, base))
    return 3;
  /* 0 = C + h (V - a b_final) Q - a G_final + the sum of x_i L_i and
     x_i^-1 R_i. */
  ipa_term(pts, ks, &m, com, &one);
  fe_mul(&u, &pf->a, &bf, f);
  fe_sub(&s, v, &u, f);
  fe_mul(&u, &h, &s, f);
  ipa_term(pts, ks, &m, &key->q, &u);
  fe_neg(&u, &pf->a, f);
  ipa_term(pts, ks, &m, &gf, &u);
  for (i = 0; i < key->c; i++) {
    ipa_term(pts, ks, &m, &pf->l[i], &x[i]);
    ipa_term(pts, ks, &m, &pf->r[i], &xi[i]);
  }
  if (m == 0)
    return 0;
  if (!msm(&sum, pts, ks, m, bk, IPA_SMALL_BUCKETS, base))
    return 3;
  return ipa_is_identity(&sum) ? 0 : 4;
}
