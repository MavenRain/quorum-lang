/* NEW (quorum-lang S10 H2): the BGW protocol. See bgw.h. */
#include <string.h>

#include "crypto/bgw.h"

#include "crypto/bn254.h"
#include "crypto/elgamal.h"

/* The Fr element of X mod r. */
static void fr_fe(Fe *out, const U256 *x) {
  U256 red;
  scalar_reduce(&red, x);
  fe_from_u256(out, &red, &BN254_FR);
}

/* 1 when N members can multiply and I is one of them. */
static int member_ok(uint32_t i, uint32_t n) {
  return n >= BGW_N_MIN && n <= THR_N_MAX && i >= 1u && i <= n;
}

/* 1 when P is the point at infinity (0, 0) or on the curve. */
static int point_ok(const G1 *p) {
  G1 inf;
  memset(&inf, 0, sizeof inf);
  return DKG_BN254.eq(p, &inf) || g1_on_curve(p);
}

/* PARTS[i].x = i + 1 for i below N, the rest 0: the x of all N members. */
static void all_members(ThrPart *parts, uint32_t n) {
  uint32_t i;
  memset(parts, 0, THR_N_MAX * sizeof *parts);
  for (i = 0; i < n; i++) {
    parts[i].x = i + 1u;
  }
}

/* OUT = the sum over m below K of lambda_m SS[m], with lambda_m =
   thr_lagrange at 0 over the x of PARTS. */
static void lagrange_at_0(U256 *out, const ThrPart *parts, const U256 *ss, uint32_t k) {
  Fe acc;
  Fe next;
  Fe l;
  Fe s;
  Fe term;
  U256 lu;
  uint32_t m;
  fe_from_u64(&acc, 0);
  for (m = 0; m < k; m++) {
    thr_lagrange(&lu, parts, k, m);
    fr_fe(&l, &lu);
    fr_fe(&s, &ss[m]);
    fe_mul(&term, &l, &s, &BN254_FR);
    fe_add(&next, &acc, &term, &BN254_FR);
    acc = next;
  }
  fe_to_u256(out, &acc);
}

BgwResult bgw_deal(DkgDealing *out, U256 *shares, const U256 *a0, const U256 *a1, uint32_t n) {
  G1 g;
  Fe f0;
  Fe f1;
  Fe x;
  Fe slope;
  Fe v;
  U256 r0;
  U256 r1;
  uint32_t j;
  if (n < BGW_T || n > THR_N_MAX) {
    return BGW_BAD_INDEX;
  }
  memset(out, 0, sizeof *out);
  scalar_reduce(&r0, a0);
  scalar_reduce(&r1, a1);
  elg_generator(&g);
  g1_mul(&out->c[0], &g, &r0);
  g1_mul(&out->c[1], &g, &r1);
  fe_from_u256(&f0, &r0, &BN254_FR);
  fe_from_u256(&f1, &r1, &BN254_FR);
  for (j = 1; j <= n; j++) {
    fe_from_u64(&x, j);
    fe_mul(&slope, &f1, &x, &BN254_FR);
    fe_add(&v, &f0, &slope, &BN254_FR);
    fe_to_u256(&shares[j - 1u], &v);
  }
  return BGW_OK;
}

int bgw_check(const DkgDealing *d, uint32_t j, const U256 *s) {
  return dkg_check_share(&DKG_BN254, d, BGW_T, j, s);
}

void bgw_sum(U256 *out, const U256 *s, uint32_t count) {
  Fe acc;
  Fe next;
  Fe x;
  uint32_t m;
  fe_from_u64(&acc, 0);
  for (m = 0; m < count; m++) {
    fr_fe(&x, &s[m]);
    fe_add(&next, &acc, &x, &BN254_FR);
    acc = next;
  }
  fe_to_u256(out, &acc);
}

void bgw_sum_commit(DkgDealing *out, const DkgDealing *ds, uint32_t count) {
  G1 next;
  uint32_t m;
  uint32_t k;
  memset(out, 0, sizeof *out);
  for (m = 0; m < count; m++) {
    for (k = 0; k < BGW_T; k++) {
      g1_add(&next, &out->c[k], &ds[m].c[k]);
      out->c[k] = next;
    }
  }
}

void bgw_affine(U256 *out, const U256 *s, const U256 *w, const U256 *k) {
  Fe fs;
  Fe fw;
  Fe fk;
  Fe prod;
  Fe v;
  fr_fe(&fs, s);
  fr_fe(&fw, w);
  fr_fe(&fk, k);
  fe_mul(&prod, &fw, &fs, &BN254_FR);
  fe_add(&v, &prod, &fk, &BN254_FR);
  fe_to_u256(out, &v);
}

void bgw_affine_commit(DkgDealing *out, const DkgDealing *d, const U256 *w, const U256 *k) {
  G1 g;
  G1 kg;
  G1 wc0;
  U256 rw;
  U256 rk;
  memset(out, 0, sizeof *out);
  scalar_reduce(&rw, w);
  scalar_reduce(&rk, k);
  elg_generator(&g);
  g1_mul(&wc0, &d->c[0], &rw);
  g1_mul(&out->c[1], &d->c[1], &rw);
  g1_mul(&kg, &g, &rk);
  g1_add(&out->c[0], &wc0, &kg);
}

BgwResult bgw_product(BgwProduct *out, U256 *subshares, const DkgDealing *da, const DkgDealing *db, uint32_t i,
                      const U256 *sa, const U256 *sb, const U256 *rho, uint32_t n) {
  ThrShare share;
  ElgCipher ct;
  Fe fa;
  Fe fb;
  Fe fp;
  U256 p;
  if (!member_ok(i, n)) {
    return BGW_BAD_INDEX;
  }
  memset(&share, 0, sizeof share);
  memset(&ct, 0, sizeof ct);
  share.x = i;
  scalar_reduce(&share.s, sa);
  dkg_eval(&DKG_BN254, &share.key, da, BGW_T, i);
  dkg_eval(&DKG_BN254, &ct.c1, db, BGW_T, i);
  thr_partial(&out->proof, &share, &ct);
  fr_fe(&fa, sa);
  fr_fe(&fb, sb);
  fe_mul(&fp, &fa, &fb, &BN254_FR);
  fe_to_u256(&p, &fp);
  return bgw_deal(&out->reshare, subshares, &p, rho, n);
}

BgwResult bgw_product_check(const BgwProduct *prod, const DkgDealing *da, const DkgDealing *db, uint32_t i, uint32_t n) {
  G1 key;
  ElgCipher ct;
  if (!member_ok(i, n) || prod->proof.x != i) {
    return BGW_BAD_INDEX;
  }
  if (!point_ok(&prod->proof.d) || !point_ok(&prod->proof.a) || !point_ok(&prod->proof.b) ||
      !point_ok(&prod->reshare.c[0]) || !point_ok(&prod->reshare.c[1])) {
    return BGW_BAD_PROOF;
  }
  memset(&ct, 0, sizeof ct);
  dkg_eval(&DKG_BN254, &key, da, BGW_T, i);
  dkg_eval(&DKG_BN254, &ct.c1, db, BGW_T, i);
  if (!thr_verify(&prod->proof, &key, &ct) || !DKG_BN254.eq(&prod->reshare.c[0], &prod->proof.d)) {
    return BGW_BAD_PROOF;
  }
  return BGW_OK;
}

BgwResult bgw_reduce(U256 *out, const BgwProduct *prods, const U256 *subshares, const DkgDealing *da,
                     const DkgDealing *db, uint32_t j, uint32_t n) {
  ThrPart parts[THR_N_MAX];
  BgwResult res = BGW_OK;
  uint32_t i;
  u256_from_u64(out, 0);
  if (!member_ok(j, n)) {
    return BGW_BAD_INDEX;
  }
  for (i = 0; i < n && res == BGW_OK; i++) {
    res = bgw_product_check(&prods[i], da, db, i + 1u, n);
  }
  for (i = 0; i < n && res == BGW_OK; i++) {
    res = bgw_check(&prods[i].reshare, j, &subshares[i]) ? BGW_OK : BGW_BAD_SHARE;
  }
  if (res != BGW_OK) {
    return res;
  }
  all_members(parts, n);
  lagrange_at_0(out, parts, subshares, n);
  return BGW_OK;
}

BgwResult bgw_reduce_commit(DkgDealing *out, const BgwProduct *prods, uint32_t n) {
  ThrPart parts[THR_N_MAX];
  G1 term;
  G1 next;
  U256 l;
  uint32_t i;
  uint32_t k;
  if (!member_ok(1u, n)) {
    return BGW_BAD_INDEX;
  }
  memset(out, 0, sizeof *out);
  all_members(parts, n);
  for (i = 0; i < n; i++) {
    thr_lagrange(&l, parts, n, i);
    for (k = 0; k < BGW_T; k++) {
      g1_mul(&term, &prods[i].reshare.c[k], &l);
      g1_add(&next, &out->c[k], &term);
      out->c[k] = next;
    }
  }
  return BGW_OK;
}

BgwResult bgw_open(U256 *out, const DkgDealing *d, const uint32_t *xs, const U256 *ss, uint32_t k, uint32_t n) {
  ThrPart parts[THR_N_MAX];
  BgwResult res = BGW_OK;
  uint32_t m;
  uint32_t q;
  u256_from_u64(out, 0);
  if (n < BGW_T || n > THR_N_MAX || k < BGW_T || k > n) {
    return BGW_BAD_INDEX;
  }
  memset(parts, 0, sizeof parts);
  for (m = 0; m < k && res == BGW_OK; m++) {
    res = (xs[m] == 0 || xs[m] > n) ? BGW_BAD_INDEX : BGW_OK;
    for (q = 0; q < m && res == BGW_OK; q++) {
      res = xs[q] == xs[m] ? BGW_BAD_INDEX : BGW_OK;
    }
    parts[m].x = xs[m];
  }
  for (m = 0; m < k && res == BGW_OK; m++) {
    if (!bgw_check(d, xs[m], &ss[m])) {
      res = BGW_BAD_SHARE;
    }
  }
  if (res != BGW_OK) {
    return res;
  }
  lagrange_at_0(out, parts, ss, k);
  return BGW_OK;
}

/* The word W at BE: 8 bytes big endian. */
static void word_to_be(unsigned char *be, uint64_t w) {
  uint32_t i;
  for (i = 0; i < 8u; i++) {
    be[i] = (unsigned char)(w >> (56u - 8u * i));
  }
}

/* The dealing at BE (16 words: C[0], then C[1]); the other points, R and z
   are 0. 1 when both points decode. */
static int dealing_from_be(DkgDealing *d, const unsigned char *be) {
  memset(d, 0, sizeof *d);
  return g1_from_be(&d->c[0], be) && g1_from_be(&d->c[1], be + 64);
}

/* The 16 words of D at BE: C[0], then C[1]. */
static void dealing_to_be(unsigned char *be, const DkgDealing *d) {
  g1_to_be(be, &d->c[0]);
  g1_to_be(be + 64, &d->c[1]);
}

/* The products of the members 1 to BGW_N_MIN at the cell M of their lists
   in LISTS, and SUBS[i - 1] the sub-shares of the member i. In order:
   BGW_BAD_INDEX when a list has more than 8 cells or no cell M;
   BGW_BAD_PROOF when a point does not decode; else BGW_OK. The reshare
   C[0] is the part d (D_i). A part index of 0 or above THR_N_MAX becomes 0
   (bgw_product_check refuses it). */
static BgwResult prods_from_be(BgwProduct *prods, const unsigned char **subs, const unsigned char *lists,
                               const uint32_t *have, uint64_t m) {
  const unsigned char *cell;
  uint64_t x;
  uint32_t i;
  uint32_t k;
  for (i = 0; i < BGW_N_MIN; i++) {
    if (have[i] > 8u || m >= have[i]) {
      return BGW_BAD_INDEX;
    }
  }
  for (i = 0; i < BGW_N_MIN; i++) {
    cell = lists + BGW_LIST_BYTES * i + BGW_CELL_BYTES * (uint32_t)m;
    memset(&prods[i], 0, sizeof prods[i]);
    x = 0;
    for (k = 0; k < 8u; k++) {
      x = x << 8 | cell[k];
    }
    prods[i].proof.x = x == 0u || x > THR_N_MAX ? 0u : (uint32_t)x;
    u256_from_be(&prods[i].proof.z, cell + 200);
    if (!g1_from_be(&prods[i].proof.d, cell + 8) || !g1_from_be(&prods[i].proof.a, cell + 72) ||
        !g1_from_be(&prods[i].proof.b, cell + 136) || !g1_from_be(&prods[i].reshare.c[1], cell + 232)) {
      return BGW_BAD_PROOF;
    }
    prods[i].reshare.c[0] = prods[i].proof.d;
    subs[i] = cell + 296;
  }
  return BGW_OK;
}

BgwResult bgw_check_be(const unsigned char *d, const unsigned char *s, uint64_t n) {
  DkgDealing x;
  U256 v;
  uint32_t j;
  if (n < BGW_T || n > BGW_SLOTS) {
    return BGW_BAD_INDEX;
  }
  if (!dealing_from_be(&x, d)) {
    return BGW_BAD_SHARE;
  }
  for (j = 1; j <= n; j++) {
    u256_from_be(&v, s + 32u * (j - 1u));
    if (!bgw_check(&x, j, &v)) {
      return BGW_BAD_SHARE;
    }
  }
  return BGW_OK;
}

void bgw_add_be(unsigned char *out, const unsigned char *a, const unsigned char *b) {
  DkgDealing ds[2];
  DkgDealing s;
  memset(out, 0, 128u);
  if (!dealing_from_be(&ds[0], a) || !dealing_from_be(&ds[1], b)) {
    return;
  }
  bgw_sum_commit(&s, ds, 2u);
  dealing_to_be(out, &s);
}

void bgw_affine_be(unsigned char *out, const unsigned char *d, const unsigned char *w, const unsigned char *k) {
  DkgDealing x;
  DkgDealing s;
  U256 uw;
  U256 uk;
  memset(out, 0, 128u);
  if (!dealing_from_be(&x, d)) {
    return;
  }
  u256_from_be(&uw, w);
  u256_from_be(&uk, k);
  bgw_affine_commit(&s, &x, &uw, &uk);
  dealing_to_be(out, &s);
}

void bgw_mul_be(unsigned char *out, const unsigned char *prods, const uint32_t *have, uint64_t m,
                const unsigned char *da, const unsigned char *db) {
  BgwProduct p[BGW_N_MIN];
  const unsigned char *subs[BGW_N_MIN];
  U256 s[BGW_N_MIN];
  U256 v;
  DkgDealing a;
  DkgDealing b;
  BgwResult res;
  uint32_t i;
  uint32_t j;
  memset(out, 0, 128u);
  res = prods_from_be(p, subs, prods, have, m);
  if (res == BGW_OK && (!dealing_from_be(&a, da) || !dealing_from_be(&b, db))) {
    res = BGW_BAD_PROOF;
  }
  for (j = 1; j <= BGW_N_MIN && res == BGW_OK; j++) {
    for (i = 0; i < BGW_N_MIN; i++) {
      u256_from_be(&s[i], subs[i] + 32u * (j - 1u));
    }
    res = bgw_reduce(&v, p, s, &a, &b, j, BGW_N_MIN);
    u256_to_be(out + 32u * (j - 1u), &v);
  }
  if (res != BGW_OK) {
    memset(out, 0, 96u);
  }
  word_to_be(out + 96, (uint64_t)res);
}

void bgw_mulc_be(unsigned char *out, const unsigned char *prods, const uint32_t *have, uint64_t m) {
  BgwProduct p[BGW_N_MIN];
  const unsigned char *subs[BGW_N_MIN];
  DkgDealing d;
  memset(out, 0, 128u);
  if (prods_from_be(p, subs, prods, have, m) != BGW_OK || bgw_reduce_commit(&d, p, BGW_N_MIN) != BGW_OK) {
    return;
  }
  dealing_to_be(out, &d);
}

void bgw_open_be(unsigned char *out, const unsigned char *d, const unsigned char *s, uint64_t n) {
  static const uint32_t XS[BGW_SLOTS] = {1u, 2u, 3u, 4u};
  DkgDealing x;
  U256 ss[BGW_SLOTS];
  U256 v;
  BgwResult res = BGW_BAD_INDEX;
  uint32_t j;
  memset(out, 0, 64u);
  if (n >= BGW_T && n <= BGW_SLOTS) {
    for (j = 0; j < n; j++) {
      u256_from_be(&ss[j], s + 32u * j);
    }
    res = dealing_from_be(&x, d) ? bgw_open(&v, &x, XS, ss, (uint32_t)n, (uint32_t)n) : BGW_BAD_SHARE;
  }
  if (res == BGW_OK) {
    u256_to_be(out, &v);
  }
  word_to_be(out + 32, (uint64_t)res);
}
