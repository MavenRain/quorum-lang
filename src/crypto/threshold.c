/* Source: intent-lang 79e1898 src/front/threshold.c, without thr_deal. */
/* Threshold opening of exponential ElGamal over BN254 G1 in the host (slice
   S6 b1). See crypto/threshold.h. */
#include <string.h>

#include "crypto/threshold.h"

#include "crypto/bn254.h"
#include "crypto/keccak.h"

const U256 THR_TAG = {{0x7368616d6972u, 0u, 0u, 0u}};
const U256 DLEQ_TAG = {{0x646c6571u, 0u, 0u, 0u}};
const U256 DLEQ_NONCE_TAG = {{0x646c657177u, 0u, 0u, 0u}};

/* The 32 big endian bytes of X at OUT (limb 3 first), as word_bytes in
   intent-lang src/front/blsag.c. */
static void word_bytes(const U256 *x, unsigned char *out) {
  uint32_t i;
  for (i = 0; i < 32u; i++)
    out[i] = (unsigned char)(x->limb[3u - i / 8u] >> (56u - 8u * (i % 8u)));
}

void thr_hash(U256 *out, const U256 *a, const U256 *b) {
  unsigned char data[64];
  unsigned char digest[32];
  uint32_t k;
  uint32_t j;
  word_bytes(a, data);
  word_bytes(b, data + 32);
  keccak256(data, sizeof data, digest);
  for (k = 0; k < 4u; k++) {
    out->limb[3u - k] = 0;
    for (j = 0; j < 8u; j++)
      out->limb[3u - k] = (out->limb[3u - k] << 8) | digest[8u * k + j];
  }
}

void thr_challenge(U256 *e, const G1 *key, const G1 *c1, const G1 *d, const G1 *a, const G1 *b) {
  const G1 *points[5];
  U256 x;
  U256 y;
  uint32_t i;
  points[0] = key;
  points[1] = c1;
  points[2] = d;
  points[3] = a;
  points[4] = b;
  *e = DLEQ_TAG;
  for (i = 0; i < 5u; i++) {
    g1_to_words(&x, &y, points[i]);
    thr_hash(e, e, &x);
    thr_hash(e, e, &y);
  }
}

void thr_nonce(U256 *out, const U256 *seed, uint64_t k) {
  U256 domain;
  U256 w;
  thr_hash(&domain, &THR_TAG, seed);
  u256_from_u64(&w, k);
  thr_hash(&w, &domain, &w);
  scalar_reduce(out, &w);
}

void thr_partial(ThrPart *out, const ThrShare *share, const ElgCipher *ct) {
  U256 w;
  U256 e;
  U256 c1x;
  U256 c1y;
  Fe fw;
  Fe fe;
  Fe fs;
  Fe es;
  Fe fz;
  G1 g;
  g1_to_words(&c1x, &c1y, &ct->c1);
  thr_hash(&w, &DLEQ_NONCE_TAG, &share->s);
  thr_hash(&w, &w, &c1x);
  thr_hash(&w, &w, &c1y);
  scalar_reduce(&w, &w);
  out->x = share->x;
  g1_mul(&out->d, &ct->c1, &share->s);
  elg_generator(&g);
  g1_mul(&out->a, &g, &w);
  g1_mul(&out->b, &ct->c1, &w);
  thr_challenge(&e, &share->key, &ct->c1, &out->d, &out->a, &out->b);
  scalar_reduce(&e, &e);
  fe_from_u256(&fw, &w, &BN254_FR);
  fe_from_u256(&fe, &e, &BN254_FR);
  fe_from_u256(&fs, &share->s, &BN254_FR);
  fe_mul(&es, &fe, &fs, &BN254_FR);
  fe_add(&fz, &fw, &es, &BN254_FR);
  fe_to_u256(&out->z, &fz);
}

int thr_verify(const ThrPart *part, const G1 *key, const ElgCipher *ct) {
  U256 e;
  G1 g;
  G1 l1;
  G1 r1;
  G1 l2;
  G1 r2;
  thr_challenge(&e, key, &ct->c1, &part->d, &part->a, &part->b);
  elg_generator(&g);
  g1_mul(&l1, &g, &part->z);
  g1_mul(&r1, key, &e);
  g1_add(&r1, &part->a, &r1);
  g1_mul(&l2, &ct->c1, &part->z);
  g1_mul(&r2, &part->d, &e);
  g1_add(&r2, &part->b, &r2);
  return g1_eq(&l1, &r1) && g1_eq(&l2, &r2);
}

void thr_lagrange(U256 *out, const ThrPart *parts, uint32_t k, uint32_t i) {
  Fe xi;
  Fe xj;
  Fe den;
  Fe inv;
  Fe tmp;
  Fe lambda;
  uint32_t j;
  fe_from_u64(&xi, parts[i].x);
  fe_from_u64(&lambda, 1u);
  for (j = 0; j < k; j++) {
    if (j != i) {
      fe_from_u64(&xj, parts[j].x);
      fe_sub(&den, &xj, &xi, &BN254_FR);
      fe_inv(&inv, &den, &BN254_FR);
      fe_mul(&tmp, &lambda, &xj, &BN254_FR);
      fe_mul(&lambda, &tmp, &inv, &BN254_FR);
    }
  }
  fe_to_u256(out, &lambda);
}

ThrResult thr_open(uint64_t *m, const ThrPart *parts, uint32_t k, const G1 *keys, uint32_t t, uint32_t n, const ElgCipher *ct, uint32_t bits) {
  uint32_t seen = 0;
  uint32_t i;
  ThrResult res = THR_REFUSED;
  U256 lambda;
  G1 sum;
  G1 term;
  ElgResult got;
  if (bits > ELG_BITS_MAX || n > THR_N_MAX || t < 1u || t > n || k > THR_N_MAX || !g1_on_curve(&ct->c1) || !g1_on_curve(&ct->c2))
    return THR_REFUSED;
  for (i = 0; i < n; i++)
    if (!g1_on_curve(&keys[i]))
      return THR_REFUSED;
  for (i = 0; i < k; i++)
    if (!g1_on_curve(&parts[i].d) || !g1_on_curve(&parts[i].a) || !g1_on_curve(&parts[i].b))
      return THR_REFUSED;
  if (k < t)
    return THR_TOO_FEW;
  for (i = 0; i < k; i++) {
    if (parts[i].x == 0u || parts[i].x > n || ((seen >> parts[i].x) & 1u) != 0u)
      return THR_BAD_INDEX;
    seen |= 1u << parts[i].x;
  }
  for (i = 0; i < k; i++)
    if (!thr_verify(&parts[i], &keys[parts[i].x - 1u], ct))
      return THR_BAD_PROOF;
  /* (0, 0) is the point at infinity. */
  memset(&sum, 0, sizeof sum);
  for (i = 0; i < k; i++) {
    thr_lagrange(&lambda, parts, k, i);
    g1_mul(&term, &parts[i].d, &lambda);
    g1_add(&sum, &sum, &term);
  }
  g1_neg(&sum, &sum);
  g1_add(&sum, &ct->c2, &sum);
  got = elg_log(m, &sum, bits);
  switch (got) {
  case ELG_FOUND:
    res = THR_FOUND;
    break;
  case ELG_NOT_FOUND:
    res = THR_NOT_FOUND;
    break;
  case ELG_REFUSED:
    res = THR_REFUSED;
    break;
  case ELG_NO_MEMORY:
    res = THR_NO_MEMORY;
    break;
  }
  return res;
}

/* The part at BE (29 words, R-E25): 1 when d, a and b decode. X becomes
   0 when the word is 0 or above THR_N_MAX. */
static int part_be(ThrPart *p, const unsigned char *be) {
  uint64_t x = 0;
  uint32_t i;
  for (i = 0; i < 8u; i++) x = x << 8 | be[i];
  p->x = x == 0u || x > THR_N_MAX ? 0u : (uint32_t)x;
  u256_from_be(&p->z, be + 200);
  return g1_from_be(&p->d, be + 8) && g1_from_be(&p->a, be + 72) && g1_from_be(&p->b, be + 136);
}

int thr_verify_be(const unsigned char *part, const unsigned char *key, const unsigned char *ct) {
  ThrPart p;
  G1 k;
  ElgCipher c;
  if (!part_be(&p, part) || p.x == 0u || !g1_from_be(&k, key) || !g1_from_be(&c.c1, ct) || !g1_from_be(&c.c2, ct + 64))
    return 1;
  return thr_verify(&p, &k, &c) ? 0 : 1;
}

ThrResult thr_open_be(uint64_t *m, const unsigned char *parts, uint32_t have_parts, const unsigned char *keys, uint32_t have_keys, const unsigned char *ct, uint64_t k, uint64_t t, uint64_t n, uint64_t bits) {
  ThrPart p[THR_N_MAX];
  G1 g[THR_N_MAX];
  ElgCipher c;
  uint32_t i;
  *m = 0;
  if (have_parts != k || have_keys != n || k > THR_N_MAX || t > THR_N_MAX || n > THR_N_MAX || bits > 64u)
    return THR_REFUSED;
  for (i = 0; i < have_parts; i++)
    if (!part_be(&p[i], parts + 232u * i))
      return THR_REFUSED;
  for (i = 0; i < have_keys; i++)
    if (!g1_from_be(&g[i], keys + 64u * i))
      return THR_REFUSED;
  if (!g1_from_be(&c.c1, ct) || !g1_from_be(&c.c2, ct + 64))
    return THR_REFUSED;
  return thr_open(m, p, have_parts, g, (uint32_t)t, have_keys, &c, (uint32_t)bits);
}
