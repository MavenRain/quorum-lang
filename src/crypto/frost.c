/* NEW (quorum-lang S7, O94). FROST(secp256k1, SHA-256) after RFC 9591
   sections 4.1 to 4.6, 5.1 to 5.4, 6.5 and App. B. */
#include "crypto/frost.h"

#include <string.h>

#include "crypto/sha256.h"

/* The context string of RFC 9591 section 6.5 (no NUL). */
static const char CTX[] = "FROST-secp256k1-SHA256-v1";
#define CTX_LEN (sizeof CTX - 1u)
/* The bytes of one encoded commitment list entry (section 4.3): the
   identifier scalar and the two SEC1 points. */
#define ENTRY_BYTES (32u + 33u + 33u)

/* The H5 input of the longest list fits the H4 and H5 buffer. */
typedef char frost_list_fits[THR_N_MAX * ENTRY_BYTES <= FROST_MSG_MAX ? 1 : -1];

/* OUT = H1, H2 or H3 of the LEN bytes M: xmd_to_scalar with the DST
   ctx || TAG. Returns 0 only when xmd_to_scalar refuses M. */
static int h_scalar(Fe *out, const char *tag, const unsigned char *m, size_t len) {
  unsigned char dst[CTX_LEN + 8u];
  size_t tag_len = strlen(tag);
  memcpy(dst, CTX, CTX_LEN);
  memcpy(dst + CTX_LEN, tag, tag_len);
  return xmd_to_scalar(out, m, len, dst, CTX_LEN + tag_len, &SECP_FN);
}

/* OUT = H4 (TAG "msg") or H5 (TAG "com") of the LEN bytes M:
   SHA-256(ctx || TAG || M). LEN is at most FROST_MSG_MAX. */
static void h_bytes(unsigned char out[32], const char *tag, const unsigned char *m, size_t len) {
  unsigned char buf[CTX_LEN + 3u + FROST_MSG_MAX];
  memcpy(buf, CTX, CTX_LEN);
  memcpy(buf + CTX_LEN, tag, 3u);
  memcpy(buf + CTX_LEN + 3u, m, len);
  sha256(buf, CTX_LEN + 3u + len, out);
}

/* OUT = K P. */
static void scalar_mul(G1 *out, const G1 *p, const Fe *k) {
  U256 w;
  fe_to_u256(&w, k);
  secp_mul(out, p, &w);
}

/* OUT = K G. */
static void base_mul(G1 *out, const Fe *k) {
  G1 g;
  secp_gen(&g);
  scalar_mul(out, &g, k);
}

/* 1 when COUNT is 1 to THR_N_MAX and IDS[0] to IDS[COUNT - 1] are 1 to
   THR_N_MAX in strictly ascending order (so each one time). */
static int ids_ok(const uint32_t ids[], size_t count) {
  int good = count >= 1u && count <= THR_N_MAX;
  for (size_t k = 0; good && k < count; k++)
    good = ids[k] >= 1u && ids[k] <= THR_N_MAX && (k == 0 || ids[k - 1u] < ids[k]);
  return good;
}

/* IDS = the identifiers of LIST (participants_from_commitment_list,
   section 4.3). Returns ids_ok of them, or 0 when COUNT is 0 or above
   THR_N_MAX. */
static int list_ids(uint32_t ids[THR_N_MAX], const FrostCommit *list, size_t count) {
  if (count < 1u || count > THR_N_MAX)
    return 0;
  for (size_t k = 0; k < count; k++)
    ids[k] = list[k].id;
  return ids_ok(ids, count);
}

/* The index of ID in IDS, or COUNT when ID is not in IDS. */
static size_t find_id(const uint32_t ids[], size_t count, uint32_t id) {
  size_t k = 0;
  while (k < count && ids[k] != id)
    k++;
  return k;
}

void frost_nonce(Fe *out, const unsigned char random[32], const Fe *secret) {
  unsigned char input[64];
  memcpy(input, random, 32u);
  scalar_encode(input + 32u, secret);
  /* 64 bytes and a 30 byte DST: xmd_to_scalar does not refuse them. */
  (void)h_scalar(out, "nonce", input, sizeof input);
}

FrostResult frost_commit(FrostNonce *nonce, FrostCommit *commit, uint32_t id, const Fe *secret,
                         const unsigned char hiding_random[32], const unsigned char binding_random[32]) {
  FrostNonce n;
  if (id < 1u || id > THR_N_MAX)
    return FROST_BAD_INDEX;
  frost_nonce(&n.hiding, hiding_random, secret);
  frost_nonce(&n.binding, binding_random, secret);
  commit->id = id;
  base_mul(&commit->hiding, &n.hiding);
  base_mul(&commit->binding, &n.binding);
  *nonce = n;
  return FROST_OK;
}

FrostResult frost_binding_factors(Fe rho[], const G1 *pk, const FrostCommit *list, size_t count,
                                  const unsigned char *msg, size_t msg_len) {
  uint32_t ids[THR_N_MAX];
  unsigned char encoded[THR_N_MAX * ENTRY_BYTES];
  unsigned char input[33u + 32u + 32u + 32u];
  Fe id;
  if (!list_ids(ids, list, count))
    return FROST_BAD_INDEX;
  if (msg_len > FROST_MSG_MAX)
    return FROST_BAD_MSG;
  if (!secp_encode(input, pk))
    return FROST_BAD_POINT;
  for (size_t k = 0; k < count; k++) {
    unsigned char *entry = encoded + k * ENTRY_BYTES;
    fe_from_u64(&id, list[k].id);
    scalar_encode(entry, &id);
    if (!secp_encode(entry + 32u, &list[k].hiding) || !secp_encode(entry + 65u, &list[k].binding))
      return FROST_BAD_POINT;
  }
  h_bytes(input + 33u, "msg", msg, msg_len);
  h_bytes(input + 65u, "com", encoded, count * ENTRY_BYTES);
  for (size_t k = 0; k < count; k++) {
    fe_from_u64(&id, list[k].id);
    scalar_encode(input + 97u, &id);
    /* 129 bytes and a 28 byte DST: xmd_to_scalar does not refuse them. */
    (void)h_scalar(&rho[k], "rho", input, sizeof input);
  }
  return FROST_OK;
}

void frost_group_commitment(G1 *out, const FrostCommit *list, const Fe rho[], size_t count) {
  G1 acc;
  G1 be;
  G1 term;
  G1 next;
  memset(&acc, 0, sizeof acc);
  for (size_t k = 0; k < count; k++) {
    scalar_mul(&be, &list[k].binding, &rho[k]);
    secp_add(&term, &list[k].hiding, &be);
    secp_add(&next, &acc, &term);
    acc = next;
  }
  *out = acc;
}

FrostResult frost_challenge(Fe *out, const G1 *r, const G1 *pk, const unsigned char *msg, size_t msg_len) {
  unsigned char input[66u + FROST_MSG_MAX];
  if (msg_len > FROST_MSG_MAX)
    return FROST_BAD_MSG;
  if (!secp_encode(input, r) || !secp_encode(input + 33u, pk))
    return FROST_BAD_POINT;
  memcpy(input + 66u, msg, msg_len);
  /* At most XMD_MSG_MAX bytes: xmd_to_scalar does not refuse them. */
  (void)h_scalar(out, "chal", input, 66u + msg_len);
  return FROST_OK;
}

FrostResult frost_lagrange(Fe *out, uint32_t id, const uint32_t ids[], size_t count) {
  Fe num;
  Fe den;
  Fe xi;
  Fe xj;
  Fe diff;
  Fe next;
  Fe inv;
  if (!ids_ok(ids, count) || find_id(ids, count, id) == count)
    return FROST_BAD_INDEX;
  fe_from_u64(&num, 1u);
  fe_from_u64(&den, 1u);
  fe_from_u64(&xi, id);
  for (size_t k = 0; k < count; k++) {
    if (ids[k] == id)
      continue;
    fe_from_u64(&xj, ids[k]);
    fe_mul(&next, &num, &xj, &SECP_FN);
    num = next;
    fe_sub(&diff, &xj, &xi, &SECP_FN);
    fe_mul(&next, &den, &diff, &SECP_FN);
    den = next;
  }
  fe_inv(&inv, &den, &SECP_FN);
  fe_mul(out, &num, &inv, &SECP_FN);
  return FROST_OK;
}

/* The values of sections 5.2 and 5.4 for the signer ID. */
typedef struct {
  size_t k;  /* the index of ID in the list */
  Fe rho;    /* its binding factor */
  G1 r;      /* the group commitment */
  Fe c;      /* the challenge */
  Fe lambda; /* its Lagrange value */
} SignerView;

static FrostResult signer_view(SignerView *v, uint32_t id, const G1 *pk, const FrostCommit *list, size_t count,
                               const unsigned char *msg, size_t msg_len) {
  uint32_t ids[THR_N_MAX];
  Fe rho[THR_N_MAX];
  FrostResult res = frost_binding_factors(rho, pk, list, count, msg, msg_len);
  if (res != FROST_OK)
    return res;
  /* frost_binding_factors checked the identifiers. */
  (void)list_ids(ids, list, count);
  res = frost_lagrange(&v->lambda, id, ids, count);
  if (res != FROST_OK)
    return res;
  v->k = find_id(ids, count, id);
  v->rho = rho[v->k];
  frost_group_commitment(&v->r, list, rho, count);
  return frost_challenge(&v->c, &v->r, pk, msg, msg_len);
}

FrostResult frost_sign(Fe *z, uint32_t id, const Fe *secret, const FrostNonce *nonce, const G1 *pk,
                       const FrostCommit *list, size_t count, const unsigned char *msg, size_t msg_len) {
  SignerView v;
  G1 d;
  G1 e;
  Fe er;
  Fe ls;
  Fe lsc;
  Fe sum;
  FrostResult res = signer_view(&v, id, pk, list, count, msg, msg_len);
  if (res != FROST_OK)
    return res;
  base_mul(&d, &nonce->hiding);
  base_mul(&e, &nonce->binding);
  if (!secp_eq(&d, &list[v.k].hiding) || !secp_eq(&e, &list[v.k].binding))
    return FROST_BAD_POINT;
  fe_mul(&er, &nonce->binding, &v.rho, &SECP_FN);
  fe_mul(&ls, &v.lambda, secret, &SECP_FN);
  fe_mul(&lsc, &ls, &v.c, &SECP_FN);
  fe_add(&sum, &nonce->hiding, &er, &SECP_FN);
  fe_add(z, &sum, &lsc, &SECP_FN);
  return FROST_OK;
}

FrostResult frost_verify_share(uint32_t id, const G1 *pk_id, const Fe *z, const G1 *pk, const FrostCommit *list,
                               size_t count, const unsigned char *msg, size_t msg_len) {
  SignerView v;
  unsigned char encoded[33];
  G1 left;
  G1 be;
  G1 comm;
  G1 cl_pk;
  G1 right;
  Fe cl;
  FrostResult res = signer_view(&v, id, pk, list, count, msg, msg_len);
  if (res != FROST_OK)
    return res;
  if (!secp_encode(encoded, pk_id))
    return FROST_BAD_POINT;
  base_mul(&left, z);
  scalar_mul(&be, &list[v.k].binding, &v.rho);
  secp_add(&comm, &list[v.k].hiding, &be);
  fe_mul(&cl, &v.c, &v.lambda, &SECP_FN);
  scalar_mul(&cl_pk, pk_id, &cl);
  secp_add(&right, &comm, &cl_pk);
  return secp_eq(&left, &right) ? FROST_OK : FROST_BAD_SHARE;
}

FrostResult frost_aggregate(unsigned char sig[FROST_SIG_BYTES], const Fe z[], const G1 *pk,
                            const FrostCommit *list, size_t count, const unsigned char *msg, size_t msg_len) {
  Fe rho[THR_N_MAX];
  Fe acc;
  Fe next;
  G1 r;
  FrostResult res = frost_binding_factors(rho, pk, list, count, msg, msg_len);
  if (res != FROST_OK)
    return res;
  frost_group_commitment(&r, list, rho, count);
  if (!secp_encode(sig, &r))
    return FROST_BAD_POINT;
  fe_from_u64(&acc, 0);
  for (size_t k = 0; k < count; k++) {
    fe_add(&next, &acc, &z[k], &SECP_FN);
    acc = next;
  }
  scalar_encode(sig + 33u, &acc);
  return FROST_OK;
}

FrostResult frost_verify(const unsigned char sig[FROST_SIG_BYTES], const G1 *pk, const unsigned char *msg,
                         size_t msg_len) {
  G1 r;
  G1 left;
  G1 cpk;
  G1 right;
  Fe z;
  Fe c;
  FrostResult res;
  if (!secp_decode(&r, sig))
    return FROST_BAD_POINT;
  if (!scalar_decode(&z, sig + 33u))
    return FROST_BAD_SIG;
  res = frost_challenge(&c, &r, pk, msg, msg_len);
  if (res != FROST_OK)
    return res;
  base_mul(&left, &z);
  scalar_mul(&cpk, pk, &c);
  secp_add(&right, &r, &cpk);
  return secp_eq(&left, &right) ? FROST_OK : FROST_BAD_SIG;
}
