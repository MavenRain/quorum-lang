/* NEW (quorum-lang S11 H5 C3): the IVC host, moved from test/ivctool.c. F_t and F_real, the caps, the
   setup of the one static key (a setup for another circuit replaces it) and the check. */
#include <string.h>

#include "crypto/bn254.h"
#include "crypto/frost.h"
#include "crypto/ivchost.h"
#include "crypto/msm.h"
#include "crypto/novacomp.h"
#include "crypto/novaivc.h"
#include "crypto/poseidon.h"
#include "crypto/poseidongadget.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/stepcase.h"
#include "crypto/stepgadget.h"
#include "crypto/u256.h"

static G1 ivc_g_p[IVC_PG];
static U256 ivc_k_p[IVC_PG];
static EcJac ivc_b_p[IVC_PBUCKETS];
static Fe ivc_z_p[IVC_PVARS];
static size_t ivc_row_p[IVC_PROWS];
static R1csTerm ivc_term_p[IVC_PTERMS];
static Fe ivc_t_p[IVC_PROWS];
static G1 ivc_g_s[IVC_SG];
static U256 ivc_k_s[IVC_SG];
static EcJac ivc_b_s[IVC_SBUCKETS];
static Fe ivc_z_s[IVC_SVARS];
static size_t ivc_row_s[IVC_SROWS];
static R1csTerm ivc_term_s[IVC_STERMS];
static Fe ivc_t_s[IVC_SROWS];
static NovaIvcKey ivc_key;
static G1 ivc_cg_p[IVC_CP];
static U256 ivc_ck_p[IVC_CP];
static EcJac ivc_cb_p[IVC_CPB];
static Fe ivc_cfe_p[IVC_CP * 5u];
static G1 ivc_cgw_p[IVC_CP / 2u];
static G1 ivc_cg_s[IVC_CS];
static U256 ivc_ck_s[IVC_CS];
static EcJac ivc_cb_s[IVC_CSB];
static Fe ivc_cfe_s[IVC_CS * 5u];
static G1 ivc_cgw_s[IVC_CS / 2u];
static Fe ivc_cz[IVC_SVARS];
static Fe ivc_ce[IVC_SROWS];
static NovaCompKey ivc_ck;
static NovaCompProof ivc_cpf2;
size_t ivc_host_bad_seen;
/* The F_t callback calls with a refused certificate (the host input
   check), and the step of the refusal (0 = none). */
size_t ivc_host_cert_refused;

/* 0: no key. 1 + c: the key of circuit c. */
static int ivc_set;

/* The prover of q_ivc_start and q_ivc_extend (S11 H5, Q-S11-26 (a)): F_t
   only, no heap. The 5 vectors at the F_t caps, the held proof, the head
   and PK of the next step, the compressed bytes and gen (the handle is
   IVC_HOST_HANDLE + gen). */
static Fe ivc_run_rwp[IVC_FT_PVARS];
static Fe ivc_run_rep[IVC_FT_PROWS];
static Fe ivc_run_rws[IVC_SVARS];
static Fe ivc_run_res[IVC_SROWS];
static Fe ivc_run_lws[IVC_SVARS];
static NovaIvcProof ivc_run;
static NovaCompProof ivc_run_cpf;
static unsigned char ivc_run_head[32];
static unsigned char ivc_run_pkb[IVC_HOST_PK_BYTES];
static unsigned char ivc_run_bytes[IVC_HOST_RUN_BYTES];
static size_t ivc_run_len;
static uint64_t ivc_gen;
static int ivc_run_live;

/* The h4 fixture of ivc_host_ready. */
static StepCase ivc_fx;
static IvcCtx ivc_fx_ctx;
static unsigned char ivc_fx_head[32];
static unsigned char ivc_fx_pkb[64];

/* F_t: a copy of nova_step_t of test/ivcr1cs.c:1237 (Q-S11-9 (a), the z
   layout of stepgadget.h): OUT[2] = IN[2] + 1 (the count), and OUT[0] and
   OUT[1] = state[1] and state[2] of one Poseidon permutation of (0, IN[0],
   IN[1]) (the head limbs). OUT[3] = IN[3] and OUT[4] = IN[4]. CTX is the
   PoseidonParams of the field of the system. */
static void ivc_step_t(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                       const void *ctx) {
  const PoseidonParams *params = (const PoseidonParams *)ctx;
  uint32_t state[POSEIDON_WIDTH];
  uint32_t next[POSEIDON_WIDTH];
  Fe v;
  Fe one;
  fe_from_u64(&v, 0);
  state[0] = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, state[0], 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, 0, 1);
  state[1] = in[0];
  state[2] = in[1];
  poseidon_gadget(cs, next, state, params);
  r1cs_value(&v, cs, in[2]);
  one = small(1);
  fe_add(&v, &v, &one, cs->f);
  out[2] = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, in[2], 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, out[2], 1);
  out[0] = next[1];
  out[1] = next[2];
  out[3] = in[3];
  out[4] = in[4];
}

/* The head after the step from HEAD (the head before the step) and BODY,
   as ivc_chain: q_hash2 (q_hash2 tagAppend HEAD) (q_hash2 BODY 0). */
static void ivc_next_head(unsigned char out[32], const unsigned char *head, const unsigned char *body) {
  unsigned char tag[32];
  unsigned char zero4[32];
  unsigned char a[32];
  unsigned char d[32];
  memset(tag, 0, sizeof tag);
  memset(zero4, 0, sizeof zero4);
  step_words(tag, step_append, 2u);
  step_hash2(a, tag, head);
  step_hash2(d, body, zero4);
  step_hash2(out, a, d);
}

/* The F_t callback. It counts the calls with the bad certificate. The F_t
   circuit does not read the certificate, thus the callback first verifies
   it natively (frost_verify_xy) against the head of the body and the
   chain PK. This is a host input check, not a circuit constraint. A
   refusal counts in ivc_host_cert_refused, and ivc_prove_to then fails. */
void ivc_host_ft(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                 const void *ctx) {
  const IvcCtx *c = (const IvcCtx *)ctx;
  const StepCase *s = (const StepCase *)c->s;
  unsigned char msg[32];
  if (c->bad) ivc_host_bad_seen++;
  ivc_next_head(msg, c->head, s->body);
  if (frost_verify_xy(c->pkb, s->sig, msg) != FROST_OK) ivc_host_cert_refused++;
  ivc_step_t(cs, out, in, c->params);
}

/* The real F callback: step_f on the case of the step. */
void ivc_host_real(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                   const void *ctx) {
  const IvcCtx *c = (const IvcCtx *)ctx;
  if (c->bad) ivc_host_bad_seen++;
  step_f(cs, out, in, c->s);
}

void ivc_host_caps(IvcCircuit c, IvcCaps *cp) {
  switch (c) {
  case IVC_FT:
    cp->fn = ivc_host_ft;
    cp->p_g = IVC_FT_PG;
    cp->p_vars = IVC_FT_PVARS;
    cp->p_rows = IVC_FT_PROWS;
    cp->p_terms = IVC_FT_PTERMS;
    cp->p_buckets = IVC_FT_PBUCKETS;
    cp->c_p = IVC_FT_CP;
    cp->c_pb = IVC_FT_CPB;
    return;
  case IVC_REAL_F:
    cp->fn = ivc_host_real;
    cp->p_g = IVC_PG;
    cp->p_vars = IVC_PVARS;
    cp->p_rows = IVC_PROWS;
    cp->p_terms = IVC_PTERMS;
    cp->p_buckets = IVC_PBUCKETS;
    cp->c_p = IVC_CP;
    cp->c_pb = IVC_CPB;
    return;
  }
}

/* The caller part of one side of the key (h4_side of test/ivch4.c). */
static void ivc_side(NovaIvcSide *sd, G1 *g, size_t g_cap, U256 *k, EcJac *bucket, size_t buckets,
                     Fe *z, size_t var_cap, size_t *rows, size_t row_cap, R1csTerm *term,
                     size_t term_cap, Fe *t, const Modulus *m) {
  sd->g = g;
  sd->g_cap = g_cap;
  sd->k = k;
  sd->bucket = bucket;
  sd->buckets = buckets;
  step_modulus(&sd->m, m);
  sd->z = z;
  sd->var_cap = var_cap;
  sd->row = rows;
  sd->row_cap = row_cap;
  sd->term = term;
  sd->term_cap = term_cap;
  sd->t = t;
}

/* One side of the comp key (h4_comp_side of test/ivch4.c). */
static void ivc_comp_side(NovaCompSide *sd, G1 *g, U256 *k, size_t n, EcJac *bucket, size_t buckets,
                          Fe *fe, G1 *gw) {
  sd->g = g;
  sd->g_cap = n;
  sd->k = k;
  sd->k_cap = n;
  sd->bucket = bucket;
  sd->buckets = buckets;
  sd->fe = fe;
  sd->fe_len = n * 5u;
  sd->gw = gw;
  sd->gw_len = n / 2u;
}

/* The setup of circuit C. S is the StepCase of the step ctx, HEAD the head before the step and PKB the
   group PK (x, then y). It records C: a setup for another circuit replaces the one static key. */
int ivc_host_setup(IvcCircuit c, IvcCtx *ctx, const void *s, const unsigned char *head,
                   const unsigned char *pkb) {
  NovaIvcKey *key = &ivc_key;
  IvcCaps caps;
  const IvcCaps *cp = &caps;
  int ok;
  ivc_host_caps(c, &caps);
  ivc_set = 0;
  ivc_run_live = 0;
  ivc_run_len = 0;
  ivc_gen++; /* a key re-setup: the held handle is stale (Q-S11-26 (a)) */
  if (msm_buckets(cp->p_g) > cp->p_buckets || msm_buckets(IVC_SG) > IVC_SBUCKETS ||
      msm_buckets(cp->c_p) > cp->c_pb || msm_buckets(IVC_CS) > IVC_CSB)
    return 0;
  ivc_side(&key->p, ivc_g_p, cp->p_g, ivc_k_p, ivc_b_p, cp->p_buckets, ivc_z_p, cp->p_vars, ivc_row_p,
           cp->p_rows, ivc_term_p, cp->p_terms, ivc_t_p, &SECP_FN);
  ivc_side(&key->s, ivc_g_s, IVC_SG, ivc_k_s, ivc_b_s, IVC_SBUCKETS, ivc_z_s, IVC_SVARS, ivc_row_s,
           IVC_SROWS, ivc_term_s, IVC_STERMS, ivc_t_s, &SECP_FP);
  ctx->params = &key->p.params;
  ctx->s = s;
  ctx->head = head;
  ctx->pkb = pkb;
  ctx->bad = 0;
  if (!nova_ivc_setup(key, cp->fn, ctx)) return 0;
  ivc_comp_side(&ivc_ck.p, ivc_cg_p, ivc_ck_p, cp->c_p, ivc_cb_p, cp->c_pb, ivc_cfe_p, ivc_cgw_p);
  ivc_comp_side(&ivc_ck.s, ivc_cg_s, ivc_ck_s, IVC_CS, ivc_cb_s, IVC_CSB, ivc_cfe_s, ivc_cgw_s);
  ivc_ck.z = ivc_cz;
  ivc_ck.var_cap = IVC_SVARS;
  ivc_ck.e = ivc_ce;
  ivc_ck.row_cap = IVC_SROWS;
  ok = nova_comp_setup(&ivc_ck, key);
  ivc_set = ok ? 1 + (int)c : 0;
  return ok;
}

/* The genesis head (S11 H5-d, Q-S11-33 (a)): the head before step 1, as
   ivc_chain of test/ivctool.c. */
void ivc_host_genesis(unsigned char head[32]) {
  unsigned char tag[32];
  unsigned char zero4[32];
  memset(tag, 0, sizeof tag);
  memset(zero4, 0, sizeof zero4);
  step_words(tag, step_genesis, 2u);
  step_hash2(head, tag, zero4);
}

/* The lazy setup of circuit C on the h4 fixture: the genesis head (ivc_host_genesis),
   PK = step_pk and step_case(&fx, head0, 0, 0, next) (seed 0 step 1 of test/ivctool.c). */
int ivc_host_ready(IvcCircuit c) {
  unsigned char next[32];
  if (ivc_set == 1 + (int)c) return 1;
  ivc_host_genesis(ivc_fx_head);
  step_words(ivc_fx_pkb, step_pk, 8u);
  step_case(&ivc_fx, ivc_fx_head, 0u, 0u, next);
  return ivc_host_setup(c, &ivc_fx_ctx, &ivc_fx, ivc_fx_head, ivc_fx_pkb);
}

NovaIvcKey *ivc_host_key(void) {
  return &ivc_key;
}

const NovaCompKey *ivc_host_ck(void) {
  return &ivc_ck;
}

/* Decode (the canonical checks), the public binding, then
   nova_comp_verify. */
IvcVerdict ivc_host_check(const unsigned char *b, size_t len, const IvcPublic *pub) {
  NovaCompProof *pf = &ivc_cpf2;
  size_t k;
  int same;
  if (!nova_comp_decode(pf, &ivc_ck, &ivc_key, b, len)) return IVC_BAD_DECODE;
  same = (uint64_t)pf->k == pub->count;
  for (k = 0; k < STEP_GADGET_Z; k++)
    same = same && fe_eq(&pf->z0[k], &pub->z0[k]) && fe_eq(&pf->zk[k], &pub->zk[k]);
  same = same && fe_eq(&pub->z0[3], &pub->pk[0]) && fe_eq(&pub->z0[4], &pub->pk[1]) &&
         fe_eq(&pub->zk[3], &pub->pk[0]) && fe_eq(&pub->zk[4], &pub->pk[1]);
  if (!same) return IVC_BAD_PUBLIC;
  return nova_comp_verify(&ivc_ck, &ivc_key, pf) == 0 ? IVC_OK : IVC_BAD_PROOF;
}

/* The values of N 32-byte big endian fields at B, each below p. */
static int ivc_host_fes(Fe *out, size_t n, const unsigned char *b) {
  U256 u;
  size_t k;
  for (k = 0; k < n; k++) {
    u256_from_be(&u, b + 32u * k);
    if (!fe_from_u256(&out[k], &u, &SECP_FP)) return 0;
  }
  return 1;
}

IvcVerdict ivc_host_verify_bytes(uint64_t c, const unsigned char *b, size_t n,
                                 const unsigned char z0[IVC_HOST_Z_BYTES],
                                 const unsigned char zk[IVC_HOST_Z_BYTES], uint64_t count,
                                 const unsigned char pk[IVC_HOST_PK_BYTES]) {
  IvcPublic pub;
  size_t size;
  size_t k;
  unsigned pad = 0;
  if (c > (uint64_t)IVC_REAL_F) return IVC_BAD_CIRCUIT;
  if (!ivc_host_fes(pub.z0, STEP_GADGET_Z, z0) || !ivc_host_fes(pub.zk, STEP_GADGET_Z, zk) ||
      !ivc_host_fes(pub.pk, 2u, pk) || count > IVC_HOST_COUNT_MAX)
    return IVC_BAD_PUBLIC;
  pub.count = count;
  /* The zero-step proof is empty and asserts the identity transition.
     It needs no circuit key and does not replace an active prover run. */
  if (count == 0u) {
    if (n != 0u) return IVC_BAD_READ;
    for (k = 0; k < STEP_GADGET_Z; k++)
      if (!fe_eq(&pub.z0[k], &pub.zk[k])) return IVC_BAD_PUBLIC;
    return fe_eq(&pub.z0[3], &pub.pk[0]) && fe_eq(&pub.z0[4], &pub.pk[1]) ? IVC_OK : IVC_BAD_PUBLIC;
  }
  if (!ivc_host_ready((IvcCircuit)c)) return IVC_BAD_READ;
  size = nova_comp_size(&ivc_ck);
  if (n != (size + 7u) / 8u) return IVC_BAD_READ;
  for (k = size; k < 8u * n; k++) pad |= b[k];
  return pad != 0u ? IVC_BAD_READ : ivc_host_check(b, size, &pub);
}

/* Bump gen (the held handle is stale) and give CODE. */
static uint64_t ivc_host_bump(uint64_t code) {
  ivc_run_live = 0;
  ivc_run_len = 0;
  ivc_gen++;
  return code;
}

/* Bump gen and give the new handle. */
static uint64_t ivc_host_handle(void) {
  ivc_run_live = 1;
  ivc_gen++;
  return IVC_HOST_HANDLE + ivc_gen;
}

uint64_t ivc_host_start(uint64_t c, const unsigned char pk[IVC_HOST_PK_BYTES], const unsigned char head[32],
                        const unsigned char z0[IVC_HOST_Z_BYTES]) {
  Fe z[STEP_GADGET_Z];
  Fe pkfe[2];
  Fe hd[2];
  ivc_run_live = 0;
  ivc_run_len = 0;
  if (c != (uint64_t)IVC_FT) return ivc_host_bump(IVC_HOST_BAD_CIRCUIT);
  if (!ivc_host_fes(z, STEP_GADGET_Z, z0) || !ivc_host_fes(pkfe, 2u, pk)) return ivc_host_bump(IVC_HOST_BAD_PUBLIC);
  hd[0] = step_fe(head + 16u, 16u);
  hd[1] = step_fe(head, 16u);
  if (!fe_eq(&z[0], &hd[0]) || !fe_eq(&z[1], &hd[1]) ||
      !fe_eq(&z[3], &pkfe[0]) || !fe_eq(&z[4], &pkfe[1]))
    return ivc_host_bump(IVC_HOST_BAD_PUBLIC);
  if (!ivc_host_ready(IVC_FT)) return ivc_host_bump(IVC_HOST_BAD_SETUP);
  ivc_run.r_w_p = ivc_run_rwp;
  ivc_run.r_e_p = ivc_run_rep;
  ivc_run.r_w_s = ivc_run_rws;
  ivc_run.r_e_s = ivc_run_res;
  ivc_run.l_w_s = ivc_run_lws;
  nova_ivc_start(&ivc_run, z);
  memcpy(ivc_run_head, head, sizeof ivc_run_head);
  memcpy(ivc_run_pkb, pk, sizeof ivc_run_pkb);
  return ivc_host_handle();
}

uint64_t ivc_host_extend(uint64_t h, const unsigned char body[32], const unsigned char cert[96]) {
  StepCase st;
  IvcCtx ctx;
  IvcCaps caps;
  unsigned char next[32];
  size_t refused = ivc_host_cert_refused;
  int ok;
  if (!ivc_run_live || h != IVC_HOST_HANDLE + ivc_gen) return IVC_HOST_STALE;
  ivc_next_head(next, ivc_run_head, body);
  if (frost_verify_xy(ivc_run_pkb, cert, next) != FROST_OK) {
    ivc_host_cert_refused++;
    return ivc_host_bump(IVC_HOST_CERT_REFUSED);
  }
  ivc_host_caps(IVC_FT, &caps);
  memcpy(st.in, ivc_run.zk, sizeof st.in);
  memcpy(st.body, body, sizeof st.body);
  memcpy(st.sig, cert, sizeof st.sig);
  ctx.params = &ivc_key.p.params;
  ctx.s = &st;
  ctx.head = ivc_run_head;
  ctx.pkb = ivc_run_pkb;
  ctx.bad = 0;
  ivc_run_len = 0;
  ok = nova_ivc_prove_step(&ivc_run, &ivc_key, caps.fn, &ctx);
  if (ivc_host_cert_refused != refused) return ivc_host_bump(IVC_HOST_CERT_REFUSED);
  if (!ok) return ivc_host_bump(IVC_HOST_FOLD_FAILED);
  memcpy(ivc_run_head, next, sizeof next);
  ivc_run_len = nova_comp_size(&ivc_ck);
  ok = ivc_run_len <= sizeof ivc_run_bytes && nova_comp_prove(&ivc_run_cpf, &ivc_ck, &ivc_key, &ivc_run) &&
       nova_comp_encode(ivc_run_bytes, ivc_run_len, &ivc_ck, &ivc_run_cpf);
  if (!ok) ivc_run_len = 0;
  return ok ? ivc_host_handle() : ivc_host_bump(IVC_HOST_COMP_FAILED);
}

/* The inverse of the unpack of q_ivc_verify (test/replicatool.c, eval.c
   host_nat_list): byte J of word K is byte 8K + J, the first byte the most
   significant; the pad bytes of the last word are 0. */
uint64_t ivc_host_word(uint64_t h, uint64_t k) {
  uint64_t w = 0;
  size_t i;
  if (!ivc_run_live || h != IVC_HOST_HANDLE + ivc_gen || k >= (ivc_run_len + 7u) / 8u) return 0u;
  for (i = 0; i < 8u; i++) w = w << 8 | (8u * k + i < ivc_run_len ? ivc_run_bytes[8u * k + i] : 0u);
  return w;
}
