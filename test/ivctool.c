/* NEW (quorum-lang S11 H4b C2a): the IVC fixture tool. The selector <c>
   picks the step circuit: `ft` (F_t, a copy of the F_t callback of
   test/ivcr1cs.c:1237) or `real-f` (step_f of test/stepcase.h). There is
   no default circuit, and the tool does not get the circuit from a file
   name. The selector also picks the key caps.

   The chain is the S8 chain: the DKG of `frosttool chain` (t 2 of n 3, the
   context 7, the dealer seeds 100 + i), the body (n, n, 10n, 0) of step n,
   the members {1, 2} (steps 1 and 2) or {2, 3} (the other steps), and one
   FROST certificate per step. The nonce bytes are the nonce bytes of
   sign_msg of test/frosttool.c with the 8 seed bytes (big endian) XOR at
   bytes 16 to 23. Thus seed 0 gives the h4 steps of test/stepcase.h. The
   storage is static. The tool does not use the heap.

     ivctool size <c>
     ivctool generate <c> <seed> <steps> <dir>
     ivctool prove <c> <seed> <steps> <proof> [<bad-step>]
     ivctool verify <c> <proof> <z0-hex> <zk-hex> <count> <pk-hex> [<proof> ...]
     (one or more groups of 5 values; one setup serves all the groups)
     ivctool refusals <c>

   generate keeps one prefix chain and writes the compressed proof after 1,
   3, 10 and 100 steps (and after STEPS) with no restart, and DIR/chain.txt.
   prove with BAD-STEP changes the z of that certificate (O153 case 6). The
   bad case goes to the step callback. The F_t circuit does not read the
   certificate, thus the F_t callback first verifies it natively with
   frost_verify_xy against the head of its body and the chain PK (a host
   input check, not a circuit constraint). A bad certificate stops prove
   (exit 1, no proof file). verify reads the exact nova_comp_size
   bytes, decodes them (all canonical field and point checks), compares z0,
   zk (STEP_GADGET_Z values, 32 bytes each, big endian), the count and the
   PK (x, then y) with the proof, then calls nova_comp_verify. refusals
   runs the 12 rows on one proof of 1 step. A failed row writes
   `FAIL ivc tool <row>` to stderr. Exit 0 = pass, 1 = fail or refusal,
   2 = usage. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crypto/bn254.h"
#include "crypto/dkg.h"
#include "crypto/frost.h"
#include "crypto/msm.h"
#include "crypto/nova.h"
#include "crypto/novacomp.h"
#include "crypto/novaivc.h"
#include "crypto/poseidon.h"
#include "crypto/poseidongadget.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/stepgadget.h"
#include "crypto/u256.h"

#include "stepcase.h"

#define IVC_FILE_CAP 32768u
#define IVC_STATE_BYTES (32u * STEP_GADGET_Z)
#define IVC_PK_BYTES 64u
#define IVC_STEPS_MAX 100u
#define IVC_COUNT_MAX 1000000u
#define IVC_ROW_STEPS 4u
#define IVC_PATH_CAP 4096u
#define DKG_T 2u
#define DKG_N 3u

/* The byte offsets of the encoded proof (test/ivcr1cs.c:1784): z0, then
   the first byte (0x04) and the x of the first point of r_U_p. */
#define IVC_AT_Z0 8u
#define IVC_AT_W (8u + 2u * STEP_GADGET_Z * 32u)
#define IVC_AT_X (IVC_AT_W + 1u)

/* The static storage has the caps of real F (test/ivch4.c). The F_t caps
   are the caps of the IVC and comp rows of test/ivcr1cs.c, or larger. */
#define IVC_PG 524288u
#define IVC_PVARS 524288u
#define IVC_PROWS 524288u
#define IVC_PTERMS 3145728u
#define IVC_PBUCKETS 262144u
#define IVC_SG 65536u
#define IVC_SVARS 65536u
#define IVC_SROWS 65536u
#define IVC_STERMS 524288u
#define IVC_SBUCKETS 65536u
#define IVC_CP 524288u
#define IVC_CPB 262144u
#define IVC_CS 65536u
#define IVC_CSB 16384u
#define IVC_FT_PG 65536u
#define IVC_FT_PVARS 65536u
#define IVC_FT_PROWS 65536u
#define IVC_FT_PTERMS 524288u
#define IVC_FT_PBUCKETS 65536u
#define IVC_FT_CP 65536u
#define IVC_FT_CPB 16384u

typedef enum { IVC_FT, IVC_REAL_F } IvcCircuit;
typedef enum {
  IVC_GENERATE, IVC_PROVE, IVC_VERIFY, IVC_SIZE, IVC_REFUSALS
} IvcMode;
typedef enum {
  IVC_READ_OK, IVC_READ_MISSING, IVC_READ_LENGTH, IVC_READ_IO
} IvcRead;
typedef enum {
  IVC_OK, IVC_BAD_READ, IVC_BAD_DECODE, IVC_BAD_PUBLIC, IVC_BAD_PROOF
} IvcVerdict;

typedef struct {
  uint32_t rows;
  uint32_t mismatches;
} IvcTally;

/* The CTX of the step callback: the PoseidonParams of F_t, the case of
   the step (the witness of real F), HEAD (the head before the step) and
   PKB (the group PK, x then y) for the host input check of F_t, and BAD
   (1 for the bad certificate). */
typedef struct {
  const PoseidonParams *params;
  const StepCase *s;
  const unsigned char *head;
  const unsigned char *pkb;
  int bad;
} IvcCtx;

/* The callback and the caps of one circuit. */
typedef struct {
  NovaStepFn fn;
  size_t p_g;
  size_t p_vars;
  size_t p_rows;
  size_t p_terms;
  size_t p_buckets;
  size_t c_p;
  size_t c_pb;
} IvcCaps;

/* The public input of verify. PK is x, then y. */
typedef struct {
  Fe z0[STEP_GADGET_Z];
  Fe zk[STEP_GADGET_Z];
  uint64_t count;
  Fe pk[2];
} IvcPublic;

/* The chain: C[k] is the case of step k + 1 (the state before the step,
   the body and the certificate), HEAD[k] is the head after k steps, and
   PKB is the group PK (x, then y). */
typedef struct {
  size_t steps;
  StepCase c[IVC_STEPS_MAX];
  unsigned char head[IVC_STEPS_MAX + 1u][32];
  unsigned char pkb[IVC_PK_BYTES];
} IvcChain;

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
static Fe ivc_rwp[IVC_PVARS];
static Fe ivc_rep[IVC_PROWS];
static Fe ivc_rws[IVC_SVARS];
static Fe ivc_res[IVC_SROWS];
static Fe ivc_lws[IVC_SVARS];
static NovaIvcKey ivc_key;
static NovaIvcProof ivc_pf;
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
static NovaCompProof ivc_cpf;
static NovaCompProof ivc_cpf2;
static unsigned char ivc_buf[IVC_FILE_CAP];
static unsigned char ivc_buf2[IVC_FILE_CAP];
static unsigned char ivc_rd[IVC_FILE_CAP];
static unsigned char ivc_mut[IVC_FILE_CAP + 1u];
static IvcChain ivc_chain_a;
static IvcChain ivc_chain_b;
static IvcChain ivc_chain_c;
static ThrShare ivc_share[DKG_N];
static G1 ivc_pk;
static size_t ivc_bad_seen;
/* The F_t callback calls with a refused certificate (the host input
   check), and the step of the refusal (0 = none). */
static size_t ivc_cert_refused;
static size_t ivc_cert_step;

static const uint32_t IVC_IDS_12[2] = {1u, 2u};
static const uint32_t IVC_IDS_23[2] = {2u, 3u};

/* The input layer of W/s11-h4b-s41-input.c (session 41). */
static int ivc_circuit(const char *s, IvcCircuit *out) {
  if (s == NULL || out == NULL) return 0;
  if (strcmp(s, "ft") == 0) {
    *out = IVC_FT;
    return 1;
  }
  if (strcmp(s, "real-f") == 0) {
    *out = IVC_REAL_F;
    return 1;
  }
  return 0;
}

static int ivc_mode(const char *s, IvcMode *out) {
  static const char *const names[5] = {
    "generate", "prove", "verify", "size", "refusals"
  };
  static const IvcMode modes[5] = {
    IVC_GENERATE, IVC_PROVE, IVC_VERIFY, IVC_SIZE, IVC_REFUSALS
  };
  size_t k;
  if (s == NULL || out == NULL) return 0;
  for (k = 0; k < 5u; k++) {
    if (strcmp(s, names[k]) == 0) {
      *out = modes[k];
      return 1;
    }
  }
  return 0;
}

/* Decimal digits only. On failure, OUT is unchanged. The same parser
   applies a count or seed bound without a cast before the range check. */
static int ivc_number(const char *s, uint64_t limit, uint64_t *out) {
  uint64_t n = 0;
  const unsigned char *p = (const unsigned char *)s;
  if (s == NULL || out == NULL || *p == 0) return 0;
  for (; *p != 0; p++) {
    uint64_t d;
    if (*p < (unsigned char)'0' || *p > (unsigned char)'9') return 0;
    d = (uint64_t)(*p - (unsigned char)'0');
    if (d > limit || n > (limit - d) / 10u) return 0;
    n = n * 10u + d;
  }
  *out = n;
  return 1;
}

static int ivc_digit(unsigned char c) {
  if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return (int)(c - (unsigned char)'0');
  if (c >= (unsigned char)'a' && c <= (unsigned char)'f') return (int)(c - (unsigned char)'a') + 10;
  if (c >= (unsigned char)'A' && c <= (unsigned char)'F') return (int)(c - (unsigned char)'A') + 10;
  return -1;
}

/* Fixed byte count. Decode only after the whole string passes. Canonical
   field and curve checks still belong to the crypto decode boundary. */
static int ivc_hex(unsigned char *out, size_t bytes, const char *s) {
  size_t k;
  if (out == NULL || s == NULL || bytes > IVC_FILE_CAP) return 0;
  for (k = 0; k < bytes * 2u; k++) {
    if (s[k] == '\0' || ivc_digit((unsigned char)s[k]) < 0) return 0;
  }
  if (s[bytes * 2u] != '\0') return 0;
  for (k = 0; k < bytes; k++) {
    int hi = ivc_digit((unsigned char)s[k * 2u]);
    int lo = ivc_digit((unsigned char)s[k * 2u + 1u]);
    out[k] = (unsigned char)((unsigned)hi * 16u + (unsigned)lo);
  }
  return 1;
}

/* A single extra byte distinguishes an exact file from a valid prefix.
   Failure can alter OUT; callers must not decode after any failure. */
static IvcRead ivc_stream(FILE *f, unsigned char *out, size_t cap, size_t exact) {
  size_t n;
  int extra;
  if (f == NULL || out == NULL || exact == 0u || exact > cap || exact > IVC_FILE_CAP)
    return IVC_READ_LENGTH;
  n = fread(out, 1u, exact, f);
  if (ferror(f)) return IVC_READ_IO;
  if (n != exact) return IVC_READ_LENGTH;
  extra = fgetc(f);
  if (ferror(f)) return IVC_READ_IO;
  if (extra != EOF) return IVC_READ_LENGTH;
  return IVC_READ_OK;
}

static IvcRead ivc_file(const char *path, unsigned char *out, size_t cap, size_t exact) {
  FILE *f;
  IvcRead result;
  if (path == NULL || out == NULL || exact == 0u || exact > cap || exact > IVC_FILE_CAP)
    return IVC_READ_LENGTH;
  f = fopen(path, "rb");
  if (f == NULL) return IVC_READ_MISSING;
  result = ivc_stream(f, out, cap, exact);
  if (fclose(f) != 0) result = IVC_READ_IO;
  return result;
}

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
   refusal counts in ivc_cert_refused, and ivc_prove_to then fails. */
static void ivc_ft(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                   const void *ctx) {
  const IvcCtx *c = (const IvcCtx *)ctx;
  unsigned char msg[32];
  if (c->bad) ivc_bad_seen++;
  ivc_next_head(msg, c->head, c->s->body);
  if (frost_verify_xy(c->pkb, c->s->sig, msg) != FROST_OK) ivc_cert_refused++;
  ivc_step_t(cs, out, in, c->params);
}

/* The real F callback: step_f on the case of the step. */
static void ivc_real(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                     const void *ctx) {
  const IvcCtx *c = (const IvcCtx *)ctx;
  if (c->bad) ivc_bad_seen++;
  step_f(cs, out, in, c->s);
}

static void ivc_caps(IvcCircuit c, IvcCaps *cp) {
  switch (c) {
  case IVC_FT:
    cp->fn = ivc_ft;
    cp->p_g = IVC_FT_PG;
    cp->p_vars = IVC_FT_PVARS;
    cp->p_rows = IVC_FT_PROWS;
    cp->p_terms = IVC_FT_PTERMS;
    cp->p_buckets = IVC_FT_PBUCKETS;
    cp->c_p = IVC_FT_CP;
    cp->c_pb = IVC_FT_CPB;
    return;
  case IVC_REAL_F:
    cp->fn = ivc_real;
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

static const char *ivc_circuit_name(IvcCircuit c) {
  switch (c) {
  case IVC_FT:
    return "ft";
  case IVC_REAL_F:
    return "real-f";
  }
  return "?";
}

/* 1 when the circuit does not read the certificate (F_t). */
static int ivc_host_only(IvcCircuit c) {
  switch (c) {
  case IVC_FT:
    return 1;
  case IVC_REAL_F:
    return 0;
  }
  return 0;
}

static const char *ivc_verdict_name(IvcVerdict v) {
  switch (v) {
  case IVC_OK:
    return "ok";
  case IVC_BAD_READ:
    return "refused read";
  case IVC_BAD_DECODE:
    return "refused decode";
  case IVC_BAD_PUBLIC:
    return "refused public input";
  case IVC_BAD_PROOF:
    return "refused proof";
  }
  return "?";
}

/* The DKG of `frosttool chain` (test/frosttool.c:1002): t 2 of n 3, the
   context 7, the dealer seeds 100 + i. */
static int ivc_dkg(void) {
  const DkgCurve *curve = &DKG_SECP256K1;
  DkgDealing dealings[DKG_N];
  U256 table[DKG_N * DKG_N];
  U256 ctx;
  U256 seed;
  uint32_t qual = 0;
  uint32_t k;
  int ok = 1;
  u256_from_u64(&ctx, 7u);
  for (k = 1u; k <= DKG_N; k++) {
    u256_from_u64(&seed, 100u + k);
    ok &= dkg_deal(curve, &dealings[k - 1u], &table[(k - 1u) * DKG_N], &seed, k, DKG_T, DKG_N, &ctx) == DKG_OK;
  }
  ok &= dkg_qual(curve, &qual, dealings, table, DKG_T, DKG_N, &ctx) == DKG_OK;
  dkg_public(curve, &ivc_pk, qual, dealings, DKG_N);
  for (k = 1u; k <= DKG_N; k++)
    ok &= dkg_share(curve, &ivc_share[k - 1u], qual, table, k, DKG_N) == DKG_OK;
  return ok;
}

/* sign_msg of test/frosttool.c:771 for 2 members, with the seed bytes:
   the FROST signature SIG of the 32-byte MSG of chain step STEP by the
   members IDS. 1 when each step gives FROST_OK. */
static int ivc_sign(unsigned char sig[FROST_SIG_BYTES], const unsigned char msg[32], const uint32_t ids[2],
                    unsigned step, uint64_t seed) {
  unsigned char hiding[32];
  unsigned char binding[32];
  FrostNonce nonce[THR_N_MAX];
  FrostCommit list[THR_N_MAX];
  Fe secret[THR_N_MAX];
  Fe z[THR_N_MAX];
  size_t k;
  size_t b;
  int ok = 1;
  for (k = 0; k < 2u; k++) {
    memset(hiding, (int)ids[k], sizeof hiding);
    memset(binding, (int)(ids[k] + 16u), sizeof binding);
    hiding[31] = (unsigned char)step;
    binding[31] = (unsigned char)step;
    for (b = 0; b < 8u; b++) {
      hiding[16u + b] ^= (unsigned char)(seed >> (56u - 8u * b));
      binding[16u + b] ^= (unsigned char)(seed >> (56u - 8u * b));
    }
    ok &= fe_from_u256(&secret[k], &ivc_share[ids[k] - 1u].s, &SECP_FN);
    ok &= frost_commit(&nonce[k], &list[k], ids[k], &secret[k], hiding, binding) == FROST_OK;
  }
  for (k = 0; k < 2u; k++)
    ok &= frost_sign(&z[k], ids[k], &secret[k], &nonce[k], &ivc_pk, list, 2u, msg, 32u) == FROST_OK;
  ok &= frost_aggregate(sig, z, &ivc_pk, list, 2u, msg, 32u) == FROST_OK;
  return ok;
}

/* The chain of STEPS steps for SEED (after ivc_dkg). The certificate of
   step BAD (0 = none) gets z XOR 1 in its last byte (badsig of
   `frosttool chain`). */
static int ivc_chain(IvcChain *ch, uint64_t seed, size_t steps, size_t bad) {
  unsigned char tag[32];
  unsigned char zero4[32];
  unsigned char a[32];
  unsigned char d[32];
  unsigned char sig[FROST_SIG_BYTES];
  unsigned char xy[64];
  uint64_t w[4];
  StepCase *s;
  G1 r;
  uint64_t n;
  size_t k;
  int ok = steps >= 1u && steps <= IVC_STEPS_MAX;
  memset(tag, 0, sizeof tag);
  memset(zero4, 0, sizeof zero4);
  step_words(tag, step_genesis, 2u);
  step_hash2(ch->head[0], tag, zero4);
  memset(tag, 0, sizeof tag);
  step_words(tag, step_append, 2u);
  secp_to_xy(ch->pkb, &ivc_pk);
  ch->steps = 0;
  for (k = 0; ok && k < steps; k++) {
    s = &ch->c[k];
    n = (uint64_t)k + 1u;
    w[0] = n;
    w[1] = n;
    w[2] = 10u * n;
    w[3] = 0;
    step_words(s->body, w, 4u);
    s->in[0] = step_fe(ch->head[k] + 16, 16u);
    s->in[1] = step_fe(ch->head[k], 16u);
    s->in[2] = small(k);
    s->in[3] = step_fe(ch->pkb, 32u);
    s->in[4] = step_fe(ch->pkb + 32, 32u);
    step_hash2(a, tag, ch->head[k]);
    step_hash2(d, s->body, zero4);
    step_hash2(ch->head[k + 1u], a, d);
    ok = ivc_sign(sig, ch->head[k + 1u], n <= 2u ? IVC_IDS_12 : IVC_IDS_23, (unsigned)n, seed) &&
         secp_decode(&r, sig) != 0;
    if (ok) {
      secp_to_xy(xy, &r);
      memcpy(s->sig, xy, 64u);
      memcpy(s->sig + 64, sig + 33, 32u);
      if (k + 1u == bad) s->sig[95] ^= 1u;
      ch->steps = k + 1u;
    }
  }
  return ok;
}

static int ivc_case_same(const StepCase *a, const StepCase *b) {
  size_t k;
  int same = memcmp(a->body, b->body, sizeof a->body) == 0 && memcmp(a->sig, b->sig, sizeof a->sig) == 0;
  for (k = 0; k < STEP_GADGET_Z; k++) same = same && fe_eq(&a->in[k], &b->in[k]);
  return same;
}

static int ivc_chain_same(const IvcChain *a, const IvcChain *b) {
  size_t k;
  int same = a->steps == b->steps && memcmp(a->head[0], b->head[0], 32u) == 0 &&
             memcmp(a->pkb, b->pkb, sizeof a->pkb) == 0;
  for (k = 0; same && k < a->steps; k++)
    same = ivc_case_same(&a->c[k], &b->c[k]) && memcmp(a->head[k + 1u], b->head[k + 1u], 32u) == 0;
  return same;
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

/* nova_ivc_setup with the callback and the caps of CP (the sizing runs use
   the case of step 1 of CH), then nova_comp_setup. */
static int ivc_setup(const IvcCaps *cp, IvcCtx *ctx, const IvcChain *ch) {
  NovaIvcKey *key = &ivc_key;
  if (msm_buckets(cp->p_g) > cp->p_buckets || msm_buckets(IVC_SG) > IVC_SBUCKETS ||
      msm_buckets(cp->c_p) > cp->c_pb || msm_buckets(IVC_CS) > IVC_CSB)
    return 0;
  ivc_side(&key->p, ivc_g_p, cp->p_g, ivc_k_p, ivc_b_p, cp->p_buckets, ivc_z_p, cp->p_vars, ivc_row_p,
           cp->p_rows, ivc_term_p, cp->p_terms, ivc_t_p, &SECP_FN);
  ivc_side(&key->s, ivc_g_s, IVC_SG, ivc_k_s, ivc_b_s, IVC_SBUCKETS, ivc_z_s, IVC_SVARS, ivc_row_s,
           IVC_SROWS, ivc_term_s, IVC_STERMS, ivc_t_s, &SECP_FP);
  ivc_pf.r_w_p = ivc_rwp;
  ivc_pf.r_e_p = ivc_rep;
  ivc_pf.r_w_s = ivc_rws;
  ivc_pf.r_e_s = ivc_res;
  ivc_pf.l_w_s = ivc_lws;
  ctx->params = &key->p.params;
  ctx->s = &ch->c[0];
  ctx->head = ch->head[0];
  ctx->pkb = ch->pkb;
  ctx->bad = 0;
  if (!nova_ivc_setup(key, cp->fn, ctx)) return 0;
  ivc_comp_side(&ivc_ck.p, ivc_cg_p, ivc_ck_p, cp->c_p, ivc_cb_p, cp->c_pb, ivc_cfe_p, ivc_cgw_p);
  ivc_comp_side(&ivc_ck.s, ivc_cg_s, ivc_ck_s, IVC_CS, ivc_cb_s, IVC_CSB, ivc_cfe_s, ivc_cgw_s);
  ivc_ck.z = ivc_cz;
  ivc_ck.var_cap = IVC_SVARS;
  ivc_ck.e = ivc_ce;
  ivc_ck.row_cap = IVC_SROWS;
  return nova_comp_setup(&ivc_ck, key);
}

/* The caps, the DKG, the chain and the setup. */
static int ivc_prepare(IvcCircuit c, IvcCaps *cp, IvcCtx *ctx, IvcChain *ch, uint64_t seed, size_t steps,
                       size_t bad) {
  time_t t0 = time(NULL);
  int ok;
  ivc_caps(c, cp);
  ok = ivc_dkg() && ivc_chain(ch, seed, steps, bad) && ivc_setup(cp, ctx, ch);
  printf("ivc tool %s setup: %ld s, n_p %lu n_s %lu, pad P %u %u %u, pad S %u %u %u, %s\n",
         ivc_circuit_name(c), (long)(time(NULL) - t0), (unsigned long)ivc_key.p.key.n,
         (unsigned long)ivc_key.s.key.n, ivc_ck.p.d.a, ivc_ck.p.d.b, ivc_ck.p.d.c, ivc_ck.s.d.a,
         ivc_ck.s.d.b, ivc_ck.s.d.c, ok ? "ok" : "failed");
  return ok;
}

static void ivc_restart(const IvcChain *ch) {
  nova_ivc_start(&ivc_pf, ch->c[0].in);
}

/* Prove the steps of CH from the step k of the proof up to TO. A refusal
   of the host input check of the F_t callback stops at that step. */
static int ivc_prove_to(const IvcCaps *cp, IvcCtx *ctx, const IvcChain *ch, size_t to, size_t bad) {
  size_t k;
  int ok = to <= ch->steps;
  ivc_cert_refused = 0;
  ivc_cert_step = 0;
  for (k = ivc_pf.k; ok && k < to; k++) {
    ctx->s = &ch->c[k];
    ctx->head = ch->head[k];
    ctx->pkb = ch->pkb;
    ctx->bad = k + 1u == bad;
    ok = nova_ivc_prove_step(&ivc_pf, &ivc_key, cp->fn, ctx) && ivc_cert_refused == 0u;
    ivc_cert_step = ivc_cert_refused != 0u ? k + 1u : 0u;
  }
  ctx->bad = 0;
  return ok;
}

/* OUT (LEN = nova_comp_size bytes) = the compressed proof of ivc_pf. */
static int ivc_compress(unsigned char *out, size_t *len) {
  *len = nova_comp_size(&ivc_ck);
  return *len <= IVC_FILE_CAP && nova_comp_prove(&ivc_cpf, &ivc_ck, &ivc_key, &ivc_pf) &&
         nova_comp_encode(out, *len, &ivc_ck, &ivc_cpf);
}

/* The values of N 32-byte big endian fields at B, each below p. */
static int ivc_fes(Fe *out, size_t n, const unsigned char *b) {
  U256 u;
  size_t k;
  for (k = 0; k < n; k++) {
    u256_from_be(&u, b + 32u * k);
    if (!fe_from_u256(&out[k], &u, &SECP_FP)) return 0;
  }
  return 1;
}

static void ivc_state_bytes(unsigned char out[IVC_STATE_BYTES], const Fe z[STEP_GADGET_Z]) {
  U256 u;
  size_t k;
  for (k = 0; k < STEP_GADGET_Z; k++) {
    fe_to_u256(&u, &z[k]);
    u256_to_be(out + 32u * k, &u);
  }
}

/* OUT (2N + 1 chars) = the lower case hex of the N bytes at B. */
static void ivc_hex_string(char *out, const unsigned char *b, size_t n) {
  static const char digits[] = "0123456789abcdef";
  size_t k;
  for (k = 0; k < n; k++) {
    out[2u * k] = digits[b[k] >> 4];
    out[2u * k + 1u] = digits[b[k] & 15u];
  }
  out[2u * n] = '\0';
}

static int ivc_public_parse(IvcPublic *pub, const char *z0, const char *zk, const char *count,
                            const char *pk) {
  unsigned char b[IVC_STATE_BYTES];
  return ivc_hex(b, IVC_STATE_BYTES, z0) && ivc_fes(pub->z0, STEP_GADGET_Z, b) &&
         ivc_hex(b, IVC_STATE_BYTES, zk) && ivc_fes(pub->zk, STEP_GADGET_Z, b) &&
         ivc_number(count, IVC_COUNT_MAX, &pub->count) && ivc_hex(b, IVC_PK_BYTES, pk) &&
         ivc_fes(pub->pk, 2u, b);
}

/* The public input of ivc_pf for CH. */
static void ivc_public_of(IvcPublic *pub, const IvcChain *ch) {
  size_t k;
  for (k = 0; k < STEP_GADGET_Z; k++) {
    pub->z0[k] = ivc_pf.z0[k];
    pub->zk[k] = ivc_pf.zk[k];
  }
  pub->count = (uint64_t)ivc_pf.k;
  pub->pk[0] = ch->c[0].in[3];
  pub->pk[1] = ch->c[0].in[4];
}

static void ivc_print_public(FILE *f, const IvcPublic *pub, const unsigned char pkb[IVC_PK_BYTES]) {
  unsigned char b[IVC_STATE_BYTES];
  char h[2u * IVC_STATE_BYTES + 1u];
  ivc_state_bytes(b, pub->z0);
  ivc_hex_string(h, b, IVC_STATE_BYTES);
  fprintf(f, "z0 %s\n", h);
  ivc_state_bytes(b, pub->zk);
  ivc_hex_string(h, b, IVC_STATE_BYTES);
  fprintf(f, "zk %s\n", h);
  fprintf(f, "count %llu\n", (unsigned long long)pub->count);
  ivc_hex_string(h, pkb, IVC_PK_BYTES);
  fprintf(f, "pk %s\n", h);
}

/* Decode (the canonical checks), the public binding, then
   nova_comp_verify. */
static IvcVerdict ivc_check(const unsigned char *b, size_t len, const IvcPublic *pub) {
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

/* Read the exact nova_comp_size bytes of PATH, then ivc_check. A failed
   read stops before nova_comp_decode. */
static IvcVerdict ivc_verify_file(const char *path, const IvcPublic *pub) {
  size_t len = nova_comp_size(&ivc_ck);
  if (ivc_file(path, ivc_rd, sizeof ivc_rd, len) != IVC_READ_OK) return IVC_BAD_READ;
  return ivc_check(ivc_rd, len, pub);
}

static int ivc_write(const char *path, const unsigned char *b, size_t n) {
  FILE *f = fopen(path, "wb");
  int ok;
  if (f == NULL) return 0;
  ok = fwrite(b, 1u, n, f) == n;
  if (fclose(f) != 0) ok = 0;
  return ok;
}

static int ivc_usage(void) {
  fputs("usage: ivctool size <c>\n"
        "       ivctool generate <c> <seed> <steps> <dir>\n"
        "       ivctool prove <c> <seed> <steps> <proof> [<bad-step>]\n"
        "       ivctool verify <c> <proof> <z0-hex> <zk-hex> <count> <pk-hex> [<proof> ...]\n"
        "       ivctool refusals <c>\n"
        "<c> is ft or real-f\n",
        stderr);
  return 2;
}

static int ivc_size_mode(IvcCircuit c) {
  IvcCaps cp;
  IvcCtx ctx;
  int ok = ivc_prepare(c, &cp, &ctx, &ivc_chain_a, 0u, 1u, 0u);
  if (ok) printf("ivc tool size %s: %lu bytes\n", ivc_circuit_name(c), (unsigned long)nova_comp_size(&ivc_ck));
  return ok ? 0 : 1;
}

/* Compress ivc_pf after AT steps to DIR/proof-AT.bin and add its lines to
   LOG. */
static int ivc_save(FILE *log, const char *dir, size_t at, const IvcChain *ch) {
  char path[IVC_PATH_CAP];
  IvcPublic pub;
  size_t len = 0;
  int n = snprintf(path, sizeof path, "%s/proof-%lu.bin", dir, (unsigned long)at);
  int ok = n > 0 && (size_t)n < sizeof path && ivc_compress(ivc_buf, &len) && ivc_write(path, ivc_buf, len);
  if (ok) {
    ivc_public_of(&pub, ch);
    fprintf(log, "proof %lu %s %lu\n", (unsigned long)at, path, (unsigned long)len);
    ivc_print_public(log, &pub, ch->pkb);
  }
  return ok;
}

static int ivc_generate_mode(IvcCircuit c, const char *seed_s, const char *steps_s, const char *dir) {
  char path[IVC_PATH_CAP];
  char hb[2u * 32u + 1u];
  char hs[2u * 96u + 1u];
  IvcCaps cp;
  IvcCtx ctx;
  IvcChain *ch = &ivc_chain_a;
  FILE *log = NULL;
  uint64_t seed;
  uint64_t steps;
  size_t at;
  size_t k;
  int n;
  int ok;
  if (!ivc_number(seed_s, UINT64_MAX, &seed) || !ivc_number(steps_s, IVC_STEPS_MAX, &steps) || steps == 0u)
    return ivc_usage();
  n = snprintf(path, sizeof path, "%s/chain.txt", dir);
  ok = n > 0 && (size_t)n < sizeof path && ivc_prepare(c, &cp, &ctx, ch, seed, (size_t)steps, 0u);
  if (ok) log = fopen(path, "w");
  ok = ok && log != NULL;
  if (ok) {
    ivc_hex_string(hs, ch->pkb, IVC_PK_BYTES);
    fprintf(log, "circuit %s\nseed %llu\nsteps %llu\npk %s\n", ivc_circuit_name(c), (unsigned long long)seed,
            (unsigned long long)steps, hs);
    for (k = 0; k < ch->steps; k++) {
      ivc_hex_string(hb, ch->c[k].body, 32u);
      ivc_hex_string(hs, ch->c[k].sig, 96u);
      fprintf(log, "step %lu body %s cert %s\n", (unsigned long)(k + 1u), hb, hs);
    }
    ivc_restart(ch);
  }
  for (at = 1u; ok && at <= steps; at++) {
    ok = ivc_prove_to(&cp, &ctx, ch, at, 0u);
    if (ok && (at == 1u || at == 3u || at == 10u || at == 100u || at == steps)) ok = ivc_save(log, dir, at, ch);
  }
  if (log != NULL && fclose(log) != 0) ok = 0;
  printf("ivc tool generate %s: %s\n", ivc_circuit_name(c), ok ? "ok" : "failed");
  return ok ? 0 : 1;
}

static int ivc_prove_mode(IvcCircuit c, const char *seed_s, const char *steps_s, const char *path,
                          const char *bad_s) {
  IvcCaps cp;
  IvcCtx ctx;
  IvcPublic pub;
  IvcChain *ch = &ivc_chain_a;
  uint64_t seed;
  uint64_t steps;
  uint64_t bad = 0;
  size_t len = 0;
  time_t t0;
  int ok;
  if (!ivc_number(seed_s, UINT64_MAX, &seed) || !ivc_number(steps_s, IVC_STEPS_MAX, &steps) || steps == 0u)
    return ivc_usage();
  if (bad_s != NULL && (!ivc_number(bad_s, steps, &bad) || bad == 0u)) return ivc_usage();
  ok = ivc_prepare(c, &cp, &ctx, ch, seed, (size_t)steps, (size_t)bad);
  ivc_bad_seen = 0;
  t0 = time(NULL);
  if (ok) ivc_restart(ch);
  ok = ok && ivc_prove_to(&cp, &ctx, ch, (size_t)steps, (size_t)bad) && ivc_compress(ivc_buf, &len) &&
       ivc_write(path, ivc_buf, len);
  printf("ivc tool prove %s: %ld s, %s\n", ivc_circuit_name(c), (long)(time(NULL) - t0), ok ? "ok" : "failed");
  if (ok) {
    ivc_public_of(&pub, ch);
    printf("proof %s %lu\n", path, (unsigned long)len);
    ivc_print_public(stdout, &pub, ch->pkb);
  }
  if (bad != 0u)
    printf("ivc tool: the bad certificate of step %llu reached the %s callback %lu times%s\n",
           (unsigned long long)bad, ivc_circuit_name(c), (unsigned long)ivc_bad_seen,
           ivc_host_only(c) ? " (host input check: the ft callback verifies it natively)" : "");
  if (ivc_cert_step != 0u)
    printf("ivc tool: host input check: the %s callback refused the certificate of step %lu "
           "(frost_verify_xy, %lu calls), not a circuit constraint\n",
           ivc_circuit_name(c), (unsigned long)ivc_cert_step, (unsigned long)ivc_cert_refused);
  return ok ? 0 : 1;
}

/* Run the setup once (READY) and then print N_c, the size line of the
   size mode. */
static int ivc_verify_ready(IvcCircuit c, IvcCaps *cp, IvcCtx *ctx, int *ready) {
  int ok = *ready || ivc_prepare(c, cp, ctx, &ivc_chain_a, 0u, 1u, 0u);
  if (ok && !*ready) printf("ivc tool size %s: %lu bytes\n", ivc_circuit_name(c), (unsigned long)nova_comp_size(&ivc_ck));
  *ready = ok;
  return ok;
}

/* ARG: N groups of 5 values: the proof, z0, zk, the count and the PK. One
   setup serves all the groups (C4): it runs at the first group with a
   public input that parses. Each group prints one verdict line, in the
   order of ARG. A public input that does not parse is refused without the
   setup. The exit code is 0 only if each group is ok. */
static int ivc_verify_mode(IvcCircuit c, char **arg, size_t n) {
  IvcCaps cp;
  IvcCtx ctx;
  IvcPublic pub;
  IvcVerdict v;
  size_t k;
  int ready = 0;
  int ok = 1;
  int all = 1;
  for (k = 0; ok && k < n; k++) {
    char **g = arg + 5u * k;
    int parsed = ivc_public_parse(&pub, g[1], g[2], g[3], g[4]);
    ok = !parsed || ivc_verify_ready(c, &cp, &ctx, &ready);
    v = parsed && ok ? ivc_verify_file(g[0], &pub) : IVC_BAD_PUBLIC;
    if (ok) printf("ivc tool verify %s: %s\n", ivc_circuit_name(c), ivc_verdict_name(v));
    all = all && v == IVC_OK;
  }
  return ok && all ? 0 : 1;
}

static void ivc_row(IvcTally *t, const char *name, int good) {
  t->rows++;
  if (!good) {
    t->mismatches++;
    fprintf(stderr, "FAIL ivc tool %s\n", name);
  }
}

/* The 12 rows (the session 40 plan) on one proof of 1 step of the chain of
   seed 0. */
static int ivc_refusals(IvcCircuit c) {
  static const char *const bad_numbers[6] = {"", "12a", "-1", "+1", " 1", "18446744073709551616"};
  static const char *const bad_modes[5] = {"", "PROVE", "verify2", "refusal", "size "};
  static const char *const bad_circuits[5] = {"", "F_t", "realf", "ft ", "REAL-F"};
  static const char *const modes[5] = {"generate", "prove", "verify", "size", "refusals"};
  static const char *const path = "build/ivctool-rows.bin";
  IvcTally t = {0, 0};
  IvcCaps cp;
  IvcCaps other;
  IvcCtx ctx;
  IvcPublic pub;
  IvcPublic bad;
  IvcCircuit sel;
  IvcMode mode;
  StepCase fx;
  unsigned char head[32];
  unsigned char next[32];
  unsigned char b[IVC_STATE_BYTES];
  char z0h[2u * IVC_STATE_BYTES + 1u];
  char zkh[2u * IVC_STATE_BYTES + 1u];
  char pkh[2u * IVC_PK_BYTES + 1u];
  char badh[2u * IVC_STATE_BYTES + 1u];
  Fe one = small(1u);
  uint64_t n;
  size_t len = 0;
  size_t len2 = 0;
  size_t k;
  time_t t0;
  int ok;
  int good;
  ok = ivc_prepare(c, &cp, &ctx, &ivc_chain_a, 0u, IVC_ROW_STEPS, 0u);
  t0 = time(NULL);
  if (ok) ivc_restart(&ivc_chain_a);
  ok = ok && ivc_prove_to(&cp, &ctx, &ivc_chain_a, 1u, 0u) && ivc_compress(ivc_buf, &len);
  printf("ivc tool %s proof of 1 step: %ld s, %lu bytes, %s\n", ivc_circuit_name(c), (long)(time(NULL) - t0),
         (unsigned long)len, ok ? "ok" : "failed");
  ivc_public_of(&pub, &ivc_chain_a);
  ivc_state_bytes(b, pub.z0);
  ivc_hex_string(z0h, b, IVC_STATE_BYTES);
  ivc_state_bytes(b, pub.zk);
  ivc_hex_string(zkh, b, IVC_STATE_BYTES);
  ivc_hex_string(pkh, ivc_chain_a.pkb, IVC_PK_BYTES);

  /* The same seed gives the same chain (and seed 0 gives the h4 steps of
     test/stepcase.h, with PK = step_pk) and the same proof bytes. */
  good = ok && ivc_chain(&ivc_chain_b, 0u, IVC_ROW_STEPS, 0u) && ivc_chain_same(&ivc_chain_a, &ivc_chain_b);
  memcpy(head, ivc_chain_a.head[0], 32u);
  for (k = 0; k < IVC_ROW_STEPS; k++) {
    step_case(&fx, head, k, k, next);
    good = good && ivc_case_same(&fx, &ivc_chain_a.c[k]) && memcmp(next, ivc_chain_a.head[k + 1u], 32u) == 0;
    memcpy(head, next, 32u);
  }
  t0 = time(NULL);
  if (good) ivc_restart(&ivc_chain_b);
  good = good && ivc_prove_to(&cp, &ctx, &ivc_chain_b, 1u, 0u) && ivc_compress(ivc_buf2, &len2) &&
         len2 == len && memcmp(ivc_buf, ivc_buf2, len) == 0;
  printf("ivc tool repeat proof: %ld s\n", (long)(time(NULL) - t0));
  ivc_row(&t, "repeat seed", good);

  /* A changed seed changes each certificate, not the bodies or the heads.
     The F_t proof bytes do not change (host-only); the real F bytes do. */
  good = ok && ivc_chain(&ivc_chain_c, 1u, IVC_ROW_STEPS, 0u);
  for (k = 0; good && k < IVC_ROW_STEPS; k++)
    good = memcmp(ivc_chain_c.c[k].body, ivc_chain_a.c[k].body, 32u) == 0 &&
           memcmp(ivc_chain_c.c[k].sig, ivc_chain_a.c[k].sig, 96u) != 0 &&
           memcmp(ivc_chain_c.head[k + 1u], ivc_chain_a.head[k + 1u], 32u) == 0;
  t0 = time(NULL);
  if (good) ivc_restart(&ivc_chain_c);
  good = good && ivc_prove_to(&cp, &ctx, &ivc_chain_c, 1u, 0u) && ivc_compress(ivc_buf2, &len2) &&
         len2 == len && (memcmp(ivc_buf, ivc_buf2, len) == 0) == ivc_host_only(c);
  printf("ivc tool changed seed proof: %ld s\n", (long)(time(NULL) - t0));
  ivc_row(&t, "changed seed", good);

  /* Two names select a circuit, with no default. The selector gives the
     callback and the caps. */
  good = ivc_circuit("ft", &sel) && sel == IVC_FT && ivc_circuit("real-f", &sel) && sel == IVC_REAL_F &&
         !ivc_circuit(NULL, &sel);
  for (k = 0; k < 5u; k++) good = good && !ivc_circuit(bad_circuits[k], &sel);
  ivc_caps(IVC_FT, &other);
  good = good && other.fn == ivc_ft && other.p_g == IVC_FT_PG && other.c_p == IVC_FT_CP;
  ivc_caps(IVC_REAL_F, &other);
  good = good && other.fn == ivc_real && other.p_g == IVC_PG && other.c_p == IVC_CP;
  ivc_caps(c, &other);
  good = good && ok && other.fn == cp.fn && ivc_check(ivc_buf, len, &pub) == IVC_OK;
  ivc_row(&t, "circuit selection", good);

  /* The file of the proof has nova_comp_size bytes and reads back. */
  good = ok && len == nova_comp_size(&ivc_ck) && len <= IVC_FILE_CAP && ivc_write(path, ivc_buf, len) &&
         ivc_file(path, ivc_rd, sizeof ivc_rd, len) == IVC_READ_OK && memcmp(ivc_rd, ivc_buf, len) == 0 &&
         ivc_verify_file(path, &pub) == IVC_OK;
  ivc_row(&t, "size round trip", good);

  /* Decode, then encode, gives the same bytes. */
  good = ok && nova_comp_decode(&ivc_cpf2, &ivc_ck, &ivc_key, ivc_buf, len) &&
         nova_comp_encode(ivc_buf2, len, &ivc_ck, &ivc_cpf2) && memcmp(ivc_buf, ivc_buf2, len) == 0 &&
         ivc_check(ivc_buf, len, &pub) == IVC_OK;
  ivc_row(&t, "decode encode bytes", good);

  good = ok && len > 1u && ivc_write(path, ivc_buf, len - 1u) &&
         ivc_file(path, ivc_rd, sizeof ivc_rd, len) == IVC_READ_LENGTH && ivc_verify_file(path, &pub) == IVC_BAD_READ;
  ivc_row(&t, "truncated file", good);

  memcpy(ivc_mut, ivc_buf, len);
  ivc_mut[len] = 0u;
  good = ok && ivc_write(path, ivc_mut, len + 1u) && ivc_file(path, ivc_rd, sizeof ivc_rd, len) == IVC_READ_LENGTH &&
         ivc_verify_file(path, &pub) == IVC_BAD_READ;
  ivc_row(&t, "trailing byte", good);

  good = ok && remove(path) == 0 && ivc_file(path, ivc_rd, sizeof ivc_rd, len) == IVC_READ_MISSING &&
         ivc_file("build/ivctool-no-dir/proof.bin", ivc_rd, sizeof ivc_rd, len) == IVC_READ_MISSING &&
         ivc_verify_file(path, &pub) == IVC_BAD_READ;
  ivc_row(&t, "missing file", good);

  /* Decimal digits only, in the bound; hex of the exact length. */
  n = 77u;
  good = !ivc_number(NULL, UINT64_MAX, &n) && !ivc_number("101", IVC_STEPS_MAX, &n);
  for (k = 0; k < 6u; k++) good = good && !ivc_number(bad_numbers[k], UINT64_MAX, &n);
  good = good && n == 77u && ivc_number("100", IVC_STEPS_MAX, &n) && n == 100u &&
         ivc_number("18446744073709551615", UINT64_MAX, &n) && n == UINT64_MAX;
  good = good && !ivc_hex(b, IVC_PK_BYTES, "00") && !ivc_hex(b, 1u, "0g") && !ivc_hex(b, 1u, "000") &&
         !ivc_hex(b, 1u, "0") && ivc_hex(b, 1u, "0F") && b[0] == 15u;
  good = good && !ivc_public_parse(&bad, z0h, zkh, "1x", pkh) && !ivc_public_parse(&bad, z0h, zkh, "", pkh) &&
         !ivc_public_parse(&bad, z0h, zkh, "1000001", pkh) && ivc_public_parse(&bad, z0h, zkh, "1", pkh);
  good = good && ivc_prove_mode(c, "0", "1", path, "2") == 2;
  ivc_row(&t, "bad numeric argument", good);

  good = !ivc_mode(NULL, &mode);
  for (k = 0; k < 5u; k++) good = good && !ivc_mode(bad_modes[k], &mode);
  for (k = 0; k < 5u; k++) good = good && ivc_mode(modes[k], &mode);
  good = good && mode == IVC_REFUSALS;
  ivc_row(&t, "unknown mode", good);

  /* The printed public input verifies. A changed z0, zk, count or PK is a
     public binding refusal. */
  good = ok && ivc_public_parse(&bad, z0h, zkh, "1", pkh) && ivc_check(ivc_buf, len, &bad) == IVC_OK;
  bad = pub;
  fe_add(&bad.z0[2], &bad.z0[2], &one, &SECP_FP);
  good = good && ivc_check(ivc_buf, len, &bad) == IVC_BAD_PUBLIC;
  bad = pub;
  fe_add(&bad.zk[0], &bad.zk[0], &one, &SECP_FP);
  good = good && ivc_check(ivc_buf, len, &bad) == IVC_BAD_PUBLIC;
  bad = pub;
  bad.count = pub.count + 1u;
  good = good && ivc_check(ivc_buf, len, &bad) == IVC_BAD_PUBLIC;
  bad = pub;
  bad.count = 0u;
  good = good && ivc_check(ivc_buf, len, &bad) == IVC_BAD_PUBLIC;
  bad = pub;
  fe_add(&bad.pk[0], &bad.pk[0], &one, &SECP_FP);
  good = good && ivc_check(ivc_buf, len, &bad) == IVC_BAD_PUBLIC;
  bad = pub;
  fe_add(&bad.pk[1], &bad.pk[1], &one, &SECP_FP);
  good = good && ivc_check(ivc_buf, len, &bad) == IVC_BAD_PUBLIC;
  ivc_row(&t, "bad public input", good);

  /* A value or a coordinate not below its modulus, or a bad point byte,
     is a decode refusal. A public value not below p is a parse refusal. */
  memcpy(ivc_mut, ivc_buf, len);
  memset(ivc_mut + IVC_AT_Z0, 0xff, 32u);
  good = ok && len > IVC_AT_X + 32u && ivc_check(ivc_mut, len, &pub) == IVC_BAD_DECODE;
  memcpy(ivc_mut, ivc_buf, len);
  ivc_mut[IVC_AT_W] = 0x05u;
  good = good && ivc_check(ivc_mut, len, &pub) == IVC_BAD_DECODE;
  memcpy(ivc_mut, ivc_buf, len);
  memset(ivc_mut + IVC_AT_X, 0xff, 32u);
  good = good && ivc_check(ivc_mut, len, &pub) == IVC_BAD_DECODE;
  memcpy(badh, z0h, sizeof badh);
  memset(badh, 'f', 64u);
  good = good && !ivc_public_parse(&bad, badh, zkh, "1", pkh);
  memcpy(badh, pkh, sizeof pkh);
  memset(badh, 'f', 64u);
  good = good && !ivc_public_parse(&bad, z0h, zkh, "1", badh);
  ivc_row(&t, "noncanonical encoding", good);

  printf("ivc tool: %u rows, %u mismatches\n", (unsigned)t.rows, (unsigned)t.mismatches);
  return ok && t.mismatches == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
  IvcMode mode;
  IvcCircuit c;
  if (argc < 3 || !ivc_mode(argv[1], &mode) || !ivc_circuit(argv[2], &c)) return ivc_usage();
  switch (mode) {
  case IVC_SIZE:
    return argc == 3 ? ivc_size_mode(c) : ivc_usage();
  case IVC_GENERATE:
    return argc == 6 ? ivc_generate_mode(c, argv[3], argv[4], argv[5]) : ivc_usage();
  case IVC_PROVE:
    return argc == 6 || argc == 7 ? ivc_prove_mode(c, argv[3], argv[4], argv[5], argc == 7 ? argv[6] : NULL)
                                  : ivc_usage();
  case IVC_VERIFY:
    return argc >= 8 && (argc - 3) % 5 == 0 ? ivc_verify_mode(c, argv + 3, (size_t)(argc - 3) / 5u)
                                            : ivc_usage();
  case IVC_REFUSALS:
    return argc == 3 ? ivc_refusals(c) : ivc_usage();
  }
  return ivc_usage();
}
