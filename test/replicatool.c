/* The replica host of S8 (O104, O105). It runs build/replica.wasm through
   the wasm2c translation build/replica.c, and it gives the 16 imports of
   module "q". q_hash2 (H2b) and q_frost_verify (H3) have a body, H5a
   gives 4 more imports a body (R-E12), S10 H3c gives the 6 imports
   q_mpc_check to q_mpc_open a body (bgw.h), and S11 H5 gives the 4
   imports q_ivc_verify to q_ivc_word a body (ivchost.h).

   Usage: replicatool hash X. It prints the 4 words of
   q_hash2 (w4 X X X X) (w4 X X X X) (the entries hash0 to hash3 of
   replica/replica.lang) in decimal, then the 32 digest bytes in hex.
   replicatool stack X1 ... XN: see run_stack. replicatool chain ENTRY X0 ..
   Y3 PRE (H3), or S PRE, or PREA PREB (H4): see run_chain. replicatool
   tally ENTRY X0 .. Y3 B P K (H5a): see run_tally. replicatool amend
   TEXT (H5b): see run_amend. replicatool ivcrows DIR and ivc FILE DIR
   (S11 H5-d): see run_ivc_rows and run_ivc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/bgw.h"
#include "crypto/elgamal.h"
#include "crypto/frost.h"
#include "crypto/ivchost.h"
#include "crypto/sha256.h"
#include "crypto/sigma.h"
#include "crypto/threshold.h"
#include "replica.h"

struct w2c_q {
  wasm_rt_memory_t *mem;
};

/* Read one unsigned decimal word without accepting signs or saturation. */
static int decimal_word(const char **text, u64 *out) {
  const char *p = *text;
  u64 n = 0;
  unsigned d;
  if (*p < '0' || *p > '9') return 0;
  for (; *p >= '0' && *p <= '9'; p++) {
    d = (unsigned)(*p - '0');
    if (n > (UINT64_MAX - d) / 10u) return 0;
    n = n * 10u + d;
  }
  *text = p;
  *out = n;
  return 1;
}

static int number(const char *text, u64 *out) {
  return decimal_word(&text, out) && *text == '\0';
}

/* A record block of N words (F2 layout: W4, W8, W12) has 1 + 2N words: the
   tag, then a word and a flag for each field. Word K of the block at A is
   at A + 8 + 16K. */
static int rec_fits(const struct w2c_q *q, u64 a, unsigned n) {
  return a <= q->mem->size && q->mem->size - a >= 8u + 16u * (u64)n;
}

static u64 rec_word(const struct w2c_q *q, u64 a, unsigned k) {
  u64 w;
  memcpy(&w, q->mem->data + a + 8u + 16u * k, sizeof w);
  return w;
}

/* The N words of the record at A as 8N bytes. Word 0 is the most
   significant. Each word is 8 bytes, big endian. */
static void rec_bytes(const struct w2c_q *q, u64 a, unsigned n, unsigned char *out) {
  unsigned i;
  for (i = 0; i < 8u * n; i++) out[i] = (unsigned char)(rec_word(q, a, i / 8u) >> (56u - 8u * (i % 8u)));
}

u64 w2c_q_q_hash2(struct w2c_q *q, u64 out, u64 a, u64 b) {
  unsigned char bytes[64];
  unsigned char digest[32];
  unsigned k;
  unsigned i;
  u64 w;
  if (!rec_fits(q, out, 4u) || !rec_fits(q, a, 4u) || !rec_fits(q, b, 4u))
    return 1;
  rec_bytes(q, a, 4u, bytes);
  rec_bytes(q, b, 4u, bytes + 32);
  sha256(bytes, sizeof bytes, digest);
  for (k = 0; k < 4u; k++) {
    w = 0;
    for (i = 0; i < 8u; i++) w = w << 8 | digest[8u * k + i];
    memcpy(q->mem->data + out + 8u + 16u * k, &w, sizeof w);
  }
  return 0;
}

/* q_frost_verify (H3, R-C1): the FrostResult code of the signature SIG (a
   W12: R x, then R y, then z) of the 32 bytes of MSG (a W4) under the key
   PK (a W8: x, then y). 0 is FROST_OK. A code that is not 0 is data, not a
   trap. A record that does not fit gives 1 (refused), as q_hash2 (R-C15). */
u64 w2c_q_q_frost_verify(struct w2c_q *q, u64 pk, u64 sig, u64 msg) {
  unsigned char pk_xy[64];
  unsigned char sig_xyz[96];
  unsigned char msg_bytes[32];
  if (!rec_fits(q, pk, 8u) || !rec_fits(q, sig, 12u) || !rec_fits(q, msg, 4u))
    return 1;
  rec_bytes(q, pk, 8u, pk_xy);
  rec_bytes(q, sig, 12u, sig_xyz);
  rec_bytes(q, msg, 4u, msg_bytes);
  return (u64)frost_verify_xy(pk_xy, sig_xyz, msg_bytes);
}

/* H5a (R-E12, R-E27): the imports call the _be functions of the crypto
   files. A record that does not fit gives 1 (refused), as q_hash2. */

/* Write the 8N bytes IN to the N words of the record at A. Word 0 is the
   most significant. Each word is 8 bytes, big endian. */
static void rec_put(struct w2c_q *q, u64 a, unsigned n, const unsigned char *in) {
  unsigned k;
  unsigned i;
  u64 w;
  for (k = 0; k < n; k++) {
    w = 0;
    for (i = 0; i < 8u; i++) w = w << 8 | in[8u * k + i];
    memcpy(q->mem->data + a + 8u + 16u * k, &w, sizeof w);
  }
}

/* The tag word of the block at A. */
static u64 rec_tag(const struct w2c_q *q, u64 a) {
  u64 w;
  memcpy(&w, q->mem->data + a, sizeof w);
  return w;
}

/* q_ivc_verify (S11 H5, Q-S11-23): the IvcVerdict code of the proof
   PROOF (a Words list: tag 1, field 0 a ℕ word, field 1 the rest; tag 0
   nil) for the circuit C, the key PK (a W8), the states Z0 and ZK (each a
   W20) and COUNT. A record or a cell that does not fit, or a list of more
   than 2079 cells, gives IVC_BAD_READ (as eval.c). */
u64 w2c_q_q_ivc_verify(struct w2c_q *q, u64 c, u64 pk, u64 z0, u64 zk, u64 count, u64 proof) {
  static unsigned char words[8u * 2079u];
  unsigned char pk_xy[IVC_HOST_PK_BYTES];
  unsigned char z0_bytes[IVC_HOST_Z_BYTES];
  unsigned char zk_bytes[IVC_HOST_Z_BYTES];
  size_t have = 0;
  unsigned i;
  u64 w;
  int more;
  if (!rec_fits(q, pk, 8u) || !rec_fits(q, z0, 20u) || !rec_fits(q, zk, 20u))
    return (u64)IVC_BAD_READ;
  rec_bytes(q, pk, 8u, pk_xy);
  rec_bytes(q, z0, 20u, z0_bytes);
  rec_bytes(q, zk, 20u, zk_bytes);
  more = rec_fits(q, proof, 2u) && rec_tag(q, proof) == 1u;
  for (; more && have < 2079u; have++) {
    w = rec_word(q, proof, 0u);
    for (i = 0; i < 8u; i++) words[8u * have + i] = (unsigned char)(w >> (56u - 8u * i));
    proof = rec_word(q, proof, 1u);
    more = rec_fits(q, proof, 2u) && rec_tag(q, proof) == 1u;
  }
  if (more || !rec_fits(q, proof, 0u) || rec_tag(q, proof) != 0u)
    return (u64)IVC_BAD_READ;
  return (u64)ivc_host_verify_bytes(c, words, have, z0_bytes, zk_bytes, count, pk_xy);
}

/* q_ivc_start (13), q_ivc_extend (14) and q_ivc_word (15) (S11 H5,
   Q-S11-26 (a)): the F_t prover of ivchost.c. The records are read as the
   W8 PK of q_ivc_verify. A record that does not fit gives IVC_HOST_BAD_READ. */
u64 w2c_q_q_ivc_start(struct w2c_q *q, u64 c, u64 pk, u64 head, u64 z0) {
  unsigned char pk_xy[IVC_HOST_PK_BYTES];
  unsigned char head_bytes[32];
  unsigned char z0_bytes[IVC_HOST_Z_BYTES];
  if (!rec_fits(q, pk, 8u) || !rec_fits(q, head, 4u) || !rec_fits(q, z0, 20u))
    return (u64)IVC_HOST_BAD_READ;
  rec_bytes(q, pk, 8u, pk_xy);
  rec_bytes(q, head, 4u, head_bytes);
  rec_bytes(q, z0, 20u, z0_bytes);
  return (u64)ivc_host_start(c, pk_xy, head_bytes, z0_bytes);
}

u64 w2c_q_q_ivc_extend(struct w2c_q *q, u64 h, u64 body, u64 cert) {
  unsigned char body_bytes[32];
  unsigned char cert_bytes[96];
  if (!rec_fits(q, body, 4u) || !rec_fits(q, cert, 12u))
    return (u64)IVC_HOST_BAD_READ;
  rec_bytes(q, body, 4u, body_bytes);
  rec_bytes(q, cert, 12u, cert_bytes);
  return (u64)ivc_host_extend(h, body_bytes, cert_bytes);
}

u64 w2c_q_q_ivc_word(struct w2c_q *q, u64 h, u64 k) {
  (void)q;
  return (u64)ivc_host_word(h, k);
}

/* q_ballot_verify: the SigResult code of the bit proof PROOF (a BitProof)
   of slot J of the cipher CT (a W16) under the key PK (a W8) and the
   context CTX (a W4). 0 is SIG_OK. */
u64 w2c_q_q_ballot_verify(struct w2c_q *q, u64 proof, u64 pk, u64 ct, u64 ctx, u64 j) {
  unsigned char proof_b[384];
  unsigned char pk_b[64];
  unsigned char ct_b[128];
  unsigned char ctx_b[32];
  if (!rec_fits(q, proof, 48u) || !rec_fits(q, pk, 8u) || !rec_fits(q, ct, 16u) || !rec_fits(q, ctx, 4u))
    return 1;
  rec_bytes(q, proof, 48u, proof_b);
  rec_bytes(q, pk, 8u, pk_b);
  rec_bytes(q, ct, 16u, ct_b);
  rec_bytes(q, ctx, 4u, ctx_b);
  return (u64)sig_or_verify_be(proof_b, pk_b, ct_b, ctx_b, j);
}

/* q_tally_add: OUT (a W16) is the sum of the ciphers A and B (K slots).
   tally_add_be writes zeros on a refusal. The result is 0. */
u64 w2c_q_q_tally_add(struct w2c_q *q, u64 out, u64 a, u64 b, u64 k) {
  unsigned char a_b[128];
  unsigned char b_b[128];
  unsigned char sum[128];
  if (!rec_fits(q, out, 16u) || !rec_fits(q, a, 16u) || !rec_fits(q, b, 16u))
    return 1;
  rec_bytes(q, a, 16u, a_b);
  rec_bytes(q, b, 16u, b_b);
  tally_add_be(sum, a_b, b_b, k);
  rec_put(q, out, 16u, sum);
  return 0;
}

/* q_partial_verify: 0 when the decryption part PART (a DecPart) of the
   cipher CT (a W16) verifies under the key KEY (a W8), else 1. */
u64 w2c_q_q_partial_verify(struct w2c_q *q, u64 part, u64 key, u64 ct) {
  unsigned char part_b[232];
  unsigned char key_b[64];
  unsigned char ct_b[128];
  if (!rec_fits(q, part, 29u) || !rec_fits(q, key, 8u) || !rec_fits(q, ct, 16u))
    return 1;
  rec_bytes(q, part, 29u, part_b);
  rec_bytes(q, key, 8u, key_b);
  rec_bytes(q, ct, 16u, ct_b);
  return (u64)thr_verify_be(part_b, key_b, ct_b);
}

/* R-E28: walk the cons cells of the list at A (tag 1; field 0 is the
   address of the head record, field FIELDS - 1 the rest), at most
   THR_N_MAX. Each head record of N words goes to OUT as 8N bytes. It gives
   the cell count, or THR_N_MAX + 1 when the list has more cells (as
   eval.c). */
static uint32_t walk_list(const struct w2c_q *q, u64 a, unsigned fields, unsigned n, unsigned char *out) {
  uint32_t count = 0;
  int more = rec_fits(q, a, fields) && rec_tag(q, a) == 1;
  for (; more && count < THR_N_MAX; count++) {
    if (rec_fits(q, rec_word(q, a, 0), n)) rec_bytes(q, rec_word(q, a, 0), n, out + 8u * n * count);
    a = rec_word(q, a, fields - 1u);
    more = rec_fits(q, a, fields) && rec_tag(q, a) == 1;
  }
  return more ? THR_N_MAX + 1u : count;
}

/* q_combine (R-E28): OUT (a W4) is m, the ThrResult code, 0 and 0 of
   thr_open_be on the cipher CT (a W16), with the parts of the list PARTS
   (DecPart, W8, rest) and the keys of the list KEYS (W8, rest). The counts
   are the walked cell counts. */
u64 w2c_q_q_combine(struct w2c_q *q, u64 out, u64 parts, u64 k, u64 keys, u64 t, u64 n, u64 ct, u64 bits) {
  unsigned char part_b[THR_N_MAX * 232u];
  unsigned char key_b[THR_N_MAX * 64u];
  unsigned char ct_b[128];
  uint32_t have_parts;
  uint32_t have_keys;
  uint64_t m = 0;
  u64 w[4];
  unsigned i;
  if (!rec_fits(q, out, 4u) || !rec_fits(q, ct, 16u))
    return 1;
  memset(part_b, 0, sizeof part_b);
  memset(key_b, 0, sizeof key_b);
  have_parts = walk_list(q, parts, 3u, 29u, part_b);
  have_keys = walk_list(q, keys, 2u, 8u, key_b);
  rec_bytes(q, ct, 16u, ct_b);
  w[1] = (u64)thr_open_be(&m, part_b, have_parts, key_b, have_keys, ct_b, k, t, n, bits);
  w[0] = m;
  w[2] = 0;
  w[3] = 0;
  for (i = 0; i < 4u; i++) memcpy(q->mem->data + out + 8u + 16u * i, &w[i], sizeof w[i]);
  return 0;
}

/* S10 H3c (bgw.h): the q_mpc imports call the _be functions of bgw.c. A
   record that does not fit gives 1 (refused), as q_hash2. A dealing and a
   share list are W16 records. */

/* The 3 Prods lists LISTS as bgw_mul_be reads them (as eval.c): the list
   of the member i at PRODS + BGW_LIST_BYTES (i - 1), BGW_CELL_BYTES for
   each cell (prodCons: the part, C[1], the sub-shares, then the rest).
   HAVE[i - 1] is the walked cell count, or THR_N_MAX + 1 when the list
   has more cells (as walk_list). */
static void walk_prods(const struct w2c_q *q, const u64 *lists, unsigned char *prods, uint32_t *have) {
  static const unsigned WORDS[3] = {29u, 8u, 16u};
  unsigned i;
  unsigned k;
  unsigned at;
  u64 a;
  int more;
  memset(prods, 0, 3u * BGW_LIST_BYTES);
  for (i = 0; i < 3u; i++) {
    a = lists[i];
    more = rec_fits(q, a, 4u) && rec_tag(q, a) == 1;
    for (have[i] = 0; more && have[i] < THR_N_MAX; have[i]++) {
      for (k = 0, at = 0; k < 3u; at += 8u * WORDS[k], k++)
        if (rec_fits(q, rec_word(q, a, k), WORDS[k]))
          rec_bytes(q, rec_word(q, a, k), WORDS[k], prods + BGW_LIST_BYTES * i + BGW_CELL_BYTES * have[i] + at);
      a = rec_word(q, a, 3u);
      more = rec_fits(q, a, 4u) && rec_tag(q, a) == 1;
    }
    have[i] = more ? THR_N_MAX + 1u : have[i];
  }
}

/* q_mpc_check: the BgwResult code of the shares S of the members 1 to N of
   the dealing D. 0 is BGW_OK. */
u64 w2c_q_q_mpc_check(struct w2c_q *q, u64 d, u64 s, u64 n) {
  unsigned char d_b[128];
  unsigned char s_b[128];
  if (!rec_fits(q, d, 16u) || !rec_fits(q, s, 16u))
    return 1;
  rec_bytes(q, d, 16u, d_b);
  rec_bytes(q, s, 16u, s_b);
  return (u64)bgw_check_be(d_b, s_b, n);
}

/* q_mpc_add: OUT is the dealing of the sum of the dealings A and B. The
   result is 0. */
u64 w2c_q_q_mpc_add(struct w2c_q *q, u64 out, u64 a, u64 b) {
  unsigned char a_b[128];
  unsigned char b_b[128];
  unsigned char sum[128];
  if (!rec_fits(q, out, 16u) || !rec_fits(q, a, 16u) || !rec_fits(q, b, 16u))
    return 1;
  rec_bytes(q, a, 16u, a_b);
  rec_bytes(q, b, 16u, b_b);
  bgw_add_be(sum, a_b, b_b);
  rec_put(q, out, 16u, sum);
  return 0;
}

/* q_mpc_affine: OUT is the dealing of W D + K (W and K are W4 scalars).
   The result is 0. */
u64 w2c_q_q_mpc_affine(struct w2c_q *q, u64 out, u64 d, u64 w, u64 k) {
  unsigned char d_b[128];
  unsigned char w_b[32];
  unsigned char k_b[32];
  unsigned char res[128];
  if (!rec_fits(q, out, 16u) || !rec_fits(q, d, 16u) || !rec_fits(q, w, 4u) || !rec_fits(q, k, 4u))
    return 1;
  rec_bytes(q, d, 16u, d_b);
  rec_bytes(q, w, 4u, w_b);
  rec_bytes(q, k, 4u, k_b);
  bgw_affine_be(res, d_b, w_b, k_b);
  rec_put(q, out, 16u, res);
  return 0;
}

/* q_mpc_mul: OUT is the share list of bgw_mul_be for the step M (the code
   in word 12) over the Prods lists PA, PB and PC and the dealings DA and
   DB. The result is 0. */
u64 w2c_q_q_mpc_mul(struct w2c_q *q, u64 out, u64 pa, u64 pb, u64 pc, u64 m, u64 da, u64 db) {
  unsigned char prods[3u * BGW_LIST_BYTES];
  unsigned char da_b[128];
  unsigned char db_b[128];
  unsigned char res[128];
  uint32_t have[3];
  const u64 lists[3] = {pa, pb, pc};
  if (!rec_fits(q, out, 16u) || !rec_fits(q, da, 16u) || !rec_fits(q, db, 16u))
    return 1;
  walk_prods(q, lists, prods, have);
  rec_bytes(q, da, 16u, da_b);
  rec_bytes(q, db, 16u, db_b);
  bgw_mul_be(res, prods, have, m, da_b, db_b);
  rec_put(q, out, 16u, res);
  return 0;
}

/* q_mpc_mulc: OUT is the dealing of bgw_mulc_be for the step M over the
   Prods lists PA, PB and PC. The result is 0. */
u64 w2c_q_q_mpc_mulc(struct w2c_q *q, u64 out, u64 pa, u64 pb, u64 pc, u64 m) {
  unsigned char prods[3u * BGW_LIST_BYTES];
  unsigned char res[128];
  uint32_t have[3];
  const u64 lists[3] = {pa, pb, pc};
  if (!rec_fits(q, out, 16u))
    return 1;
  walk_prods(q, lists, prods, have);
  bgw_mulc_be(res, prods, have, m);
  rec_put(q, out, 16u, res);
  return 0;
}

/* q_mpc_open: OUT (a W8) is the value of the dealing D from the shares S
   of the members 1 to N (words 0 to 3) and the code (word 4) of
   bgw_open_be. The result is 0. */
u64 w2c_q_q_mpc_open(struct w2c_q *q, u64 out, u64 d, u64 s, u64 n) {
  unsigned char d_b[128];
  unsigned char s_b[128];
  unsigned char res[64];
  if (!rec_fits(q, out, 8u) || !rec_fits(q, d, 16u) || !rec_fits(q, s, 16u))
    return 1;
  rec_bytes(q, d, 16u, d_b);
  rec_bytes(q, s, 16u, s_b);
  bgw_open_be(res, d_b, s_b, n);
  rec_put(q, out, 8u, res);
  return 0;
}

/* Word W at address A of MEM: 8 bytes, little-endian. */
static void put_word(wasm_rt_memory_t *mem, u64 a, u64 w) {
  unsigned i;
  for (i = 0; i < 8u; i++) mem->data[a + i] = (uint8_t)(w >> (8u * i));
}

#define STACK_MAX 64u

/* O109 (i): `stack X1 ... XN` writes push X1 (... (push XN bottom)) below
   heap_base (bottom at address 0, then a 5-word push block for each item),
   then prints total and the 4 words of chainOf. */
static int run_stack(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  wasm_rt_memory_t *mem;
  u64 xs[STACK_MAX];
  u64 w[5];
  u64 a = 8;
  u64 head = 0;
  int n = argc - 2;
  int i;
  unsigned k;
  if (n < 0 || n > (int)STACK_MAX) {
    fprintf(stderr, "usage: replicatool stack X1 ... XN (N at most %u)\n", STACK_MAX);
    return 2;
  }
  for (i = 0; i < n; i++) {
    if (!number(argv[2 + i], &xs[i])) {
      fprintf(stderr, "replicatool: '%s' is not a number\n", argv[2 + i]);
      return 2;
    }
  }
  memset(&q, 0, sizeof q);
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  mem = q.mem;
  put_word(mem, 0, 0);
  for (i = n - 1; i >= 0; i--) {
    put_word(mem, a, 1);
    put_word(mem, a + 8, xs[i]);
    put_word(mem, a + 16, 0);
    put_word(mem, a + 24, head);
    put_word(mem, a + 32, 0);
    head = a;
    a += 40;
  }
  *w2c_replica_heap_base(&inst) = a;
  w[0] = w2c_replica_total(&inst, head);
  w[1] = w2c_replica_chain0(&inst, head);
  w[2] = w2c_replica_chain1(&inst, head);
  w[3] = w2c_replica_chain2(&inst, head);
  w[4] = w2c_replica_chain3(&inst, head);
  for (k = 0; k < 5u; k++) printf("%s%llu", k == 0 ? "" : " ", (unsigned long long)w[k]);
  printf("\n");
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}

#define CHAIN_MAX 16u
/* The words of one step in the eval text of a CertChain (R-C4): 1, then the
   body W4, the sigR W8 and the sigZ W4, each a tag 0 and its words. */
#define STEP_WORDS 20u

/* Write a block at A: TAG, then each of the N words W and its flag 0. It
   gives the next free address. */
static u64 put_block(wasm_rt_memory_t *mem, u64 a, u64 tag, const u64 w[], unsigned n) {
  unsigned k;
  put_word(mem, a, tag);
  for (k = 0; k < n; k++) {
    put_word(mem, a + 8u + 16u * k, w[k]);
    put_word(mem, a + 16u + 16u * k, 0);
  }
  return a + 8u + 16u * n;
}

/* R-C4: the eval text P of a CertChain (the newest step first, certGenesis
   = 0) in WORDS. It gives the step count, or -1 when P is not that text. */
static int parse_chain(const char *p, u64 words[]) {
  const char *end = NULL;
  unsigned n = 0;
  unsigned steps;
  unsigned s;
  int good;
  do {
    if (n == CHAIN_MAX * STEP_WORDS + 1u || !decimal_word(&p, &words[n++])) return -1;
    end = p;
    if (*p == ',') p++;
  } while (*end == ',');
  steps = (n - 1u) / STEP_WORDS;
  good = *end == '\0' && (n - 1u) % STEP_WORDS == 0 && words[n - 1u] == 0;
  for (s = 0; s < steps; s++)
    good &= words[STEP_WORDS * s] == 1 && words[STEP_WORDS * s + 1u] == 0 && words[STEP_WORDS * s + 6u] == 0 &&
            words[STEP_WORDS * s + 15u] == 0;
  return good ? (int)steps : -1;
}

/* R-C11: write the STEPS steps of WORDS at *A, from the oldest step: its
   body, sigR and sigZ blocks and its cert block (tag 1, then the 3 record
   addresses and the prev address, flags 0). The prev of the oldest step is
   certGenesis at address 0. It gives the address of the newest cert block
   (0 when STEPS is 0) and moves *A to the next free address. */
static u64 put_chain(wasm_rt_memory_t *mem, u64 *a, const u64 words[], unsigned steps) {
  u64 at[4];
  u64 head = 0;
  unsigned s;
  for (s = steps; s > 0; s--) {
    const u64 *w = words + STEP_WORDS * (s - 1u);
    at[0] = *a;
    *a = put_block(mem, *a, 0, w + 2, 4u);
    at[1] = *a;
    *a = put_block(mem, *a, 0, w + 7, 8u);
    at[2] = *a;
    *a = put_block(mem, *a, 0, w + 16, 4u);
    at[3] = head;
    head = *a;
    *a = put_block(mem, *a, 1, at, 4u);
  }
  return head;
}

/* The entries of `chain ENTRY X0 .. Y3 ...`: cert_verify and rep_tip take
   PRE (H3); step_apply takes S PRE; rep_merge and merge_tip take PREA PREB
   (H4, R-D4). */
static const char *const CHAIN_ENTRIES[5] = {"cert_verify", "rep_tip", "step_apply", "rep_merge", "merge_tip"};

/* `chain ENTRY X0 .. Y3 ...` writes certGenesis at address 0, then each
   chain argument by put_chain, below heap_base. It prints ENTRY of the key
   X0 .. Y3 in decimal (R-C16). */
static int run_chain(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  wasm_rt_memory_t *mem;
  u64 x[8];
  u64 words[2][CHAIN_MAX * STEP_WORDS + 1u];
  u64 head[2] = {0, 0};
  u64 a = 8;
  u64 s = 0;
  u64 got;
  int steps[2] = {0, 0};
  int e = -1;
  int chains;
  int i;
  for (i = 0; argc >= 3 && i < 5; i++)
    if (strcmp(argv[2], CHAIN_ENTRIES[i]) == 0) e = i;
  if (e < 0 || argc != (e < 2 ? 12 : 13)) {
    fputs("usage: replicatool chain cert_verify|rep_tip X0 .. Y3 PRE | step_apply X0 .. Y3 S PRE |\n"
          "       rep_merge|merge_tip X0 .. Y3 PREA PREB\n",
          stderr);
    return 2;
  }
  for (i = 0; i < 8; i++) {
    if (!number(argv[3 + i], &x[i])) {
      fprintf(stderr, "replicatool: '%s' is not a number\n", argv[3 + i]);
      return 2;
    }
  }
  if (e == 2) {
    if (!number(argv[11], &s)) {
      fprintf(stderr, "replicatool: '%s' is not a number\n", argv[11]);
      return 2;
    }
  }
  chains = e < 3 ? 1 : 2;
  for (i = 0; i < chains; i++) {
    steps[i] = parse_chain(argv[argc - chains + i], words[i]);
    if (steps[i] < 0) {
      fputs("replicatool: PRE is not the eval text of a CertChain\n", stderr);
      return 2;
    }
  }
  memset(&q, 0, sizeof q);
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  mem = q.mem;
  put_word(mem, 0, 0);
  for (i = 0; i < chains; i++) head[i] = put_chain(mem, &a, words[i], (unsigned)steps[i]);
  *w2c_replica_heap_base(&inst) = a;
  got = e == 0   ? w2c_replica_cert_verify(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0])
        : e == 1 ? w2c_replica_rep_tip(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0])
        : e == 2 ? w2c_replica_step_apply(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], s, head[0])
        : e == 3 ? w2c_replica_rep_merge(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0], head[1])
                 : w2c_replica_merge_tip(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0], head[1]);
  printf("%llu\n", (unsigned long long)got);
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}

#define LIST_MAX 8u
/* The words of the eval text of LIST_MAX Ballots conses, and nil. */
#define LIST_WORDS (LIST_MAX * 67u + 1u)

/* R-E12: the records of one cons of Ballots (W16, BitProof), Parts
   (DecPart, W8), KeyList (W8), Sharings (W16, W16) and Prods (DecPart, W8,
   W16; S10 H3c), and their widths in words. */
static const unsigned LIST_FIELDS[5] = {2u, 2u, 1u, 2u, 3u};
static const unsigned LIST_WIDTH[5][3] = {{16u, 48u}, {29u, 8u}, {8u, 0u}, {16u, 16u}, {29u, 8u, 16u}};

/* The words of one cons of family F in the eval text: 1, then each record
   as a tag 0 and its words. */
static unsigned cons_words(unsigned f) {
  unsigned i;
  unsigned n = 1;
  for (i = 0; i < LIST_FIELDS[f]; i++) n += 1u + LIST_WIDTH[f][i];
  return n;
}

/* The eval text P of a list of family F (the head first, nil = 0) in
   WORDS. It gives the cons count, or -1 when P is not that text. */
static int parse_list(const char *p, unsigned f, u64 words[]) {
  const char *end = NULL;
  unsigned e = cons_words(f);
  unsigned n = 0;
  unsigned c;
  unsigned i;
  unsigned at;
  int good;
  do {
    if (n == LIST_MAX * e + 1u || !decimal_word(&p, &words[n++])) return -1;
    end = p;
    if (*p == ',') p++;
  } while (*end == ',');
  good = *end == '\0' && (n - 1u) % e == 0 && words[n - 1u] == 0;
  for (c = 0; c < (n - 1u) / e; c++) {
    good &= words[e * c] == 1;
    at = e * c + 1u;
    for (i = 0; i < LIST_FIELDS[f]; i++) {
      good &= words[at] == 0;
      at += 1u + LIST_WIDTH[f][i];
    }
  }
  return good ? (int)((n - 1u) / e) : -1;
}

/* Write the COUNT conses of WORDS (family F) at *A, from the last cons:
   its record blocks (tag 0), then its cons block (tag 1, the record
   addresses, then the rest address). The rest of the last cons is nil at
   address 0. It gives the address of the head cons block (0 when COUNT is
   0) and moves *A to the next free address. */
static u64 put_list(wasm_rt_memory_t *mem, u64 *a, unsigned f, const u64 words[], unsigned count) {
  u64 at[4];
  u64 head = 0;
  unsigned e = cons_words(f);
  unsigned c;
  unsigned i;
  unsigned w;
  for (c = count; c > 0; c--) {
    w = e * (c - 1u) + 2u;
    for (i = 0; i < LIST_FIELDS[f]; i++) {
      at[i] = *a;
      *a = put_block(mem, *a, 0, words + w, LIST_WIDTH[f][i]);
      w += 1u + LIST_WIDTH[f][i];
    }
    at[i] = head;
    head = *a;
    *a = put_block(mem, *a, 1, at, LIST_FIELDS[f] + 1u);
  }
  return head;
}

/* The entries of `tally ENTRY X0 .. Y3 B P K` (H5a, R-E29). */
static const char *const TALLY_ENTRIES[4] = {"ballot_verify", "tally_sum", "partial_verify", "combine"};

/* `tally ENTRY X0 .. Y3 B P K` writes nil at address 0, then the lists B
   (Ballots), P (Parts) and K (KeyList) by put_list, below heap_base. It
   prints ENTRY of the key X0 .. Y3 in decimal (R-E12). */
static int run_tally(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  wasm_rt_memory_t *mem;
  u64 x[8];
  u64 words[3][LIST_WORDS];
  u64 head[3] = {0, 0, 0};
  u64 a = 8;
  u64 got;
  int count[3] = {0, 0, 0};
  int e = -1;
  int i;
  for (i = 0; argc >= 3 && i < 4; i++)
    if (strcmp(argv[2], TALLY_ENTRIES[i]) == 0) e = i;
  if (e < 0 || argc != 14) {
    fputs("usage: replicatool tally ballot_verify|tally_sum|partial_verify|combine X0 .. Y3 B P K\n", stderr);
    return 2;
  }
  for (i = 0; i < 8; i++) {
    if (!number(argv[3 + i], &x[i])) {
      fprintf(stderr, "replicatool: '%s' is not a number\n", argv[3 + i]);
      return 2;
    }
  }
  for (i = 0; i < 3; i++) {
    count[i] = parse_list(argv[11 + i], (unsigned)i, words[i]);
    if (count[i] < 0) {
      fputs("replicatool: B, P or K is not the eval text of its list\n", stderr);
      return 2;
    }
  }
  memset(&q, 0, sizeof q);
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  mem = q.mem;
  put_word(mem, 0, 0);
  for (i = 0; i < 3; i++) head[i] = put_list(mem, &a, (unsigned)i, words[i], (unsigned)count[i]);
  *w2c_replica_heap_base(&inst) = a;
  got = e == 0   ? w2c_replica_ballot_verify(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0], head[1], head[2])
        : e == 1 ? w2c_replica_tally_sum(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0], head[1], head[2])
        : e == 2 ? w2c_replica_partial_verify(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0], head[1], head[2])
                 : w2c_replica_combine(&inst, x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], head[0], head[1], head[2]);
  printf("%llu\n", (unsigned long long)got);
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}

/* The entries of `mpc ENTRY K B P1 P2 P3 OS` (H4, O141) and the LIST
   family of each list argument: B and OS are Sharings, P1 to P3 are Prods. */
static const char *const MPC_ENTRIES[2] = {"mpc_route", "mpc_tally"};
static const unsigned MPC_LISTS[5] = {3u, 4u, 4u, 4u, 3u};

/* `mpc ENTRY K B P1 P2 P3 OS` writes nil at address 0, then the lists B,
   P1, P2, P3 and OS by put_list, below heap_base. It prints ENTRY of the
   threshold K in decimal: the route code (mpc_route) or the outcome bit
   (mpc_tally) of the BGW tally (O141). */
static int run_mpc(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  wasm_rt_memory_t *mem;
  u64 k;
  u64 words[5][LIST_WORDS];
  u64 head[5] = {0, 0, 0, 0, 0};
  u64 a = 8;
  u64 got;
  int count[5] = {0, 0, 0, 0, 0};
  int e = -1;
  int i;
  for (i = 0; argc >= 3 && i < 2; i++)
    if (strcmp(argv[2], MPC_ENTRIES[i]) == 0) e = i;
  if (e < 0 || argc != 9) {
    fputs("usage: replicatool mpc mpc_route|mpc_tally K B P1 P2 P3 OS\n", stderr);
    return 2;
  }
  if (!number(argv[3], &k)) {
    fprintf(stderr, "replicatool: '%s' is not a number\n", argv[3]);
    return 2;
  }
  for (i = 0; i < 5; i++) {
    count[i] = parse_list(argv[4 + i], MPC_LISTS[i], words[i]);
    if (count[i] < 0) {
      fputs("replicatool: B, P1, P2, P3 or OS is not the eval text of its list\n", stderr);
      return 2;
    }
  }
  memset(&q, 0, sizeof q);
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  mem = q.mem;
  put_word(mem, 0, 0);
  for (i = 0; i < 5; i++) head[i] = put_list(mem, &a, MPC_LISTS[i], words[i], (unsigned)count[i]);
  *w2c_replica_heap_base(&inst) = a;
  got = e == 0 ? w2c_replica_mpc_route(&inst, k, head[0], head[1], head[2], head[3], head[4])
               : w2c_replica_mpc_tally(&inst, k, head[0], head[1], head[2], head[3], head[4]);
  printf("%llu\n", (unsigned long long)got);
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}

/* `decide K C` prints tally_decide of the threshold K and the count C in
   decimal: 1 when K is not 0 and K is at most C, else 0 (O141). */
static int run_decide(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  u64 x[2];
  u64 got;
  int i;
  if (argc != 4) {
    fputs("usage: replicatool decide K C\n", stderr);
    return 2;
  }
  for (i = 0; i < 2; i++) {
    if (!number(argv[2 + i], &x[i])) {
      fprintf(stderr, "replicatool: '%s' is not a number\n", argv[2 + i]);
      return 2;
    }
  }
  memset(&q, 0, sizeof q);
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  got = w2c_replica_tally_decide(&inst, x[0], x[1]);
  printf("%llu\n", (unsigned long long)got);
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}

/* H5b (R-E19): the eval text P of a Stack (1,X, for each item, the top
   first, then 0) in WORDS. It gives the item count, or -1 when P is not
   that text or has more than STACK_MAX items. */
static int parse_stack(const char *p, u64 words[]) {
  const char *end = NULL;
  unsigned n = 0;
  unsigned c;
  int good;
  do {
    if (n == 2u * STACK_MAX + 1u || !decimal_word(&p, &words[n++])) return -1;
    end = p;
    if (*p == ',') p++;
  } while (*end == ',');
  good = *end == '\0' && (n - 1u) % 2u == 0 && words[n - 1u] == 0;
  for (c = 0; c < (n - 1u) / 2u; c++) good &= words[2u * c] == 1;
  return good ? (int)((n - 1u) / 2u) : -1;
}

/* H5b (R-E19): `amend TEXT` writes the Stack of TEXT below heap_base as
   run_stack does (bottom at address 0, then a 5-word push block for each
   item), then prints amend_accept of it. */
static int run_amend(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  wasm_rt_memory_t *mem;
  u64 words[2u * STACK_MAX + 1u];
  u64 a = 8;
  u64 head = 0;
  int n = argc == 3 ? parse_stack(argv[2], words) : -1;
  int i;
  if (n < 0) {
    fprintf(stderr, "usage: replicatool amend TEXT (the eval text of a Stack, at most %u items)\n", STACK_MAX);
    return 2;
  }
  memset(&q, 0, sizeof q);
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  mem = q.mem;
  put_word(mem, 0, 0);
  for (i = n - 1; i >= 0; i--) {
    put_word(mem, a, 1);
    put_word(mem, a + 8, words[2 * i + 1]);
    put_word(mem, a + 16, 0);
    put_word(mem, a + 24, head);
    put_word(mem, a + 32, 0);
    head = a;
    a += 40;
  }
  *w2c_replica_heap_base(&inst) = a;
  printf("%llu\n", (unsigned long long)w2c_replica_amend_accept(&inst, head));
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}

/* S11 H5-d (Q-S11-30 to Q-S11-33): the 7 ivc_verify rows of
   test/replica/ivc.txt and the live round trip. A row is `ROW ivc_verify
   WANT C X0 X1 X2 X3 Y0 Y1 Y2 Y3 K Z P` (single spaces, decimal words): X0
   to Y3 are the 64 PK bytes as 8 words, Z is the eval text of an IvcZ cell
   (1,0,A0,...,A19,0,B0,...,B19,0: z0, then zk) and P is the eval text of the
   Words of the proof bytes (1,W0,...,1,WN,0). Word K is the bytes 8K to
   8K + 7, big endian, pad 0. */
#define IVC_ROW_COUNT 12u
#define IVC_ROW_GROUPS 4u
#define IVC_ROW_WORDS 1854u
#define IVC_ROW_CELLS 2079u
#define IVC_ROW_PROOF 14825u
#define IVC_ROW_LINE 65536u
#define IVC_ROW_ROOM 65536u
#define IVC_ROW_PATH 4096u

/* The data of DIR/chain.txt for the rows and the round trip: the chain PK,
   the body and the cert of step 1, and for the proofs 1, 3, 10 and 100 the
   z0, the zk, the count and the PK. */
typedef struct {
  unsigned char pk[IVC_HOST_PK_BYTES];
  unsigned char body[32];
  unsigned char cert[96];
  unsigned char z0[IVC_ROW_GROUPS][IVC_HOST_Z_BYTES];
  unsigned char zk[IVC_ROW_GROUPS][IVC_HOST_Z_BYTES];
  unsigned char gpk[IVC_ROW_GROUPS][IVC_HOST_PK_BYTES];
  u64 count[IVC_ROW_GROUPS];
} IvcChain;

/* One row: WANT, the 10 entry words C, X0 .. Y3 and K, the 40 words of Z
   (z0, then zk) and the N words of P. */
typedef struct {
  u64 want;
  u64 arg[10];
  u64 z[40];
  u64 p[IVC_ROW_CELLS];
  unsigned n;
} IvcRow;

static const u64 IVC_ROW_N[IVC_ROW_GROUPS] = {1u, 3u, 10u, 100u};

/* Read one line of F into BUF without its newline: 1, or 0 at the end of F,
   or -1 for a line without a newline (a line longer than CAP - 2 bytes, a
   NUL byte or no newline at the end of F). */
static int ivcrow_line(FILE *f, char *buf, size_t cap) {
  size_t n;
  if (fgets(buf, (int)cap, f) == NULL) return 0;
  n = strlen(buf);
  if (n == 0u || buf[n - 1u] != '\n') return -1;
  buf[n - 1u] = '\0';
  return 1;
}

static int ivcrow_get(FILE *f, char *buf, size_t cap) {
  return ivcrow_line(f, buf, cap) == 1;
}

static int ivcrow_nib(char c) {
  return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* The N bytes of the 2N lower-case hex digits at P. */
static int ivcrow_hex(const char *p, unsigned char *out, size_t n) {
  size_t i;
  int hi;
  int lo;
  for (i = 0; i < n; i++) {
    hi = ivcrow_nib(p[2u * i]);
    lo = hi < 0 ? -1 : ivcrow_nib(p[2u * i + 1u]);
    if (lo < 0) return 0;
    out[i] = (unsigned char)(hi << 4 | lo);
  }
  return 1;
}

/* LINE is NAME, then exactly 2N hex digits. */
static int ivcrow_field(const char *line, const char *name, unsigned char *out, size_t n) {
  size_t k = strlen(name);
  return strncmp(line, name, k) == 0 && ivcrow_hex(line + k, out, n) && line[k + 2u * n] == '\0';
}

/* The 5 lines of proof group G: `proof N PATH 14825`, z0, zk, count, pk. */
static int ivcrow_group(FILE *f, char *line, size_t cap, IvcChain *ch, unsigned g) {
  const char *p = line + 6;
  size_t len;
  u64 n;
  if (!ivcrow_get(f, line, cap) || strncmp(line, "proof ", 6) != 0 || !decimal_word(&p, &n) || n != IVC_ROW_N[g])
    return 0;
  len = strlen(line);
  return *p == ' ' && len >= 6u && strcmp(line + len - 6u, " 14825") == 0 && ivcrow_get(f, line, cap)
         && ivcrow_field(line, "z0 ", ch->z0[g], IVC_HOST_Z_BYTES) && ivcrow_get(f, line, cap)
         && ivcrow_field(line, "zk ", ch->zk[g], IVC_HOST_Z_BYTES) && ivcrow_get(f, line, cap)
         && strncmp(line, "count ", 6) == 0 && number(line + 6, &ch->count[g]) && ivcrow_get(f, line, cap)
         && ivcrow_field(line, "pk ", ch->gpk[g], IVC_HOST_PK_BYTES);
}

/* DIR/chain.txt (Q-S11-31 (a)): circuit ft, seed 0, steps 100, the PK, the
   100 steps, then the 4 proof groups (1, 3, 10, 100) and nothing after. */
static int ivcrow_chain(const char *dir, IvcChain *ch) {
  static char line[1024];
  char path[IVC_ROW_PATH];
  FILE *f;
  unsigned i;
  int n = snprintf(path, sizeof path, "%s/chain.txt", dir);
  int ok;
  f = n < 0 || (size_t)n >= sizeof path ? NULL : fopen(path, "rb");
  if (f == NULL) return 0;
  ok = ivcrow_get(f, line, sizeof line) && strcmp(line, "circuit ft") == 0 && ivcrow_get(f, line, sizeof line)
       && strcmp(line, "seed 0") == 0 && ivcrow_get(f, line, sizeof line) && strcmp(line, "steps 100") == 0
       && ivcrow_get(f, line, sizeof line) && ivcrow_field(line, "pk ", ch->pk, IVC_HOST_PK_BYTES)
       && ivcrow_get(f, line, sizeof line) && strncmp(line, "step 1 body ", 12) == 0
       && ivcrow_hex(line + 12, ch->body, 32u) && ivcrow_field(line + 76, " cert ", ch->cert, 96u);
  for (i = 2; ok && i <= 100u; i++) ok = ivcrow_get(f, line, sizeof line);
  for (i = 0; ok && i < IVC_ROW_GROUPS; i++) ok = ivcrow_group(f, line, sizeof line, ch, i);
  ok = ok && fgetc(f) == EOF;
  fclose(f);
  return ok;
}

/* The IVC_ROW_PROOF bytes of DIR/NAME. A shorter or a longer file gives 0. */
static int ivcrow_bin(const char *dir, const char *name, unsigned char out[IVC_ROW_PROOF]) {
  char path[IVC_ROW_PATH];
  FILE *f;
  int n = snprintf(path, sizeof path, "%s/%s", dir, name);
  int ok;
  f = n < 0 || (size_t)n >= sizeof path ? NULL : fopen(path, "rb");
  if (f == NULL) return 0;
  ok = fread(out, 1u, IVC_ROW_PROOF, f) == IVC_ROW_PROOF && fgetc(f) == EOF;
  fclose(f);
  return ok;
}

/* Word K of the LEN bytes B: the bytes 8K to 8K + 7, big endian, pad 0. */
static u64 ivcrow_be(const unsigned char *b, size_t k, size_t len) {
  u64 w = 0;
  size_t i;
  for (i = 0; i < 8u; i++) w = w << 8 | (8u * k + i < len ? (u64)b[8u * k + i] : 0u);
  return w;
}

/* Print one row: WANT, C, the 8 words of PK, COUNT, Z and P. */
static void ivcrow_print(u64 want, u64 c, const unsigned char *pk, u64 count, const unsigned char *z0,
                         const unsigned char *zk, const unsigned char *proof, unsigned proof_words) {
  unsigned k;
  printf("ROW ivc_verify %llu %llu", (unsigned long long)want, (unsigned long long)c);
  for (k = 0; k < 8u; k++) printf(" %llu", (unsigned long long)ivcrow_be(pk, k, IVC_HOST_PK_BYTES));
  printf(" %llu 1,0", (unsigned long long)count);
  for (k = 0; k < 20u; k++) printf(",%llu", (unsigned long long)ivcrow_be(z0, k, IVC_HOST_Z_BYTES));
  printf(",0");
  for (k = 0; k < 20u; k++) printf(",%llu", (unsigned long long)ivcrow_be(zk, k, IVC_HOST_Z_BYTES));
  printf(",0 ");
  for (k = 0; k < proof_words; k++) printf("1,%llu,", (unsigned long long)ivcrow_be(proof, k, IVC_ROW_PROOF));
  printf("0\n");
}

/* `ivcrows DIR` (Q-S11-31 (a), no crypto): the 12 rows from DIR/chain.txt and
   the .bin files of DIR. ivc1, ivc3, ivc10 and ivc100 (WANT 0); ivcneg (the
   proof-3 bytes and the zk of proof-10, WANT 3); ivcbad (refusal-5.bin and
   the proof-10 public input, WANT 4, Q-S11-30 (a)); ivcc2 (circuit 2 and the
   proof-1 data, WANT 5); genesis for circuits 0 and 1 (WANT 0); genesis
   with a different zk or PK (WANT 3); genesis with one proof word (WANT 1). */
static int run_ivc_rows(int argc, char **argv) {
  static IvcChain ch;
  static unsigned char bin[IVC_ROW_GROUPS + 1u][IVC_ROW_PROOF];
  static const unsigned char zero_word[8] = {0};
  unsigned char bad_pk[IVC_HOST_PK_BYTES];
  static const char *const names[IVC_ROW_GROUPS + 1u] = {"proof-1.bin", "proof-3.bin", "proof-10.bin",
                                                          "proof-100.bin", "refusal-5.bin"};
  unsigned g;
  int ok;
  if (argc != 3) {
    fputs("usage: replicatool ivcrows DIR\n", stderr);
    return 2;
  }
  ok = ivcrow_chain(argv[2], &ch);
  for (g = 0; ok && g <= IVC_ROW_GROUPS; g++) ok = ivcrow_bin(argv[2], names[g], bin[g]);
  if (!ok) {
    fprintf(stderr, "replicatool: %s is not an ivc fixture directory\n", argv[2]);
    return 1;
  }
  for (g = 0; g < IVC_ROW_GROUPS; g++)
    ivcrow_print(0u, 0u, ch.gpk[g], ch.count[g], ch.z0[g], ch.zk[g], bin[g], IVC_ROW_WORDS);
  ivcrow_print((u64)IVC_BAD_PUBLIC, 0u, ch.gpk[1], ch.count[1], ch.z0[1], ch.zk[2], bin[1], IVC_ROW_WORDS);
  ivcrow_print((u64)IVC_BAD_PROOF, 0u, ch.gpk[2], ch.count[2], ch.z0[2], ch.zk[2], bin[4], IVC_ROW_WORDS);
  ivcrow_print((u64)IVC_BAD_CIRCUIT, 2u, ch.gpk[0], ch.count[0], ch.z0[0], ch.zk[0], bin[0], IVC_ROW_WORDS);
  ivcrow_print((u64)IVC_OK, 0u, ch.pk, 0u, ch.z0[0], ch.z0[0], NULL, 0u);
  ivcrow_print((u64)IVC_OK, 1u, ch.pk, 0u, ch.z0[0], ch.z0[0], NULL, 0u);
  ivcrow_print((u64)IVC_BAD_PUBLIC, 0u, ch.pk, 0u, ch.z0[0], ch.zk[0], NULL, 0u);
  memcpy(bad_pk, ch.pk, sizeof bad_pk);
  bad_pk[IVC_HOST_PK_BYTES - 1u] ^= 1u;
  ivcrow_print((u64)IVC_BAD_PUBLIC, 0u, bad_pk, 0u, ch.z0[0], ch.z0[0], NULL, 0u);
  ivcrow_print((u64)IVC_BAD_READ, 0u, ch.pk, 0u, ch.z0[0], ch.z0[0], zero_word, 1u);
  return 0;
}

/* SEP, then a decimal word, at *S. */
static int ivcrow_word(const char **s, char sep, u64 *out) {
  if (**s != sep) return 0;
  ++*s;
  return decimal_word(s, out);
}

static int ivcrow_tag(const char **s, char sep, u64 tag) {
  u64 w;
  return ivcrow_word(s, sep, &w) && w == tag;
}

/* One row in the format above. P has at most IVC_ROW_CELLS words (as
   q_ivc_verify). */
static int ivcrow_parse(const char *s, IvcRow *r) {
  unsigned k;
  u64 tag = 0;
  int ok = strncmp(s, "ROW ivc_verify", 14) == 0;
  s += ok ? 14 : 0;
  ok = ok && ivcrow_word(&s, ' ', &r->want);
  for (k = 0; ok && k < 10u; k++) ok = ivcrow_word(&s, ' ', &r->arg[k]);
  ok = ok && ivcrow_tag(&s, ' ', 1u) && ivcrow_tag(&s, ',', 0u);
  for (k = 0; ok && k < 20u; k++) ok = ivcrow_word(&s, ',', &r->z[k]);
  ok = ok && ivcrow_tag(&s, ',', 0u);
  for (k = 20; ok && k < 40u; k++) ok = ivcrow_word(&s, ',', &r->z[k]);
  ok = ok && ivcrow_tag(&s, ',', 0u) && ivcrow_word(&s, ' ', &tag);
  for (r->n = 0; ok && tag == 1u && r->n < IVC_ROW_CELLS; r->n++)
    ok = ivcrow_word(&s, ',', &r->p[r->n]) && ivcrow_word(&s, ',', &tag);
  return ok && tag == 0u && *s == '\0';
}

/* ROW on a fresh instance: the 2 W20 blocks and the ivcZ cell of Z, then a
   wordCons cell for each word of P (noIvcZ and noWord are the nil at 0),
   below heap_base, with IVC_ROW_ROOM bytes above it. It gives the result of
   the export ivc_verify, or UINT64_MAX when the memory does not grow. */
static u64 ivcrow_run(const IvcRow *r) {
  w2c_replica inst;
  struct w2c_q q;
  wasm_rt_memory_t *mem;
  u64 need = 8u + 2u * (8u + 16u * 20u) + (8u + 16u * 3u) + (8u + 16u * 2u) * (u64)r->n + IVC_ROW_ROOM;
  u64 a = 8;
  u64 cell[3] = {0, 0, 0};
  u64 z = 0;
  u64 head = 0;
  u64 got = UINT64_MAX;
  unsigned k;
  memset(&q, 0, sizeof q);
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  mem = q.mem;
  if (mem->size < need) (void)wasm_rt_grow_memory(mem, (need - mem->size + 65535u) / 65536u);
  if (mem->size >= need) {
    put_word(mem, 0, 0);
    cell[0] = a;
    a = put_block(mem, a, 0, r->z, 20u);
    cell[1] = a;
    a = put_block(mem, a, 0, r->z + 20, 20u);
    z = a;
    a = put_block(mem, a, 1, cell, 3u);
    for (k = r->n; k > 0u; k--) {
      cell[0] = r->p[k - 1u];
      cell[1] = head;
      head = a;
      a = put_block(mem, a, 1, cell, 2u);
    }
    *w2c_replica_heap_base(&inst) = a;
    got = w2c_replica_ivc_verify(&inst, r->arg[0], r->arg[1], r->arg[2], r->arg[3], r->arg[4], r->arg[5], r->arg[6],
                                 r->arg[7], r->arg[8], r->arg[9], z, head);
  }
  wasm2c_replica_free(&inst);
  return got;
}

/* The live round trip (Q-S11-32 (a)): ivc_host_start (circuit 0, the chain
   PK, the genesis head, the z0 of proof-1), ivc_host_extend with step 1 of
   chain.txt, the 1854 held words, then the export ivc_verify with them, the
   count and the zk of proof-1 (WANT 0). It prints one line and gives the
   verdict. The held bytes against proof-1.bin are not a check. */
static u64 ivcrow_trip(const IvcChain *ch, const unsigned char *proof, IvcRow *r) {
  unsigned char head[32];
  unsigned char bad_cert[96];
  unsigned char bad_z0[IVC_HOST_Z_BYTES];
  u64 h;
  u64 h2;
  u64 v;
  unsigned k;
  int same = 1;
  ivc_host_genesis(head);
  /* The host certificate key and head must be those in the public state. */
  memcpy(bad_z0, ch->z0[0], sizeof bad_z0);
  bad_z0[IVC_HOST_Z_BYTES - 1u] ^= 1u;
  if (ivc_host_start(0u, ch->pk, head, bad_z0) != IVC_HOST_BAD_PUBLIC) {
    fprintf(stderr, "FAIL ivc start accepts a different public key\n");
    return IVC_BAD_PUBLIC;
  }
  memcpy(bad_z0, ch->z0[0], sizeof bad_z0);
  bad_z0[31] ^= 1u;
  if (ivc_host_start(0u, ch->pk, head, bad_z0) != IVC_HOST_BAD_PUBLIC) {
    fprintf(stderr, "FAIL ivc start accepts a different public head\n");
    return IVC_BAD_PUBLIC;
  }
  /* A refused certificate invalidates the run, including a guessed next
     generation. It must not leave an extra step available to resume. */
  h = ivc_host_start(0u, ch->pk, head, ch->z0[0]);
  if (h < IVC_HOST_HANDLE) return h;
  memcpy(bad_cert, ch->cert, sizeof bad_cert);
  bad_cert[0] ^= 1u;
  if (ivc_host_extend(h, ch->body, bad_cert) != IVC_HOST_CERT_REFUSED ||
      ivc_host_extend(h + 1u, ch->body, ch->cert) != IVC_HOST_STALE ||
      ivc_host_word(h + 1u, 0u) != 0u) {
    fprintf(stderr, "FAIL ivc refused certificate leaves a live run\n");
    return IVC_BAD_PROOF;
  }
  h = ivc_host_start(0u, ch->pk, head, ch->z0[0]);
  h2 = h >= IVC_HOST_HANDLE ? ivc_host_extend(h, ch->body, ch->cert) : h;
  r->want = 0u;
  r->arg[0] = 0u;
  for (k = 0; k < 8u; k++) r->arg[1u + k] = ivcrow_be(ch->pk, k, IVC_HOST_PK_BYTES);
  r->arg[9] = ch->count[0];
  for (k = 0; k < 20u; k++) r->z[k] = ivcrow_be(ch->z0[0], k, IVC_HOST_Z_BYTES);
  for (k = 0; k < 20u; k++) r->z[20u + k] = ivcrow_be(ch->zk[0], k, IVC_HOST_Z_BYTES);
  r->n = 0u;
  if (ivcrow_run(r) != IVC_BAD_READ) {
    fprintf(stderr, "FAIL ivc nonzero count accepts an empty proof\n");
    return IVC_BAD_READ;
  }
  for (k = 0; k < IVC_ROW_WORDS; k++) r->p[k] = ivc_host_word(h2, k);
  for (k = 0; k < IVC_ROW_WORDS; k++) same = same && r->p[k] == ivcrow_be(proof, k, IVC_ROW_PROOF);
  r->n = IVC_ROW_WORDS;
  v = ivcrow_run(r);
  printf("ivc round trip: start %llu, extend %llu, %u words, verify %llu (want 0), bytes = proof-1.bin: %s\n",
         (unsigned long long)h, (unsigned long long)h2, IVC_ROW_WORDS, (unsigned long long)v,
         same ? "same" : "differ");
  return v;
}

/* `ivc FILE DIR` (Q-S11-32 (a)): each row of FILE (the stdout of `ivcrows
   DIR`) on a fresh instance, one line a row and a summary, then the round
   trip. The ivc host keeps the F_t setup across them. Exit 0 only if the 12
   rows match and the round trip gives 0. */
static int run_ivc(int argc, char **argv) {
  static char line[IVC_ROW_LINE];
  static IvcRow row;
  static IvcChain ch;
  static unsigned char proof[IVC_ROW_PROOF];
  FILE *f;
  unsigned rows = 0;
  unsigned bad = 0;
  int st;
  u64 got;
  u64 v;
  if (argc != 4) {
    fputs("usage: replicatool ivc FILE DIR\n", stderr);
    return 2;
  }
  f = ivcrow_chain(argv[3], &ch) && ivcrow_bin(argv[3], "proof-1.bin", proof) ? fopen(argv[2], "rb") : NULL;
  if (f == NULL) {
    fprintf(stderr, "replicatool: cannot read %s or the ivc fixture directory %s\n", argv[2], argv[3]);
    return 1;
  }
  wasm_rt_init();
  for (st = ivcrow_line(f, line, sizeof line); st == 1 && rows < IVC_ROW_COUNT && ivcrow_parse(line, &row);
       st = ivcrow_line(f, line, sizeof line)) {
    got = ivcrow_run(&row);
    bad += (unsigned)(got != row.want);
    rows++;
    printf("row %u: got %llu, want %llu\n", rows, (unsigned long long)got, (unsigned long long)row.want);
    fflush(stdout);
  }
  fclose(f);
  if (st != 0 || rows != IVC_ROW_COUNT) {
    fprintf(stderr, "replicatool: line %u of %s is not an ivc row\n", rows + 1u, argv[2]);
    wasm_rt_free();
    return 1;
  }
  printf("ivc rows: %u cases, %u mismatches\n", rows, bad);
  fflush(stdout);
  v = ivcrow_trip(&ch, proof, &row);
  wasm_rt_free();
  return bad == 0u && v == 0u ? 0 : 1;
}

int main(int argc, char **argv) {
  w2c_replica inst;
  struct w2c_q q;
  u64 w[4];
  u64 x;
  int k;
  if (argc >= 2 && strcmp(argv[1], "stack") == 0)
    return run_stack(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "chain") == 0)
    return run_chain(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "tally") == 0)
    return run_tally(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "amend") == 0)
    return run_amend(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "mpc") == 0)
    return run_mpc(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "decide") == 0)
    return run_decide(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "ivcrows") == 0)
    return run_ivc_rows(argc, argv);
  if (argc >= 2 && strcmp(argv[1], "ivc") == 0)
    return run_ivc(argc, argv);
  if (argc != 3 || strcmp(argv[1], "hash") != 0) {
    fputs("usage: replicatool hash X | stack X1 ... XN | chain ENTRY X0 .. Y3 [S] PRE [PREB] |\n"
          "       tally ENTRY X0 .. Y3 B P K | amend TEXT | mpc ENTRY K B P1 P2 P3 OS | decide K C |\n"
          "       ivcrows DIR | ivc FILE DIR\n",
          stderr);
    return 2;
  }
  if (!number(argv[2], &x)) {
    fputs("replicatool: X is not a number\n", stderr);
    return 2;
  }
  wasm_rt_init();
  wasm2c_replica_instantiate(&inst, &q);
  q.mem = w2c_replica_memory(&inst);
  w[0] = w2c_replica_hash0(&inst, x);
  w[1] = w2c_replica_hash1(&inst, x);
  w[2] = w2c_replica_hash2(&inst, x);
  w[3] = w2c_replica_hash3(&inst, x);
  printf("%llu %llu %llu %llu ", (unsigned long long)w[0], (unsigned long long)w[1], (unsigned long long)w[2],
         (unsigned long long)w[3]);
  for (k = 0; k < 4; k++) printf("%016llx", (unsigned long long)w[k]);
  printf("\n");
  wasm2c_replica_free(&inst);
  wasm_rt_free();
  return 0;
}
