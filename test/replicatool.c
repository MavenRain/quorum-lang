/* The replica host of S8 (O104, O105). It runs build/replica.wasm through
   the wasm2c translation build/replica.c, and it gives the 6 imports of
   module "q". q_hash2 (H2b) and q_frost_verify (H3) have a body, and H5a
   gives the other 4 imports a body (R-E12).

   Usage: replicatool hash X. It prints the 4 words of
   q_hash2 (w4 X X X X) (w4 X X X X) (the entries hash0 to hash3 of
   replica/replica.lang) in decimal, then the 32 digest bytes in hex.
   replicatool stack X1 ... XN: see run_stack. replicatool chain ENTRY X0 ..
   Y3 PRE (H3), or S PRE, or PREA PREB (H4): see run_chain. replicatool
   tally ENTRY X0 .. Y3 B P K (H5a): see run_tally. replicatool amend
   TEXT (H5b): see run_amend. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/elgamal.h"
#include "crypto/frost.h"
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
   (DecPart, W8) and KeyList (W8), and their widths in words. */
static const unsigned LIST_FIELDS[3] = {2u, 2u, 1u};
static const unsigned LIST_WIDTH[3][2] = {{16u, 48u}, {29u, 8u}, {8u, 0u}};

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
  u64 at[3];
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
  if (argc != 3 || strcmp(argv[1], "hash") != 0) {
    fputs("usage: replicatool hash X | stack X1 ... XN | chain ENTRY X0 .. Y3 [S] PRE [PREB] |\n"
          "       tally ENTRY X0 .. Y3 B P K | amend TEXT\n",
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
