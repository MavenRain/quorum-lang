/* Host tally regressions (S6): the known answers of the src/crypto port
   (H2a), the DKG rows and the invalid-proof rows (H2b). With the argument
   `rep`, the eval lines of the representation map (H3, O80).
   Each constant has its source and a second source (Python integers and
   `cast keccak`) in a comment. */
#include <stdio.h>
#include <string.h>

#include "crypto/dkg.h"
#include "crypto/elgamal.h"
#include "crypto/keccak.h"
#include "crypto/sigma.h"
#include "crypto/threshold.h"

#define ZERO "0000000000000000000000000000000000000000000000000000000000000000"
#define ONE "0000000000000000000000000000000000000000000000000000000000000001"
#define TWO "0000000000000000000000000000000000000000000000000000000000000002"
/* The group order r of G1 (src/crypto/bn254.c BN254_FR) and r - 1. */
#define ORDER "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
#define ORDER_LESS_ONE "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"
/* p - 2 for the field prime p (src/crypto/bn254.c BN254_FP). */
#define PRIME_LESS_TWO "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"
/* 2G and 3G. The sources are at the rows in main. */
#define TWO_GX "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3"
#define TWO_GY "15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4"
#define THREE_GX "0769bf9ac56bea3ff40232bcb1b6bd159315d84715b8e679f2d355961915abf0"
#define THREE_GY "2ab799bee0489429554fdb7c8d086475319e63b40b9c5b57cdf1ff3dd9fe2261"

/* The word of the 64 hex digits HEX, the most significant digit first. */
static void word_hex(U256 *out, const char *hex) {
  uint32_t i;
  for (i = 0; i < 4u; i++)
    out->limb[i] = 0;
  for (i = 0; i < 64u; i++) {
    char c = hex[i];
    uint64_t d = c >= 'a' ? (uint64_t)(c - 'a' + 10) : (uint64_t)(c - '0');
    out->limb[3u - i / 16u] |= d << (60u - 4u * (i % 16u));
  }
}

static void word_print(const U256 *x) {
  fprintf(stderr, "%016llx%016llx%016llx%016llx", (unsigned long long)x->limb[3],
          (unsigned long long)x->limb[2], (unsigned long long)x->limb[1], (unsigned long long)x->limb[0]);
}

/* 1 when keccak256 of TEXT is the 64 hex digits WANT. */
static int hash_row(const char *name, const char *text, const char *want) {
  unsigned char digest[32];
  char got[65];
  uint32_t i;
  keccak256((const unsigned char *)text, strlen(text), digest);
  for (i = 0; i < 32u; i++)
    snprintf(got + 2u * i, 3, "%02x", digest[i]);
  if (strcmp(got, want) == 0)
    return 1;
  fprintf(stderr, "FAIL tally %s: keccak256 %s\n", name, got);
  return 0;
}

/* 1 when GOT is the word WANT. */
static int word_row(const char *name, const U256 *got, const char *want) {
  U256 w;
  word_hex(&w, want);
  if (u256_cmp(got, &w) == 0)
    return 1;
  fprintf(stderr, "FAIL tally %s: word ", name);
  word_print(got);
  fputc('\n', stderr);
  return 0;
}

/* 1 when P is on the curve and is the point (X, Y). */
static int point_row(const char *name, const G1 *p, const char *x, const char *y) {
  U256 px;
  U256 py;
  U256 wx;
  U256 wy;
  g1_to_words(&px, &py, p);
  word_hex(&wx, x);
  word_hex(&wy, y);
  if (g1_on_curve(p) && u256_cmp(&px, &wx) == 0 && u256_cmp(&py, &wy) == 0)
    return 1;
  fprintf(stderr, "FAIL tally %s: point (", name);
  word_print(&px);
  fputs(", ", stderr);
  word_print(&py);
  fputs(")\n", stderr);
  return 0;
}

/* K G for a small K. */
static void times_g(G1 *out, const G1 *g, uint64_t k) {
  U256 w;
  u256_from_u64(&w, k);
  g1_mul(out, g, &w);
}

/* The DKG of the rows: t 2 of n 3. Each open uses 8 bits. */
#define DKG_T 2u
#define DKG_N 3u
#define OPEN_BITS 8u

/* The keys of a DKG: the member shares, KEYS[j - 1] = PK_j, and PK. */
typedef struct {
  ThrShare share[DKG_N];
  G1 keys[DKG_N];
  G1 pk;
} Keys;

/* 1 when the code GOT is WANT. */
static int code_row(const char *name, int got, int want) {
  if (got == want)
    return 1;
  fprintf(stderr, "FAIL tally %s: code %d, want %d\n", name, got, want);
  return 0;
}

/* 1 when the points A and B are equal. */
static int same_row(const char *name, const G1 *a, const G1 *b) {
  if (g1_eq(a, b))
    return 1;
  fprintf(stderr, "FAIL tally %s: the points differ\n", name);
  return 0;
}

/* X + 1 mod r, for X below r. */
static void plus_one(U256 *x) {
  Fe a;
  Fe one;
  Fe sum;
  fe_from_u256(&a, x, &BN254_FR);
  fe_from_u64(&one, 1u);
  fe_add(&sum, &a, &one, &BN254_FR);
  fe_to_u256(x, &sum);
}

/* The cast of M under PK with the nonce elg_nonce(NONCE). */
static void cast(ElgCipher *out, const G1 *pk, uint64_t m, uint64_t nonce) {
  U256 wm;
  U256 r;
  u256_from_u64(&wm, m);
  elg_nonce(&r, nonce);
  elg_encrypt(out, pk, &wm, &r);
}

/* The threshold open of CT by the members A and B into M. */
static ThrResult open_pair(uint64_t *m, const Keys *keys, uint32_t a, uint32_t b, const ElgCipher *ct) {
  ThrPart parts[2];
  thr_partial(&parts[0], &keys->share[a - 1u], ct);
  thr_partial(&parts[1], &keys->share[b - 1u], ct);
  return thr_open(m, parts, 2u, keys->keys, DKG_T, DKG_N, ct, OPEN_BITS);
}

/* 1 when the threshold open of CT by the members A and B gives WANT. */
static int open_row(const char *name, const Keys *keys, uint32_t a, uint32_t b, const ElgCipher *ct, uint64_t want) {
  uint64_t m = 0;
  ThrResult res = open_pair(&m, keys, a, b, ct);
  if (res == THR_FOUND && m == want)
    return 1;
  fprintf(stderr, "FAIL tally %s: code %d, m %llu, want %llu\n", name, (int)res, (unsigned long long)m,
          (unsigned long long)want);
  return 0;
}

/* The keys of the members for QUAL: PK, sk_j from the share table, and
   PK_j from the commitments only. Each row checks PK_j = sk_j G. */
static int keys_of(const char *name, Keys *out, const DkgDealing *dealings, const U256 *table, uint32_t qual) {
  uint32_t j;
  int ok = 1;
  dkg_public(&out->pk, qual, dealings, DKG_N);
  for (j = 1u; j <= DKG_N; j++) {
    ok &= code_row(name, dkg_share(&out->share[j - 1u], qual, table, j, DKG_N), DKG_OK);
    ok &= code_row(name, dkg_key(&out->keys[j - 1u], qual, dealings, DKG_T, j, DKG_N), DKG_OK);
    ok &= same_row(name, &out->keys[j - 1u], &out->share[j - 1u].key);
  }
  return ok;
}

/* The DKG rows (O84). KEYS gets the keys of the good dealing. */
/* The good dealing: t 2 of n 3 under the context 7, the dealer i with the
   seed 100 + i. QUAL = {1, 2, 3}, and SUM is the sum of the a_{i,0}. */
static int deal_good(Keys *keys, DkgDealing *dealings, U256 *table, U256 *ctx, Fe *sum) {
  U256 seed;
  U256 w;
  Fe a0;
  Fe tmp;
  uint32_t qual = 0;
  uint32_t i;
  int ok = 1;
  u256_from_u64(ctx, 7u);
  fe_from_u64(sum, 0u);
  for (i = 1u; i <= DKG_N; i++) {
    u256_from_u64(&seed, 100u + i);
    ok &= code_row("dkg deal", dkg_deal(&dealings[i - 1u], &table[(i - 1u) * DKG_N], &seed, i, DKG_T, DKG_N, ctx), DKG_OK);
    ok &= code_row("dkg proof", dkg_check_proof(&dealings[i - 1u], i, DKG_T, ctx), 1);
    thr_nonce(&w, &seed, 0u);
    fe_from_u256(&a0, &w, &BN254_FR);
    fe_add(&tmp, sum, &a0, &BN254_FR);
    *sum = tmp;
  }
  ok &= code_row("dkg good", dkg_qual(&qual, dealings, table, DKG_T, DKG_N, ctx), DKG_OK);
  ok &= code_row("dkg good QUAL", (int)qual, 14);
  ok &= keys_of("dkg good keys", keys, dealings, table, qual);
  return ok;
}

static int dkg_rows(Keys *keys) {
  DkgDealing dealings[DKG_N];
  DkgDealing bad[DKG_N];
  U256 table[DKG_N * DKG_N];
  U256 forged[DKG_N * DKG_N];
  Keys quorum;
  ThrShare share;
  ElgCipher ct;
  U256 ctx;
  U256 w;
  Fe sum;
  G1 g;
  G1 pk;
  uint32_t qual = 0;
  /* (1) The good dealing: QUAL = {1, 2, 3}, PK = (the sum of a_{i,0}) G,
     and each pair of members opens a cast. */
  int ok = deal_good(keys, dealings, table, &ctx, &sum);
  fe_to_u256(&w, &sum);
  elg_generator(&g);
  g1_mul(&pk, &g, &w);
  ok &= same_row("dkg good PK", &keys->pk, &pk);
  cast(&ct, &keys->pk, 5u, 1u);
  ok &= open_row("dkg open {1, 2}", keys, 1u, 2u, &ct, 5u);
  ok &= open_row("dkg open {1, 3}", keys, 1u, 3u, &ct, 5u);
  ok &= open_row("dkg open {2, 3}", keys, 2u, 3u, &ct, 5u);
  /* (2) The dealer 2 sends f_2(3) + 1 to the member 3: QUAL = {1, 3}, and
     the key of QUAL decrypts. */
  memcpy(forged, table, sizeof forged);
  plus_one(&forged[DKG_N + 2u]);
  ok &= code_row("dkg bad share", dkg_qual(&qual, dealings, forged, DKG_T, DKG_N, &ctx), DKG_BAD_SHARE);
  ok &= code_row("dkg bad share QUAL", (int)qual, 10);
  ok &= keys_of("dkg bad share keys", &quorum, dealings, forged, qual);
  cast(&ct, &quorum.pk, 6u, 2u);
  ok &= open_row("dkg bad share open {1, 3}", &quorum, 1u, 3u, &ct, 6u);
  /* (3) The dealer 1 with z + 1: QUAL = {2, 3}. */
  memcpy(bad, dealings, sizeof bad);
  plus_one(&bad[0].z);
  ok &= code_row("dkg bad proof", dkg_qual(&qual, bad, table, DKG_T, DKG_N, &ctx), DKG_BAD_PROOF);
  ok &= code_row("dkg bad proof QUAL", (int)qual, 12);
  /* The member 0 and the member n + 1. */
  ok &= code_row("dkg member 0", dkg_share(&share, 14u, table, 0u, DKG_N), DKG_BAD_INDEX);
  ok &= code_row("dkg member n + 1", dkg_share(&share, 14u, table, DKG_N + 1u, DKG_N), DKG_BAD_INDEX);
  /* Each dealing is bad: QUAL is empty. */
  plus_one(&bad[1].z);
  plus_one(&bad[2].z);
  ok &= code_row("dkg too few", dkg_qual(&qual, bad, table, DKG_T, DKG_N, &ctx), DKG_TOO_FEW);
  ok &= code_row("dkg too few QUAL", (int)qual, 0);
  return ok;
}

/* The result of sig_onehot_verify on a ballot of K slots with the bits
   BITS and the nonces elg_nonce(20 + j): each slot has its valid bit
   proof, and the sum has a proof of randomness for m = 1 (a forged ballot
   when the bits do not sum to 1). */
static SigResult forged_ballot(const G1 *pk, const uint32_t *bits, uint32_t k, const U256 *ctx) {
  ElgCipher cts[SIG_K_MAX];
  SigOr slots[SIG_K_MAX];
  SigDleq sum;
  ElgCipher total;
  U256 r;
  U256 m;
  Fe rsum;
  Fe fr;
  Fe tmp;
  uint32_t j;
  fe_from_u64(&rsum, 0u);
  for (j = 0; j < k; j++) {
    elg_nonce(&r, 20u + j);
    u256_from_u64(&m, bits[j]);
    elg_encrypt(&cts[j], pk, &m, &r);
    sig_or_prove(&slots[j], pk, &cts[j], bits[j], &r, ctx, j);
    fe_from_u256(&fr, &r, &BN254_FR);
    fe_add(&tmp, &rsum, &fr, &BN254_FR);
    rsum = tmp;
  }
  total = cts[0];
  for (j = 1u; j < k; j++)
    elg_add(&total, &total, &cts[j]);
  fe_to_u256(&r, &rsum);
  u256_from_u64(&m, 1u);
  sig_rand_prove(&sum, pk, &total, &m, &r, ctx);
  return sig_onehot_verify(cts, slots, &sum, pk, k, ctx);
}

/* The invalid-proof rows and the good rows (O83), under the keys of the
   good dealing. */
static int proof_rows(const Keys *keys) {
  static const uint32_t two_hot[2] = {1u, 1u};
  static const uint32_t all_zero[2] = {0u, 0u};
  ElgCipher cts[SIG_K_MAX];
  ElgCipher moved[SIG_K_MAX];
  ElgCipher tally[SIG_K_MAX];
  SigOr slots[SIG_K_MAX];
  SigOr forged[SIG_K_MAX];
  SigOr sim;
  SigDleq sum;
  ThrPart parts[2];
  ElgCipher ct;
  U256 ctx;
  U256 other;
  U256 seed;
  U256 m0;
  U256 m1;
  G1 g;
  G1 two;
  G1 y0;
  G1 y1;
  uint64_t m = 0;
  int ok = 1;
  u256_from_u64(&ctx, 7u);
  u256_from_u64(&other, 8u);
  elg_generator(&g);
  /* (1) A slot with plaintext 2 and a simulated OR proof: no branch is
     real, so the split fails. */
  cast(&ct, &keys->pk, 2u, 30u);
  u256_from_u64(&m0, 0u);
  u256_from_u64(&m1, 1u);
  sig_plain(&y0, &ct, &m0);
  sig_plain(&y1, &ct, &m1);
  u256_from_u64(&sim.e0, 3u);
  u256_from_u64(&sim.z0, 4u);
  u256_from_u64(&sim.e1, 5u);
  u256_from_u64(&sim.z1, 6u);
  sig_simulate(&sim.a0, &sim.b0, &keys->pk, &ct.c1, &y0, &sim.e0, &sim.z0);
  sig_simulate(&sim.a1, &sim.b1, &keys->pk, &ct.c1, &y1, &sim.e1, &sim.z1);
  ok &= code_row("plaintext 2", sig_or_verify(&sim, &keys->pk, &ct, &ctx, 0u), SIG_BAD_SLOT);
  /* (2) A two-hot ballot and (3) an all-zero ballot: each bit proof is
     valid, and the sum proof fails. */
  ok &= code_row("two-hot", forged_ballot(&keys->pk, two_hot, 2u, &ctx), SIG_BAD_SUM);
  ok &= code_row("all-zero", forged_ballot(&keys->pk, all_zero, 2u, &ctx), SIG_BAD_SUM);
  /* The good row k 2: the ballot for the choice 1 verifies. */
  u256_from_u64(&seed, 40u);
  ok &= code_row("one-hot k 2 prove", sig_onehot_prove(cts, slots, &sum, &keys->pk, 2u, 1u, &seed, &ctx), SIG_OK);
  ok &= code_row("one-hot k 2", sig_onehot_verify(cts, slots, &sum, &keys->pk, 2u, &ctx), SIG_OK);
  /* (4) A forged split: e0 + e1 != e. */
  memcpy(forged, slots, sizeof forged);
  forged[0].e0.limb[0] ^= 1u;
  ok &= code_row("forged split", sig_onehot_verify(cts, forged, &sum, &keys->pk, 2u, &ctx), SIG_BAD_SLOT);
  /* (5) Each slot (with its bit proof) at the other slot index j. */
  moved[0] = cts[1];
  moved[1] = cts[0];
  forged[0] = slots[1];
  forged[1] = slots[0];
  ok &= code_row("slot moved", sig_onehot_verify(moved, forged, &sum, &keys->pk, 2u, &ctx), SIG_BAD_SLOT);
  /* (6) The valid ballot under another ctx: the points are on the curve,
     so the first bit proof fails (CTX is in its challenge). */
  ok &= code_row("other ctx", sig_onehot_verify(cts, slots, &sum, &keys->pk, 2u, &other), SIG_BAD_SLOT);
  /* The tally of the k 2 ballot with itself, slot by slot: the slot 0
     opens to 0 and the slot 1 to 2. */
  memset(tally, 0, sizeof tally);
  tally_add(tally, cts, cts, 2u);
  ok &= open_row("tally k 2 slot 0", keys, 1u, 2u, &tally[0], 0u);
  ok &= open_row("tally k 2 slot 1", keys, 1u, 2u, &tally[1], 2u);
  /* The good row k 4: the ballot for the choice 2 verifies, and each open
     is the count. */
  u256_from_u64(&seed, 41u);
  ok &= code_row("one-hot k 4 prove", sig_onehot_prove(cts, slots, &sum, &keys->pk, 4u, 2u, &seed, &ctx), SIG_OK);
  ok &= code_row("one-hot k 4", sig_onehot_verify(cts, slots, &sum, &keys->pk, 4u, &ctx), SIG_OK);
  ok &= open_row("k 4 slot 2", keys, 2u, 3u, &cts[2], 1u);
  ok &= open_row("k 4 slot 3", keys, 2u, 3u, &cts[3], 0u);
  /* (7) A part with D + G and (8) a part with z + 1: the DLEQ check
     refuses each. */
  cast(&ct, &keys->pk, 3u, 31u);
  thr_partial(&parts[0], &keys->share[0], &ct);
  thr_partial(&parts[1], &keys->share[1], &ct);
  g1_add(&parts[0].d, &parts[0].d, &g);
  ok &= code_row("part D + G", thr_open(&m, parts, 2u, keys->keys, DKG_T, DKG_N, &ct, OPEN_BITS), THR_BAD_PROOF);
  thr_partial(&parts[0], &keys->share[0], &ct);
  plus_one(&parts[1].z);
  ok &= code_row("part z + 1", thr_open(&m, parts, 2u, keys->keys, DKG_T, DKG_N, &ct, OPEN_BITS), THR_BAD_PROOF);
  /* (9) An off-curve C1: (1, the y of 2G). */
  g1_add(&two, &g, &g);
  ct.c1 = g;
  ct.c1.y = two.y;
  ok &= code_row("off-curve C1", thr_open(&m, parts, 2u, keys->keys, DKG_T, DKG_N, &ct, OPEN_BITS), THR_REFUSED);
  return ok;
}

/* The ballot I of the case C of length LEN: the bit LEN - 1 - I of C. */
static uint32_t ballot_of(uint32_t c, uint32_t len, uint32_t i) {
  return (c >> (len - 1u - i)) & 1u;
}

/* The rep mode (O80): the good dealing, then for each ballot list over Bool
   of length 1 to 3 (14 cases), the cast of each ballot (Enc(1) at the slot
   of the ballot, Enc(0) at the other slot), the sum slot by slot
   (tally_add), and the open of each slot by the members 1 and 2. Each line
   is an eval line of the entry denCountLEN of examples/denote.lang:
   `denote denCountLEN J B1 .. BLEN => COUNT` (28 lines). */
static int rep_lines(void) {
  DkgDealing dealings[DKG_N];
  U256 table[DKG_N * DKG_N];
  Keys keys;
  ElgCipher sum[2];
  ElgCipher ballot[2];
  ElgCipher next[2];
  U256 ctx;
  Fe a0;
  uint64_t nonce = 1000u;
  uint64_t count;
  uint32_t len;
  uint32_t c;
  uint32_t i;
  uint32_t j;
  ThrResult res;
  int ok = deal_good(&keys, dealings, table, &ctx, &a0);
  for (len = 1u; len <= 3u; len++) {
    for (c = 0; c < (1u << len); c++) {
      for (i = 0; i < len; i++) {
        for (j = 0; j < 2u; j++)
          cast(&ballot[j], &keys.pk, ballot_of(c, len, i) == j, nonce++);
        if (i == 0) {
          memcpy(sum, ballot, sizeof sum);
        } else {
          /* NEXT is zero first, so a skipped slot opens to 0. */
          memset(next, 0, sizeof next);
          tally_add(next, sum, ballot, 2u);
          memcpy(sum, next, sizeof sum);
        }
      }
      for (j = 0; j < 2u; j++) {
        count = 0;
        res = open_pair(&count, &keys, 1u, 2u, &sum[j]);
        printf("denote denCount%u %u", len, j);
        for (i = 0; i < len; i++)
          printf(" %u", ballot_of(c, len, i));
        if (res == THR_FOUND)
          printf(" => %llu\n", (unsigned long long)count);
        else
          printf(" => open-%d\n", (int)res);
        ok &= code_row("rep open", (int)res, THR_FOUND);
      }
    }
  }
  return ok ? 0 : 1;
}

int main(int argc, char **argv) {
  G1 g;
  G1 two;
  G1 p;
  U256 k;
  Keys keys;
  if (argc == 2 && strcmp(argv[1], "rep") == 0)
    return rep_lines();
  if (argc != 1) {
    fputs("usage: tallytool [rep]\n", stderr);
    return 2;
  }
  elg_generator(&g);
  /* Ethereum Keccak (not SHA3). Second source: cast keccak '' and 'abc'. */
  int ok = hash_row("keccak empty", "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  ok &= hash_row("keccak abc", "abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  /* G = (1, 2) (EIP-196). */
  ok &= point_row("G", &g, ONE, TWO);
  /* 2G: intent-lang test/eval/expect.txt:53 (decimal) and test/precompile.sh:51-52
     (hex). Second source: Python affine double of (1, 2). */
  g1_add(&two, &g, &g);
  ok &= point_row("G + G", &two, TWO_GX, TWO_GY);
  g1_double(&p, &g);
  ok &= point_row("double G", &p, TWO_GX, TWO_GY);
  times_g(&p, &g, 2u);
  ok &= point_row("2 G", &p, TWO_GX, TWO_GY);
  /* 3G: intent-lang test/eval/expect.txt:60 (decimal). Second source: Python. */
  g1_add(&p, &two, &g);
  ok &= point_row("2G + G", &p, THREE_GX, THREE_GY);
  times_g(&p, &g, 3u);
  ok &= point_row("3 G", &p, THREE_GX, THREE_GY);
  /* r G = (0, 0), the point at infinity, and (r - 1) G = -G = (1, p - 2):
     exact by the group order. Second source: Python. */
  word_hex(&k, ORDER);
  g1_mul(&p, &g, &k);
  ok &= point_row("r G", &p, ZERO, ZERO);
  word_hex(&k, ORDER_LESS_ONE);
  g1_mul(&p, &g, &k);
  ok &= point_row("(r - 1) G", &p, ONE, PRIME_LESS_TWO);
  /* scalar_reduce: r gives 0, and 2^256 - 1 gives (2^256 - 1) mod r
     (Python). */
  word_hex(&k, ORDER);
  scalar_reduce(&k, &k);
  ok &= word_row("reduce r", &k, ZERO);
  word_hex(&k, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
  scalar_reduce(&k, &k);
  ok &= word_row("reduce 2^256 - 1", &k, "0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffa");
  /* elg_nonce(1) = keccak256(ELG_TAG word, word 1) mod r (Python with cast
     keccak), and C1 = elg_nonce(1) G: intent-lang test/precompile.sh:110-111.
     Second source: Python. */
  elg_nonce(&k, 1u);
  ok &= word_row("nonce 1", &k, "2c624b94b15b5d6b3f60a38a41d472fb1e3a20b411c167aa289cf048b9e4253a");
  g1_mul(&p, &g, &k);
  ok &= point_row("C1", &p, "06107e6b6511db3eb78edf5b81e309c1ce2d43ffc1f99878add70ec94232f5bd",
                  "0c417387621eb1e2f78895cafc1ba63b3141ad838c1718913898a716e2513dcc");
  ok &= dkg_rows(&keys);
  ok &= proof_rows(&keys);
  if (ok) puts("tally regressions: passed");
  return ok ? 0 : 1;
}
