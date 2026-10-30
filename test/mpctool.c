/* NEW (quorum-lang S10 H2, O137 to O140, O143; H4, O141): host BGW
   regressions of src/crypto/bgw.c, and the generator of
   test/replica/mpc.txt. Each row group has its decision in a comment. The
   rows that kill the three S10 mutants of O143 name the mutant. The values
   are small, and the comments give the arithmetic. With no argument,
   mpctool runs the regressions. `mpctool lang` writes the lines of
   test/replica/mpc.txt (O141). */
#include <stdio.h>
#include <string.h>

#include "crypto/bgw.h"

/* The committee of S8: x = 1, 2, 3 (t' = 1 corrupt member). */
#define MEMBERS 3u

/* A sharing: the dealing and the share of each member. */
typedef struct {
  DkgDealing d;
  U256 s[MEMBERS];
} Sharing;

static int row(const char *name, int good) {
  if (!good) {
    fprintf(stderr, "FAIL bgw %s\n", name);
  }
  return good;
}

/* The sharing of SECRET + SLOPE x. */
static void share(Sharing *out, uint64_t secret, uint64_t slope) {
  U256 a0;
  U256 a1;
  u256_from_u64(&a0, secret);
  u256_from_u64(&a1, slope);
  bgw_deal(&out->d, out->s, &a0, &a1, MEMBERS);
}

/* -V mod r. */
static void minus(U256 *out, uint64_t v) {
  Fe a;
  Fe neg;
  fe_from_u64(&a, v);
  fe_neg(&neg, &a, &BN254_FR);
  fe_to_u256(out, &neg);
}

/* 1 when the open of SH by the members X1 and X2 gives WANT. */
static int opens(const Sharing *sh, uint32_t x1, uint32_t x2, uint64_t want) {
  uint32_t xs[2];
  U256 ss[2];
  U256 out;
  U256 w;
  xs[0] = x1;
  xs[1] = x2;
  ss[0] = sh->s[x1 - 1u];
  ss[1] = sh->s[x2 - 1u];
  u256_from_u64(&w, want);
  return bgw_open(&out, &sh->d, xs, ss, 2u, MEMBERS) == BGW_OK && u256_cmp(&out, &w) == 0;
}

/* 1 when each share of SH checks. */
static int all_check(const Sharing *sh) {
  uint32_t j;
  int good = 1;
  for (j = 1; j <= MEMBERS; j++) {
    good &= bgw_check(&sh->d, j, &sh->s[j - 1u]);
  }
  return good;
}

/* The products of A and B of all members, with the reshare coefficient
   RHO + i - 1 for the member i: PRODS[i - 1], SUB[i - 1][j - 1] = s_ij. */
static void products(BgwProduct *prods, U256 sub[MEMBERS][MEMBERS], const Sharing *a, const Sharing *b, uint64_t rho) {
  U256 r;
  uint32_t i;
  for (i = 0; i < MEMBERS; i++) {
    u256_from_u64(&r, rho + i);
    bgw_product(&prods[i], sub[i], &a->d, &b->d, i + 1u, &a->s[i], &b->s[i], &r, MEMBERS);
  }
}

/* COL[i - 1] = s_ij for i = 1 to 3: the sub-shares of the member J. */
static void column(U256 *col, U256 sub[MEMBERS][MEMBERS], uint32_t j) {
  uint32_t i;
  for (i = 0; i < MEMBERS; i++) {
    col[i] = sub[i][j - 1u];
  }
}

/* The BGW multiply (O138) of A and B into OUT. */
static BgwResult mul(Sharing *out, const Sharing *a, const Sharing *b, uint64_t rho) {
  BgwProduct prods[MEMBERS];
  U256 sub[MEMBERS][MEMBERS];
  U256 col[MEMBERS];
  BgwResult res = BGW_OK;
  uint32_t j;
  memset(out, 0, sizeof *out);
  products(prods, sub, a, b, rho);
  for (j = 1; j <= MEMBERS && res == BGW_OK; j++) {
    column(col, sub, j);
    res = bgw_reduce(&out->s[j - 1u], prods, col, &a->d, &b->d, j, MEMBERS);
  }
  return res == BGW_OK ? bgw_reduce_commit(&out->d, prods, MEMBERS) : res;
}

/* O137: the dealing of 7 + 11 x (the shares 18, 29, 40). */
static int deal_rows(void) {
  Sharing a;
  U256 bad;
  int ok = 1;
  share(&a, 7u, 11u);
  ok &= row("deal and check", all_check(&a));
  bad = a.s[1];
  bad.limb[0] ^= 1u;
  ok &= row("a bad share rejects", !bgw_check(&a.d, 2u, &bad));
  ok &= row("the share of member 2 at member 3 rejects", !bgw_check(&a.d, 3u, &a.s[1]));
  ok &= row("deal opens to the secret", opens(&a, 1u, 2u, 7u));
  return ok;
}

/* O137: the local add of the ballots 1, 1, 0 (the sum 2). Mutant 1 (a share
   dropped from the local sum) fails both rows: the sum of 2 shares does not
   check against the sum of the 3 dealings. */
static int add_rows(void) {
  Sharing b[3];
  Sharing sum;
  DkgDealing ds[3];
  U256 col[3];
  uint32_t i;
  uint32_t j;
  int ok = 1;
  share(&b[0], 1u, 5u);
  share(&b[1], 1u, 9u);
  share(&b[2], 0u, 13u);
  for (j = 0; j < MEMBERS; j++) {
    for (i = 0; i < 3u; i++) {
      col[i] = b[i].s[j];
    }
    bgw_sum(&sum.s[j], col, 3u);
  }
  for (i = 0; i < 3u; i++) {
    ds[i] = b[i].d;
  }
  bgw_sum_commit(&sum.d, ds, 3u);
  ok &= row("mutant 1: each sum share checks", all_check(&sum));
  ok &= row("mutant 1: add opens to the sum", opens(&sum, 1u, 2u, 2u) && opens(&sum, 2u, 3u, 2u));
  return ok;
}

/* O138: the multiply of 3 + 4 x and 5 + 6 x opens to 15 at each pair. */
static int mul_rows(void) {
  Sharing a;
  Sharing b;
  Sharing c;
  int ok = 1;
  share(&a, 3u, 4u);
  share(&b, 5u, 6u);
  ok &= row("multiply runs", mul(&c, &a, &b, 21u) == BGW_OK);
  ok &= row("multiply: each output share checks", all_check(&c));
  ok &= row("multiply opens to the product",
            opens(&c, 1u, 2u, 15u) && opens(&c, 1u, 3u, 15u) && opens(&c, 2u, 3u, 15u));
  return ok;
}

/* O140 (Q-S10-3 (a)): the bit check b (b - 1), with b - 1 from the public
   affine map (w 1, k -1). It opens to 0 for b in {0, 1}, and to 20, not 0,
   for the ballot 5. */
static int bit_row(const char *name, uint64_t bit, uint64_t want) {
  Sharing b;
  Sharing bm;
  Sharing c;
  U256 one;
  U256 m1;
  uint32_t j;
  share(&b, bit, 17u);
  u256_from_u64(&one, 1u);
  minus(&m1, 1u);
  for (j = 0; j < MEMBERS; j++) {
    bgw_affine(&bm.s[j], &b.s[j], &one, &m1);
  }
  bgw_affine_commit(&bm.d, &b.d, &one, &m1);
  return row(name, all_check(&bm) && mul(&c, &b, &bm, 31u) == BGW_OK && opens(&c, 1u, 3u, want));
}

/* O139: the open. Mutant 2 (a wrong lambda index at the open) fails the
   first row: at the members 1 and 2, lambda = (2, -1), and the mutant takes
   2 for each. Mutant 3 (the output check off) fails the second row. */
static int open_rows(void) {
  Sharing a;
  Sharing b;
  Sharing c;
  uint32_t xs[2];
  U256 ss[2];
  U256 out;
  int ok = 1;
  share(&a, 7u, 11u);
  ok &= row("mutant 2: open at each pair of members",
            opens(&a, 1u, 2u, 7u) && opens(&a, 2u, 1u, 7u) && opens(&a, 1u, 3u, 7u) && opens(&a, 2u, 3u, 7u));
  share(&a, 3u, 4u);
  share(&b, 5u, 6u);
  mul(&c, &a, &b, 21u);
  xs[0] = 1u;
  xs[1] = 2u;
  ss[0] = c.s[0];
  ss[1] = c.s[1];
  ss[1].limb[0] ^= 1u;
  ok &= row("mutant 3: open with a bad output share rejects",
            bgw_open(&out, &c.d, xs, ss, 2u, MEMBERS) == BGW_BAD_SHARE);
  return ok;
}

/* O138 (Q-S10-4 (b)): the product proofs and the reshare checks. The shares
   of member 2 are a_2 = 11 and b_2 = 17. */
static int proof_rows(void) {
  Sharing a;
  Sharing b;
  BgwProduct prods[MEMBERS];
  BgwProduct bad;
  U256 sub[MEMBERS][MEMBERS];
  U256 badsub[MEMBERS];
  U256 col[MEMBERS];
  U256 off;
  U256 r;
  U256 out;
  int ok = 1;
  share(&a, 3u, 4u);
  share(&b, 5u, 6u);
  products(prods, sub, &a, &b, 21u);
  ok &= row("the product of each member checks", bgw_product_check(&prods[0], &a.d, &b.d, 1u, MEMBERS) == BGW_OK &&
                                                     bgw_product_check(&prods[1], &a.d, &b.d, 2u, MEMBERS) == BGW_OK &&
                                                     bgw_product_check(&prods[2], &a.d, &b.d, 3u, MEMBERS) == BGW_OK);
  bad = prods[1];
  bad.proof.z.limb[0] ^= 1u;
  ok &= row("a bad product proof rejects", bgw_product_check(&bad, &a.d, &b.d, 2u, MEMBERS) == BGW_BAD_PROOF);
  ok &= row("a product proof at the wrong member rejects",
            bgw_product_check(&prods[1], &a.d, &b.d, 3u, MEMBERS) == BGW_BAD_INDEX);
  /* Member 2 reshares 11 x 16: the proof holds, but the reshare C[0] is
     not D_2. */
  u256_from_u64(&r, 22u);
  off = b.s[1];
  off.limb[0] ^= 1u;
  bgw_product(&bad, badsub, &a.d, &b.d, 2u, &a.s[1], &off, &r, MEMBERS);
  ok &= row("a reshare of a wrong product rejects", bgw_product_check(&bad, &a.d, &b.d, 2u, MEMBERS) == BGW_BAD_PROOF);
  /* Member 2 uses the share 10, not the share 11 of A: the proof fails. */
  off = a.s[1];
  off.limb[0] ^= 1u;
  bgw_product(&bad, badsub, &a.d, &b.d, 2u, &off, &b.s[1], &r, MEMBERS);
  ok &= row("a product of a share off its dealing rejects",
            bgw_product_check(&bad, &a.d, &b.d, 2u, MEMBERS) == BGW_BAD_PROOF);
  /* The reduce at member 1: a bad proof of member 2, then a bad sub-share
     of member 2. */
  column(col, sub, 1u);
  prods[1].proof.z.limb[0] ^= 1u;
  ok &= row("the reduce rejects a bad product proof",
            bgw_reduce(&out, prods, col, &a.d, &b.d, 1u, MEMBERS) == BGW_BAD_PROOF);
  prods[1].proof.z.limb[0] ^= 1u;
  col[1].limb[0] ^= 1u;
  ok &= row("the reduce rejects a bad sub-share", bgw_reduce(&out, prods, col, &a.d, &b.d, 1u, MEMBERS) == BGW_BAD_SHARE);
  return ok;
}

/* The index refusals of bgw_open and bgw_product. */
static int index_rows(void) {
  Sharing a;
  BgwProduct prod;
  U256 sub[MEMBERS];
  U256 ss[2];
  U256 out;
  U256 r;
  uint32_t xs[2];
  int ok = 1;
  share(&a, 7u, 11u);
  xs[0] = 2u;
  xs[1] = 2u;
  ss[0] = a.s[1];
  ss[1] = a.s[1];
  ok &= row("open with a repeated member rejects", bgw_open(&out, &a.d, xs, ss, 2u, MEMBERS) == BGW_BAD_INDEX);
  xs[0] = 0u;
  ok &= row("open with member 0 rejects", bgw_open(&out, &a.d, xs, ss, 2u, MEMBERS) == BGW_BAD_INDEX);
  xs[0] = 4u;
  ok &= row("open with member 4 of 3 rejects", bgw_open(&out, &a.d, xs, ss, 2u, MEMBERS) == BGW_BAD_INDEX);
  xs[0] = 1u;
  ss[0] = a.s[0];
  ok &= row("open with 1 share rejects", bgw_open(&out, &a.d, xs, ss, 1u, MEMBERS) == BGW_BAD_INDEX);
  u256_from_u64(&r, 1u);
  ok &= row("multiply with 2 members rejects",
            bgw_product(&prod, sub, &a.d, &a.d, 1u, &a.s[0], &a.s[0], &r, 2u) == BGW_BAD_INDEX);
  return ok;
}

/* H4 (O141, Q-S10-2 (b)): `mpctool lang` writes the lines of
   test/replica/mpc.txt: ROW ENTRY WANT K B P1 P2 P3 OS (B, P1 to P3 and OS
   are list texts, the input_value form: a cell is the tag 1, then each
   field; a record field is 0, then its words; nil is 0). The row mcV_C_K
   has the V ballot bits of the tally.txt row tcV_C (the first ballot is the
   high bit) and the public k = K. Its WANT is the mpc_tally outcome: 1 when
   the count is K or more. The route rows (the partial_verify model) take
   the ballots 1, 1, 0 and k 2. The steps are the steps of the guest terms
   in replica.lang. */
#define LANG_BALLOTS 3u
#define LANG_STEPS 5u
#define LANG_CELL 53u

/* The words of mpcW0 to mpcW3 (replica.lang) for the index 0 to 10. */
static const uint64_t LANG_COEF[11][4] = {
    {0ULL, 0ULL, 0ULL, 0ULL},
    {0ULL, 0ULL, 0ULL, 1ULL},
    {3486998266802970665ULL, 13281191951274694749ULL, 2896914383306846353ULL, 4891460686036598784ULL},
    {1743499133401485332ULL, 15863968012492123182ULL, 10671829228508198984ULL, 11669102379873075201ULL},
    {1743499133401485332ULL, 15863968012492123182ULL, 10671829228508198984ULL, 11669102379873075200ULL},
    {1743499133401485332ULL, 15863968012492123182ULL, 10671829228508198984ULL, 11669102379873075202ULL},
    {2905831889002475554ULL, 14142117305013837560ULL, 5488552665040630563ULL, 13299589275218608129ULL},
    {581166377800495110ULL, 17585818719970408804ULL, 15855105791975767405ULL, 10038615484527542274ULL},
    {581166377800495110ULL, 17585818719970408804ULL, 15855105791975767405ULL, 10038615484527542271ULL},
    {2324665511201980443ULL, 15003042658752980371ULL, 8080190946774414774ULL, 3260973790691065857ULL},
    {1162332755600990221ULL, 16724893366231265993ULL, 13263467510241983195ULL, 1630486895345532928ULL},
};

/* mpcCoefIx v k e (replica.lang) for v and k 1 to 3, e 0 to 3. */
static const uint32_t LANG_COEF_IX[4][4][4] = {
    {{0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u}},
    {{0u, 0u, 0u, 0u}, {0u, 1u, 0u, 0u}, {0u, 0u, 0u, 0u}, {0u, 0u, 0u, 0u}},
    {{0u, 0u, 0u, 0u}, {0u, 5u, 4u, 0u}, {0u, 4u, 3u, 0u}, {0u, 0u, 0u, 0u}},
    {{0u, 0u, 0u, 0u}, {0u, 7u, 2u, 6u}, {0u, 8u, 5u, 10u}, {0u, 9u, 4u, 6u}},
};

/* The word that a reject row sets off (O141). */
typedef enum { LANG_GOOD, LANG_BAD_IN, LANG_BAD_PROOF, LANG_BAD_OUT } LangBad;

/* The N words at BE, each 8 bytes big endian. */
static void lang_words(uint64_t *w, const unsigned char *be, uint32_t n) {
  uint32_t i;
  uint32_t k;
  for (i = 0; i < n; i++) {
    w[i] = 0;
    for (k = 0; k < 8u; k++) {
      w[i] = w[i] << 8 | be[8u * i + k];
    }
  }
}

static void lang_coef(U256 *out, uint32_t ix) {
  unsigned char be[32];
  uint32_t i;
  uint32_t k;
  for (i = 0; i < 4u; i++) {
    for (k = 0; k < 8u; k++) {
      be[8u * i + k] = (unsigned char)(LANG_COEF[ix][i] >> (56u - 8u * k));
    }
  }
  u256_from_be(out, be);
}

static void lang_print(const uint64_t *w, uint32_t n) {
  uint32_t i;
  for (i = 0; i < n; i++) {
    printf("%llu,", (unsigned long long)w[i]);
  }
}

/* The dealing D as 128 bytes: C[0], then C[1]. */
static void lang_dealing_be(unsigned char *be, const DkgDealing *d) {
  g1_to_be(be, &d->c[0]);
  g1_to_be(be + 64, &d->c[1]);
}

/* One Sharings cell: the tag 1, the dealing DEALING (16 words), then the
   share list of S (16 words: the member j in the words 4 j - 4 to 4 j - 1,
   the slot 4 zero). */
static void lang_sharing(const unsigned char *dealing, const U256 *s) {
  unsigned char be[128];
  uint64_t w[16];
  uint32_t j;
  lang_words(w, dealing, 16u);
  printf("1,0,");
  lang_print(w, 16u);
  memset(be, 0, sizeof be);
  for (j = 0; j < MEMBERS; j++) {
    u256_to_be(be + 32u * j, &s[j]);
  }
  lang_words(w, be, 16u);
  printf("0,");
  lang_print(w, 16u);
}

/* The Prods cell of the member I (53 words, bgw.h :105): x = I, d, a, b, z,
   the reshare C[1], then the sub-shares SUB as a share list. */
static void lang_cell(uint64_t *w, const BgwProduct *p, const U256 *sub, uint32_t i) {
  unsigned char be[8u * LANG_CELL];
  uint32_t j;
  memset(be, 0, sizeof be);
  be[7] = (unsigned char)i;
  g1_to_be(be + 8, &p->proof.d);
  g1_to_be(be + 72, &p->proof.a);
  g1_to_be(be + 136, &p->proof.b);
  u256_to_be(be + 200, &p->proof.z);
  g1_to_be(be + 232, &p->reshare.c[1]);
  for (j = 0; j < MEMBERS; j++) {
    u256_to_be(be + 296 + 32u * j, &sub[j]);
  }
  lang_words(w, be, LANG_CELL);
}

/* The public affine map W s + K of A (q_mpc_affine). */
static void lang_affine(Sharing *out, const Sharing *a, const U256 *w, const U256 *k) {
  uint32_t j;
  for (j = 0; j < MEMBERS; j++) {
    bgw_affine(&out->s[j], &a->s[j], w, k);
  }
  bgw_affine_commit(&out->d, &a->d, w, k);
}

/* mpcSum: the sum of the N ballots BS. */
static void lang_sum(Sharing *out, const Sharing *bs, uint32_t n) {
  DkgDealing ds[LANG_BALLOTS];
  U256 col[LANG_BALLOTS];
  uint32_t i;
  uint32_t j;
  for (j = 0; j < MEMBERS; j++) {
    for (i = 0; i < n; i++) {
      col[i] = bs[i].s[j];
    }
    bgw_sum(&out->s[j], col, n);
  }
  for (i = 0; i < n; i++) {
    ds[i] = bs[i].d;
  }
  bgw_sum_commit(&out->d, ds, n);
}

/* The step A * B (mul), with the Prods cells of the members 1 to 3 in
   CELL. */
static BgwResult lang_mul(Sharing *out, uint64_t cell[MEMBERS][LANG_CELL], const Sharing *a, const Sharing *b,
                          uint64_t rho) {
  BgwProduct prods[MEMBERS];
  U256 sub[MEMBERS][MEMBERS];
  U256 col[MEMBERS];
  BgwResult res = BGW_OK;
  uint32_t i;
  uint32_t j;
  memset(out, 0, sizeof *out);
  products(prods, sub, a, b, rho);
  for (j = 1; j <= MEMBERS && res == BGW_OK; j++) {
    column(col, sub, j);
    res = bgw_reduce(&out->s[j - 1u], prods, col, &a->d, &b->d, j, MEMBERS);
  }
  for (i = 0; i < MEMBERS; i++) {
    lang_cell(cell[i], &prods[i], sub[i], i + 1u);
  }
  return res == BGW_OK ? bgw_reduce_commit(&out->d, prods, MEMBERS) : res;
}

/* One line of mpc.txt. The ballot at the text position p is the bit V - 1 -
   p of C. The step m (the reshare coefficients 100 + 10 m + i - 1) is the
   bit check of the ballot at the text position V - 1 - m for m < V (the
   guest folds from the last cell), then a Horner step on the sum. The line
   is written when the honest open of the output gives the outcome; BAD then
   sets one word off. */
static int lang_row(const char *name, const char *entry, uint32_t want, uint32_t v, uint32_t c, uint32_t k,
                    LangBad bad) {
  static const unsigned char zero[128] = {0u};
  static uint64_t cell[LANG_STEPS][MEMBERS][LANG_CELL];
  Sharing bs[LANG_BALLOTS];
  Sharing bm;
  Sharing prod;
  Sharing total;
  Sharing h;
  U256 one;
  U256 m1;
  U256 a[4];
  U256 vote;
  U256 slope;
  unsigned char be[128];
  BgwResult res = BGW_OK;
  uint32_t count = 0;
  uint32_t bit;
  uint32_t m;
  uint32_t p;
  uint32_t i;
  int good = 1;
  memset(cell, 0, sizeof cell);
  u256_from_u64(&one, 1u);
  minus(&m1, 1u);
  for (i = 0; i < 4u; i++) {
    lang_coef(&a[i], LANG_COEF_IX[v][k][i]);
  }
  for (p = 0; p < v; p++) {
    bit = (c >> (v - 1u - p)) & 1u;
    count += bit;
    u256_from_u64(&vote, bit);
    u256_from_u64(&slope, 7u + 6u * p);
    good &= bgw_deal(&bs[p].d, bs[p].s, &vote, &slope, MEMBERS) == BGW_OK;
  }
  for (m = 0; m < v && res == BGW_OK; m++) {
    p = v - 1u - m;
    lang_affine(&bm, &bs[p], &one, &m1);
    res = lang_mul(&prod, cell[m], &bs[p], &bm, 100u + 10u * m);
  }
  /* h = a_V s + a_(V-1), then h = h s + a_e for e = V - 2 to 0. */
  lang_sum(&total, bs, v);
  lang_affine(&h, &total, &a[v], &a[v - 1u]);
  for (m = v; m + 1u < 2u * v && res == BGW_OK; m++) {
    res = lang_mul(&prod, cell[m], &h, &total, 100u + 10u * m);
    lang_affine(&h, &prod, &one, &a[2u * v - 2u - m]);
  }
  good &= res == BGW_OK && opens(&h, 1u, 2u, count >= k ? 1u : 0u);
  switch (bad) {
    case LANG_GOOD:
      break;
    case LANG_BAD_IN:
      bs[0].s[0].limb[0] ^= 1u;
      break;
    case LANG_BAD_PROOF:
      /* The low word of z (the words 25 to 28) of the member 1 at the step
         0. */
      cell[0][0][28] ^= 1u;
      break;
    case LANG_BAD_OUT:
      h.s[0].limb[0] ^= 1u;
      break;
  }
  printf("%s %s %u %u ", name, entry, (unsigned)want, (unsigned)k);
  for (p = 0; p < v; p++) {
    lang_dealing_be(be, &bs[p].d);
    lang_sharing(be, bs[p].s);
  }
  printf("0");
  for (i = 0; i < MEMBERS; i++) {
    printf(" ");
    for (m = 0; m + 1u < 2u * v; m++) {
      printf("1,0,");
      lang_print(cell[m][i], 29u);
      printf("0,");
      lang_print(cell[m][i] + 29, 8u);
      printf("0,");
      lang_print(cell[m][i] + 37, 16u);
    }
    printf("0");
  }
  printf(" ");
  lang_sharing(zero, h.s);
  printf("0\n");
  if (!good) {
    fprintf(stderr, "FAIL mpc lang %s\n", name);
  }
  return good;
}

/* The 34 rows of Q-S10-2 (b): each tally.txt combine row with each k in 1
   to V. Then the route rows: the good route, a bad input share (code 9), a
   bad product proof (code 10) and a bad output share (code 12). */
static int lang_rows(void) {
  char name[32];
  uint32_t v;
  uint32_t c;
  uint32_t k;
  uint32_t i;
  uint32_t count;
  int ok = 1;
  for (v = 1; v <= LANG_BALLOTS; v++) {
    for (c = 0; c < (1u << v); c++) {
      count = 0;
      for (i = 0; i < v; i++) {
        count += (c >> i) & 1u;
      }
      for (k = 1; k <= v; k++) {
        snprintf(name, sizeof name, "mc%u_%u_%u", (unsigned)v, (unsigned)c, (unsigned)k);
        ok &= lang_row(name, "mpc_tally", count >= k ? 1u : 0u, v, c, k, LANG_GOOD);
      }
    }
  }
  ok &= lang_row("mr", "mpc_route", 0u, 3u, 6u, 2u, LANG_GOOD);
  ok &= lang_row("badin", "mpc_route", 9u, 3u, 6u, 2u, LANG_BAD_IN);
  ok &= lang_row("badproof", "mpc_route", 10u, 3u, 6u, 2u, LANG_BAD_PROOF);
  ok &= lang_row("badout", "mpc_route", 12u, 3u, 6u, 2u, LANG_BAD_OUT);
  return ok;
}

int main(int argc, char **argv) {
  int ok = 1;
  if (argc == 2 && strcmp(argv[1], "lang") == 0) {
    return lang_rows() ? 0 : 1;
  }
  if (argc != 1) {
    fprintf(stderr, "usage: mpctool [lang]\n");
    return 2;
  }
  ok &= deal_rows();
  ok &= add_rows();
  ok &= mul_rows();
  ok &= bit_row("bit check of 0 opens to 0", 0u, 0u);
  ok &= bit_row("bit check of 1 opens to 0", 1u, 0u);
  ok &= bit_row("bit check of the ballot 5 opens to 20, not 0", 5u, 20u);
  ok &= open_rows();
  ok &= proof_rows();
  ok &= index_rows();
  if (ok) {
    puts("bgw regressions: passed");
  }
  return ok ? 0 : 1;
}
