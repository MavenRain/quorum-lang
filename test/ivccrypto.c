/* NEW (quorum-lang S11 H2, O155, O156, O157): host regressions of the IVC
   crypto (src/crypto/secq256k1.c, poseidon.c, gens.c and msm.c, and the
   fe_mul of bn254.c) against the vectors of test/ivcvectors.h. Each row is
   one vector or one group of vectors. A failed row writes
   `FAIL ivc <name>` to stderr. The last line gives the number of rows and
   the number of mismatches. */
#include <stdio.h>
#include <string.h>

#include "crypto/gens.h"
#include "crypto/msm.h"
#include "crypto/poseidon.h"
#include "crypto/secq256k1.h"
#include "ivcvectors.h"

#define GENS_COUNT 4u

typedef struct {
  uint32_t rows;
  uint32_t mismatches;
} Tally;

static void row(Tally *t, const char *name, int good) {
  t->rows++;
  if (!good) {
    t->mismatches++;
    fprintf(stderr, "FAIL ivc %s\n", name);
  }
}

/* The vectors of one field of the cycle. */
typedef struct {
  const char *name;
  const Modulus *f;
  const char *rc_first;
  const char *rc_last;
  const char *const *mds;
  const char *const *in1;
  const char *const *in1_out;
  const char *const *in2;
  const char *const *in2_out;
} FieldVectors;

static uint32_t nibble(char c) {
  if (c >= '0' && c <= '9')
    return (uint32_t)(c - '0');
  if (c >= 'a' && c <= 'f')
    return (uint32_t)(c - 'a' + 10);
  return 0;
}

/* OUT = the word of the 64 hex digits at HEX. */
static void hex_word(U256 *out, const char *hex) {
  unsigned char be[32];
  uint32_t i;
  for (i = 0; i < 32u; i++)
    be[i] = (unsigned char)((nibble(hex[2u * i]) << 4) | nibble(hex[2u * i + 1u]));
  u256_from_be(out, be);
}

/* Returns 1, or 0 when the value of HEX is F or more. */
static int hex_fe(Fe *out, const char *hex, const Modulus *f) {
  U256 w;
  hex_word(&w, hex);
  return fe_from_u256(out, &w, f);
}

static int fe_is_hex(const Fe *x, const char *hex, const Modulus *f) {
  Fe want;
  return hex_fe(&want, hex, f) && fe_eq(x, &want);
}

static int point_is_hex(const G1 *p, const char *const *xy, const Modulus *f) {
  return fe_is_hex(&p->x, xy[0], f) && fe_is_hex(&p->y, xy[1], f);
}

static void modulus_word(U256 *out, const Modulus *f) {
  uint32_t i;
  for (i = 0; i < 4u; i++)
    out->limb[i] = (uint64_t)f->w[2u * i] | ((uint64_t)f->w[2u * i + 1u] << 32);
}

static int is_even(const Fe *x) {
  U256 w;
  fe_to_u256(&w, x);
  return (w.limb[0] & 1u) == 0u;
}

/* 1 when the permutation of IN is OUT. */
static int perm_is(const PoseidonParams *p, const char *const *in, const char *const *out) {
  Fe state[POSEIDON_WIDTH];
  uint32_t i;
  int good = 1;
  for (i = 0; i < POSEIDON_WIDTH; i++)
    good = hex_fe(&state[i], in[i], &p->f) && good;
  poseidon_perm(state, p);
  for (i = 0; i < POSEIDON_WIDTH; i++)
    good = good && fe_is_hex(&state[i], out[i], &p->f);
  return good;
}

/* The width, R_F and R_P of the script are the ones of poseidon.h. The
   BN254 Fr row: the permutation of [0, 1, 2] is the one of circomlib. */
static void bn254_rows(Tally *t) {
  static const char *const in[3] = {
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002"};
  PoseidonParams p;
  row(t, "poseidon parameters",
      IVC_POSEIDON_WIDTH == POSEIDON_WIDTH && IVC_POSEIDON_RF == POSEIDON_RF && IVC_POSEIDON_RP == POSEIDON_RP);
  poseidon_params(&p, &BN254_FR);
  row(t, "poseidon bn254 circomlib", perm_is(&p, in, BN254_POSEIDON_0_1_2));
}

/* The C Grain against the script: the first and the last round constant,
   the MDS matrix, and two permutations. */
static void field_rows(Tally *t, const FieldVectors *v) {
  PoseidonParams p;
  char name[64];
  uint32_t i;
  uint32_t j;
  int good = 1;
  poseidon_params(&p, v->f);
  snprintf(name, sizeof name, "poseidon %s rc first", v->name);
  row(t, name, fe_is_hex(&p.rc[0], v->rc_first, v->f));
  snprintf(name, sizeof name, "poseidon %s rc last", v->name);
  row(t, name, fe_is_hex(&p.rc[POSEIDON_CONSTANTS - 1u], v->rc_last, v->f));
  for (i = 0; i < POSEIDON_WIDTH; i++)
    for (j = 0; j < POSEIDON_WIDTH; j++)
      good = good && fe_is_hex(&p.mds[i][j], v->mds[i * POSEIDON_WIDTH + j], v->f);
  snprintf(name, sizeof name, "poseidon %s mds", v->name);
  row(t, name, good);
  snprintf(name, sizeof name, "poseidon %s in1", v->name);
  row(t, name, perm_is(&p, v->in1, v->in1_out));
  snprintf(name, sizeof name, "poseidon %s in2", v->name);
  row(t, name, perm_is(&p, v->in2, v->in2_out));
}

static void poseidon_rows(Tally *t) {
  const FieldVectors fp = {"fp", &SECP_FP, POSEIDON_FP_RC_FIRST, POSEIDON_FP_RC_LAST, POSEIDON_FP_MDS,
                           POSEIDON_FP_IN1, POSEIDON_FP_IN1_OUT, POSEIDON_FP_IN2, POSEIDON_FP_IN2_OUT};
  const FieldVectors fn = {"fn", &SECP_FN, POSEIDON_FN_RC_FIRST, POSEIDON_FN_RC_LAST, POSEIDON_FN_MDS,
                           POSEIDON_FN_IN1, POSEIDON_FN_IN1_OUT, POSEIDON_FN_IN2, POSEIDON_FN_IN2_OUT};
  bn254_rows(t);
  field_rows(t, &fp);
  field_rows(t, &fn);
}

/* secq256k1: the generator (O156), the group order p, and the small
   multiples against the script. fe_sqrt on F_p (p = 3 mod 4, s = 1) too. */
static void secq_rows(Tally *t) {
  G1 g;
  G1 r;
  G1 s;
  G1 zero;
  G1 neg;
  Fe seven;
  Fe one;
  Fe y;
  Fe sq;
  U256 k;
  U256 unit;
  memset(&zero, 0, sizeof zero);
  fe_from_u64(&seven, 7);
  fe_from_u64(&one, 1);
  u256_from_u64(&unit, 1);
  secq_gen(&g);
  row(t, "secq g vector", point_is_hex(&g, SECQ_G, &SECQ_FB));
  row(t, "secq g on curve", secq_on_curve(&g) && !secq_eq(&g, &zero));
  /* No point has x = 0 (7 is not a square in F_n), so x = 1 is the least
     x; the root is the even one. */
  row(t, "secq g least x", !fe_sqrt(&y, &seven, &SECQ_FB) && fe_eq(&g.x, &one) && is_even(&g.y));
  modulus_word(&k, &SECQ_FS);
  secq_mul(&r, &g, &k);
  row(t, "secq p g = o", secq_eq(&r, &zero));
  (void)u256_sub(&k, &k, &unit);
  secq_mul(&r, &g, &k);
  secq_neg(&neg, &g);
  row(t, "secq (p - 1) g = -g", secq_eq(&r, &neg));
  secq_double(&r, &g);
  secq_add(&s, &g, &g);
  row(t, "secq 2g", point_is_hex(&r, SECQ_2G, &SECQ_FB) && secq_eq(&r, &s));
  secq_add(&s, &r, &g);
  row(t, "secq 3g", point_is_hex(&s, SECQ_3G, &SECQ_FB) && secq_on_curve(&s));
  hex_word(&k, SECQ_K);
  secq_mul(&r, &g, &k);
  row(t, "secq k g", point_is_hex(&r, SECQ_KG, &SECQ_FB));
  secp_gen(&s);
  fe_mul(&sq, &s.y, &s.y, &SECP_FP);
  fe_neg(&neg.y, &s.y, &SECP_FP);
  row(t, "fe_sqrt secp g y",
      fe_sqrt(&y, &sq, &SECP_FP) && (fe_eq(&y, &s.y) || fe_eq(&y, &neg.y)));
}

/* The generators of each curve: on the curve, and the words of the
   script. */
static void gens_rows(Tally *t) {
  G1 p;
  char name[64];
  uint32_t i;
  for (i = 0; i < GENS_COUNT; i++) {
    gens_point(&p, GENS_SECP256K1, i);
    snprintf(name, sizeof name, "gens secp256k1 %u", (unsigned)i);
    row(t, name, secp_on_curve(&p) && point_is_hex(&p, GENS_SECP + 2u * i, &SECP_FP));
  }
  for (i = 0; i < GENS_COUNT; i++) {
    gens_point(&p, GENS_SECQ256K1, i);
    snprintf(name, sizeof name, "gens secq256k1 %u", (unsigned)i);
    row(t, name, secq_on_curve(&p) && point_is_hex(&p, GENS_SECQ + 2u * i, &SECQ_FB));
  }
}

/* The bit-serial fe_mul of S1 to S10 (crypto/bn254.c before S11 H2), the
   reference for the word-wise remainder (Q-S11-6 ruling (a), O157): the
   same code with other names. */
/* -1, 0 or 1 as A is less than, equal to or more than B. */
static int ref_cmp(const uint32_t *a, const uint32_t *b) {
  unsigned i;
  for (i = BN_LIMBS; i > 0; i--) {
    if (a[i - 1] != b[i - 1])
      return a[i - 1] < b[i - 1] ? -1 : 1;
  }
  return 0;
}

/* A = A - B modulo 2^256. Returns the borrow. */
static uint32_t ref_sub(uint32_t *a, const uint32_t *b) {
  uint64_t borrow = 0;
  unsigned i;
  for (i = 0; i < BN_LIMBS; i++) {
    uint64_t d = (uint64_t)a[i] - b[i] - borrow;
    a[i] = (uint32_t)d;
    borrow = d >> 63;
  }
  return (uint32_t)borrow;
}

static void ref_mul(Fe *out, const Fe *a, const Fe *b, const Modulus *f) {
  uint32_t p[2u * BN_LIMBS];
  Fe rem;
  unsigned i;
  unsigned j;
  memset(p, 0, sizeof p);
  memset(&rem, 0, sizeof rem);
  for (i = 0; i < BN_LIMBS; i++) {
    uint64_t carry = 0;
    for (j = 0; j < BN_LIMBS; j++) {
      uint64_t t = (uint64_t)a->w[i] * b->w[j] + p[i + j] + carry;
      p[i + j] = (uint32_t)t;
      carry = t >> 32;
    }
    p[i + BN_LIMBS] = (uint32_t)carry;
  }
  for (i = 2u * BN_LIMBS * 32u; i > 0; i--) {
    uint32_t bit = (p[(i - 1) / 32u] >> ((i - 1) % 32u)) & 1u;
    uint32_t top = rem.w[BN_LIMBS - 1] >> 31;
    for (j = BN_LIMBS - 1; j > 0; j--)
      rem.w[j] = (rem.w[j] << 1) | (rem.w[j - 1] >> 31);
    rem.w[0] = (rem.w[0] << 1) | bit;
    if (top != 0 || ref_cmp(rem.w, f->w) >= 0)
      ref_sub(rem.w, f->w);
  }
  *out = rem;
}


/* splitmix64 (G. Steele, D. Lea and C. Flood, 2014): the fixed source of
   the test words. Each call adds the golden-ratio step to the state S and
   mixes it. */
static uint64_t mix_next(uint64_t *s) {
  uint64_t z;
  *s += 0x9e3779b97f4a7c15ull;
  z = *s;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

/* 4 words of the source (least significant first) as a value below F: the
   ref_mul of the 256-bit value and 1. */
static void mix_fe(Fe *out, uint64_t *s, const Modulus *f) {
  Fe raw;
  Fe one;
  unsigned i;
  for (i = 0; i < 4u; i++) {
    uint64_t w = mix_next(s);
    raw.w[2u * i] = (uint32_t)w;
    raw.w[2u * i + 1u] = (uint32_t)(w >> 32);
  }
  fe_from_u64(&one, 1);
  ref_mul(out, &raw, &one, f);
}

/* mul_matches compares fe_mul with ref_mul on the 16 pairs of 0, 1, m - 1
   and m - 2, then on MUL_PAIRS pairs (a, then b) from the source with the
   seed MUL_SEED plus the field number. */
#define MUL_PAIRS 10000u
#define MUL_SEED 0x51315u

static int mul_matches(const Modulus *f, uint64_t seed) {
  Fe e[4];
  Fe a;
  Fe b;
  Fe got;
  Fe want;
  uint64_t s = seed;
  unsigned i;
  unsigned j;
  int good = 1;
  fe_from_u64(&e[0], 0);
  fe_from_u64(&e[1], 1);
  fe_neg(&e[2], &e[1], f);
  fe_sub(&e[3], &e[2], &e[1], f);
  for (i = 0; i < 4u; i++) {
    for (j = 0; j < 4u; j++) {
      fe_mul(&got, &e[i], &e[j], f);
      ref_mul(&want, &e[i], &e[j], f);
      good = fe_eq(&got, &want) && good;
    }
  }
  for (i = 0; i < MUL_PAIRS; i++) {
    mix_fe(&a, &s, f);
    mix_fe(&b, &s, f);
    fe_mul(&got, &a, &b, f);
    ref_mul(&want, &a, &b, f);
    good = fe_eq(&got, &want) && good;
  }
  return good;
}

/* One vector of a rare step of rem_words: A times B is E. */
typedef struct {
  const char *a;
  const char *b;
  const char *e;
} MulVector;

/* A field of mul_rows: the pairs of mul_matches, and the vectors of step D6
   (add back) and of a first estimate of 2^32 or more (test/ivcvectors.h). */
typedef struct {
  const char *pairs_name;
  const char *rare_name;
  const Modulus *f;
  MulVector add_back;
  MulVector top;
} MulField;

static int mul_vector_is(const MulVector *v, const Modulus *f) {
  Fe a;
  Fe b;
  Fe got;
  Fe want;
  int good;
  fe_from_u64(&a, 0);
  fe_from_u64(&b, 0);
  good = hex_fe(&a, v->a, f) && hex_fe(&b, v->b, f);
  fe_mul(&got, &a, &b, f);
  ref_mul(&want, &a, &b, f);
  return good && fe_is_hex(&got, v->e, f) && fe_eq(&got, &want);
}

static void mul_rows(Tally *t) {
  MulField fields[4] = {
    {"fe_mul pairs bn254 p", "fe_mul rare bn254 p", &BN254_FP,
     {IVC_MUL_BN254_P_ADD_A, IVC_MUL_BN254_P_ADD_B, IVC_MUL_BN254_P_ADD_E},
     {IVC_MUL_BN254_P_TOP_A, IVC_MUL_BN254_P_TOP_B, IVC_MUL_BN254_P_TOP_E}},
    {"fe_mul pairs bn254 r", "fe_mul rare bn254 r", &BN254_FR,
     {IVC_MUL_BN254_R_ADD_A, IVC_MUL_BN254_R_ADD_B, IVC_MUL_BN254_R_ADD_E},
     {IVC_MUL_BN254_R_TOP_A, IVC_MUL_BN254_R_TOP_B, IVC_MUL_BN254_R_TOP_E}},
    {"fe_mul pairs secp256k1 p", "fe_mul rare secp256k1 p", &SECP_FP,
     {IVC_MUL_SECP_P_ADD_A, IVC_MUL_SECP_P_ADD_B, IVC_MUL_SECP_P_ADD_E},
     {IVC_MUL_SECP_P_TOP_A, IVC_MUL_SECP_P_TOP_B, IVC_MUL_SECP_P_TOP_E}},
    {"fe_mul pairs secp256k1 n", "fe_mul rare secp256k1 n", &SECP_FN,
     {IVC_MUL_SECP_N_ADD_A, IVC_MUL_SECP_N_ADD_B, IVC_MUL_SECP_N_ADD_E},
     {IVC_MUL_SECP_N_TOP_A, IVC_MUL_SECP_N_TOP_B, IVC_MUL_SECP_N_TOP_E}}
  };
  unsigned i;
  for (i = 0; i < 4u; i++) {
    row(t, fields[i].pairs_name, mul_matches(fields[i].f, MUL_SEED + i));
    row(t, fields[i].rare_name,
        mul_vector_is(&fields[i].add_back, fields[i].f) && mul_vector_is(&fields[i].top, fields[i].f));
  }
}

/* The points, scalars and buckets of msm_rows. msm_buckets(2^10) is 127. */
#define MSM_LOG_MAX 10u
#define MSM_POINTS (1u << MSM_LOG_MAX)
#define MSM_SPACE 127u
#define MSM_SEED 0x4d534du

static G1 msm_points[MSM_POINTS];
static U256 msm_scalars[MSM_POINTS];
static EcJac msm_space[MSM_SPACE];

static int point_same(const G1 *a, const G1 *b) {
  return fe_eq(&a->x, &b->x) && fe_eq(&a->y, &b->y);
}

/* msm against the plain sum on secq256k1 (the field SECQ_FB). Point i is
   gens_point(GENS_SECQ256K1, i). Scalar i is the next 4 words of the source
   from the seed MSM_SEED (least significant first), with all 256 bits. For
   k = 0 to MSM_LOG_MAX, the row "msm 2^k" compares msm over the first 2^k
   pairs with the sum of ec0_mul(P_i, k_i) by ec0_add. */
static void msm_rows(Tally *t) {
  G1 sum;
  G1 term;
  G1 got;
  char name[32];
  uint64_t s = MSM_SEED;
  uint32_t i;
  unsigned j;
  unsigned k = 0;
  memset(&sum, 0, sizeof sum);
  for (i = 0; i < MSM_POINTS; i++) {
    gens_point(&msm_points[i], GENS_SECQ256K1, i);
    for (j = 0; j < 4u; j++)
      msm_scalars[i].limb[j] = mix_next(&s);
    ec0_mul(&term, &msm_points[i], &msm_scalars[i], &SECQ_FB);
    ec0_add(&sum, &sum, &term, &SECQ_FB);
    if (i + 1u == (1u << k)) {
      int good = msm(&got, msm_points, msm_scalars, (size_t)i + 1u, msm_space, MSM_SPACE, &SECQ_FB);
      snprintf(name, sizeof name, "msm 2^%u", k);
      row(t, name, good && point_same(&got, &sum));
      k++;
    }
  }
}

int main(void) {
  Tally t = {0, 0};
  mul_rows(&t);
  poseidon_rows(&t);
  secq_rows(&t);
  gens_rows(&t);
  msm_rows(&t);
  printf("crypto ivc: %u vectors, %u mismatches\n", (unsigned)t.rows, (unsigned)t.mismatches);
  return t.mismatches == 0u ? 0 : 1;
}
