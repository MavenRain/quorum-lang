/* NEW (quorum-lang S11 H3a P3): the SHA-256 compression of sha256.c as
   rows of a rank-1 constraint system. The design and the count are in
   sha256gadget.h. */
#include "crypto/sha256gadget.h"

#include "crypto/sha256.h"

#define WORD_BITS 32u
#define ROUNDS 64u
/* A bit that is the constant 0 (a high bit of a right shift). It is not a
   variable of the system. */
#define ZERO_BIT UINT32_MAX
/* The most carry bits of a sum: 7 terms are less than 2^35. */
#define MAX_CARRY 3u

typedef struct {
  uint32_t bit[WORD_BITS];
} Word;

static Word word_rotr(const Word *x, unsigned n) {
  Word out;
  for (unsigned i = 0; i < WORD_BITS; i++)
    out.bit[i] = x->bit[(i + n) % WORD_BITS];
  return out;
}

static Word word_shr(const Word *x, unsigned n) {
  Word out;
  for (unsigned i = 0; i < WORD_BITS; i++)
    out.bit[i] = i + n < WORD_BITS ? x->bit[i + n] : ZERO_BIT;
  return out;
}

/* X ^ Y ^ Z: 2 rows for each bit, or 1 row where Z is the constant 0. */
static Word word_xor3(R1cs *cs, const Word *x, const Word *y, const Word *z) {
  Word out;
  for (unsigned i = 0; i < WORD_BITS; i++) {
    uint32_t xy = r1cs_xor(cs, x->bit[i], y->bit[i]);
    out.bit[i] = z->bit[i] == ZERO_BIT ? xy : r1cs_xor(cs, xy, z->bit[i]);
  }
  return out;
}

/* Section 4.1.2, (4.4) and (4.5). */
static Word big_sigma(R1cs *cs, const Word *x, unsigned r0, unsigned r1, unsigned r2) {
  Word a = word_rotr(x, r0);
  Word b = word_rotr(x, r1);
  Word c = word_rotr(x, r2);
  return word_xor3(cs, &a, &b, &c);
}

/* Section 4.1.2, (4.6) and (4.7). */
static Word small_sigma(R1cs *cs, const Word *x, unsigned r0, unsigned r1, unsigned s) {
  Word a = word_rotr(x, r0);
  Word b = word_rotr(x, r1);
  Word c = word_shr(x, s);
  return word_xor3(cs, &a, &b, &c);
}

static Word word_ch(R1cs *cs, const Word *e, const Word *f, const Word *g) {
  Word out;
  for (unsigned i = 0; i < WORD_BITS; i++)
    out.bit[i] = r1cs_select(cs, e->bit[i], f->bit[i], g->bit[i]);
  return out;
}

static Word word_maj(R1cs *cs, const Word *a, const Word *b, const Word *c) {
  Word out;
  for (unsigned i = 0; i < WORD_BITS; i++) {
    uint32_t differ = r1cs_xor(cs, a->bit[i], b->bit[i]);
    out.bit[i] = r1cs_select(cs, differ, c->bit[i], a->bit[i]);
  }
  return out;
}

static uint64_t bit_value(const R1cs *cs, uint32_t var) {
  Fe v;
  Fe one;
  r1cs_value(&v, cs, var);
  fe_from_u64(&one, 1);
  return (uint64_t)(fe_eq(&v, &one) != 0);
}

/* The sum mod 2^32 of the N words WORD[0] to WORD[N - 1] and the constant
   K. N + (K != 0) must be at most 8 (MAX_CARRY). */
static Word word_add(R1cs *cs, const Word *const *word, unsigned n, uint32_t k) {
  Word out;
  uint32_t high[MAX_CARRY];
  uint64_t sum = k;
  unsigned carry = 0;
  Fe v;
  for (unsigned m = n + (k != 0) - 1u; m != 0; m >>= 1)
    carry++;
  for (unsigned w = 0; w < n; w++)
    for (unsigned i = 0; i < WORD_BITS; i++)
      sum += bit_value(cs, word[w]->bit[i]) << i;
  for (unsigned i = 0; i < WORD_BITS; i++) {
    fe_from_u64(&v, (sum >> i) & 1u);
    out.bit[i] = r1cs_bool(cs, &v);
  }
  for (unsigned i = 0; i < carry; i++) {
    fe_from_u64(&v, (sum >> (WORD_BITS + i)) & 1u);
    high[i] = r1cs_bool(cs, &v);
  }
  r1cs_row(cs);
  for (unsigned w = 0; w < n; w++)
    for (unsigned i = 0; i < WORD_BITS; i++) {
      fe_from_u64(&v, (uint64_t)1 << i);
      r1cs_term(cs, R1CS_A, word[w]->bit[i], &v);
    }
  if (k != 0) {
    fe_from_u64(&v, k);
    r1cs_term(cs, R1CS_A, 0, &v);
  }
  r1cs_term_int(cs, R1CS_B, 0, 1);
  for (unsigned i = 0; i < WORD_BITS; i++) {
    fe_from_u64(&v, (uint64_t)1 << i);
    r1cs_term(cs, R1CS_C, out.bit[i], &v);
  }
  for (unsigned i = 0; i < carry; i++) {
    fe_from_u64(&v, (uint64_t)1 << (WORD_BITS + i));
    r1cs_term(cs, R1CS_C, high[i], &v);
  }
  return out;
}

void sha256_gadget(R1cs *cs, uint32_t out[SHA256_GADGET_STATE],
                   const uint32_t state[SHA256_GADGET_STATE],
                   const uint32_t block[SHA256_GADGET_BLOCK]) {
  Word w[ROUNDS];
  Word in[8];
  Word v[8];
  for (unsigned t = 0; t < 16; t++)
    for (unsigned i = 0; i < WORD_BITS; i++)
      w[t].bit[i] = block[WORD_BITS * t + i];
  for (unsigned t = 16; t < ROUNDS; t++) {
    Word s0 = small_sigma(cs, &w[t - 15], 7, 18, 3);
    Word s1 = small_sigma(cs, &w[t - 2], 17, 19, 10);
    const Word *sum[4] = {&w[t - 16], &s0, &w[t - 7], &s1};
    w[t] = word_add(cs, sum, 4, 0);
  }
  for (unsigned i = 0; i < 8; i++)
    for (unsigned j = 0; j < WORD_BITS; j++)
      in[i].bit[j] = state[WORD_BITS * i + j];
  for (unsigned i = 0; i < 8; i++)
    v[i] = in[i];
  for (unsigned t = 0; t < ROUNDS; t++) {
    Word s1 = big_sigma(cs, &v[4], 6, 11, 25);
    Word ch = word_ch(cs, &v[4], &v[5], &v[6]);
    Word s0 = big_sigma(cs, &v[0], 2, 13, 22);
    Word maj = word_maj(cs, &v[0], &v[1], &v[2]);
    const Word *e_sum[5] = {&v[3], &v[7], &s1, &ch, &w[t]};
    const Word *a_sum[6] = {&v[7], &s1, &ch, &w[t], &s0, &maj};
    Word e = word_add(cs, e_sum, 5, sha256_round_constant[t]);
    Word a = word_add(cs, a_sum, 6, sha256_round_constant[t]);
    for (unsigned i = 7; i > 0; i--)
      v[i] = v[i - 1];
    v[4] = e;
    v[0] = a;
  }
  for (unsigned i = 0; i < 8; i++) {
    const Word *sum[2] = {&in[i], &v[i]};
    Word s = word_add(cs, sum, 2, 0);
    for (unsigned j = 0; j < WORD_BITS; j++)
      out[WORD_BITS * i + j] = s.bit[j];
  }
}
