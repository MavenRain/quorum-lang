/* NEW (quorum-lang S11 H3a P2): the Poseidon gadget. poseidongadget.h
   gives the row layout and the count. */
#include "crypto/poseidongadget.h"

#include <string.h>

/* A linear combination: the sum of COEFF[k] VAR[k] for k below N, plus
   the constant ADD. */
typedef struct {
  uint32_t var[POSEIDON_WIDTH];
  Fe coeff[POSEIDON_WIDTH];
  Fe add;
  size_t n;
} Lc;

static void lc_value(Fe *out, const R1cs *cs, const Lc *x) {
  Fe v;
  size_t k;
  *out = x->add;
  for (k = 0; k < x->n; k++) {
    r1cs_value(&v, cs, x->var[k]);
    fe_mul(&v, &x->coeff[k], &v, cs->f);
    fe_add(out, out, &v, cs->f);
  }
}

/* Adds the terms of X to one side of the current row. A zero constant adds
   no term. */
static void lc_terms(R1cs *cs, R1csSide side, const Lc *x) {
  Fe zero;
  size_t k;
  memset(&zero, 0, sizeof zero);
  for (k = 0; k < x->n; k++)
    r1cs_term(cs, side, x->var[k], &x->coeff[k]);
  if (!fe_eq(&x->add, &zero))
    r1cs_term(cs, side, 0, &x->add);
}

/* A new variable X^5 in three rows: X X = S, S S = Q, Q X = OUT. */
static uint32_t sbox(R1cs *cs, const Lc *x) {
  Fe vx;
  Fe v;
  uint32_t sq;
  uint32_t quad;
  uint32_t out;
  lc_value(&vx, cs, x);
  fe_mul(&v, &vx, &vx, cs->f);
  sq = r1cs_var(cs, &v);
  r1cs_row(cs);
  lc_terms(cs, R1CS_A, x);
  lc_terms(cs, R1CS_B, x);
  r1cs_term_int(cs, R1CS_C, sq, 1);
  quad = r1cs_mul(cs, sq, sq);
  r1cs_value(&v, cs, quad);
  fe_mul(&v, &v, &vx, cs->f);
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, quad, 1);
  lc_terms(cs, R1CS_B, x);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}

/* A new variable equal to X in one row: X 1 = OUT. */
static uint32_t copy(R1cs *cs, const Lc *x) {
  Fe v;
  uint32_t out;
  lc_value(&v, cs, x);
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  lc_terms(cs, R1CS_A, x);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}

void poseidon_gadget(R1cs *cs, uint32_t out[POSEIDON_WIDTH],
                     const uint32_t in[POSEIDON_WIDTH], const PoseidonParams *p) {
  Lc state[POSEIDON_WIDTH];
  uint32_t v[POSEIDON_WIDTH];
  uint32_t half = POSEIDON_RF / 2u;
  uint32_t r;
  uint32_t i;
  uint32_t j;
  int full;
  for (i = 0; i < POSEIDON_WIDTH; i++) {
    memset(&state[i], 0, sizeof state[i]);
    state[i].var[0] = in[i];
    fe_from_u64(&state[i].coeff[0], 1);
    state[i].n = 1;
  }
  for (r = 0; r < POSEIDON_RF + POSEIDON_RP; r++) {
    full = r < half || r >= half + POSEIDON_RP;
    for (i = 0; i < POSEIDON_WIDTH; i++) {
      fe_add(&state[i].add, &state[i].add, &p->rc[r * POSEIDON_WIDTH + i], cs->f);
      v[i] = (full || i == 0u) ? sbox(cs, &state[i]) : copy(cs, &state[i]);
    }
    for (i = 0; i < POSEIDON_WIDTH; i++) {
      memset(&state[i], 0, sizeof state[i]);
      for (j = 0; j < POSEIDON_WIDTH; j++) {
        state[i].var[j] = v[j];
        state[i].coeff[j] = p->mds[i][j];
      }
      state[i].n = POSEIDON_WIDTH;
    }
  }
  for (i = 0; i < POSEIDON_WIDTH; i++)
    out[i] = copy(cs, &state[i]);
}
