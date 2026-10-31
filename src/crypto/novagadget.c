/* NEW (quorum-lang S11 H3c C3): the in-circuit NIFS verifier of Nova and
   the non-native X fold (crypto/novagadget.h, O162 item 7). */
#include "crypto/novagadget.h"

#include "crypto/ec7gadget.h"
#include "crypto/poseidongadget.h"

#define NOVA_COLS 6u
#define NOVA_COL_TERMS 16u

/* OUT = 2^K in F. K is below 256. */
static void ng_pow2(Fe *out, unsigned k, const Modulus *f) {
  U256 u;
  u256_from_u64(&u, 0);
  u.limb[k / 64u] = (uint64_t)1 << (k % 64u);
  fe_from_u256(out, &u, f);
}

/* OUT = the sum of COEFF[i] times the value of VAR[i]. */
static void ng_eval(Fe *out, const R1cs *cs, const uint32_t *var, const Fe *coeff, size_t n) {
  Fe v;
  Fe p;
  Fe sum;
  size_t i;
  fe_from_u64(out, 0);
  for (i = 0; i < n; i++) {
    r1cs_value(&v, cs, var[i]);
    fe_mul(&p, &v, &coeff[i], cs->f);
    fe_add(&sum, out, &p, cs->f);
    *out = sum;
  }
}

/* A new row with A = the sum of COEFF[i] VAR[i] and B = 1. C is empty
   until the caller adds a term. */
static void ng_terms(R1cs *cs, const uint32_t *var, const Fe *coeff, size_t n) {
  size_t i;
  r1cs_row(cs);
  for (i = 0; i < n; i++)
    r1cs_term(cs, R1CS_A, var[i], &coeff[i]);
  r1cs_term_int(cs, R1CS_B, 0, 1);
}

/* A new variable for the sum of COEFF[i] VAR[i] (1 row). */
static uint32_t ng_lin(R1cs *cs, const uint32_t *var, const Fe *coeff, size_t n) {
  Fe sum;
  uint32_t out;
  ng_eval(&sum, cs, var, coeff, n);
  out = r1cs_var(cs, &sum);
  ng_terms(cs, var, coeff, n);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}

/* A new variable with the value 0 (1 row: z 1 = 0). */
static uint32_t ng_zero(R1cs *cs) {
  Fe v;
  Fe one;
  uint32_t z;
  fe_from_u64(&v, 0);
  z = r1cs_var(cs, &v);
  fe_from_u64(&one, 1);
  ng_terms(cs, &z, &one, 1);
  return z;
}

/* New boolean variables for the N low bits of X (N r1cs_bool rows). */
static void ng_bits(R1cs *cs, uint32_t *bit, const U256 *x, size_t n) {
  Fe b;
  size_t i;
  for (i = 0; i < n; i++) {
    fe_from_u64(&b, (x->limb[i / 64u] >> (i % 64u)) & 1u);
    bit[i] = r1cs_bool(cs, &b);
  }
}

/* OUT = the integer of the N limb variables VAR (N at most 4). */
static void ng_join(U256 *out, const R1cs *cs, const uint32_t *var, size_t n) {
  Fe v;
  U256 u;
  size_t k;
  u256_from_u64(out, 0);
  for (k = 0; k < n; k++) {
    r1cs_value(&v, cs, var[k]);
    fe_to_u256(&u, &v);
    out->limb[k] = u.limb[0];
  }
}

/* ACC + V = Q' M + ACC' with ACC' below M, and Q' = Q + 0 or 1. ACC and V
   must be below M. */
static void ng_add_mod(U256 *acc, U256 *q, const U256 *v, const U256 *m) {
  U256 gap;
  U256 next;
  U256 one;
  u256_sub(&gap, m, v);
  if (u256_cmp(acc, &gap) >= 0) {
    u256_sub(&next, acc, &gap);
    *acc = next;
    u256_from_u64(&one, 1);
    u256_add(&next, q, &one);
    *q = next;
  } else {
    u256_add(&next, acc, v);
    *acc = next;
  }
}

void nova_xfold_witness(U256 *q, U256 *rem, const U256 *x1, const U256 *x2, const U256 *r,
                        const U256 *m) {
  U256 acc;
  U256 quo;
  U256 prev;
  unsigned i;
  u256_from_u64(&acc, 0);
  u256_from_u64(&quo, 0);
  for (i = NOVA_R_BITS; i-- > 0;) {
    u256_add(&prev, &quo, &quo);
    quo = prev;
    prev = acc;
    ng_add_mod(&acc, &quo, &prev, m);
    if ((r->limb[i / 64u] >> (i % 64u)) & 1u)
      ng_add_mod(&acc, &quo, x2, m);
  }
  ng_add_mod(&acc, &quo, x1, m);
  *q = quo;
  *rem = acc;
}

void nova_xfold_qr_gadget(R1cs *cs, uint32_t out[NOVA_LIMBS], const uint32_t x1[NOVA_LIMBS],
                          const uint32_t x2[NOVA_LIMBS], const uint32_t r[2], const U256 *m,
                          const U256 *q, const U256 *rem) {
  uint32_t rem_bit[STEP_GADGET_BITS];
  uint32_t q_bit[NOVA_Q_BITS];
  uint32_t carry_bit[NOVA_CARRY_BITS];
  uint32_t qv[3];
  uint32_t prod[2][NOVA_LIMBS];
  uint32_t var[NOVA_COL_TERMS];
  Fe coeff[NOVA_COL_TERMS];
  Fe one;
  Fe minus_one;
  Fe two64;
  Fe inv64;
  Fe offset;
  Fe minus_offset;
  Fe big;
  Fe mj;
  Fe val;
  Fe tmp;
  U256 cb;
  uint32_t carry = 0;
  unsigned i;
  unsigned j;
  unsigned k;
  size_t n;
  const Modulus *f = cs->f;
  fe_from_u64(&one, 1);
  fe_neg(&minus_one, &one, f);
  ng_pow2(&two64, NOVA_LIMB_BITS, f);
  fe_inv(&inv64, &two64, f);
  ng_pow2(&offset, NOVA_CARRY_BITS - 1u, f);
  fe_neg(&minus_offset, &offset, f);
  ng_pow2(&big, NOVA_LIMB_BITS + NOVA_CARRY_BITS - 1u, f);
  ng_bits(cs, rem_bit, rem, STEP_GADGET_BITS);
  for (k = 0; k < NOVA_LIMBS; k++)
    out[k] = r1cs_pack(cs, rem_bit + NOVA_LIMB_BITS * k, NOVA_LIMB_BITS);
  step_below_gadget(cs, rem_bit, m);
  ng_bits(cs, q_bit, q, NOVA_Q_BITS);
  qv[0] = r1cs_pack(cs, q_bit, NOVA_LIMB_BITS);
  qv[1] = r1cs_pack(cs, q_bit + NOVA_LIMB_BITS, NOVA_LIMB_BITS);
  qv[2] = q_bit[2u * NOVA_LIMB_BITS];
  for (i = 0; i < 2u; i++)
    for (j = 0; j < NOVA_LIMBS; j++)
      prod[i][j] = r1cs_mul(cs, r[i], x2[j]);
  for (k = 0; k < NOVA_COLS; k++) {
    n = 0;
    if (k < NOVA_LIMBS) {
      var[n] = x1[k];
      coeff[n++] = one;
      var[n] = out[k];
      coeff[n++] = minus_one;
    }
    for (i = 0; i < 2u; i++)
      for (j = 0; j < NOVA_LIMBS; j++)
        if (i + j == k) {
          var[n] = prod[i][j];
          coeff[n++] = one;
        }
    for (i = 0; i < 3u; i++)
      for (j = 0; j < NOVA_LIMBS; j++)
        if (i + j == k) {
          fe_from_u64(&mj, m->limb[j]);
          var[n] = qv[i];
          fe_neg(&coeff[n++], &mj, f);
        }
    if (k > 0) {
      var[n] = carry;
      coeff[n++] = one;
      var[n] = 0;
      coeff[n++] = minus_offset;
    }
    if (k + 1u < NOVA_COLS) {
      ng_eval(&val, cs, var, coeff, n);
      fe_mul(&tmp, &val, &inv64, f);
      fe_add(&val, &tmp, &offset, f);
      fe_to_u256(&cb, &val);
      ng_bits(cs, carry_bit, &cb, NOVA_CARRY_BITS);
      carry = r1cs_pack(cs, carry_bit, NOVA_CARRY_BITS);
      var[n] = carry;
      fe_neg(&coeff[n++], &two64, f);
      var[n] = 0;
      coeff[n++] = big;
    }
    ng_terms(cs, var, coeff, n);
  }
}

void nova_xfold_gadget(R1cs *cs, uint32_t out[NOVA_LIMBS], const uint32_t x1[NOVA_LIMBS],
                       const uint32_t x2[NOVA_LIMBS], const uint32_t r[2], const U256 *m) {
  U256 a;
  U256 b;
  U256 rr;
  U256 q;
  U256 rem;
  ng_join(&a, cs, x1, NOVA_LIMBS);
  ng_join(&b, cs, x2, NOVA_LIMBS);
  ng_join(&rr, cs, r, 2u);
  nova_xfold_witness(&q, &rem, &a, &b, &rr, m);
  nova_xfold_qr_gadget(cs, out, x1, x2, r, m, &q, &rem);
}

uint32_t nova_cut_gadget(R1cs *cs, uint32_t bit[STEP_GADGET_BITS], uint32_t x) {
  step_bits_gadget(cs, bit, x);
  return r1cs_pack(cs, bit, NOVA_CUT_BITS);
}

/* STATE = (NEXT[0], NEXT[1] + A, NEXT[2] + B), with A = A[0] (N 1) or
   A[0] + 2^64 A[1] (N 2), and B the same (2 rows). */
static void ng_absorb(R1cs *cs, uint32_t state[POSEIDON_WIDTH],
                      const uint32_t next[POSEIDON_WIDTH], const uint32_t *a, const uint32_t *b,
                      size_t n) {
  uint32_t var[3];
  Fe coeff[3];
  size_t i;
  fe_from_u64(&coeff[0], 1);
  fe_from_u64(&coeff[1], 1);
  ng_pow2(&coeff[2], NOVA_LIMB_BITS, cs->f);
  state[0] = next[0];
  var[0] = next[1];
  for (i = 0; i < n; i++)
    var[1 + i] = a[i];
  state[1] = ng_lin(cs, var, coeff, 1 + n);
  var[0] = next[2];
  for (i = 0; i < n; i++)
    var[1 + i] = b[i];
  state[2] = ng_lin(cs, var, coeff, 1 + n);
}

/* An input of the hash sponge: 0 (N 0), VAR[0] (N 1) or
   VAR[0] + 2^64 VAR[1] (N 2). */
typedef struct {
  uint32_t var[2];
  size_t n;
} NgInput;

/* The hash sponge on variables: NEXT is the state after the last
   permutation, and HELD is the input that waits for its pair (HAS 1). */
typedef struct {
  R1cs *cs;
  const PoseidonParams *params;
  uint32_t next[POSEIDON_WIDTH];
  NgInput held;
  int has;
} NgSponge;

static NgInput ng_input(uint32_t lo, uint32_t hi, size_t n) {
  NgInput in;
  in.var[0] = lo;
  in.var[1] = hi;
  in.n = n;
  return in;
}

/* The variable NEXT + IN (1 row), or NEXT when IN is 0 (no row). */
static uint32_t ng_add_input(R1cs *cs, uint32_t next, const NgInput *in) {
  uint32_t var[3];
  Fe coeff[3];
  if (in->n == 0u)
    return next;
  fe_from_u64(&coeff[0], 1);
  fe_from_u64(&coeff[1], 1);
  ng_pow2(&coeff[2], NOVA_LIMB_BITS, cs->f);
  var[0] = next;
  var[1] = in->var[0];
  var[2] = in->var[1];
  return ng_lin(cs, var, coeff, 1 + in->n);
}

/* One permutation of the sponge S after A goes in to state[1] and B goes
   in to state[2]. */
static void ng_hash_pair(NgSponge *s, const NgInput *a, const NgInput *b) {
  uint32_t state[POSEIDON_WIDTH];
  state[0] = s->next[0];
  state[1] = ng_add_input(s->cs, s->next[1], a);
  state[2] = ng_add_input(s->cs, s->next[2], b);
  poseidon_gadget(s->cs, s->next, state, s->params);
}

/* Adds IN to the sponge S. The second input of a pair starts a
   permutation. */
static void ng_hash_in(NgSponge *s, NgInput in) {
  if (s->has) {
    ng_hash_pair(s, &s->held, &in);
    s->has = 0;
  } else {
    s->held = in;
    s->has = 1;
  }
}

uint32_t nova_hash_gadget(R1cs *cs, uint32_t d, uint32_t i, const uint32_t *z0,
                          const uint32_t *zi, size_t z_len, const NovaVars *u,
                          const PoseidonParams *params) {
  NgSponge s;
  NgInput pad;
  uint32_t state[POSEIDON_WIDTH];
  uint32_t bit[STEP_GADGET_BITS];
  size_t k;
  unsigned j;
  pad = ng_input(0, 0, 0);
  s.cs = cs;
  s.params = params;
  s.held = pad;
  s.has = 0;
  state[0] = ng_zero(cs);
  state[1] = d;
  state[2] = i;
  poseidon_gadget(cs, s.next, state, params);
  for (k = 0; k < z_len; k++)
    ng_hash_in(&s, ng_input(z0[k], 0, 1));
  for (k = 0; k < z_len; k++)
    ng_hash_in(&s, ng_input(zi[k], 0, 1));
  ng_hash_in(&s, ng_input(u->com_w[0], 0, 1));
  ng_hash_in(&s, ng_input(u->com_w[1], 0, 1));
  ng_hash_in(&s, ng_input(u->com_e[0], 0, 1));
  ng_hash_in(&s, ng_input(u->com_e[1], 0, 1));
  ng_hash_in(&s, ng_input(u->u, 0, 1));
  for (j = 0; j < NOVA_X; j++) {
    ng_hash_in(&s, ng_input(u->x[j][0], u->x[j][1], 2));
    ng_hash_in(&s, ng_input(u->x[j][2], u->x[j][3], 2));
  }
  if (s.has)
    ng_hash_pair(&s, &s.held, &pad);
  return nova_cut_gadget(cs, bit, s.next[1]);
}

/* OUT = 1 when X is 0, else 0. 2 rows: X inv = 1 - OUT and
   X OUT = ZERO. */
static uint32_t ng_is_zero(R1cs *cs, uint32_t x, uint32_t zero) {
  Fe v;
  Fe nil;
  Fe inv;
  Fe b;
  uint32_t inv_var;
  uint32_t out;
  r1cs_value(&v, cs, x);
  fe_from_u64(&nil, 0);
  if (fe_eq(&v, &nil)) {
    inv = nil;
    fe_from_u64(&b, 1);
  } else {
    fe_inv(&inv, &v, cs->f);
    b = nil;
  }
  inv_var = r1cs_var(cs, &inv);
  out = r1cs_var(cs, &b);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, x, 1);
  r1cs_term_int(cs, R1CS_B, inv_var, 1);
  r1cs_term_int(cs, R1CS_C, 0, 1);
  r1cs_term_int(cs, R1CS_C, out, -1);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, x, 1);
  r1cs_term_int(cs, R1CS_B, out, 1);
  r1cs_term_int(cs, R1CS_C, zero, 1);
  return out;
}

/* The id flag of the point P: 1 when P = (0, 0), else 0 (nova.c keeps
   the identity as (0, 0)). 5 rows. */
static uint32_t ng_id(R1cs *cs, const uint32_t p[2], uint32_t zero) {
  uint32_t zx = ng_is_zero(cs, p[0], zero);
  uint32_t zy = ng_is_zero(cs, p[1], zero);
  return r1cs_mul(cs, zx, zy);
}

void nova_verify_gadget(R1cs *cs, NovaVars *out, uint32_t d, uint32_t h1, const NovaVars *u1,
                        const NovaVars *u2, const uint32_t com_t[2], const PoseidonParams *params,
                        const U256 *m) {
  uint32_t state[POSEIDON_WIDTH];
  uint32_t next[POSEIDON_WIDTH];
  uint32_t bit[STEP_GADGET_BITS];
  uint32_t r[2];
  uint32_t point[2];
  uint32_t safe[2];
  uint32_t sum[2];
  uint32_t t_id;
  uint32_t var[3];
  Fe coeff[3];
  NovaVars res;
  unsigned j;
  uint32_t zero = ng_zero(cs);
  state[0] = zero;
  state[1] = d;
  state[2] = h1;
  poseidon_gadget(cs, next, state, params);
  ng_absorb(cs, state, next, &u2->com_w[0], &u2->com_w[1], 1);
  poseidon_gadget(cs, next, state, params);
  for (j = 0; j < NOVA_X; j++) {
    ng_absorb(cs, state, next, &u2->x[j][0], &u2->x[j][2], 2);
    poseidon_gadget(cs, next, state, params);
  }
  ng_absorb(cs, state, next, &com_t[0], &com_t[1], 1);
  poseidon_gadget(cs, next, state, params);
  step_bits_gadget(cs, bit, next[1]);
  r[0] = r1cs_pack(cs, bit, NOVA_LIMB_BITS);
  r[1] = r1cs_pack(cs, bit + NOVA_LIMB_BITS, NOVA_LIMB_BITS);
  var[0] = u1->u;
  var[1] = r[0];
  var[2] = r[1];
  fe_from_u64(&coeff[0], 1);
  fe_from_u64(&coeff[1], 1);
  ng_pow2(&coeff[2], NOVA_LIMB_BITS, cs->f);
  res.u = ng_lin(cs, var, coeff, 3);
  ec7_mul_bits_gadget(cs, point, u2->com_w, bit, NOVA_R_BITS);
  ec7_add_id_gadget(cs, res.com_w, u1->com_w, u1->w_id, point);
  /* COM_T = (0, 0) is the identity. Then comE' = comE of U1, and the mul
     uses comW of U2 (a point of the curve) in place of COM_T. */
  t_id = ng_id(cs, com_t, zero);
  safe[0] = r1cs_select(cs, t_id, u2->com_w[0], com_t[0]);
  safe[1] = r1cs_select(cs, t_id, u2->com_w[1], com_t[1]);
  ec7_mul_bits_gadget(cs, point, safe, bit, NOVA_R_BITS);
  ec7_add_id_gadget(cs, sum, u1->com_e, u1->e_id, point);
  res.com_e[0] = r1cs_select(cs, t_id, u1->com_e[0], sum[0]);
  res.com_e[1] = r1cs_select(cs, t_id, u1->com_e[1], sum[1]);
  res.w_id = zero;
  res.e_id = r1cs_mul(cs, t_id, u1->e_id);
  for (j = 0; j < NOVA_X; j++)
    nova_xfold_gadget(cs, res.x[j], u1->x[j], u2->x[j], r, m);
  *out = res;
}
