/* NEW (quorum-lang S11 H3a, Q-S11-8 (a)): see crypto/r1cs.h. */
#include "crypto/r1cs.h"

void r1cs_init(R1cs *cs, const Modulus *f, Fe *z, size_t var_cap, size_t *row,
               size_t row_cap, R1csTerm *term, size_t term_cap) {
  Fe one;
  cs->f = f;
  cs->z = z;
  cs->row = row;
  cs->term = term;
  cs->cap.vars = var_cap;
  cs->cap.rows = row_cap;
  cs->cap.terms = term_cap;
  cs->used.vars = 0;
  cs->used.rows = 0;
  cs->used.terms = 0;
  fe_from_u64(&one, 1);
  r1cs_var(cs, &one);
}

void r1cs_size(R1csSize *out, const R1cs *cs) { *out = cs->used; }

int r1cs_full(const R1cs *cs) {
  return cs->used.vars > cs->cap.vars || cs->used.rows > cs->cap.rows ||
         cs->used.terms > cs->cap.terms;
}

uint32_t r1cs_var(R1cs *cs, const Fe *v) {
  size_t i = cs->used.vars;
  if (i < cs->cap.vars) cs->z[i] = *v;
  cs->used.vars = i + 1;
  return (uint32_t)i;
}

void r1cs_value(Fe *out, const R1cs *cs, uint32_t var) {
  Fe zero = {{0}};
  *out = var < cs->used.vars && var < cs->cap.vars ? cs->z[var] : zero;
}

void r1cs_row(R1cs *cs) {
  size_t i = cs->used.rows;
  if (i < cs->cap.rows) cs->row[i] = cs->used.terms;
  cs->used.rows = i + 1;
}

void r1cs_term(R1cs *cs, R1csSide side, uint32_t var, const Fe *c) {
  size_t i = cs->used.terms;
  if (i < cs->cap.terms) {
    cs->term[i].var = var;
    cs->term[i].side = side;
    cs->term[i].coeff = *c;
  }
  cs->used.terms = i + 1;
}

void r1cs_term_int(R1cs *cs, R1csSide side, uint32_t var, int32_t c) {
  Fe v;
  int64_t wide = c;
  fe_from_u64(&v, (uint64_t)(wide < 0 ? -wide : wide));
  if (wide < 0) fe_neg(&v, &v, cs->f);
  r1cs_term(cs, side, var, &v);
}

static Fe *side_sum(Fe sum[3], R1csSide side) {
  switch (side) {
  case R1CS_A:
    return &sum[0];
  case R1CS_B:
    return &sum[1];
  case R1CS_C:
    return &sum[2];
  }
  return &sum[2];
}

/* 1 when row I holds. */
static int row_holds(const R1cs *cs, size_t i) {
  Fe sum[3] = {{{0}}, {{0}}, {{0}}};
  Fe part;
  Fe ab;
  size_t end = i + 1 < cs->used.rows ? cs->row[i + 1] : cs->used.terms;
  size_t k;
  for (k = cs->row[i]; k < end; k++) {
    const R1csTerm *t = &cs->term[k];
    Fe *s = side_sum(sum, t->side);
    if (t->var >= cs->used.vars) return 0;
    fe_mul(&part, &t->coeff, &cs->z[t->var], cs->f);
    fe_add(s, s, &part, cs->f);
  }
  fe_mul(&ab, &sum[0], &sum[1], cs->f);
  return fe_eq(&ab, &sum[2]);
}

int r1cs_check(const R1cs *cs, size_t *failed) {
  Fe one;
  size_t i;
  fe_from_u64(&one, 1);
  if (r1cs_full(cs) || !fe_eq(&cs->z[0], &one)) {
    *failed = cs->used.rows;
    return 0;
  }
  for (i = 0; i < cs->used.rows; i++) {
    if (!row_holds(cs, i)) {
      *failed = i;
      return 0;
    }
  }
  return 1;
}

void r1cs_assert_bool(R1cs *cs, uint32_t b) {
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, b, 1);
  r1cs_term_int(cs, R1CS_B, b, 1);
  r1cs_term_int(cs, R1CS_C, b, 1);
}

uint32_t r1cs_bool(R1cs *cs, const Fe *v) {
  uint32_t b = r1cs_var(cs, v);
  r1cs_assert_bool(cs, b);
  return b;
}

uint32_t r1cs_mul(R1cs *cs, uint32_t x, uint32_t y) {
  Fe vx;
  Fe vy;
  Fe v;
  uint32_t out;
  r1cs_value(&vx, cs, x);
  r1cs_value(&vy, cs, y);
  fe_mul(&v, &vx, &vy, cs->f);
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, x, 1);
  r1cs_term_int(cs, R1CS_B, y, 1);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}

uint32_t r1cs_select(R1cs *cs, uint32_t b, uint32_t x, uint32_t y) {
  Fe vb;
  Fe vx;
  Fe vy;
  Fe v;
  uint32_t out;
  r1cs_value(&vb, cs, b);
  r1cs_value(&vx, cs, x);
  r1cs_value(&vy, cs, y);
  fe_sub(&v, &vx, &vy, cs->f);
  fe_mul(&v, &vb, &v, cs->f);
  fe_add(&v, &v, &vy, cs->f);
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, b, 1);
  r1cs_term_int(cs, R1CS_B, x, 1);
  r1cs_term_int(cs, R1CS_B, y, -1);
  r1cs_term_int(cs, R1CS_C, out, 1);
  r1cs_term_int(cs, R1CS_C, y, -1);
  return out;
}

uint32_t r1cs_xor(R1cs *cs, uint32_t a, uint32_t b) {
  Fe va;
  Fe vb;
  Fe ab;
  Fe v;
  uint32_t out;
  r1cs_value(&va, cs, a);
  r1cs_value(&vb, cs, b);
  fe_mul(&ab, &va, &vb, cs->f);
  fe_add(&v, &va, &vb, cs->f);
  fe_sub(&v, &v, &ab, cs->f);
  fe_sub(&v, &v, &ab, cs->f);
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, a, 2);
  r1cs_term_int(cs, R1CS_B, b, 1);
  r1cs_term_int(cs, R1CS_C, a, 1);
  r1cs_term_int(cs, R1CS_C, b, 1);
  r1cs_term_int(cs, R1CS_C, out, -1);
  return out;
}

uint32_t r1cs_pack(R1cs *cs, const uint32_t *bit, size_t n) {
  Fe v = {{0}};
  Fe weight;
  Fe vb;
  uint32_t out;
  size_t i;
  fe_from_u64(&weight, 1);
  for (i = 0; i < n; i++) {
    r1cs_value(&vb, cs, bit[i]);
    fe_mul(&vb, &vb, &weight, cs->f);
    fe_add(&v, &v, &vb, cs->f);
    fe_add(&weight, &weight, &weight, cs->f);
  }
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  fe_from_u64(&weight, 1);
  for (i = 0; i < n; i++) {
    r1cs_term(cs, R1CS_A, bit[i], &weight);
    fe_add(&weight, &weight, &weight, cs->f);
  }
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}
