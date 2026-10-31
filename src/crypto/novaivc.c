#include "crypto/novaivc.h"

#include "crypto/bn254.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/u256.h"

/* The base case of the running instance at i = 0. */
typedef enum { NI_BASE_DEFAULT, NI_BASE_LAST } NiBase;

/* OUT = 2^(64 K) in F (K below NOVA_LIMBS). */
static void ni_pow64(Fe *out, unsigned k, const Modulus *f) {
  U256 a;
  u256_from_u64(&a, 0);
  a.limb[k] = 1;
  (void)fe_from_u256(out, &a, f);
}

/* A variable with the value 0: 1 row 1 * (zero + 1) = 1. */
static uint32_t ni_zero(R1cs *cs) {
  Fe v;
  uint32_t zero;
  fe_from_u64(&v, 0);
  zero = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, zero, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, 0, 1);
  return zero;
}

/* OUT = 1 when X is 0, else 0. 2 rows: X inv = 1 - OUT and
   X OUT = ZERO. */
static uint32_t ni_is_zero(R1cs *cs, uint32_t x, uint32_t zero) {
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

/* OUT = X + 1: 1 row. */
static uint32_t ni_plus1(R1cs *cs, uint32_t x) {
  Fe v;
  Fe one;
  uint32_t out;
  r1cs_value(&v, cs, x);
  fe_from_u64(&one, 1);
  fe_add(&v, &v, &one, cs->f);
  out = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, x, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}

/* 1 row 1 * A = B. */
static void ni_eq(R1cs *cs, uint32_t a, uint32_t b) {
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, a, 1);
  r1cs_term_int(cs, R1CS_C, b, 1);
}

/* 1 row (1 - G) (A - B) = ZERO: A = B when G is 0. */
static void ni_eq_unless(R1cs *cs, uint32_t g, uint32_t a, uint32_t b, uint32_t zero) {
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_A, g, -1);
  r1cs_term_int(cs, R1CS_B, a, 1);
  r1cs_term_int(cs, R1CS_B, b, -1);
  r1cs_term_int(cs, R1CS_C, zero, 1);
}

/* V = the 4 limbs of 64 bits of the integer of X. For each limb: 64
   r1cs_bool and r1cs_pack (65 rows). */
static void ni_limbs(R1cs *cs, uint32_t v[NOVA_LIMBS], const Fe *x) {
  uint32_t bit[NOVA_LIMB_BITS];
  U256 a;
  Fe b;
  unsigned k;
  unsigned j;
  fe_to_u256(&a, x);
  for (k = 0; k < NOVA_LIMBS; k++) {
    for (j = 0; j < NOVA_LIMB_BITS; j++) {
      fe_from_u64(&b, (a.limb[k] >> j) & 1u);
      bit[j] = r1cs_bool(cs, &b);
    }
    v[k] = r1cs_pack(cs, bit, NOVA_LIMB_BITS);
  }
}

/* OUT = limb 0 + 2^64 limb 1 + 2^128 limb 2 + 2^192 limb 3: 1 row. */
static uint32_t ni_pack(R1cs *cs, const uint32_t limb[NOVA_LIMBS]) {
  Fe c[NOVA_LIMBS];
  Fe sum;
  Fe v;
  Fe t;
  uint32_t out;
  unsigned k;
  fe_from_u64(&sum, 0);
  for (k = 0; k < NOVA_LIMBS; k++) {
    ni_pow64(&c[k], k, cs->f);
    r1cs_value(&v, cs, limb[k]);
    fe_mul(&t, &c[k], &v, cs->f);
    fe_add(&sum, &sum, &t, cs->f);
  }
  out = r1cs_var(cs, &sum);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  for (k = 0; k < NOVA_LIMBS; k++)
    r1cs_term(cs, R1CS_B, limb[k], &c[k]);
  r1cs_term_int(cs, R1CS_C, out, 1);
  return out;
}

static void ni_point(R1cs *cs, uint32_t v[2], const G1 *p) {
  v[0] = r1cs_var(cs, &p->x);
  v[1] = r1cs_var(cs, &p->y);
}

/* The id flag of the point P: 1 when P = (0, 0), else 0 (O162 item 2:
   nova.c keeps the identity as (0, 0)). 5 rows. */
static uint32_t ni_id(R1cs *cs, const uint32_t p[2], uint32_t zero) {
  uint32_t zx = ni_is_zero(cs, p[0], zero);
  uint32_t zy = ni_is_zero(cs, p[1], zero);
  return r1cs_mul(cs, zx, zy);
}

/* The variables of the instance U: each id flag tied to its point, each
   X limb range checked. Returns 0 when u is not below the modulus of the
   system. */
static int ni_instance(R1cs *cs, NovaVars *v, const NovaInstance *u, uint32_t zero) {
  U256 a;
  U256 back;
  Fe b;
  unsigned j;
  ni_point(cs, v->com_w, &u->com_w);
  v->w_id = ni_id(cs, v->com_w, zero);
  ni_point(cs, v->com_e, &u->com_e);
  v->e_id = ni_id(cs, v->com_e, zero);
  fe_to_u256(&a, &u->u);
  fe_from_u64(&b, 0);
  (void)fe_from_u256(&b, &a, cs->f);
  fe_to_u256(&back, &b);
  v->u = r1cs_var(cs, &b);
  for (j = 0; j < NOVA_X; j++)
    ni_limbs(cs, v->x[j], &u->x[j]);
  return u256_cmp(&back, &a) == 0;
}

/* OUT = B ? BASE : FOLD on each variable (15 rows). */
static void ni_select(R1cs *cs, NovaVars *out, uint32_t b, const NovaVars *base,
                      const NovaVars *fold) {
  unsigned j;
  unsigned k;
  for (k = 0; k < 2u; k++) {
    out->com_w[k] = r1cs_select(cs, b, base->com_w[k], fold->com_w[k]);
    out->com_e[k] = r1cs_select(cs, b, base->com_e[k], fold->com_e[k]);
  }
  out->w_id = r1cs_select(cs, b, base->w_id, fold->w_id);
  out->e_id = r1cs_select(cs, b, base->e_id, fold->e_id);
  out->u = r1cs_select(cs, b, base->u, fold->u);
  for (j = 0; j < NOVA_X; j++)
    for (k = 0; k < NOVA_LIMBS; k++)
      out->x[j][k] = r1cs_select(cs, b, base->x[j][k], fold->x[j][k]);
}

/* The common part of P and S (O162 item 4). Variable 0 is the 1 of the
   base instance (an id flag of 1, u = 1). */
static int ni_step(R1cs *cs, Fe out_x[NOVA_X], Fe *z_out, const NovaStepIn *in, size_t z_len,
                   NovaStepFn step, const void *ctx, NiBase base_case) {
  uint32_t x_var[NOVA_X];
  uint32_t z0[STEP_GADGET_Z];
  uint32_t zi[STEP_GADGET_Z];
  uint32_t zsel[STEP_GADGET_Z];
  uint32_t znext[STEP_GADGET_Z];
  uint32_t t[2];
  uint32_t zero;
  uint32_t d;
  uint32_t i;
  uint32_t i1;
  uint32_t is0;
  uint32_t h_in;
  uint32_t h_out;
  uint32_t p0;
  uint32_t p1;
  NovaVars big;
  NovaVars last;
  NovaVars fold;
  NovaVars base;
  NovaVars out;
  size_t k;
  unsigned j;
  int ok;
  for (j = 0; j < NOVA_X; j++)
    x_var[j] = r1cs_var(cs, &in->x[j]);
  zero = ni_zero(cs);
  d = r1cs_var(cs, &in->d);
  i = r1cs_var(cs, &in->i);
  for (k = 0; k < STEP_GADGET_Z; k++) {
    z0[k] = zero;
    zi[k] = zero;
    zsel[k] = zero;
    znext[k] = zero;
  }
  for (k = 0; k < z_len; k++) {
    z0[k] = r1cs_var(cs, &in->z0[k]);
    zi[k] = r1cs_var(cs, &in->zi[k]);
  }
  ok = ni_instance(cs, &big, in->big, zero);
  ok = ni_instance(cs, &last, in->last, zero) && ok;
  ni_point(cs, t, &in->com_t);
  is0 = ni_is_zero(cs, i, zero);
  i1 = ni_plus1(cs, i);
  h_in = nova_hash_gadget(cs, d, i, z0, zi, z_len, &big, in->params);
  nova_verify_gadget(cs, &fold, d, h_in, &big, &last, t, in->params, in->m);
  base = last;
  switch (base_case) {
  case NI_BASE_DEFAULT:
    base.com_w[0] = zero;
    base.com_w[1] = zero;
    base.w_id = 0;
    base.com_e[0] = zero;
    base.com_e[1] = zero;
    base.e_id = 0;
    base.u = zero;
    for (j = 0; j < NOVA_X; j++)
      for (k = 0; k < NOVA_LIMBS; k++)
        base.x[j][k] = zero;
    break;
  case NI_BASE_LAST:
    base.com_e[0] = zero;
    base.com_e[1] = zero;
    base.e_id = 0;
    base.u = 0;
    break;
  }
  ni_select(cs, &out, is0, &base, &fold);
  for (k = 0; k < z_len; k++)
    zsel[k] = r1cs_select(cs, is0, z0[k], zi[k]);
  step(cs, znext, zsel, ctx);
  h_out = nova_hash_gadget(cs, d, i1, z0, znext, z_len, &out, in->params);
  p0 = ni_pack(cs, last.x[0]);
  ni_eq_unless(cs, is0, p0, h_in, zero);
  p1 = ni_pack(cs, last.x[1]);
  ni_eq(cs, p1, x_var[0]);
  ni_eq(cs, h_out, x_var[1]);
  r1cs_value(&out_x[0], cs, p1);
  r1cs_value(&out_x[1], cs, h_out);
  for (k = 0; k < z_len; k++)
    r1cs_value(&z_out[k], cs, znext[k]);
  return ok && !r1cs_full(cs);
}

int nova_primary(R1cs *cs, Fe out_x[NOVA_X], Fe z_out[STEP_GADGET_Z], const NovaStepIn *in,
                 NovaStepFn step, const void *ctx) {
  return ni_step(cs, out_x, z_out, in, STEP_GADGET_Z, step, ctx, NI_BASE_DEFAULT);
}

/* The trivial step of S: z' = z (NOVA_S_Z values). */
static void ni_trivial(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                       const void *ctx) {
  (void)cs;
  (void)ctx;
  out[0] = in[0];
}

int nova_secondary(R1cs *cs, Fe out_x[NOVA_X], Fe z_out[NOVA_S_Z], const NovaStepIn *in) {
  return ni_step(cs, out_x, z_out, in, NOVA_S_Z, ni_trivial, (const void *)0, NI_BASE_LAST);
}

/* The IVC (O162 item 5). */

/* OUT = the default instance: both points (0, 0), u = 0, X = 0. */
static void ni_default(NovaInstance *out) {
  fe_from_u64(&out->com_w.x, 0);
  out->com_w.y = out->com_w.x;
  out->com_e = out->com_w;
  out->u = out->com_w.x;
  out->x[0] = out->com_w.x;
  out->x[1] = out->com_w.x;
}

/* OUT = a step 0 dummy u: comW = P0, comE = (0, 0), u = 1, X = 0. */
static void ni_dummy(NovaInstance *out, const G1 *p0) {
  ni_default(out);
  out->com_w = *p0;
  fe_from_u64(&out->u, 1);
}

/* OUT[k] = IN[k] for k below N. */
static void ni_copy(Fe *out, const Fe *in, size_t n) {
  size_t k;
  for (k = 0; k < n; k++)
    out[k] = in[k];
}

/* OUT[k] = 0 for k below N. */
static void ni_clear(Fe *out, size_t n) {
  size_t k;
  for (k = 0; k < n; k++)
    fe_from_u64(&out[k], 0);
}

/* 1 when A = B. */
static int ni_g1_eq(const G1 *a, const G1 *b) {
  return fe_eq(&a->x, &b->x) && fe_eq(&a->y, &b->y);
}

/* The commitment key of SD with the first N generators. */
static void ni_key(NovaIvcSide *sd, size_t n) {
  sd->key.g = sd->g;
  sd->key.n = n;
  sd->key.k = sd->k;
  sd->key.bucket = sd->bucket;
  sd->key.buckets = sd->buckets;
}

/* The generator count that the last build of SD needs: the length of W
   (the variables from NOVA_W) or of E (the rows), the larger. */
static size_t ni_need(const NovaIvcSide *sd) {
  R1csSize size;
  size_t w;
  r1cs_size(&size, &sd->cs);
  w = size.vars < NOVA_W ? 0u : size.vars - NOVA_W;
  return w > size.rows ? w : size.rows;
}

/* One run of P (PRIMARY 1) or of S in a new system in SD->cs. */
static int ni_run(NovaIvcSide *sd, Fe out_x[NOVA_X], Fe *z_out, const NovaStepIn *in, int primary,
                  NovaStepFn step, const void *ctx) {
  r1cs_init(&sd->cs, sd->f, sd->z, sd->var_cap, sd->row, sd->row_cap, sd->term, sd->term_cap);
  return primary ? nova_primary(&sd->cs, out_x, z_out, in, step, ctx)
                 : nova_secondary(&sd->cs, out_x, z_out, in);
}

/* A build (O162 item 5 (2)): a run with X = 0 gives the tie values, then
   the real run with X = these values. Returns 1 when both runs pass and
   the real run holds (r1cs_check). */
static int ni_build(NovaIvcSide *sd, Fe *z_out, NovaStepIn *in, int primary, NovaStepFn step,
                    const void *ctx) {
  Fe out_x[NOVA_X];
  size_t failed;
  fe_from_u64(&in->x[0], 0);
  in->x[1] = in->x[0];
  if (!ni_run(sd, out_x, z_out, in, primary, step, ctx))
    return 0;
  in->x[0] = out_x[0];
  in->x[1] = out_x[1];
  return ni_run(sd, out_x, z_out, in, primary, step, ctx) && r1cs_check(&sd->cs, &failed);
}

/* OUT = the plain instance of the last build of SD: comW = Com(W) (the
   values from NOVA_W), comE = (0, 0), u = z[0] and X = (z[1], z[2]). */
static int ni_plain(NovaInstance *out, const NovaIvcSide *sd) {
  R1csSize size;
  r1cs_size(&size, &sd->cs);
  if (size.vars < NOVA_W || !nova_com(&out->com_w, &sd->key, sd->z + NOVA_W, size.vars - NOVA_W))
    return 0;
  fe_from_u64(&out->com_e.x, 0);
  out->com_e.y = out->com_e.x;
  out->u = sd->z[0];
  out->x[0] = sd->z[1];
  out->x[1] = sd->z[2];
  return 1;
}

/* The native NIFS (O162 item 3) of the running (BIG; W, E) with the plain
   (LAST; LW) of the circuit of SD: T = the cross term (in SD->t),
   COM_T = Com(T), r = the challenge over PARAMS (the field of the circuit
   that folds these instances) with H1, OUT = the fold of the instances,
   and (W, E) = the fold of the witness (in place). OUT can be BIG. */
static int ni_fold(NovaInstance *out, G1 *com_t, const NovaInstance *big, Fe *w, Fe *e,
                   const NovaInstance *last, const Fe *lw, const NovaIvcSide *sd,
                   const PoseidonParams *params, const Fe *d, const Fe *h1) {
  R1csSize size;
  Fe r;
  r1cs_size(&size, &sd->cs);
  if (!nova_cross(sd->t, &sd->cs, w, lw) || !nova_com(com_t, &sd->key, sd->t, size.rows))
    return 0;
  nova_challenge(&r, params, d, h1, &last->com_w, last->x, com_t);
  nova_fold_instance(out, big, last, com_t, &r, sd->f, sd->key.curve);
  nova_fold_witness(w, e, w, e, lw, sd->t, &r, size.vars, size.rows, sd->f);
  return 1;
}

/* Prove step (3) at i = 0: r_U_p = L_U_P (E = 0), and r_U_s = the default
   instance (W = 0, E = 0). */
static int ni_first(NovaIvcProof *pf, const NovaIvcKey *key, const NovaInstance *l_u_p) {
  R1csSize size;
  r1cs_size(&size, &key->p.cs);
  pf->r_u_p = *l_u_p;
  ni_copy(pf->r_w_p, key->p.z, size.vars);
  ni_clear(pf->r_e_p, size.rows);
  r1cs_size(&size, &key->s.cs);
  ni_default(&pf->r_u_s);
  ni_clear(pf->r_w_s, size.vars);
  ni_clear(pf->r_e_s, size.rows);
  return 1;
}

/* Prove step (3) at i at least 1: h1 = H_n(D, I, z0_s, z0_s, U_P), the
   fold of (U_P; r_W_p, r_E_p) with (L_U_P; the witness of the last build
   of P) into r_U_p (COM_T gets comT_p), then r_U_s = U_S. */
static int ni_next(NovaIvcProof *pf, const NovaIvcKey *key, G1 *com_t, const NovaInstance *u_p,
                   const NovaInstance *l_u_p, const NovaInstance *u_s, const Fe *i) {
  Fe h1;
  Fe z0_s[NOVA_S_Z];
  fe_from_u64(&z0_s[0], 0);
  if (!nova_hash(&h1, &key->s.params, &key->d, i, z0_s, z0_s, NOVA_S_Z, u_p) ||
      !ni_fold(&pf->r_u_p, com_t, u_p, pf->r_w_p, pf->r_e_p, l_u_p, key->p.z, &key->p,
               &key->s.params, &key->d, &h1))
    return 0;
  pf->r_u_s = *u_s;
  return 1;
}

/* Check (3) of one pair: z[0] = u and (z[1], z[2]) = X of U, and the rows
   of SD hold for (Z, E) (nova_check). */
static int ni_holds(const NovaIvcSide *sd, const NovaInstance *u, const Fe *z, const Fe *e) {
  size_t failed;
  return fe_eq(&z[0], &u->u) && fe_eq(&z[1], &u->x[0]) && fe_eq(&z[2], &u->x[1]) &&
         nova_check(&sd->cs, z, e, &failed);
}

/* Check (4) of one vector: Com(V) = PT (V of LEN values). */
static int ni_com_eq(const NovaIvcSide *sd, const Fe *v, size_t len, const G1 *pt) {
  G1 c;
  return nova_com(&c, &sd->key, v, len) && ni_g1_eq(&c, pt);
}

/* Rebuilding a circuit must preserve the shapes bound by setup. */
static int ni_shape(const NovaIvcKey *key) {
  Fe d;
  return nova_digest(&d, &key->p.cs, (uint32_t)key->p.key.n, &key->s.cs,
                     (uint32_t)key->s.key.n) && fe_eq(&d, &key->d);
}

int nova_ivc_setup(NovaIvcKey *key, NovaStepFn step, const void *ctx) {
  NovaIvcSide *p = &key->p;
  NovaIvcSide *s = &key->s;
  NovaStepIn in;
  NovaInstance big;
  NovaInstance last;
  Fe out_x[NOVA_X];
  Fe z0[STEP_GADGET_Z];
  Fe z_out[STEP_GADGET_Z];
  Fe z0_s[NOVA_S_Z];
  Fe z_s[NOVA_S_Z];
  size_t n_p;
  size_t n_s;
  size_t k;
  if (p->g_cap < 3u || s->g_cap < 3u || !nova_curve(&p->key.curve, &SECP_FP) ||
      !nova_curve(&s->key.curve, &SECP_FN))
    return 0;
  p->f = &SECP_FP;
  s->f = &SECP_FN;
  poseidon_params(&p->params, p->f);
  poseidon_params(&s->params, s->f);
  ni_key(p, 3u);
  ni_key(s, 3u);
  nova_gens(p->g, p->key.curve, 3u);
  nova_gens(s->g, s->key.curve, 3u);
  for (k = 0; k < STEP_GADGET_Z; k++)
    fe_from_u64(&z0[k], 0);
  z0_s[0] = z0[0];
  ni_default(&big);
  ni_dummy(&last, &s->g[1]);
  in.params = &p->params;
  in.m = &p->m;
  in.d = z0[0];
  in.i = z0[0];
  in.z0 = z0;
  in.zi = z0;
  in.big = &big;
  in.last = &last;
  in.com_t = s->g[2];
  in.x[0] = z0[0];
  in.x[1] = z0[0];
  if (!ni_run(p, out_x, z_out, &in, 1, step, ctx))
    return 0;
  ni_dummy(&last, &p->g[1]);
  in.params = &s->params;
  in.m = &s->m;
  in.z0 = z0_s;
  in.zi = z0_s;
  in.com_t = p->g[2];
  if (!ni_run(s, out_x, z_s, &in, 0, step, ctx))
    return 0;
  n_p = ni_need(p);
  n_s = ni_need(s);
  if (n_p > p->g_cap || n_s > s->g_cap)
    return 0;
  ni_key(p, n_p);
  ni_key(s, n_s);
  nova_gens(p->g, p->key.curve, n_p);
  nova_gens(s->g, s->key.curve, n_s);
  return nova_digest(&key->d, &p->cs, (uint32_t)n_p, &s->cs, (uint32_t)n_s);
}

void nova_ivc_start(NovaIvcProof *pf, const Fe z0[STEP_GADGET_Z]) {
  pf->k = 0;
  ni_copy(pf->z0, z0, STEP_GADGET_Z);
  ni_copy(pf->zk, z0, STEP_GADGET_Z);
  ni_default(&pf->r_u_p);
  ni_default(&pf->r_u_s);
  ni_default(&pf->l_u_s);
}

int nova_ivc_prove_step(NovaIvcProof *pf, NovaIvcKey *key, NovaStepFn step, const void *ctx) {
  NovaIvcSide *p = &key->p;
  NovaIvcSide *s = &key->s;
  NovaStepIn in;
  NovaInstance dflt;
  NovaInstance dummy;
  NovaInstance u_s;
  NovaInstance u_p;
  NovaInstance l_u_p;
  R1csSize size;
  G1 com_t;
  Fe h1;
  Fe z0_s[NOVA_S_Z];
  Fe z_s[NOVA_S_Z];
  Fe z_next[STEP_GADGET_Z];
  int base = pf->k == 0u;
  int ok;
  ni_default(&dflt);
  ni_dummy(&dummy, &s->g[1]);
  fe_from_u64(&z0_s[0], 0);
  in.d = key->d;
  fe_from_u64(&in.i, pf->k);
  /* (1) The fold of the S instances (i at least 1). */
  u_s = dflt;
  com_t = s->g[2];
  ok = base ||
       (nova_hash(&h1, &p->params, &key->d, &in.i, pf->z0, pf->zk, STEP_GADGET_Z, &pf->r_u_s) &&
        ni_fold(&u_s, &com_t, &pf->r_u_s, pf->r_w_s, pf->r_e_s, &pf->l_u_s, pf->l_w_s, s,
                &p->params, &key->d, &h1));
  /* (2) The build of P. */
  in.params = &p->params;
  in.m = &p->m;
  in.z0 = pf->z0;
  in.zi = pf->zk;
  in.big = base ? &dflt : &pf->r_u_s;
  in.last = base ? &dummy : &pf->l_u_s;
  in.com_t = com_t;
  ok = ok && ni_build(p, z_next, &in, 1, step, ctx) && ni_plain(&l_u_p, p);
  /* (3) The fold of the P instances (i = 0: r_U_p = l_u_p). */
  u_p = base ? dflt : pf->r_u_p;
  com_t = p->g[2];
  ok = ok && (base ? ni_first(pf, key, &l_u_p) : ni_next(pf, key, &com_t, &u_p, &l_u_p, &u_s, &in.i));
  /* (4) The build of S with r_U_p before the fold of (3). */
  in.params = &s->params;
  in.m = &s->m;
  in.z0 = z0_s;
  in.zi = z0_s;
  in.big = &u_p;
  in.last = &l_u_p;
  in.com_t = com_t;
  ok = ok && ni_build(s, z_s, &in, 0, step, ctx) && ni_plain(&pf->l_u_s, s);
  if (!ok || !ni_shape(key))
    return 0;
  r1cs_size(&size, &s->cs);
  ni_copy(pf->l_w_s, s->z, size.vars);
  ni_copy(pf->zk, z_next, STEP_GADGET_Z);
  pf->k = pf->k + 1u;
  return 1;
}

int nova_ivc_verify(const NovaIvcKey *key, const NovaIvcProof *pf) {
  const NovaIvcSide *p = &key->p;
  const NovaIvcSide *s = &key->s;
  R1csSize sp;
  R1csSize ss;
  Fe fk;
  Fe h;
  Fe one;
  Fe z0_s[NOVA_S_Z];
  if (pf->k == 0u || !ni_shape(key))
    return 1;
  fe_from_u64(&fk, pf->k);
  fe_from_u64(&one, 1);
  fe_from_u64(&z0_s[0], 0);
  if (!nova_hash(&h, &p->params, &key->d, &fk, pf->z0, pf->zk, STEP_GADGET_Z, &pf->r_u_s) ||
      !fe_eq(&h, &pf->l_u_s.x[0]) ||
      !nova_hash(&h, &s->params, &key->d, &fk, z0_s, z0_s, NOVA_S_Z, &pf->r_u_p) ||
      !fe_eq(&h, &pf->l_u_s.x[1]))
    return 2;
  r1cs_size(&sp, &p->cs);
  r1cs_size(&ss, &s->cs);
  if (sp.vars < NOVA_W || ss.vars < NOVA_W || !fe_eq(&pf->l_u_s.u, &one))
    return 3;
  ni_clear(s->t, ss.rows);
  if (!ni_holds(p, &pf->r_u_p, pf->r_w_p, pf->r_e_p) ||
      !ni_holds(s, &pf->r_u_s, pf->r_w_s, pf->r_e_s) || !ni_holds(s, &pf->l_u_s, pf->l_w_s, s->t))
    return 3;
  if (!ni_com_eq(p, pf->r_w_p + NOVA_W, sp.vars - NOVA_W, &pf->r_u_p.com_w) ||
      !ni_com_eq(p, pf->r_e_p, sp.rows, &pf->r_u_p.com_e) ||
      !ni_com_eq(s, pf->r_w_s + NOVA_W, ss.vars - NOVA_W, &pf->r_u_s.com_w) ||
      !ni_com_eq(s, pf->r_e_s, ss.rows, &pf->r_u_s.com_e) ||
      !ni_com_eq(s, pf->l_w_s + NOVA_W, ss.vars - NOVA_W, &pf->l_u_s.com_w))
    return 4;
  return 0;
}
