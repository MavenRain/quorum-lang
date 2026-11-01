/* NEW (quorum-lang S11 H4a C3): Spartan for relaxed R1CS with the IPA
   opening (spartan.h). */
#include "crypto/spartan.h"

/* 2^K. */
static size_t sp_pow2(unsigned k) {
  return (size_t)1 << k;
}

/* The smallest K with 2^K >= N (IPA_C_MAX + 1 when N is more than
   2^IPA_C_MAX). */
static unsigned sp_log2(size_t n) {
  unsigned k = 0;
  while (k <= IPA_C_MAX && sp_pow2(k) < n)
    k++;
  return k;
}

/* V[i] = 0 for i below N. */
static void sp_zero(Fe *v, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    fe_from_u64(&v[i], 0);
}

/* ACC = ACC + X Y. */
static void sp_mac(Fe *acc, const Fe *x, const Fe *y, const Modulus *f) {
  Fe t;
  fe_mul(&t, x, y, f);
  fe_add(acc, acc, &t, f);
}

/* ACC = ACC - X Y. */
static void sp_msub(Fe *acc, const Fe *x, const Fe *y, const Modulus *f) {
  Fe t;
  Fe s;
  fe_mul(&t, x, y, f);
  fe_sub(&s, acc, &t, f);
  *acc = s;
}

/* ACC = ACC - X. */
static void sp_sub(Fe *acc, const Fe *x, const Modulus *f) {
  Fe s;
  fe_sub(&s, acc, x, f);
  *acc = s;
}

/* L = the line of entry J of the table T with the half length H: L(0) =
   T[J] and L(1) = T[J + H], as the coefficients (T[J], T[J + H] - T[J]). */
static void sp_line(Fe l[2], const Fe *t, size_t j, size_t h, const Modulus *f) {
  l[0] = t[j];
  fe_sub(&l[1], &t[j + h], &t[j], f);
}

/* S = S + the coefficients of X(T) Y(T) for the lines X and Y. */
static void sp_prod2(Fe s[3], const Fe x[2], const Fe y[2], const Modulus *f) {
  sp_mac(&s[0], &x[0], &y[0], f);
  sp_mac(&s[1], &x[0], &y[1], f);
  sp_mac(&s[1], &x[1], &y[0], f);
  sp_mac(&s[2], &x[1], &y[1], f);
}

/* The top variable of the table T (2 H values) gets the value R: T[J] =
   T[J] + R (T[J + H] - T[J]) for J below H. */
static void sp_bind(Fe *t, size_t h, const Fe *r, const Modulus *f) {
  size_t j;
  Fe l[2];
  for (j = 0; j < h; j++) {
    sp_line(l, t, j, h, f);
    sp_mac(&l[0], &l[1], r, f);
    t[j] = l[0];
  }
}

/* OUT = the polynomial S (the coefficients S[0] .. S[DEG]) at R. */
static void sp_poly_at(Fe *out, const Fe *s, unsigned deg, const Fe *r, const Modulus *f) {
  Fe acc = s[deg];
  Fe t;
  unsigned i;
  for (i = deg; i > 0; i--) {
    fe_mul(&t, &acc, r, f);
    fe_add(&acc, &t, &s[i - 1u], f);
  }
  *out = acc;
}

/* TS adds the N values of S. */
static void sp_send(IpaTranscript *ts, const Fe *s, unsigned n) {
  unsigned i;
  for (i = 0; i < n; i++)
    ipa_ts_fe(ts, &s[i]);
}

/* OUT = the next N challenges of TS. */
static void sp_challenges(Fe *out, unsigned n, IpaTranscript *ts) {
  unsigned i;
  for (i = 0; i < n; i++)
    ipa_ts_challenge(ts, &out[i]);
}

/* TS adds the instance U: comW, comE, u and X. */
static void sp_instance(IpaTranscript *ts, const NovaInstance *u) {
  unsigned i;
  ipa_ts_point(ts, &u->com_w);
  ipa_ts_point(ts, &u->com_e);
  ipa_ts_fe(ts, &u->u);
  for (i = 0; i < NOVA_X; i++)
    ipa_ts_fe(ts, &u->x[i]);
}

/* TS adds v_A, v_B, v_C and v_E of PF. */
static void sp_send_ends(IpaTranscript *ts, const SpartanProof *pf) {
  ipa_ts_fe(ts, &pf->va);
  ipa_ts_fe(ts, &pf->vb);
  ipa_ts_fe(ts, &pf->vc);
  ipa_ts_fe(ts, &pf->ve);
}

/* The column of VAR is TOP 2^b + LOW: TOP 0 and LOW = VAR - NOVA_W for a
   W variable, TOP 1 and LOW = VAR for u and X (the column map). */
static unsigned sp_top(uint32_t var) {
  return var < NOVA_W ? 1u : 0u;
}

static size_t sp_low(uint32_t var) {
  return var >= NOVA_W ? (size_t)var - NOVA_W : (size_t)var;
}

static size_t sp_col(uint32_t var, size_t nw) {
  return (size_t)sp_top(var) * nw + sp_low(var);
}

/* The end of the terms of row K (the first term of row K + 1). */
static size_t sp_row_end(const R1cs *cs, size_t k) {
  return k + 1u < cs->used.rows ? cs->row[k + 1u] : cs->used.terms;
}

/* OUT = EQX_K r_side coeff for the term T of row K (RS = r_A, r_B, r_C). */
static void sp_weight(Fe *out, const R1csTerm *t, const Fe *eqx_k, const Fe rs[3],
                      const Modulus *f) {
  Fe s;
  fe_mul(&s, eqx_k, &rs[t->side], f);
  fe_mul(out, &s, &t->coeff, f);
}

/* OUT = comW + D comE of U. */
static void sp_com(G1 *out, const NovaInstance *u, const Fe *d, GensCurve curve) {
  G1 t;
  nova_mul(&t, &u->com_e, d, curve);
  nova_add(out, &u->com_w, &t, curve);
}

/* WV = W and EV = E of the system, each 2^c values (0 after the length). */
static void sp_fill(Fe *wv, Fe *ev, size_t c2, const R1cs *cs, const Fe *z, const Fe *e) {
  size_t j;
  sp_zero(wv, c2);
  sp_zero(ev, c2);
  for (j = 0; j + NOVA_W < cs->used.vars; j++)
    wv[j] = z[NOVA_W + j];
  for (j = 0; j < cs->used.rows; j++)
    ev[j] = e[j];
}

/* Returns 1 when CS is not full, D = the pad of CS, the key has c = D->c,
   WK has the space and each term variable is in the system. */
static int sp_shape(SpartanDims *d, const IpaKey *key, const R1cs *cs, const SpartanWork *wk) {
  size_t t;
  if (r1cs_full(cs) || !spartan_dims(d, cs) || key->c != d->c ||
      wk->fe_len < spartan_work_len(d) || (d->c > 0 && wk->gw_len < sp_pow2(d->c - 1u)))
    return 0;
  for (t = 0; t < cs->used.terms; t++)
    if (cs->term[t].var >= cs->used.vars)
      return 0;
  return 1;
}

int spartan_dims(SpartanDims *out, const R1cs *cs) {
  size_t wl;
  unsigned a;
  unsigned b;
  if (cs->used.vars < NOVA_W)
    return 0;
  wl = cs->used.vars - NOVA_W;
  a = sp_log2(cs->used.rows);
  b = sp_log2(wl > NOVA_W ? wl : NOVA_W);
  if (a > IPA_C_MAX || b > IPA_C_MAX)
    return 0;
  out->a = a;
  out->b = b;
  out->c = a > b ? a : b;
  return 1;
}

size_t spartan_work_len(const SpartanDims *d) {
  size_t a2 = sp_pow2(d->a);
  size_t y4 = sp_pow2(d->b) * 4u;
  size_t c4 = sp_pow2(d->c) * 4u;
  size_t n = a2 * 5u;
  if (a2 + y4 > n)
    n = a2 + y4;
  if (c4 > n)
    n = c4;
  return n;
}

/* S = S + the coefficients of eq(X) (A(X) B(X) - U C(X) - E(X)) at entry J
   of the tables EQ, A, B, C, E (TAB, stride A2) with the half length H. */
static void sp_term1(Fe s[4], const Fe *tab, size_t a2, size_t j, size_t h, const Fe *u,
                     const Modulus *f) {
  Fe l[5][2];
  Fe q[3];
  unsigned i;
  for (i = 0; i < 5u; i++)
    sp_line(l[i], tab + i * a2, j, h, f);
  /* q = A B - u C - E. */
  fe_mul(&q[0], &l[1][0], &l[2][0], f);
  sp_msub(&q[0], u, &l[3][0], f);
  sp_sub(&q[0], &l[4][0], f);
  fe_mul(&q[1], &l[1][0], &l[2][1], f);
  sp_mac(&q[1], &l[1][1], &l[2][0], f);
  sp_msub(&q[1], u, &l[3][1], f);
  sp_sub(&q[1], &l[4][1], f);
  fe_mul(&q[2], &l[1][1], &l[2][1], f);
  /* S = S + eq q. */
  sp_mac(&s[0], &l[0][0], &q[0], f);
  sp_mac(&s[1], &l[0][0], &q[1], f);
  sp_mac(&s[1], &l[0][1], &q[0], f);
  sp_mac(&s[2], &l[0][0], &q[2], f);
  sp_mac(&s[2], &l[0][1], &q[1], f);
  sp_mac(&s[3], &l[0][1], &q[2], f);
}

/* Sum-check 1 of the prover: the tables EQ (of tau), Az, Bz, Cz and E in
   TAB (5 x 2^a values). RX = the a challenges. */
static void sp_prove1(SpartanProof *out, IpaTranscript *ts, const R1cs *cs, const NovaInstance *u,
                      const Fe *z, const Fe *e, const Fe *tau, Fe *rx, Fe *tab, const Modulus *f) {
  size_t a2 = sp_pow2(out->d.a);
  size_t k;
  size_t h;
  unsigned i;
  unsigned l;
  (void)ipa_eq(tab, tau, out->d.a, f);
  sp_zero(tab + a2, 4u * a2);
  for (k = 0; k < cs->used.rows; k++) {
    (void)nova_row(&tab[a2 + k], &tab[2u * a2 + k], &tab[3u * a2 + k], cs, z, k);
    tab[4u * a2 + k] = e[k];
  }
  for (i = 0; i < out->d.a; i++) {
    h = sp_pow2(out->d.a - 1u - i);
    sp_zero(out->sc1[i], 4u);
    for (k = 0; k < h; k++)
      sp_term1(out->sc1[i], tab, a2, k, h, &u->u, f);
    sp_send(ts, out->sc1[i], 4u);
    ipa_ts_challenge(ts, &rx[i]);
    for (l = 0; l < 5u; l++)
      sp_bind(tab + l * a2, h, &rx[i], f);
  }
  out->va = tab[a2];
  out->vb = tab[2u * a2];
  out->vc = tab[3u * a2];
  out->ve = tab[4u * a2];
}

/* Sum-check 2 of the prover: EQX (2^a values), then the tables M(r_x, .)
   and Z (2^(b + 1) values each) in FE. RY = the b + 1 challenges. */
static void sp_prove2(SpartanProof *out, IpaTranscript *ts, const R1cs *cs, const Fe *z,
                      const Fe *rx, const Fe rs[3], Fe *ry, Fe *fe, const Modulus *f) {
  size_t a2 = sp_pow2(out->d.a);
  size_t nw = sp_pow2(out->d.b);
  Fe *eqx = fe;
  Fe *mt = fe + a2;
  Fe *zt = mt + 2u * nw;
  Fe *m;
  Fe w;
  Fe lm[2];
  Fe lz[2];
  size_t j;
  size_t k;
  size_t h;
  unsigned i;
  (void)ipa_eq(eqx, rx, out->d.a, f);
  sp_zero(mt, 4u * nw);
  for (j = 0; j < cs->used.vars; j++)
    zt[sp_col((uint32_t)j, nw)] = z[j];
  for (k = 0; k < cs->used.rows; k++)
    for (j = cs->row[k]; j < sp_row_end(cs, k); j++) {
      sp_weight(&w, &cs->term[j], &eqx[k], rs, f);
      m = &mt[sp_col(cs->term[j].var, nw)];
      fe_add(m, m, &w, f);
    }
  for (i = 0; i <= out->d.b; i++) {
    h = sp_pow2(out->d.b - i);
    sp_zero(out->sc2[i], 3u);
    for (j = 0; j < h; j++) {
      sp_line(lm, mt, j, h, f);
      sp_line(lz, zt, j, h, f);
      sp_prod2(out->sc2[i], lm, lz, f);
    }
    sp_send(ts, out->sc2[i], 3u);
    ipa_ts_challenge(ts, &ry[i]);
    sp_bind(mt, h, &ry[i], f);
    sp_bind(zt, h, &ry[i], f);
  }
}

/* One round of sum-check 3 of the prover on the tables TW, TE, W and E
   (TAB, stride C2) with the half length H: S, then R = the challenge. */
static void sp_round3(Fe s[3], IpaTranscript *ts, Fe *r, Fe *tab, size_t c2, size_t h,
                      const Fe *g, const Modulus *f) {
  Fe sw[3];
  Fe se[3];
  Fe x[2];
  Fe y[2];
  size_t j;
  unsigned l;
  sp_zero(sw, 3u);
  sp_zero(se, 3u);
  for (j = 0; j < h; j++) {
    sp_line(x, tab, j, h, f);
    sp_line(y, tab + 2u * c2, j, h, f);
    sp_prod2(sw, x, y, f);
    sp_line(x, tab + c2, j, h, f);
    sp_line(y, tab + 3u * c2, j, h, f);
    sp_prod2(se, x, y, f);
  }
  for (l = 0; l < 3u; l++) {
    s[l] = sw[l];
    sp_mac(&s[l], g, &se[l], f);
  }
  sp_send(ts, s, 3u);
  ipa_ts_challenge(ts, r);
  for (l = 0; l < 4u; l++)
    sp_bind(tab + l * c2, h, r, f);
}

/* v_W, sum-check 3 and the IPA of the prover: the tables TW = eq(r_y', .),
   TE = eq(r_x, .), W and E (2^c values each, 0 after the length). */
static int sp_prove3(SpartanProof *out, const IpaKey *key, IpaTranscript *ts, const R1cs *cs,
                     const NovaInstance *u, const Fe *z, const Fe *e, const Fe *rx, const Fe *ry,
                     const SpartanWork *wk) {
  const Modulus *f = key->f;
  size_t c2 = sp_pow2(out->d.c);
  size_t nw = sp_pow2(out->d.b);
  Fe *tw = wk->fe;
  Fe *tq = tw + c2;
  Fe *wv = tq + c2;
  Fe *ev = wv + c2;
  Fe rho[IPA_C_MAX];
  Fe g;
  Fe d;
  Fe v;
  G1 com;
  size_t j;
  unsigned i;
  sp_zero(tw, 2u * c2);
  (void)ipa_eq(tw, ry + 1, out->d.b, f);
  (void)ipa_eq(tq, rx, out->d.a, f);
  sp_fill(wv, ev, c2, cs, z, e);
  sp_zero(&out->vw, 1u);
  for (j = 0; j < nw; j++)
    sp_mac(&out->vw, &tw[j], &wv[j], f);
  ipa_ts_fe(ts, &out->vw);
  ipa_ts_challenge(ts, &g);
  for (i = 0; i < out->d.c; i++)
    sp_round3(out->sc3[i], ts, &rho[i], tw, c2, sp_pow2(out->d.c - 1u - i), &g, f);
  out->w = wv[0];
  out->e = ev[0];
  ipa_ts_fe(ts, &out->w);
  ipa_ts_fe(ts, &out->e);
  ipa_ts_challenge(ts, &d);
  /* The IPA vector W + d E in WV; TW is the B work space of the IPA. */
  sp_fill(wv, ev, c2, cs, z, e);
  for (j = 0; j < cs->used.rows; j++)
    sp_mac(&wv[j], &d, &ev[j], f);
  sp_com(&com, u, &d, key->curve);
  v = out->w;
  sp_mac(&v, &d, &out->e, f);
  return ipa_prove(&out->ipa, key, ts, &com, wv, tw, rho, &v, wk->gw);
}

int spartan_prove(SpartanProof *out, const IpaKey *key, IpaTranscript *ts, const R1cs *cs,
                  const NovaInstance *u, const Fe *z, const Fe *e, const SpartanWork *wk) {
  Fe tau[IPA_C_MAX];
  Fe rx[IPA_C_MAX];
  Fe ry[IPA_C_MAX + 1u];
  Fe rs[3];
  if (!sp_shape(&out->d, key, cs, wk))
    return 0;
  sp_instance(ts, u);
  sp_challenges(tau, out->d.a, ts);
  sp_prove1(out, ts, cs, u, z, e, tau, rx, wk->fe, key->f);
  sp_send_ends(ts, out);
  sp_challenges(rs, 3u, ts);
  sp_prove2(out, ts, cs, z, rx, rs, ry, wk->fe, key->f);
  return sp_prove3(out, key, ts, cs, u, z, e, rx, ry, wk);
}

/* The verifier side of one round: checks S(0) + S(1) = CLAIM, TS adds S,
   R = the challenge and CLAIM = S(R). Returns 1 when the check holds. */
static int sp_round(Fe *claim, Fe *r, IpaTranscript *ts, const Fe *s, unsigned deg,
                    const Modulus *f) {
  Fe sum = s[0];
  unsigned i;
  for (i = 0; i <= deg; i++)
    fe_add(&sum, &sum, &s[i], f);
  if (!fe_eq(&sum, claim))
    return 0;
  sp_send(ts, s, deg + 1u);
  ipa_ts_challenge(ts, r);
  sp_poly_at(claim, s, deg, r, f);
  return 1;
}

/* The last check of sum-check 1: eq(tau, r_x) (v_A v_B - u v_C - v_E) =
   CLAIM. */
static int sp_check1(const SpartanProof *pf, const NovaInstance *u, const Fe *tau, const Fe *rx,
                     const Fe *claim, const Modulus *f) {
  Fe x;
  Fe q;
  Fe t;
  ipa_eq_at(&x, tau, rx, pf->d.a, f);
  fe_mul(&q, &pf->va, &pf->vb, f);
  sp_msub(&q, &u->u, &pf->vc, f);
  sp_sub(&q, &pf->ve, f);
  fe_mul(&t, &x, &q, f);
  return fe_eq(&t, claim);
}

/* The last check of sum-check 2: M~(r_x, r_y) Z~(r_y) = CLAIM, with EQX
   (2^a values) and EQB = eq(r_y', .) (2^b values) in FE. */
static int sp_check2(const SpartanProof *pf, const R1cs *cs, const NovaInstance *u, const Fe *rx,
                     const Fe *ry, const Fe rs[3], const Fe *claim, Fe *fe, const Modulus *f) {
  size_t a2 = sp_pow2(pf->d.a);
  Fe *eqx = fe;
  Fe *eqb = fe + a2;
  /* SD[0] = 1 - y_0 for the W columns, SD[1] = y_0 for u and X. */
  Fe sd[2];
  Fe acc[2];
  Fe one;
  Fe w;
  Fe mv;
  Fe zv;
  size_t k;
  size_t j;
  uint32_t var;
  (void)ipa_eq(eqx, rx, pf->d.a, f);
  (void)ipa_eq(eqb, ry + 1, pf->d.b, f);
  fe_from_u64(&one, 1);
  fe_sub(&sd[0], &one, &ry[0], f);
  sd[1] = ry[0];
  sp_zero(acc, 2u);
  for (k = 0; k < cs->used.rows; k++)
    for (j = cs->row[k]; j < sp_row_end(cs, k); j++) {
      var = cs->term[j].var;
      sp_weight(&w, &cs->term[j], &eqx[k], rs, f);
      sp_mac(&acc[sp_top(var)], &w, &eqb[sp_low(var)], f);
    }
  fe_mul(&mv, &sd[0], &acc[0], f);
  sp_mac(&mv, &sd[1], &acc[1], f);
  /* Z~(r_y) = (1 - y_0) v_W + y_0 P~(r_y') with P = (u, X_0, X_1). */
  fe_mul(&w, &eqb[0], &u->u, f);
  for (var = 1; var < NOVA_W; var++)
    sp_mac(&w, &eqb[var], &u->x[var - 1u], f);
  fe_mul(&zv, &sd[0], &pf->vw, f);
  sp_mac(&zv, &sd[1], &w, f);
  fe_mul(&w, &mv, &zv, f);
  return fe_eq(&w, claim);
}

/* OUT = the product of (1 - R[i]) for i below N. */
static void sp_low_at(Fe *out, const Fe *r, unsigned n, const Modulus *f) {
  Fe one;
  Fe t;
  Fe s;
  unsigned i;
  fe_from_u64(&one, 1);
  *out = one;
  for (i = 0; i < n; i++) {
    fe_sub(&t, &one, &r[i], f);
    fe_mul(&s, out, &t, f);
    *out = s;
  }
}

/* The last check of sum-check 3: TW~(rho) w + G TE~(rho) e = CLAIM. A
   table of 2^k values in 2^c values has TW~(rho) = the product of
   (1 - rho_i) for i below c - k, times eq(r, rho_(c - k) ..). */
static int sp_check3(const SpartanProof *pf, const Fe *rx, const Fe *ry, const Fe *rho,
                     const Fe *g, const Fe *claim, const Modulus *f) {
  unsigned a = pf->d.a;
  unsigned b = pf->d.b;
  unsigned c = pf->d.c;
  Fe x;
  Fe y;
  Fe tw;
  Fe te;
  Fe s;
  Fe t;
  sp_low_at(&x, rho, c - b, f);
  ipa_eq_at(&y, ry + 1, rho + (c - b), b, f);
  fe_mul(&tw, &x, &y, f);
  sp_low_at(&x, rho, c - a, f);
  ipa_eq_at(&y, rx, rho + (c - a), a, f);
  fe_mul(&te, &x, &y, f);
  fe_mul(&s, &tw, &pf->w, f);
  fe_mul(&t, &te, &pf->e, f);
  sp_mac(&s, g, &t, f);
  return fe_eq(&s, claim);
}

int spartan_verify(const IpaKey *key, IpaTranscript *ts, const R1cs *cs, const NovaInstance *u,
                   const SpartanProof *pf, const SpartanWork *wk) {
  const Modulus *f = key->f;
  SpartanDims d;
  Fe tau[IPA_C_MAX];
  Fe rx[IPA_C_MAX];
  Fe ry[IPA_C_MAX + 1u];
  Fe rho[IPA_C_MAX];
  Fe rs[3];
  Fe claim;
  Fe g;
  Fe dd;
  Fe v;
  G1 com;
  unsigned i;
  if (!sp_shape(&d, key, cs, wk) || pf->d.a != d.a || pf->d.b != d.b || pf->d.c != d.c)
    return 1;
  sp_instance(ts, u);
  sp_challenges(tau, d.a, ts);
  fe_from_u64(&claim, 0);
  for (i = 0; i < d.a; i++)
    if (!sp_round(&claim, &rx[i], ts, pf->sc1[i], 3u, f))
      return 2;
  if (!sp_check1(pf, u, tau, rx, &claim, f))
    return 3;
  sp_send_ends(ts, pf);
  sp_challenges(rs, 3u, ts);
  fe_mul(&claim, &rs[0], &pf->va, f);
  sp_mac(&claim, &rs[1], &pf->vb, f);
  sp_mac(&claim, &rs[2], &pf->vc, f);
  for (i = 0; i <= d.b; i++)
    if (!sp_round(&claim, &ry[i], ts, pf->sc2[i], 2u, f))
      return 4;
  if (!sp_check2(pf, cs, u, rx, ry, rs, &claim, wk->fe, f))
    return 5;
  ipa_ts_fe(ts, &pf->vw);
  ipa_ts_challenge(ts, &g);
  claim = pf->vw;
  sp_mac(&claim, &g, &pf->ve, f);
  for (i = 0; i < d.c; i++)
    if (!sp_round(&claim, &rho[i], ts, pf->sc3[i], 2u, f))
      return 6;
  if (!sp_check3(pf, rx, ry, rho, &g, &claim, f))
    return 7;
  ipa_ts_fe(ts, &pf->w);
  ipa_ts_fe(ts, &pf->e);
  ipa_ts_challenge(ts, &dd);
  sp_com(&com, u, &dd, key->curve);
  v = pf->w;
  sp_mac(&v, &dd, &pf->e, f);
  return ipa_verify(key, ts, &com, rho, &v, &pf->ipa, wk->fe) == 0 ? 0 : 8;
}
