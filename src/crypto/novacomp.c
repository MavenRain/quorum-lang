/* NEW (quorum-lang S11 H4a C4): the compressed proof (novacomp.h). */

#include "crypto/novacomp.h"

#include "crypto/bn254.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/u256.h"

/* The byte counts of a value, a point, an instance and the head. */
#define NC_FE 32u
#define NC_PT 65u
#define NC_INST (2u * NC_PT + 3u * NC_FE)
#define NC_HEAD (8u + 2u * STEP_GADGET_Z * NC_FE + 3u * NC_INST + NC_PT)

/* The writer and the reader of the bytes. The callers check the length
   first, thus each access is in the buffer. */
typedef struct {
  unsigned char *out;
  size_t at;
} NcPut;

typedef struct {
  const unsigned char *in;
  size_t at;
  int ok;
} NcGet;

/* 1 when P is (0, 0), the identity. */
static int nc_zero(const G1 *p) {
  Fe z;
  fe_from_u64(&z, 0);
  return fe_eq(&p->x, &z) && fe_eq(&p->y, &z);
}

/* The base field of the points of CURVE. */
static const Modulus *nc_base(GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return &SECP_FP;
  case GENS_SECQ256K1:
    return &SECP_FN;
  }
  return &SECP_FP;
}

/* 1 when P is on CURVE. */
static int nc_on_curve(const G1 *p, GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return secp_on_curve(p);
  case GENS_SECQ256K1:
    return secq_on_curve(p);
  }
  return 0;
}

/* TS adds the field value V as the point (V, 0). */
static void nc_ts_wide(IpaTranscript *ts, const Fe *v) {
  G1 pt;
  pt.x = *v;
  fe_from_u64(&pt.y, 0);
  ipa_ts_point(ts, &pt);
}

/* TS adds the instance U: comW, comE, u, X[0] and X[1]. */
static void nc_ts_inst(IpaTranscript *ts, const NovaInstance *u) {
  ipa_ts_point(ts, &u->com_w);
  ipa_ts_point(ts, &u->com_e);
  nc_ts_wide(ts, &u->u);
  nc_ts_wide(ts, &u->x[0]);
  nc_ts_wide(ts, &u->x[1]);
}

/* TS = the start state of NOVA_COMP_DOMAIN in PARAMS, then the head of PF
   with the digest D. */
static void nc_head(IpaTranscript *ts, const PoseidonParams *params, const Fe *d,
                    const NovaCompProof *pf) {
  Fe dom;
  Fe fk;
  size_t i;
  fe_from_u64(&dom, NOVA_COMP_DOMAIN);
  fe_from_u64(&fk, (uint64_t)pf->k);
  ipa_ts_start(ts, params, &dom);
  nc_ts_wide(ts, d);
  nc_ts_wide(ts, &fk);
  for (i = 0; i < STEP_GADGET_Z; i++)
    nc_ts_wide(ts, &pf->z0[i]);
  for (i = 0; i < STEP_GADGET_Z; i++)
    nc_ts_wide(ts, &pf->zk[i]);
  nc_ts_inst(ts, &pf->r_u_p);
  nc_ts_inst(ts, &pf->r_u_s);
  nc_ts_inst(ts, &pf->l_u_s);
  ipa_ts_point(ts, &pf->com_t_s);
}

/* The last fold (plan item 2): TS = the secondary transcript after the
   head of PF, R = its 128-bit challenge, and OUT = the fold of r_U_s with
   l_u_s and comT_s. */
static void nc_fold(NovaInstance *out, Fe *r, IpaTranscript *ts, const NovaIvcKey *key,
                    const NovaCompProof *pf) {
  const NovaIvcSide *s = &key->s;
  nc_head(ts, &s->params, &key->d, pf);
  ipa_ts_challenge128(ts, r);
  nova_fold_instance(out, &pf->r_u_s, &pf->l_u_s, &pf->com_t_s, r, s->f, s->key.curve);
}

/* WK = the Spartan work space of the side CP. */
static void nc_work(SpartanWork *wk, const NovaCompSide *cp) {
  wk->fe = cp->fe;
  wk->fe_len = cp->fe_len;
  wk->gw = cp->gw;
  wk->gw_len = cp->gw_len;
}

/* Sets the pad and the IPA key of CP for the circuit of SD. */
static int nc_side_setup(NovaCompSide *cp, const NovaIvcSide *sd) {
  size_t n;
  if (!spartan_dims(&cp->d, &sd->cs))
    return 0;
  n = (size_t)1 << cp->d.c;
  return cp->g_cap >= n && cp->k_cap >= n && cp->fe_len >= spartan_work_len(&cp->d) &&
         (cp->d.c == 0u || cp->gw_len >= n / 2u) &&
         ipa_key(&cp->ipa, &sd->key, cp->d.c, cp->g, cp->k, cp->bucket, cp->buckets);
}

int nova_comp_setup(NovaCompKey *ck, const NovaIvcKey *key) {
  R1csSize ss;
  r1cs_size(&ss, &key->s.cs);
  return ss.vars <= ck->var_cap && ss.rows <= ck->row_cap && nc_side_setup(&ck->p, &key->p) &&
         nc_side_setup(&ck->s, &key->s);
}

int nova_comp_prove(NovaCompProof *out, const NovaCompKey *ck, const NovaIvcKey *key,
                    const NovaIvcProof *pf) {
  const NovaIvcSide *p = &key->p;
  const NovaIvcSide *s = &key->s;
  R1csSize ss;
  IpaTranscript tp;
  IpaTranscript ts;
  SpartanWork wp;
  SpartanWork ws;
  NovaInstance f_u_s;
  Fe r;
  size_t i;
  r1cs_size(&ss, &s->cs);
  if (pf->k == 0u || ss.vars > ck->var_cap || ss.rows > ck->row_cap ||
      !nova_cross(s->t, &s->cs, pf->r_w_s, pf->l_w_s) ||
      !nova_com(&out->com_t_s, &s->key, s->t, ss.rows))
    return 0;
  out->k = pf->k;
  for (i = 0; i < STEP_GADGET_Z; i++) {
    out->z0[i] = pf->z0[i];
    out->zk[i] = pf->zk[i];
  }
  out->r_u_p = pf->r_u_p;
  out->r_u_s = pf->r_u_s;
  out->l_u_s = pf->l_u_s;
  nc_fold(&f_u_s, &r, &ts, key, out);
  nova_fold_witness(ck->z, ck->e, pf->r_w_s, pf->r_e_s, pf->l_w_s, s->t, &r, ss.vars, ss.rows,
                    s->f);
  nc_head(&tp, &p->params, &key->d, out);
  nc_work(&wp, &ck->p);
  nc_work(&ws, &ck->s);
  return spartan_prove(&out->p, &ck->p.ipa, &tp, &p->cs, &pf->r_u_p, pf->r_w_p, pf->r_e_p, &wp) &&
         spartan_prove(&out->s, &ck->s.ipa, &ts, &s->cs, &f_u_s, ck->z, ck->e, &ws);
}

int nova_comp_verify(const NovaCompKey *ck, const NovaIvcKey *key, const NovaCompProof *pf) {
  const NovaIvcSide *p = &key->p;
  const NovaIvcSide *s = &key->s;
  IpaTranscript tp;
  IpaTranscript ts;
  SpartanWork wp;
  SpartanWork ws;
  NovaInstance f_u_s;
  Fe d;
  Fe fk;
  Fe h;
  Fe one;
  Fe r;
  Fe z0_s[NOVA_S_Z];
  int rc;
  if (pf->k == 0u ||
      !nova_digest(&d, &p->cs, (uint32_t)p->key.n, &s->cs, (uint32_t)s->key.n) ||
      !fe_eq(&d, &key->d))
    return 1;
  fe_from_u64(&fk, (uint64_t)pf->k);
  fe_from_u64(&one, 1);
  fe_from_u64(&z0_s[0], 0);
  if (!nova_hash(&h, &p->params, &key->d, &fk, pf->z0, pf->zk, STEP_GADGET_Z, &pf->r_u_s) ||
      !fe_eq(&h, &pf->l_u_s.x[0]) ||
      !nova_hash(&h, &s->params, &key->d, &fk, z0_s, z0_s, NOVA_S_Z, &pf->r_u_p) ||
      !fe_eq(&h, &pf->l_u_s.x[1]))
    return 2;
  if (!fe_eq(&pf->l_u_s.u, &one) || !nc_zero(&pf->l_u_s.com_e))
    return 3;
  nc_fold(&f_u_s, &r, &ts, key, pf);
  nc_head(&tp, &p->params, &key->d, pf);
  nc_work(&wp, &ck->p);
  nc_work(&ws, &ck->s);
  rc = spartan_verify(&ck->p.ipa, &tp, &p->cs, &pf->r_u_p, &pf->p, &wp);
  if (rc != 0)
    return 10 + rc;
  rc = spartan_verify(&ck->s.ipa, &ts, &s->cs, &f_u_s, &pf->s, &ws);
  if (rc != 0)
    return 20 + rc;
  return 0;
}

/* The byte count of the Spartan part of the pad D. */
static size_t nc_side_size(const SpartanDims *d) {
  return NC_FE * (4u * (size_t)d->a + 3u * ((size_t)d->b + 1u) + 3u * (size_t)d->c + 8u) +
         2u * NC_PT * (size_t)d->c;
}

size_t nova_comp_size(const NovaCompKey *ck) {
  return NC_HEAD + nc_side_size(&ck->p.d) + nc_side_size(&ck->s.d);
}

/* W adds the value V (32 bytes little-endian). */
static void nc_put_fe(NcPut *w, const Fe *v) {
  U256 x;
  unsigned char be[32];
  size_t i;
  fe_to_u256(&x, v);
  u256_to_be(be, &x);
  for (i = 0; i < 32u; i++)
    w->out[w->at + i] = be[31u - i];
  w->at += NC_FE;
}

/* W adds the point P (65 bytes: 0x04, x and y big-endian; the identity is
   65 zero bytes). */
static void nc_put_pt(NcPut *w, const G1 *p) {
  U256 x;
  size_t i;
  for (i = 0; i < NC_PT; i++)
    w->out[w->at + i] = 0u;
  if (!nc_zero(p)) {
    w->out[w->at] = 0x04u;
    fe_to_u256(&x, &p->x);
    u256_to_be(w->out + w->at + 1u, &x);
    fe_to_u256(&x, &p->y);
    u256_to_be(w->out + w->at + 33u, &x);
  }
  w->at += NC_PT;
}

/* W adds the instance U: comW, comE, u, X[0] and X[1]. */
static void nc_put_inst(NcPut *w, const NovaInstance *u) {
  nc_put_pt(w, &u->com_w);
  nc_put_pt(w, &u->com_e);
  nc_put_fe(w, &u->u);
  nc_put_fe(w, &u->x[0]);
  nc_put_fe(w, &u->x[1]);
}

/* W adds the Spartan part PF (the order of novacomp.h). */
static void nc_put_side(NcPut *w, const SpartanProof *pf) {
  unsigned i;
  unsigned j;
  for (i = 0; i < pf->d.a; i++)
    for (j = 0; j < 4u; j++)
      nc_put_fe(w, &pf->sc1[i][j]);
  nc_put_fe(w, &pf->va);
  nc_put_fe(w, &pf->vb);
  nc_put_fe(w, &pf->vc);
  nc_put_fe(w, &pf->ve);
  for (i = 0; i <= pf->d.b; i++)
    for (j = 0; j < 3u; j++)
      nc_put_fe(w, &pf->sc2[i][j]);
  nc_put_fe(w, &pf->vw);
  for (i = 0; i < pf->d.c; i++)
    for (j = 0; j < 3u; j++)
      nc_put_fe(w, &pf->sc3[i][j]);
  nc_put_fe(w, &pf->w);
  nc_put_fe(w, &pf->e);
  for (i = 0; i < pf->d.c; i++) {
    nc_put_pt(w, &pf->ipa.l[i]);
    nc_put_pt(w, &pf->ipa.r[i]);
  }
  nc_put_fe(w, &pf->ipa.a);
}

/* R reads a value of F into V. */
static void nc_get_fe(NcGet *r, Fe *v, const Modulus *f) {
  U256 x;
  unsigned char be[32];
  size_t i;
  for (i = 0; i < 32u; i++)
    be[i] = r->in[r->at + 31u - i];
  u256_from_be(&x, be);
  fe_from_u64(v, 0);
  if (!fe_from_u256(v, &x, f))
    r->ok = 0;
  r->at += NC_FE;
}

/* R reads a point of CURVE into P. A point with the byte 0x04 must not be
   (0, 0), thus the identity has one encoding only. */
static void nc_get_pt(NcGet *r, G1 *p, GensCurve curve) {
  const unsigned char *b = r->in + r->at;
  const Modulus *q = nc_base(curve);
  U256 x;
  U256 y;
  size_t i;
  int zero = 1;
  for (i = 0; i < NC_PT; i++)
    zero = zero && b[i] == 0;
  fe_from_u64(&p->x, 0);
  p->y = p->x;
  r->at += NC_PT;
  if (zero)
    return;
  u256_from_be(&x, b + 1);
  u256_from_be(&y, b + 33);
  if (b[0] != 0x04 || !fe_from_u256(&p->x, &x, q) || !fe_from_u256(&p->y, &y, q) ||
      nc_zero(p) || !nc_on_curve(p, curve))
    r->ok = 0;
}

/* R reads an instance of the field F and the curve CURVE into U. */
static void nc_get_inst(NcGet *r, NovaInstance *u, const Modulus *f, GensCurve curve) {
  nc_get_pt(r, &u->com_w, curve);
  nc_get_pt(r, &u->com_e, curve);
  nc_get_fe(r, &u->u, f);
  nc_get_fe(r, &u->x[0], f);
  nc_get_fe(r, &u->x[1], f);
}

/* R reads the Spartan part of the pad D into PF. */
static void nc_get_side(NcGet *r, SpartanProof *pf, const SpartanDims *d, const Modulus *f,
                        GensCurve curve) {
  unsigned i;
  unsigned j;
  pf->d = *d;
  pf->ipa.c = d->c;
  for (i = 0; i < d->a; i++)
    for (j = 0; j < 4u; j++)
      nc_get_fe(r, &pf->sc1[i][j], f);
  nc_get_fe(r, &pf->va, f);
  nc_get_fe(r, &pf->vb, f);
  nc_get_fe(r, &pf->vc, f);
  nc_get_fe(r, &pf->ve, f);
  for (i = 0; i <= d->b; i++)
    for (j = 0; j < 3u; j++)
      nc_get_fe(r, &pf->sc2[i][j], f);
  nc_get_fe(r, &pf->vw, f);
  for (i = 0; i < d->c; i++)
    for (j = 0; j < 3u; j++)
      nc_get_fe(r, &pf->sc3[i][j], f);
  nc_get_fe(r, &pf->w, f);
  nc_get_fe(r, &pf->e, f);
  for (i = 0; i < d->c; i++) {
    nc_get_pt(r, &pf->ipa.l[i], curve);
    nc_get_pt(r, &pf->ipa.r[i], curve);
  }
  nc_get_fe(r, &pf->ipa.a, f);
}

/* 1 when the pad of PF is D. */
static int nc_dims_eq(const SpartanProof *pf, const SpartanDims *d) {
  return pf->d.a == d->a && pf->d.b == d->b && pf->d.c == d->c && pf->ipa.c == d->c;
}

int nova_comp_encode(unsigned char *out, size_t len, const NovaCompKey *ck,
                     const NovaCompProof *pf) {
  NcPut w;
  size_t i;
  if (len != nova_comp_size(ck) || !nc_dims_eq(&pf->p, &ck->p.d) || !nc_dims_eq(&pf->s, &ck->s.d))
    return 0;
  for (i = 0; i < 8u; i++)
    out[i] = (unsigned char)(((uint64_t)pf->k >> (8u * i)) & 0xffu);
  w.out = out;
  w.at = 8u;
  for (i = 0; i < STEP_GADGET_Z; i++)
    nc_put_fe(&w, &pf->z0[i]);
  for (i = 0; i < STEP_GADGET_Z; i++)
    nc_put_fe(&w, &pf->zk[i]);
  nc_put_inst(&w, &pf->r_u_p);
  nc_put_inst(&w, &pf->r_u_s);
  nc_put_inst(&w, &pf->l_u_s);
  nc_put_pt(&w, &pf->com_t_s);
  nc_put_side(&w, &pf->p);
  nc_put_side(&w, &pf->s);
  return w.at == len;
}

int nova_comp_decode(NovaCompProof *out, const NovaCompKey *ck, const NovaIvcKey *key,
                     const unsigned char *in, size_t len) {
  const NovaIvcSide *p = &key->p;
  const NovaIvcSide *s = &key->s;
  NcGet r;
  uint64_t k = 0;
  size_t i;
  if (len != nova_comp_size(ck))
    return 0;
  for (i = 0; i < 8u; i++)
    k |= (uint64_t)in[i] << (8u * i);
  if ((uint64_t)(size_t)k != k)
    return 0;
  out->k = (size_t)k;
  r.in = in;
  r.at = 8u;
  r.ok = 1;
  for (i = 0; i < STEP_GADGET_Z; i++)
    nc_get_fe(&r, &out->z0[i], p->f);
  for (i = 0; i < STEP_GADGET_Z; i++)
    nc_get_fe(&r, &out->zk[i], p->f);
  nc_get_inst(&r, &out->r_u_p, p->f, p->key.curve);
  nc_get_inst(&r, &out->r_u_s, s->f, s->key.curve);
  nc_get_inst(&r, &out->l_u_s, s->f, s->key.curve);
  nc_get_pt(&r, &out->com_t_s, s->key.curve);
  nc_get_side(&r, &out->p, &ck->p.d, p->f, p->key.curve);
  nc_get_side(&r, &out->s, &ck->s.d, s->f, s->key.curve);
  return r.ok && r.at == len;
}
