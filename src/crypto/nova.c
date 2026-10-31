/* NEW (quorum-lang S11 H3c C2): the native parts of Nova (see nova.h). */
#include "crypto/nova.h"

#include <string.h>

#include "crypto/msm.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/sha256.h"

/* D, H1, the x and y of comW2, 2 limbs for each X value, the x and y of
   comT. */
#define CHALLENGE_INPUTS (4u + 2u * NOVA_X + 2u)

static const char params_tag[] = "quorum-lang/ivc/params/v1";
static const char gens_tag[] = "quorum-lang/ivc/gens/v1";

static void identity(G1 *out) {
  fe_from_u64(&out->x, 0);
  fe_from_u64(&out->y, 0);
}

static int is_identity(const G1 *p) {
  G1 id;
  identity(&id);
  return fe_eq(&p->x, &id.x) && fe_eq(&p->y, &id.y);
}

int nova_curve(GensCurve *out, const Modulus *f) {
  if (memcmp(f->w, SECP_FP.w, sizeof f->w) == 0) {
    *out = GENS_SECQ256K1;
    return 1;
  }
  if (memcmp(f->w, SECP_FN.w, sizeof f->w) == 0) {
    *out = GENS_SECP256K1;
    return 1;
  }
  return 0;
}

const Modulus *nova_base(GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return &SECP_FP;
  case GENS_SECQ256K1:
    return &SECQ_FB;
  }
  return &SECP_FP;
}

void nova_gens(G1 *out, GensCurve curve, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    gens_point(&out[i], curve, (uint32_t)i);
}

void nova_add(G1 *out, const G1 *a, const G1 *b, GensCurve curve) {
  G1 sum;
  if (is_identity(a)) {
    *out = *b;
    return;
  }
  if (is_identity(b)) {
    *out = *a;
    return;
  }
  identity(&sum);
  switch (curve) {
  case GENS_SECP256K1:
    secp_add(&sum, a, b);
    break;
  case GENS_SECQ256K1:
    secq_add(&sum, a, b);
    break;
  }
  *out = sum;
}

void nova_mul(G1 *out, const G1 *p, const Fe *k, GensCurve curve) {
  G1 prod;
  U256 x;
  identity(&prod);
  fe_to_u256(&x, k);
  if (!is_identity(p)) {
    switch (curve) {
    case GENS_SECP256K1:
      secp_mul(&prod, p, &x);
      break;
    case GENS_SECQ256K1:
      secq_mul(&prod, p, &x);
      break;
    }
  }
  *out = prod;
}

int nova_com(G1 *out, const NovaKey *key, const Fe *v, size_t len) {
  size_t i;
  if (len > key->n)
    return 0;
  if (len == 0) {
    identity(out);
    return 1;
  }
  for (i = 0; i < len; i++)
    fe_to_u256(&key->k[i], &v[i]);
  return msm(out, key->g, key->k, len, key->bucket, key->buckets, nova_base(key->curve));
}

/* SHA-256 over a byte stream, on sha256_initial and sha256_compress, for
   the digest of the large systems (no copy of the bytes). */
typedef struct {
  uint32_t state[8];
  unsigned char block[64];
  size_t fill;
  uint64_t size;
} NovaSha;

static void sha_start(NovaSha *s) {
  sha256_initial(s->state);
  s->fill = 0;
  s->size = 0;
}

static void sha_byte(NovaSha *s, unsigned char b) {
  s->block[s->fill] = b;
  s->fill++;
  s->size++;
  if (s->fill == sizeof s->block) {
    sha256_compress(s->state, s->block);
    s->fill = 0;
  }
}

static void sha_bytes(NovaSha *s, const unsigned char *b, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    sha_byte(s, b[i]);
}

static void sha_be32(NovaSha *s, uint32_t v) {
  unsigned i;
  for (i = 0; i < 4; i++)
    sha_byte(s, (unsigned char)(v >> (24 - 8 * i)));
}

static void sha_tag(NovaSha *s, const char *tag) {
  sha_bytes(s, (const unsigned char *)tag, strlen(tag));
  sha_byte(s, 0);
}

static void sha_end(NovaSha *s, unsigned char digest[32]) {
  uint64_t bits = s->size * 8u;
  unsigned i;
  sha_byte(s, 0x80);
  while (s->fill != 56)
    sha_byte(s, 0);
  for (i = 0; i < 8; i++)
    sha_byte(s, (unsigned char)(bits >> (56 - 8 * i)));
  for (i = 0; i < 32; i++)
    digest[i] = (unsigned char)(s->state[i / 4] >> (24 - 8 * (i % 4)));
}

/* The end of the terms of row K (the start of the next row, or the term
   count after the last row). */
static size_t row_end(const R1cs *cs, size_t k) {
  return k + 1 < cs->used.rows ? cs->row[k + 1] : cs->used.terms;
}

static unsigned char side_byte(R1csSide side) {
  switch (side) {
  case R1CS_A:
    return 0;
  case R1CS_B:
    return 1;
  case R1CS_C:
    return 2;
  }
  return 3;
}

static void sha_system(NovaSha *s, const R1cs *cs) {
  size_t k;
  size_t j;
  sha_be32(s, (uint32_t)cs->used.vars);
  sha_be32(s, (uint32_t)cs->used.rows);
  sha_be32(s, (uint32_t)cs->used.terms);
  for (k = 0; k < cs->used.rows; k++)
    for (j = cs->row[k]; j < row_end(cs, k); j++) {
      unsigned char be[32];
      U256 c;
      sha_be32(s, (uint32_t)k);
      sha_byte(s, side_byte(cs->term[j].side));
      sha_be32(s, cs->term[j].var);
      fe_to_u256(&c, &cs->term[j].coeff);
      u256_to_be(be, &c);
      sha_bytes(s, be, sizeof be);
    }
}

int nova_digest(Fe *out, const R1cs *p, uint32_t n_p, const R1cs *s, uint32_t n_s) {
  NovaSha sha;
  unsigned char digest[32];
  U256 x;
  if (r1cs_full(p) || r1cs_full(s))
    return 0;
  sha_start(&sha);
  sha_tag(&sha, params_tag);
  sha_tag(&sha, gens_tag);
  sha_be32(&sha, n_p);
  sha_be32(&sha, n_s);
  sha_system(&sha, p);
  sha_system(&sha, s);
  sha_end(&sha, digest);
  digest[0] &= (unsigned char)(0xffu >> (256u - NOVA_CUT_BITS));
  u256_from_be(&x, digest);
  (void)fe_from_u256(out, &x, p->f);
  return 1;
}

int nova_row(Fe *a, Fe *b, Fe *c, const R1cs *cs, const Fe *z, size_t k) {
  size_t j;
  int known = 1;
  fe_from_u64(a, 0);
  fe_from_u64(b, 0);
  fe_from_u64(c, 0);
  for (j = cs->row[k]; j < row_end(cs, k); j++) {
    const R1csTerm *term = &cs->term[j];
    Fe part;
    if (term->var >= cs->used.vars) {
      known = 0;
      continue;
    }
    fe_mul(&part, &term->coeff, &z[term->var], cs->f);
    switch (term->side) {
    case R1CS_A:
      fe_add(a, a, &part, cs->f);
      break;
    case R1CS_B:
      fe_add(b, b, &part, cs->f);
      break;
    case R1CS_C:
      fe_add(c, c, &part, cs->f);
      break;
    }
  }
  return known;
}

int nova_check(const R1cs *cs, const Fe *z, const Fe *e, size_t *failed) {
  size_t k;
  if (r1cs_full(cs)) {
    *failed = cs->used.rows;
    return 0;
  }
  for (k = 0; k < cs->used.rows; k++) {
    Fe a, b, c, ab, uc;
    int known = nova_row(&a, &b, &c, cs, z, k);
    fe_mul(&ab, &a, &b, cs->f);
    fe_mul(&uc, &z[0], &c, cs->f);
    fe_add(&uc, &uc, &e[k], cs->f);
    if (!known || !fe_eq(&ab, &uc)) {
      *failed = k;
      return 0;
    }
  }
  return 1;
}

int nova_instance(NovaInstance *out, const NovaKey *key, const R1cs *cs, const Fe *z,
                  const Fe *e) {
  unsigned j;
  if (r1cs_full(cs) || cs->used.vars < NOVA_W)
    return 0;
  if (!nova_com(&out->com_w, key, z + NOVA_W, cs->used.vars - NOVA_W) ||
      !nova_com(&out->com_e, key, e, cs->used.rows))
    return 0;
  out->u = z[0];
  for (j = 0; j < NOVA_X; j++)
    out->x[j] = z[1 + j];
  return 1;
}

int nova_cross(Fe *t, const R1cs *cs, const Fe *z1, const Fe *z2) {
  size_t k;
  if (r1cs_full(cs))
    return 0;
  for (k = 0; k < cs->used.rows; k++) {
    Fe a1, b1, c1, a2, b2, c2, x, y;
    nova_row(&a1, &b1, &c1, cs, z1, k);
    nova_row(&a2, &b2, &c2, cs, z2, k);
    fe_mul(&x, &a1, &b2, cs->f);
    fe_mul(&y, &a2, &b1, cs->f);
    fe_add(&t[k], &x, &y, cs->f);
    fe_mul(&x, &z1[0], &c2, cs->f);
    fe_sub(&t[k], &t[k], &x, cs->f);
    fe_mul(&x, &z2[0], &c1, cs->f);
    fe_sub(&t[k], &t[k], &x, cs->f);
  }
  return 1;
}

/* OUT[0] and OUT[1] = the low and the high 128 bits of X, in F. */
static void limbs(Fe out[2], const Fe *x, const Modulus *f) {
  U256 v;
  U256 lo;
  U256 hi;
  fe_to_u256(&v, x);
  u256_from_u64(&lo, 0);
  u256_from_u64(&hi, 0);
  lo.limb[0] = v.limb[0];
  lo.limb[1] = v.limb[1];
  hi.limb[0] = v.limb[2];
  hi.limb[1] = v.limb[3];
  (void)fe_from_u256(&out[0], &lo, f);
  (void)fe_from_u256(&out[1], &hi, f);
}

void nova_challenge(Fe *r, const PoseidonParams *params, const Fe *d, const Fe *h1,
                    const G1 *com_w2, const Fe x2[NOVA_X], const G1 *com_t) {
  const Modulus *f = &params->f;
  Fe in[CHALLENGE_INPUTS];
  Fe state[POSEIDON_WIDTH];
  U256 h;
  unsigned i;
  in[0] = *d;
  in[1] = *h1;
  in[2] = com_w2->x;
  in[3] = com_w2->y;
  for (i = 0; i < NOVA_X; i++)
    limbs(&in[4 + 2 * i], &x2[i], f);
  in[4 + 2 * NOVA_X] = com_t->x;
  in[5 + 2 * NOVA_X] = com_t->y;
  for (i = 0; i < POSEIDON_WIDTH; i++)
    fe_from_u64(&state[i], 0);
  for (i = 0; i < CHALLENGE_INPUTS; i += 2) {
    fe_add(&state[1], &state[1], &in[i], f);
    fe_add(&state[2], &state[2], &in[i + 1], f);
    poseidon_perm(state, params);
  }
  fe_to_u256(&h, &state[1]);
  h.limb[2] = 0;
  h.limb[3] = 0;
  (void)fe_from_u256(r, &h, f);
}

/* The sponge of nova_hash: STATE, and HELD, the count of the inputs that
   are in state[1] and state[2] before the next permutation. */
typedef struct {
  Fe state[POSEIDON_WIDTH];
  unsigned held;
  const PoseidonParams *params;
} NovaSponge;

/* Adds X to the sponge S. The second input of a pair starts a
   permutation. */
static void sponge_in(NovaSponge *s, const Fe *x) {
  fe_add(&s->state[1 + s->held], &s->state[1 + s->held], x, &s->params->f);
  s->held++;
  if (s->held == 2u) {
    poseidon_perm(s->state, s->params);
    s->held = 0;
  }
}

int nova_hash(Fe *h, const PoseidonParams *params, const Fe *d, const Fe *i, const Fe *z0,
              const Fe *zi, size_t z_len, const NovaInstance *u) {
  const Modulus *f = &params->f;
  NovaSponge s;
  Fe pair[2];
  Fe v;
  U256 x;
  U256 back;
  size_t k;
  unsigned j;
  fe_to_u256(&x, &u->u);
  fe_from_u64(&v, 0);
  (void)fe_from_u256(&v, &x, f);
  fe_to_u256(&back, &v);
  if (u256_cmp(&back, &x) != 0)
    return 0;
  for (j = 0; j < POSEIDON_WIDTH; j++)
    fe_from_u64(&s.state[j], 0);
  s.held = 0;
  s.params = params;
  sponge_in(&s, d);
  sponge_in(&s, i);
  for (k = 0; k < z_len; k++)
    sponge_in(&s, &z0[k]);
  for (k = 0; k < z_len; k++)
    sponge_in(&s, &zi[k]);
  sponge_in(&s, &u->com_w.x);
  sponge_in(&s, &u->com_w.y);
  sponge_in(&s, &u->com_e.x);
  sponge_in(&s, &u->com_e.y);
  sponge_in(&s, &v);
  for (j = 0; j < NOVA_X; j++) {
    limbs(pair, &u->x[j], f);
    sponge_in(&s, &pair[0]);
    sponge_in(&s, &pair[1]);
  }
  if (s.held == 1u)
    poseidon_perm(s.state, params);
  fe_to_u256(&x, &s.state[1]);
  x.limb[3] &= ((uint64_t)1 << (NOVA_CUT_BITS - 192u)) - 1u;
  (void)fe_from_u256(h, &x, f);
  return 1;
}

void nova_fold_instance(NovaInstance *out, const NovaInstance *u1, const NovaInstance *u2,
                        const G1 *com_t, const Fe *r, const Modulus *f, GensCurve curve) {
  NovaInstance next;
  G1 p;
  Fe v;
  unsigned j;
  nova_mul(&p, &u2->com_w, r, curve);
  nova_add(&next.com_w, &u1->com_w, &p, curve);
  nova_mul(&p, com_t, r, curve);
  nova_add(&next.com_e, &u1->com_e, &p, curve);
  fe_mul(&v, r, &u2->u, f);
  fe_add(&next.u, &u1->u, &v, f);
  for (j = 0; j < NOVA_X; j++) {
    fe_mul(&v, r, &u2->x[j], f);
    fe_add(&next.x[j], &u1->x[j], &v, f);
  }
  *out = next;
}

void nova_fold_witness(Fe *z, Fe *e, const Fe *z1, const Fe *e1, const Fe *z2, const Fe *t,
                       const Fe *r, size_t vars, size_t rows, const Modulus *f) {
  size_t i;
  for (i = 0; i < vars; i++) {
    Fe v;
    fe_mul(&v, r, &z2[i], f);
    fe_add(&z[i], &z1[i], &v, f);
  }
  for (i = 0; i < rows; i++) {
    Fe v;
    fe_mul(&v, r, &t[i], f);
    fe_add(&e[i], &e1[i], &v, f);
  }
}
