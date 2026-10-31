/* NEW (quorum-lang S11 H3a, Q-S11-7 (a)): host regressions of the R1CS
   core and its gadgets (src/crypto/r1cs.c) over F_p and F_n of secp256k1.
   In each row, a good witness must satisfy the system, or a bad witness
   must fail it at the named row. The storage is static (Q-S11-8 (a)), but
   step_rows (H3b) takes the storage of F from a sizing run. A failed row writes `FAIL r1cs <field> <name>` to stderr. The last line
   gives the number of rows and the number of mismatches. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/ec7gadget.h"
#include "crypto/frost.h"
#include "crypto/nova.h"
#include "crypto/novagadget.h"
#include "crypto/novaivc.h"
#include "crypto/poseidongadget.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/sha256.h"
#include "crypto/sha256gadget.h"
#include "crypto/stepgadget.h"

#include "stepcase.h"

/* The SHA-256 rows need the most storage: 27001 variables, 27184 rows
   and 156584 terms (the row `sha256 sizes`). */
#define VARS 32768u
#define ROWS 32768u
#define TERMS 163840u

typedef struct {
  uint32_t rows;
  uint32_t mismatches;
} Tally;

static Fe z_space[VARS];
static size_t row_space[ROWS];
static R1csTerm term_space[TERMS];

static void row(Tally *t, const char *field, const char *name, int good) {
  t->rows++;
  if (!good) {
    t->mismatches++;
    fprintf(stderr, "FAIL r1cs %s %s\n", field, name);
  }
}

static void start(R1cs *cs, const Modulus *f) {
  r1cs_init(cs, f, z_space, VARS, row_space, ROWS, term_space, TERMS);
}

static int holds(const R1cs *cs) {
  size_t failed = 0;
  return r1cs_check(cs, &failed);
}

static int fails_at(const R1cs *cs, size_t at) {
  size_t failed = 0;
  return !r1cs_check(cs, &failed) && failed == at;
}

static int value_is(const R1cs *cs, uint32_t var, uint64_t n) {
  Fe v;
  Fe want = small(n);
  r1cs_value(&v, cs, var);
  return fe_eq(&v, &want);
}

static int size_is(const R1cs *cs, size_t vars, size_t rows, size_t terms) {
  R1csSize s;
  r1cs_size(&s, cs);
  return s.vars == vars && s.rows == rows && s.terms == terms;
}

/* The hand system x^3 + x + 5 = 35. The variables are 1, x (1), x^2 (2),
   x^3 (3) and the sum (4). Rows 0 and 1 make x^2 and x^3, row 2 makes the
   sum, row 3 sets the sum to 35. 5 variables, 4 rows, 14 terms. */
static void hand(R1cs *cs, uint64_t x) {
  Fe v = small(x);
  uint32_t ix = r1cs_var(cs, &v);
  uint32_t ix2 = r1cs_mul(cs, ix, ix);
  uint32_t ix3 = r1cs_mul(cs, ix2, ix);
  uint32_t sum;
  v = small(x * x * x + x + 5);
  sum = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, ix3, 1);
  r1cs_term_int(cs, R1CS_A, ix, 1);
  r1cs_term_int(cs, R1CS_A, 0, 5);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, sum, 1);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, sum, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, 0, 35);
}

static void hand_rows(Tally *t, const char *name, const Modulus *f) {
  R1cs cs;
  start(&cs, f);
  hand(&cs, 3);
  row(t, name, "hand good", holds(&cs) && size_is(&cs, 5, 4, 14));
  start(&cs, f);
  hand(&cs, 4);
  row(t, name, "hand x 4 bad", fails_at(&cs, 3));
  start(&cs, f);
  hand(&cs, 3);
  z_space[3] = small(28);
  row(t, name, "hand wire bad", fails_at(&cs, 1));
  r1cs_init(&cs, f, NULL, 0, NULL, 0, NULL, 0);
  hand(&cs, 3);
  row(t, name, "hand sizing", size_is(&cs, 5, 4, 14) && r1cs_full(&cs) && fails_at(&cs, 4));
  r1cs_init(&cs, f, z_space, VARS, row_space, ROWS, term_space, 13);
  hand(&cs, 3);
  row(t, name, "hand full", fails_at(&cs, 4));
  start(&cs, f);
  hand(&cs, 3);
  z_space[0] = small(2);
  row(t, name, "hand z0 bad", fails_at(&cs, 4));
  start(&cs, f);
  r1cs_row(&cs);
  r1cs_term_int(&cs, R1CS_A, 5, 0);
  r1cs_term_int(&cs, R1CS_B, 0, 1);
  row(t, name, "unknown var bad", fails_at(&cs, 0));
}

static void gadget_rows(Tally *t, const char *name, const Modulus *f) {
  R1cs cs;
  Fe v;
  uint32_t a;
  uint32_t b;
  uint32_t x;
  uint32_t y;
  uint32_t out = 0;
  uint32_t bits[8];
  unsigned i;
  int all = 1;
  for (i = 0; i < 3; i++) {
    start(&cs, f);
    v = small(i);
    r1cs_bool(&cs, &v);
    row(t, name, i == 0 ? "bool 0" : i == 1 ? "bool 1" : "bool 2 bad",
        i < 2 ? holds(&cs) : fails_at(&cs, 0));
  }
  for (i = 0; i < 2; i++) {
    start(&cs, f);
    v = small(i);
    b = r1cs_bool(&cs, &v);
    v = small(7);
    x = r1cs_var(&cs, &v);
    v = small(9);
    y = r1cs_var(&cs, &v);
    out = r1cs_select(&cs, b, x, y);
    row(t, name, i ? "select 1" : "select 0", holds(&cs) && value_is(&cs, out, i ? 7 : 9));
  }
  z_space[out] = small(9);
  row(t, name, "select bad", fails_at(&cs, 1));
  for (i = 0; i < 4; i++) {
    start(&cs, f);
    v = small(i & 1u);
    a = r1cs_bool(&cs, &v);
    v = small(i >> 1);
    b = r1cs_bool(&cs, &v);
    out = r1cs_xor(&cs, a, b);
    all = all && holds(&cs) && value_is(&cs, out, (i & 1u) ^ (i >> 1));
  }
  row(t, name, "xor table", all);
  z_space[out] = small(1);
  row(t, name, "xor bad", fails_at(&cs, 2));
  start(&cs, f);
  for (i = 0; i < 8; i++) {
    v = small((0xA5u >> i) & 1u);
    bits[i] = r1cs_bool(&cs, &v);
  }
  out = r1cs_pack(&cs, bits, 8);
  row(t, name, "pack a5", holds(&cs) && value_is(&cs, out, 0xA5u));
  z_space[out] = small(0xA4u);
  row(t, name, "pack bad", fails_at(&cs, 8));
}

/* The Poseidon gadget on the state (0, 1, 2), against poseidon_perm.
   Variables 1 to 3 are the input. Rounds 0 to 3 have 12 S-boxes (rows 0
   to 35, variables 4 to 39), so the S-box of round 4 (the first partial
   round) makes its output, variable 42, in row 38. Rows 357 to 359 make
   the output variables. */
static void poseidon_rows(Tally *t, const char *name, const Modulus *f) {
  PoseidonParams params;
  R1cs cs;
  Fe state[POSEIDON_WIDTH];
  Fe one = small(1);
  Fe v;
  uint32_t in[POSEIDON_WIDTH];
  uint32_t out[POSEIDON_WIDTH];
  unsigned i;
  int same = 1;
  poseidon_params(&params, f);
  r1cs_init(&cs, f, NULL, 0, NULL, 0, NULL, 0);
  for (i = 0; i < POSEIDON_WIDTH; i++) {
    state[i] = small(i);
    in[i] = r1cs_var(&cs, &state[i]);
  }
  poseidon_gadget(&cs, out, in, &params);
  row(t, name, "poseidon sizes", r1cs_full(&cs) && size_is(&cs, 364, 360, 2139));
  start(&cs, f);
  for (i = 0; i < POSEIDON_WIDTH; i++)
    in[i] = r1cs_var(&cs, &state[i]);
  poseidon_gadget(&cs, out, in, &params);
  poseidon_perm(state, &params);
  for (i = 0; i < POSEIDON_WIDTH; i++) {
    r1cs_value(&v, &cs, out[i]);
    same = same && fe_eq(&v, &state[i]);
  }
  row(t, name, "poseidon good", holds(&cs) && same);
  fe_add(&z_space[out[0]], &z_space[out[0]], &one, f);
  row(t, name, "poseidon out bad", fails_at(&cs, 357));
  /* Row 38 comes before row 357, so the check stops at row 38. */
  fe_add(&z_space[42], &z_space[42], &one, f);
  row(t, name, "poseidon round bad", fails_at(&cs, 38));
}

/* The bits of STATE (bit j of word i is entry 32 i + j) and of the
   big-endian words of BLOCK, as new boolean variables (1 row each). */
static void sha256_inputs(R1cs *cs, uint32_t in_state[SHA256_GADGET_STATE],
                          uint32_t in_block[SHA256_GADGET_BLOCK],
                          const uint32_t state[8], const unsigned char block[64]) {
  unsigned i;
  Fe v;
  for (i = 0; i < SHA256_GADGET_STATE; i++) {
    v = small((state[i >> 5] >> (i & 31u)) & 1u);
    in_state[i] = r1cs_bool(cs, &v);
  }
  for (i = 0; i < SHA256_GADGET_BLOCK; i++) {
    unsigned word = i >> 5;
    unsigned bit = i & 31u;
    v = small(((unsigned)block[4u * word + 3u - (bit >> 3)] >> (bit & 7u)) & 1u);
    in_block[i] = r1cs_bool(cs, &v);
  }
}

/* The SHA-256 gadget on the initial hash and the padded block of "abc",
   against sha256_compress. Variables 1 to 768 are the input bits (rows 0
   to 767). The 48 schedule words take rows 768 to 7967 and variables 769
   to 7920, so the first xor of round 0 makes variable 7921 in row 7968.
   The 64 rounds end at row 26911. The final sum of word 0 makes its 33
   bits in rows 26912 to 26944 and has its linear row at 26945. A bad row
   changes one bit to the other boolean value, so that only a row that
   uses the bit fails. */
static void sha256_rows(Tally *t, const char *name, const Modulus *f) {
  R1cs cs;
  uint32_t state[8];
  unsigned char block[64];
  uint32_t in_state[SHA256_GADGET_STATE];
  uint32_t in_block[SHA256_GADGET_BLOCK];
  uint32_t out[SHA256_GADGET_STATE];
  unsigned i;
  int same = 1;
  for (i = 0; i < 64; i++)
    block[i] = 0;
  block[0] = 'a';
  block[1] = 'b';
  block[2] = 'c';
  block[3] = 0x80u;
  block[63] = 24u;
  sha256_initial(state);
  r1cs_init(&cs, f, NULL, 0, NULL, 0, NULL, 0);
  sha256_inputs(&cs, in_state, in_block, state, block);
  sha256_gadget(&cs, out, in_state, in_block);
  row(t, name, "sha256 sizes", r1cs_full(&cs) && size_is(&cs, 27001, 27184, 156584));
  start(&cs, f);
  sha256_inputs(&cs, in_state, in_block, state, block);
  sha256_gadget(&cs, out, in_state, in_block);
  sha256_compress(state, block);
  for (i = 0; i < SHA256_GADGET_STATE; i++)
    same = same && value_is(&cs, out[i], (state[i >> 5] >> (i & 31u)) & 1u);
  row(t, name, "sha256 good", holds(&cs) && same);
  z_space[out[0]] = small((uint64_t)value_is(&cs, out[0], 0));
  row(t, name, "sha256 out bad", fails_at(&cs, 26945));
  /* Row 7968 comes before row 26945, so the check stops at row 7968. */
  z_space[7921] = small((uint64_t)value_is(&cs, 7921, 0));
  row(t, name, "sha256 round bad", fails_at(&cs, 7968));
}

/* The ec7 gadgets (O159) on y^2 = x^3 + 7 over F, against the curve
   functions of CURVE: secp256k1.c over F_p, secq256k1.c over F_n. */
typedef struct {
  void (*gen)(G1 *out);
  void (*add)(G1 *out, const G1 *a, const G1 *b);
  void (*mul)(G1 *out, const G1 *p, const U256 *k);
} Curve;

/* New variables for the coordinates of P. */
static void point_vars(R1cs *cs, uint32_t v[2], const G1 *p) {
  v[0] = r1cs_var(cs, &p->x);
  v[1] = r1cs_var(cs, &p->y);
}

/* 1 when the variables V hold the point P. */
static int point_is(const R1cs *cs, const uint32_t v[2], const G1 *p) {
  Fe x;
  Fe y;
  r1cs_value(&x, cs, v[0]);
  r1cs_value(&y, cs, v[1]);
  return fe_eq(&x, &p->x) && fe_eq(&y, &p->y);
}

/* The variables of P (1 and 2) and of the 2 limbs of the 32 big endian
   bytes KB (3: the low 16 bytes, 4: the high 16 bytes). */
static void mul_inputs(R1cs *cs, uint32_t p_var[2], uint32_t k_var[2], const G1 *p,
                       const unsigned char kb[32], const Modulus *f) {
  unsigned char half[32];
  unsigned i;
  unsigned j;
  U256 u;
  Fe v;
  point_vars(cs, p_var, p);
  for (j = 0; j < 2; j++) {
    for (i = 0; i < 32; i++)
      half[i] = i < 16 ? 0 : kb[i - 16u * j];
    u256_from_be(&u, half);
    fe_from_u256(&v, &u, f);
    k_var[j] = r1cs_var(cs, &v);
  }
}

/* The variables of P (1 and 2) and of the 128 bits of the low 16 bytes of
   the 32 big endian bytes KB (3 to 130, least significant first). */
static void bits_inputs(R1cs *cs, uint32_t p_var[2], uint32_t r_var[128], const G1 *p,
                        const unsigned char kb[32]) {
  unsigned i;
  Fe v;
  point_vars(cs, p_var, p);
  for (i = 0; i < 128; i++) {
    v = small(((unsigned)kb[31u - (i >> 3)] >> (i & 7u)) & 1u);
    r_var[i] = r1cs_var(cs, &v);
  }
}

/* P = 5 G and B = 3 G. In the add system, A is variables 1 and 2, B is 3
   and 4, and rows 0 to 3 are (x2 - x1) inv = 1, lambda, x3 and y3. In the
   double system, A is variables 1 and 2, and rows 0 to 3 are x x, lambda,
   x3 and y3. In the mul system, rows 0 to 2 are the curve check of P, rows
   3 to 258 make the bits (bit 0 is variable 7), rows 259 and 260 are the
   limb rows, and rows 2820 to 2823 are the last add (x3 in row 2822). */
static void ec7_rows(Tally *t, const char *name, const Modulus *f, const Curve *curve) {
  R1cs cs;
  G1 g;
  G1 p;
  G1 b;
  G1 want;
  U256 k;
  Fe one = small(1);
  Fe zero = small(0);
  uint32_t a_var[2];
  uint32_t b_var[2];
  uint32_t k_var[2];
  uint32_t r_var[128];
  uint32_t id_var;
  uint32_t out[2];
  unsigned char kb[32];
  unsigned i;
  curve->gen(&g);
  u256_from_u64(&k, 5);
  curve->mul(&p, &g, &k);
  u256_from_u64(&k, 3);
  curve->mul(&b, &g, &k);
  start(&cs, f);
  point_vars(&cs, a_var, &p);
  ec7_curve_gadget(&cs, a_var);
  row(t, name, "ec7 curve good", holds(&cs) && size_is(&cs, 5, 3, 10));
  fe_add(&z_space[a_var[1]], &z_space[a_var[1]], &one, f);
  row(t, name, "ec7 curve bad", fails_at(&cs, 2));
  start(&cs, f);
  point_vars(&cs, a_var, &p);
  point_vars(&cs, b_var, &b);
  ec7_add_gadget(&cs, out, a_var, b_var);
  curve->add(&want, &p, &b);
  row(t, name, "ec7 add good", holds(&cs) && size_is(&cs, 9, 4, 19) && point_is(&cs, out, &want));
  fe_add(&z_space[out[0]], &z_space[out[0]], &one, f);
  row(t, name, "ec7 add bad", fails_at(&cs, 2));
  /* A = B: x2 - x1 = 0 has no inverse, so row 0 fails for each inv. */
  start(&cs, f);
  point_vars(&cs, a_var, &p);
  point_vars(&cs, b_var, &p);
  ec7_add_gadget(&cs, out, a_var, b_var);
  row(t, name, "ec7 add same", fails_at(&cs, 0));
  start(&cs, f);
  point_vars(&cs, a_var, &p);
  ec7_double_gadget(&cs, out, a_var);
  u256_from_u64(&k, 2);
  curve->mul(&want, &p, &k);
  row(t, name, "ec7 double good", holds(&cs) && size_is(&cs, 7, 4, 15) && point_is(&cs, out, &want));
  fe_add(&z_space[out[1]], &z_space[out[1]], &one, f);
  row(t, name, "ec7 double bad", fails_at(&cs, 3));
  for (i = 0; i < 32; i++)
    kb[i] = (unsigned char)(0xc3u + 29u * i);
  u256_from_be(&k, kb);
  r1cs_init(&cs, f, NULL, 0, NULL, 0, NULL, 0);
  mul_inputs(&cs, a_var, k_var, &p, kb, f);
  ec7_mul_gadget(&cs, out, a_var, k_var);
  row(t, name, "ec7 mul sizes", r1cs_full(&cs) && size_is(&cs, 2826, 2824, 12315));
  start(&cs, f);
  mul_inputs(&cs, a_var, k_var, &p, kb, f);
  ec7_mul_gadget(&cs, out, a_var, k_var);
  curve->mul(&want, &p, &k);
  row(t, name, "ec7 mul good", holds(&cs) && point_is(&cs, out, &want));
  fe_add(&z_space[out[0]], &z_space[out[0]], &one, f);
  row(t, name, "ec7 mul bad", fails_at(&cs, 2822));
  /* Row 259 comes before row 2822, so the check stops at row 259. */
  z_space[7] = small((uint64_t)value_is(&cs, 7, 0));
  row(t, name, "ec7 mul bit bad", fails_at(&cs, 259));
  /* K = 0: K P is the identity, which has no form (O159), so the last add
     (x2 = x1) fails at row 2820. */
  for (i = 0; i < 32; i++)
    kb[i] = 0;
  start(&cs, f);
  mul_inputs(&cs, a_var, k_var, &p, kb, f);
  ec7_mul_gadget(&cs, out, a_var, k_var);
  row(t, name, "ec7 mul zero", fails_at(&cs, 2820));
  /* The scalar as 128 bits (O160), as the fold challenge r: K = the 16
     bytes 0x5a + 37 i. In the mul bits system, rows 0 to 2 are the curve
     check of P, rows 3 and 4 are Q, and row 9 + 10 i is the select of x
     for bit i. */
  for (i = 0; i < 32; i++)
    kb[i] = (unsigned char)(i < 16 ? 0u : 0x5au + 37u * i);
  u256_from_be(&k, kb);
  r1cs_init(&cs, f, NULL, 0, NULL, 0, NULL, 0);
  bits_inputs(&cs, a_var, r_var, &p, kb);
  ec7_mul_bits_gadget(&cs, out, a_var, r_var, 128);
  row(t, name, "ec7 mul bits sizes", r1cs_full(&cs) && size_is(&cs, 1416, 1286, 5655));
  start(&cs, f);
  bits_inputs(&cs, a_var, r_var, &p, kb);
  ec7_mul_bits_gadget(&cs, out, a_var, r_var, 128);
  curve->mul(&want, &p, &k);
  row(t, name, "ec7 mul bits good", holds(&cs) && point_is(&cs, out, &want));
  z_space[r_var[0]] = small((uint64_t)value_is(&cs, r_var[0], 0));
  row(t, name, "ec7 mul bits bad", fails_at(&cs, 9));
  /* The add with the identity flag (O160). A is variables 1 and 2, A_ID
     is 3 and B is 4 and 5. Row 0 is the boolean check of A_ID, rows 1 and
     2 are Q, rows 3 and 4 select the left point, rows 5 to 8 are the add,
     and rows 9 and 10 select OUT. */
  start(&cs, f);
  point_vars(&cs, a_var, &p);
  id_var = r1cs_var(&cs, &zero);
  point_vars(&cs, b_var, &b);
  ec7_add_id_gadget(&cs, out, a_var, id_var, b_var);
  curve->add(&want, &p, &b);
  row(t, name, "ec7 add id good", holds(&cs) && size_is(&cs, 16, 11, 48) && point_is(&cs, out, &want));
  fe_add(&z_space[out[0]], &z_space[out[0]], &one, f);
  row(t, name, "ec7 add id bad", fails_at(&cs, 9));
  start(&cs, f);
  a_var[0] = r1cs_var(&cs, &zero);
  a_var[1] = r1cs_var(&cs, &zero);
  id_var = r1cs_var(&cs, &one);
  point_vars(&cs, b_var, &b);
  ec7_add_id_gadget(&cs, out, a_var, id_var, b_var);
  row(t, name, "ec7 add id identity", holds(&cs) && point_is(&cs, out, &b));
  z_space[id_var] = small(2);
  row(t, name, "ec7 add id flag bad", fails_at(&cs, 0));
}

/* The storage of F, from the sizing run. */
typedef struct {
  Fe *z;
  size_t *row;
  R1csTerm *term;
  R1csSize cap;
} StepSpace;

/* New variables for the 256 bits of X, least significant first. */
static void step_u256_vars(R1cs *cs, uint32_t bit[STEP_GADGET_BITS], const U256 *x) {
  Fe b;
  size_t i;
  for (i = 0; i < STEP_GADGET_BITS; i++) {
    b = small((x->limb[i / 64u] >> (i % 64u)) & 1u);
    bit[i] = r1cs_var(cs, &b);
  }
}

/* A new system with F for the values of S. The inputs are new variables
   with no rows, so the rows of F start at row 0. */
static void step_build(R1cs *cs, const StepSpace *sp, uint32_t out[STEP_GADGET_Z], const StepCase *s) {
  uint32_t in[STEP_GADGET_Z];
  size_t i;
  r1cs_init(cs, &SECP_FP, sp->z, sp->cap.vars, sp->row, sp->cap.rows, sp->term, sp->cap.terms);
  for (i = 0; i < STEP_GADGET_Z; i++) in[i] = r1cs_var(cs, &s->in[i]);
  step_f(cs, out, in, s);
}

/* 1 when OUT holds the native new head NEXT, the count COUNT and the PK
   of S. */
static int step_out_is(const R1cs *cs, const uint32_t out[STEP_GADGET_Z], const unsigned char next[32],
                       uint64_t count, const StepCase *s) {
  Fe want[STEP_GADGET_Z];
  Fe v;
  size_t i;
  int good = 1;
  want[0] = step_fe(next + 16, 16u);
  want[1] = step_fe(next, 16u);
  want[2] = small(count);
  want[3] = s->in[3];
  want[4] = s->in[4];
  for (i = 0; i < STEP_GADGET_Z; i++) {
    r1cs_value(&v, cs, out[i]);
    good &= fe_eq(&v, &want[i]);
  }
  return good;
}

/* step_below_gadget and step_bits_gadget, then F over the 4 steps of h4
   (z chained: OUT of a step is IN of the next step; each OUT against the
   native values and each signature against frost_verify_xy), then bad
   steps on step 1, each with one changed value. The storage of F comes
   from a sizing run and is freed at the end. */
static void step_rows(Tally *t) {
  R1cs cs;
  StepSpace sp = {NULL, NULL, NULL, {0, 0, 0}};
  StepCase s;
  StepCase bad;
  R1csSize size;
  uint32_t bit[STEP_GADGET_BITS];
  uint32_t out[STEP_GADGET_Z];
  uint32_t x;
  unsigned char genesis[32];
  unsigned char zero4[32];
  unsigned char head[32];
  unsigned char next[32];
  unsigned char pk[64];
  const char *good_name[4] = {"step good 1", "step good 2", "step good 3", "step good 4"};
  Fe chain[STEP_GADGET_Z];
  Fe one = small(1);
  Fe v;
  U256 p;
  U256 c;
  G1 a;
  G1 b;
  G1 q;
  size_t i;
  size_t k;
  int good;
  step_modulus(&p, &SECP_FP);
  step_modulus(&c, &SECP_FN);
  start(&cs, &SECP_FP);
  step_u256_vars(&cs, bit, &c);
  step_below_gadget(&cs, bit, &p);
  row(t, "p", "step below good", holds(&cs));
  c = p;
  c.limb[0] += 5u; /* p + 5 (no carry) */
  start(&cs, &SECP_FP);
  step_u256_vars(&cs, bit, &c);
  step_below_gadget(&cs, bit, &p);
  row(t, "p", "step below bad", fails_at(&cs, 256u));
  c = p;
  c.limb[0] -= 1u; /* p - 1 (p is odd) */
  fe_from_u256(&v, &c, &SECP_FP);
  start(&cs, &SECP_FP);
  x = r1cs_var(&cs, &v);
  step_bits_gadget(&cs, bit, x);
  row(t, "p", "step bits good",
      holds(&cs) && value_is(&cs, bit[0], 0) && value_is(&cs, bit[1], 1) && value_is(&cs, bit[255], 1));

  memset(genesis, 0, sizeof genesis);
  memset(zero4, 0, sizeof zero4);
  step_words(genesis, step_genesis, 2u);
  step_hash2(head, genesis, zero4);
  step_case(&s, head, 0u, 0u, next);
  step_build(&cs, &sp, out, &s);
  r1cs_size(&size, &cs);
  sp.cap = size;
  sp.z = malloc(size.vars * sizeof *sp.z);
  sp.row = malloc(size.rows * sizeof *sp.row);
  sp.term = malloc(size.terms * sizeof *sp.term);
  good = sp.z != NULL && sp.row != NULL && sp.term != NULL;
  row(t, "p", "step sizes", good && size.vars == 350774u && size.rows == 353175u && size.terms == 2046207u);
  if (good) {
    for (k = 0; k < 4u; k++) {
      step_case(&s, head, k, k, next);
      if (k > 0u) memcpy(s.in, chain, sizeof chain);
      step_build(&cs, &sp, out, &s);
      for (i = 0; i < STEP_GADGET_Z; i++) r1cs_value(&chain[i], &cs, out[i]);
      step_words(pk, step_pk, 8u);
      row(t, "p", good_name[k],
          frost_verify_xy(pk, s.sig, next) == FROST_OK && holds(&cs) &&
              size_is(&cs, size.vars, size.rows, size.terms) && step_out_is(&cs, out, next, k + 1u, &s));
      memcpy(head, next, sizeof head);
    }
    step_hash2(head, genesis, zero4);
    step_case(&s, head, 0u, 0u, next);
    bad = s;
    fe_add(&bad.in[0], &s.in[0], &one, &SECP_FP);
    step_build(&cs, &sp, out, &bad);
    row(t, "p", "step head bad", fails_at(&cs, size.rows - 2u));
    bad = s;
    bad.in[2] = one;
    step_build(&cs, &sp, out, &bad);
    row(t, "p", "step count bad", fails_at(&cs, 3087u));
    bad = s;
    a.x = s.in[3];
    a.y = s.in[4];
    secp_add(&q, &a, &a);
    bad.in[3] = q.x;
    bad.in[4] = q.y;
    step_build(&cs, &sp, out, &bad);
    row(t, "p", "step pk bad", fails_at(&cs, size.rows - 2u));
    bad = s;
    secp_from_xy(&a, s.sig);
    secp_gen(&b);
    secp_add(&q, &a, &b);
    secp_to_xy(bad.sig, &q);
    step_build(&cs, &sp, out, &bad);
    row(t, "p", "step r bad", fails_at(&cs, size.rows - 2u));
    bad = s;
    bad.sig[95] ^= 1u;
    step_build(&cs, &sp, out, &bad);
    row(t, "p", "step z bad", fails_at(&cs, size.rows - 2u));
  }
  free(sp.z);
  free(sp.row);
  free(sp.term);
}

/* NEW (quorum-lang S11 H3c C2): the rows of crypto/nova.h. A system over F
   commits on the other curve of the cycle (F_p on secq256k1, F_n on
   secp256k1) with the first NOVA_N generators. On the hand system and on
   the Poseidon system: a plain instance holds, the fold of two good
   instances holds, a bad T fails at its row, and the fold equals a direct
   computation on the curve. Also the commitment of 3 values and D. */
#define NOVA_N 512u
#define NOVA_BUCKETS 255u

typedef struct {
  NovaKey key;
  PoseidonParams challenge; /* over the base field of the curve */
  const Modulus *f;
} NovaCase;

static G1 nova_g[NOVA_N];
static U256 nova_k[NOVA_N];
static EcJac nova_bucket[NOVA_BUCKETS];
static Fe nova_e0[NOVA_N];
static Fe nova_z1[NOVA_N];
static Fe nova_e1[NOVA_N];
static Fe nova_z2[NOVA_N];
static Fe nova_z3[NOVA_N];
static Fe nova_e3[NOVA_N];
static Fe nova_t[NOVA_N];
static unsigned char nova_bytes[2048];

static void nova_copy(Fe *out, const R1cs *cs) {
  memcpy(out, cs->z, cs->used.vars * sizeof *out);
}

static void nova_zero(Fe *out, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    out[i] = small(0);
}

static int nova_is_identity(const G1 *p) {
  Fe zero = small(0);
  return fe_eq(&p->x, &zero) && fe_eq(&p->y, &zero);
}

static int nova_point_is(const G1 *a, const G1 *b) {
  return fe_eq(&a->x, &b->x) && fe_eq(&a->y, &b->y);
}

static int nova_same(const NovaInstance *a, const NovaInstance *b) {
  unsigned j;
  int same = nova_point_is(&a->com_w, &b->com_w) && nova_point_is(&a->com_e, &b->com_e) &&
             fe_eq(&a->u, &b->u);
  for (j = 0; j < NOVA_X; j++)
    same = same && fe_eq(&a->x[j], &b->x[j]);
  return same;
}

/* The direct curve operations of the rows. */
static int nova_on_curve(const G1 *p, GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return secp_on_curve(p);
  case GENS_SECQ256K1:
    return secq_on_curve(p);
  }
  return 0;
}

static void nova_direct_mul(G1 *out, const G1 *p, const Fe *k, GensCurve curve) {
  U256 x;
  fe_to_u256(&x, k);
  switch (curve) {
  case GENS_SECP256K1:
    secp_mul(out, p, &x);
    break;
  case GENS_SECQ256K1:
    secq_mul(out, p, &x);
    break;
  }
}

static void nova_direct_add(G1 *out, const G1 *a, const G1 *b, GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    secp_add(out, a, b);
    break;
  case GENS_SECQ256K1:
    secq_add(out, a, b);
    break;
  }
}

/* 1 when (Z, E) holds as a relaxed witness of CS and U is its instance. */
static int nova_good(const NovaCase *nc, const R1cs *cs, const NovaInstance *u, const Fe *z,
                     const Fe *e) {
  NovaInstance v;
  size_t failed = 0;
  return nova_check(cs, z, e, &failed) && nova_instance(&v, &nc->key, cs, z, e) &&
         nova_same(u, &v);
}

static int nova_fails_at(const R1cs *cs, const Fe *z, const Fe *e, size_t at) {
  size_t failed = 0;
  return !nova_check(cs, z, e, &failed) && failed == at;
}

/* Folds the running (U1; Z1, E1) with the plain (U2; Z2) of CS: OUT gets
   the new instance, Z1 and E1 the new witness, R the challenge and COM_T
   the commitment of T. BAD below the row count adds 1 to T[BAD]. The
   challenge uses D = 7 and h1 = H. H is in place of the cut hash of U1,
   thus give a new H to a new U1. When U2 satisfies CS, a second fold with
   the same U2 gives the same T as the first fold, and the same H then
   gives the same R. After the first fold of a plain U1, comE1 = R comT,
   thus the E add of nova_verify_gadget gets A = B, and A = B has no
   witness (ec7gadget.h). */
static int nova_fold(NovaInstance *out, Fe *r, G1 *com_t, const NovaCase *nc, const R1cs *cs,
                     const NovaInstance *u1, Fe *z1, Fe *e1, const NovaInstance *u2,
                     const Fe *z2, size_t bad, uint64_t h) {
  Fe d = small(7);
  Fe h1 = small(h);
  Fe one = small(1);
  if (!nova_cross(nova_t, cs, z1, z2))
    return 0;
  if (bad < cs->used.rows)
    fe_add(&nova_t[bad], &nova_t[bad], &one, nc->f);
  if (!nova_com(com_t, &nc->key, nova_t, cs->used.rows))
    return 0;
  nova_challenge(r, &nc->challenge, &d, &h1, &u2->com_w, u2->x, com_t);
  nova_fold_witness(z1, e1, z1, e1, z2, nova_t, r, cs->used.vars, cs->used.rows, nc->f);
  nova_fold_instance(out, u1, u2, com_t, r, nc->f, nc->key.curve);
  return 1;
}

static void nova_com_rows(Tally *t, const char *name, const NovaCase *nc) {
  Fe v[3];
  G1 com, p, q, s;
  int ok;
  v[0] = small(5);
  v[1] = small(7);
  v[2] = small(11);
  ok = nova_com(&com, &nc->key, v, 3);
  nova_direct_mul(&p, &nova_g[0], &v[0], nc->key.curve);
  nova_direct_mul(&q, &nova_g[1], &v[1], nc->key.curve);
  nova_direct_add(&s, &p, &q, nc->key.curve);
  nova_direct_mul(&p, &nova_g[2], &v[2], nc->key.curve);
  nova_direct_add(&q, &s, &p, nc->key.curve);
  row(t, name, "nova com 3", ok && nova_point_is(&com, &q) && !nova_is_identity(&com));
}

static size_t nova_put32(unsigned char *b, size_t at, uint32_t v) {
  b[at] = (unsigned char)(v >> 24);
  b[at + 1] = (unsigned char)(v >> 16);
  b[at + 2] = (unsigned char)(v >> 8);
  b[at + 3] = (unsigned char)v;
  return at + 4;
}

static size_t nova_put_tag(unsigned char *b, size_t at, const char *tag) {
  size_t n = strlen(tag);
  memcpy(b + at, tag, n);
  b[at + n] = 0;
  return at + n + 1;
}

static unsigned char nova_side(R1csSide side) {
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

/* The bytes of one system in D, as the comment of nova_digest gives them. */
static size_t nova_put_system(unsigned char *b, size_t at, const R1cs *cs) {
  size_t k;
  size_t j;
  at = nova_put32(b, at, (uint32_t)cs->used.vars);
  at = nova_put32(b, at, (uint32_t)cs->used.rows);
  at = nova_put32(b, at, (uint32_t)cs->used.terms);
  for (k = 0; k < cs->used.rows; k++) {
    size_t end = k + 1 < cs->used.rows ? cs->row[k + 1] : cs->used.terms;
    for (j = cs->row[k]; j < end; j++) {
      U256 c;
      at = nova_put32(b, at, (uint32_t)k);
      b[at] = nova_side(cs->term[j].side);
      at = nova_put32(b, at + 1, cs->term[j].var);
      fe_to_u256(&c, &cs->term[j].coeff);
      u256_to_be(b + at, &c);
      at += 32;
    }
  }
  return at;
}

/* D of the hand system as P (N_P 4) and as S (N_S 8) = SHA-256 of the
   byte string in one call, cut to 250 bits. */
static void nova_digest_rows(Tally *t, const char *name, const NovaCase *nc) {
  R1cs cs;
  Fe d;
  Fe want;
  U256 x;
  unsigned char digest[32];
  size_t at = 0;
  int ok;
  start(&cs, nc->f);
  hand(&cs, 3);
  ok = nova_digest(&d, &cs, 4, &cs, 8);
  at = nova_put_tag(nova_bytes, at, "quorum-lang/ivc/params/v1");
  at = nova_put_tag(nova_bytes, at, "quorum-lang/ivc/gens/v1");
  at = nova_put32(nova_bytes, at, 4);
  at = nova_put32(nova_bytes, at, 8);
  at = nova_put_system(nova_bytes, at, &cs);
  at = nova_put_system(nova_bytes, at, &cs);
  sha256(nova_bytes, at, digest);
  digest[0] &= 3;
  u256_from_be(&x, digest);
  fe_from_u256(&want, &x, nc->f);
  row(t, name, "nova digest", ok && fe_eq(&d, &want));
}

/* The hand system has one good x (3), thus its two plain instances are the
   same and T = 0. */
static void nova_hand_rows(Tally *t, const char *name, const NovaCase *nc) {
  R1cs cs;
  NovaInstance u1, u2, run;
  G1 com_t;
  Fe r;
  Fe one = small(1);
  int ok;
  start(&cs, nc->f);
  hand(&cs, 3);
  nova_copy(nova_z1, &cs);
  nova_copy(nova_z2, &cs);
  nova_copy(nova_z3, &cs);
  nova_zero(nova_e1, cs.used.rows);
  nova_zero(nova_e3, cs.used.rows);
  ok = nova_instance(&u1, &nc->key, &cs, nova_z1, nova_e0) &&
       nova_instance(&u2, &nc->key, &cs, nova_z2, nova_e0);
  row(t, name, "nova hand plain",
      ok && nova_good(nc, &cs, &u1, nova_z1, nova_e0) && nova_is_identity(&u1.com_e) &&
          fe_eq(&u1.u, &one));
  ok = nova_fold(&run, &r, &com_t, nc, &cs, &u1, nova_z1, nova_e1, &u2, nova_z2, cs.used.rows,
                 12345);
  row(t, name, "nova hand fold",
      ok && nova_good(nc, &cs, &run, nova_z1, nova_e1) && !fe_eq(&run.u, &one));
  ok = nova_fold(&run, &r, &com_t, nc, &cs, &u1, nova_z3, nova_e3, &u2, nova_z2, 2, 12345);
  row(t, name, "nova hand bad T", ok && nova_fails_at(&cs, nova_z3, nova_e3, 2));
}

/* NEW (quorum-lang S11 H3c C3): the rows of crypto/novagadget.h. The
   circuit is over the base field of the curve of the instances (the field
   of the challenge sponge). The X values are 4 limbs of 64 bits of the
   field of the instances. */
#define NOVA_GVARS 16384u
#define NOVA_GROWS 16384u
#define NOVA_GTERMS 131072u

static Fe nova_gz[NOVA_GVARS];
static size_t nova_grow[NOVA_GROWS];
static R1csTerm nova_gterm[NOVA_GTERMS];

static void nova_gstart(R1cs *cs, const NovaCase *nc) {
  r1cs_init(cs, nova_base(nc->key.curve), nova_gz, NOVA_GVARS, nova_grow, NOVA_GROWS, nova_gterm,
            NOVA_GTERMS);
}

/* New variables for the 4 limbs of X. */
static void nova_limb_vars(R1cs *cs, uint32_t v[NOVA_LIMBS], const U256 *x) {
  U256 l;
  Fe b;
  unsigned k;
  for (k = 0; k < NOVA_LIMBS; k++) {
    u256_from_u64(&l, x->limb[k]);
    fe_from_u256(&b, &l, cs->f);
    v[k] = r1cs_var(cs, &b);
  }
}

/* 1 when the limb variables V hold X. */
static int nova_limbs_are(const R1cs *cs, const uint32_t v[NOVA_LIMBS], const U256 *x) {
  U256 u;
  Fe b;
  unsigned k;
  int same = 1;
  for (k = 0; k < NOVA_LIMBS; k++) {
    r1cs_value(&b, cs, v[k]);
    fe_to_u256(&u, &b);
    same = same && u.limb[0] == x->limb[k] && (u.limb[1] | u.limb[2] | u.limb[3]) == 0;
  }
  return same;
}

/* The variables of the native instance U. */
static void nova_instance_vars(R1cs *cs, NovaVars *v, const NovaInstance *u) {
  U256 x;
  Fe b;
  unsigned j;
  point_vars(cs, v->com_w, &u->com_w);
  b = small((uint64_t)nova_is_identity(&u->com_w));
  v->w_id = r1cs_var(cs, &b);
  point_vars(cs, v->com_e, &u->com_e);
  b = small((uint64_t)nova_is_identity(&u->com_e));
  v->e_id = r1cs_var(cs, &b);
  fe_to_u256(&x, &u->u);
  fe_from_u256(&b, &x, cs->f);
  v->u = r1cs_var(cs, &b);
  for (j = 0; j < NOVA_X; j++) {
    fe_to_u256(&x, &u->x[j]);
    nova_limb_vars(cs, v->x[j], &x);
  }
}

/* The in-circuit NIFS verifier on the native fold RUN of U1 with U2 and
   COM_T (D = 7 and h1 = H, as nova_fold). */
static void nova_verify_rows(Tally *t, const char *name, const char *label, const NovaCase *nc,
                             const NovaInstance *u1, const NovaInstance *u2, const G1 *com_t,
                             const NovaInstance *run, uint64_t h) {
  R1cs cs;
  NovaVars v1;
  NovaVars v2;
  NovaVars out;
  uint32_t t_var[2];
  uint32_t d;
  uint32_t h1;
  U256 m;
  U256 x;
  Fe v;
  Fe w;
  unsigned j;
  int same;
  step_modulus(&m, nc->f);
  nova_gstart(&cs, nc);
  v = small(7);
  d = r1cs_var(&cs, &v);
  v = small(h);
  h1 = r1cs_var(&cs, &v);
  nova_instance_vars(&cs, &v1, u1);
  nova_instance_vars(&cs, &v2, u2);
  point_vars(&cs, t_var, com_t);
  nova_verify_gadget(&cs, &out, d, h1, &v1, &v2, t_var, &nc->challenge, &m);
  same = point_is(&cs, out.com_w, &run->com_w) && point_is(&cs, out.com_e, &run->com_e);
  fe_to_u256(&x, &run->u);
  fe_from_u256(&v, &x, cs.f);
  r1cs_value(&w, &cs, out.u);
  same = same && fe_eq(&v, &w);
  for (j = 0; j < NOVA_X; j++) {
    fe_to_u256(&x, &run->x[j]);
    same = same && nova_limbs_are(&cs, out.x[j], &x);
  }
  v = small((uint64_t)nova_is_identity(&run->com_e));
  r1cs_value(&w, &cs, out.e_id);
  same = same && fe_eq(&v, &w);
  row(t, name, label, !r1cs_full(&cs) && holds(&cs) && same);
}

/* The nova verify row with COM_T = the identity (0, 0): comE' = comE of
   U1, and the id flag of comE' is 1 when comE of U1 is the identity. */
static void nova_verify_id_row(Tally *t, const char *name, const NovaCase *nc,
                               const NovaInstance *u1, const NovaInstance *u2) {
  NovaInstance run;
  G1 com_t;
  Fe d;
  Fe h1;
  Fe r;
  com_t.x = small(0);
  com_t.y = small(0);
  d = small(7);
  h1 = small(12347);
  nova_challenge(&r, &nc->challenge, &d, &h1, &u2->com_w, u2->x, &com_t);
  nova_fold_instance(&run, u1, u2, &com_t, &r, nc->f, nc->key.curve);
  nova_verify_rows(t, name, "nova verify comT id", nc, u1, u2, &com_t, &run, 12347);
}

/* A new system with the limb variables of A (X1), B (X2) and RR (R, the
   first 2 limbs). */
static void nova_xfold_start(R1cs *cs, const NovaCase *nc, uint32_t x1[NOVA_LIMBS],
                             uint32_t x2[NOVA_LIMBS], uint32_t r[2], const U256 *a, const U256 *b,
                             const U256 *rr) {
  uint32_t r4[NOVA_LIMBS];
  nova_gstart(cs, nc);
  nova_limb_vars(cs, x1, a);
  nova_limb_vars(cs, x2, b);
  nova_limb_vars(cs, r4, rr);
  r[0] = r4[0];
  r[1] = r4[1];
}

/* The X fold with X1 = M - 5, X2 = M - 3 and R = 2^128 - 99 (a good fold
   and a bad quotient), then with X2 = 1 and X1 = M + 7 - R (X' = 7 and
   Q = 1: a good fold, and the remainder X' + M with Q = 0). Then the cut
   of c - 1 (c the modulus of the circuit). */
static void nova_xfold_case_rows(Tally *t, const char *name, const NovaCase *nc) {
  R1cs cs;
  uint32_t x1[NOVA_LIMBS];
  uint32_t x2[NOVA_LIMBS];
  uint32_t out[NOVA_LIMBS];
  uint32_t r[2];
  uint32_t bit[STEP_GADGET_BITS];
  uint32_t cut;
  U256 m;
  U256 a;
  U256 b;
  U256 rr;
  U256 q;
  U256 q1;
  U256 rem;
  U256 c;
  U256 k;
  U256 tmp;
  Fe fa;
  Fe fb;
  Fe fr;
  Fe v;
  Fe w;
  step_modulus(&m, nc->f);
  u256_from_u64(&k, 5);
  u256_sub(&a, &m, &k);
  u256_from_u64(&k, 3);
  u256_sub(&b, &m, &k);
  u256_from_u64(&rr, 0);
  rr.limb[0] = 0xffffffffffffff9dull;
  rr.limb[1] = 0xffffffffffffffffull;
  fe_from_u256(&fa, &a, nc->f);
  fe_from_u256(&fb, &b, nc->f);
  fe_from_u256(&fr, &rr, nc->f);
  fe_mul(&v, &fr, &fb, nc->f);
  fe_add(&w, &fa, &v, nc->f);
  fe_to_u256(&c, &w);
  nova_xfold_witness(&q, &rem, &a, &b, &rr, &m);
  nova_xfold_start(&cs, nc, x1, x2, r, &a, &b, &rr);
  nova_xfold_gadget(&cs, out, x1, x2, r, &m);
  row(t, name, "nova xfold",
      !r1cs_full(&cs) && holds(&cs) && nova_limbs_are(&cs, out, &c) && u256_cmp(&rem, &c) == 0);
  u256_from_u64(&k, 1);
  u256_add(&q1, &q, &k);
  nova_xfold_start(&cs, nc, x1, x2, r, &a, &b, &rr);
  nova_xfold_qr_gadget(&cs, out, x1, x2, r, &m, &q1, &rem);
  row(t, name, "nova xfold bad quotient", !r1cs_full(&cs) && !holds(&cs));
  u256_from_u64(&b, 1);
  u256_sub(&tmp, &m, &rr);
  u256_from_u64(&k, 7);
  u256_add(&a, &tmp, &k);
  nova_xfold_start(&cs, nc, x1, x2, r, &a, &b, &rr);
  nova_xfold_gadget(&cs, out, x1, x2, r, &m);
  row(t, name, "nova xfold small", !r1cs_full(&cs) && holds(&cs) && nova_limbs_are(&cs, out, &k));
  u256_from_u64(&q, 0);
  u256_add(&rem, &m, &k);
  nova_xfold_start(&cs, nc, x1, x2, r, &a, &b, &rr);
  nova_xfold_qr_gadget(&cs, out, x1, x2, r, &m, &q, &rem);
  row(t, name, "nova xfold remainder plus m", !r1cs_full(&cs) && !holds(&cs));
  nova_gstart(&cs, nc);
  step_modulus(&c, cs.f);
  u256_from_u64(&k, 1);
  u256_sub(&a, &c, &k);
  fe_from_u256(&v, &a, cs.f);
  cut = nova_cut_gadget(&cs, bit, r1cs_var(&cs, &v));
  a.limb[3] &= ((uint64_t)1 << (NOVA_CUT_BITS - 192u)) - 1u;
  fe_from_u256(&v, &a, cs.f);
  r1cs_value(&w, &cs, cut);
  row(t, name, "nova cut", !r1cs_full(&cs) && holds(&cs) && fe_eq(&v, &w));
}

/* The cut hash of a fixed instance with Z_LEN values in z_0 and in z_i:
   nova_hash_gadget against nova_hash. BAD adds 1 to the cut variable after
   the gadget, and the check must then fail. */
static int nova_hash_case(const NovaCase *nc, size_t z_len, int bad) {
  R1cs cs;
  NovaInstance u;
  NovaVars v;
  U256 a;
  Fe d;
  Fe i;
  Fe z0[STEP_GADGET_Z];
  Fe zi[STEP_GADGET_Z];
  uint32_t z0v[STEP_GADGET_Z];
  uint32_t ziv[STEP_GADGET_Z];
  uint32_t dv;
  uint32_t iv;
  uint32_t cut;
  Fe h;
  Fe w;
  Fe one;
  size_t k;
  int ok;
  u.com_w = nova_g[1];
  u.com_e = nova_g[2];
  u.u = small(12347);
  u256_from_u64(&a, 0x0123456789abcdefu);
  a.limb[1] = 0xfedcba9876543210u;
  a.limb[2] = 0x0f1e2d3c4b5a6978u;
  a.limb[3] = 0x7766554433221100u;
  (void)fe_from_u256(&u.x[0], &a, nc->f);
  a.limb[0] = 0x1122334455667788u;
  a.limb[3] = 0x0123456789abcdefu;
  (void)fe_from_u256(&u.x[1], &a, nc->f);
  nova_gstart(&cs, nc);
  d = small(29);
  i = small(3);
  dv = r1cs_var(&cs, &d);
  iv = r1cs_var(&cs, &i);
  for (k = 0; k < z_len; k++) {
    z0[k] = small(100u + k);
    zi[k] = small(200u + k);
    z0v[k] = r1cs_var(&cs, &z0[k]);
    ziv[k] = r1cs_var(&cs, &zi[k]);
  }
  nova_instance_vars(&cs, &v, &u);
  cut = nova_hash_gadget(&cs, dv, iv, z0v, ziv, z_len, &v, &nc->challenge);
  ok = nova_hash(&h, &nc->challenge, &d, &i, z0, zi, z_len, &u);
  r1cs_value(&w, &cs, cut);
  fe_to_u256(&a, &h);
  ok = ok && !r1cs_full(&cs) && fe_eq(&h, &w) && fe_eq(&w, &nova_gz[cut]) &&
       (a.limb[3] >> (NOVA_CUT_BITS - 192u)) == 0;
  one = small(1);
  if (bad)
    fe_add(&nova_gz[cut], &nova_gz[cut], &one, cs.f);
  return ok && (bad ? !holds(&cs) : holds(&cs));
}

static void nova_hash_rows(Tally *t, const char *name, const NovaCase *nc) {
  row(t, name, "nova hash", nova_hash_case(nc, STEP_GADGET_Z, 0));
  row(t, name, "nova hash short", nova_hash_case(nc, 1, 0));
  row(t, name, "nova hash bad", nova_hash_case(nc, STEP_GADGET_Z, 1));
}

/* The Poseidon system on the inputs FIRST, FIRST + 1 and FIRST + 2: the X
   values are the first two inputs. */
static void nova_poseidon(R1cs *cs, const PoseidonParams *params, uint64_t first) {
  Fe v;
  uint32_t in[POSEIDON_WIDTH];
  uint32_t out[POSEIDON_WIDTH];
  unsigned i;
  start(cs, &params->f);
  for (i = 0; i < POSEIDON_WIDTH; i++) {
    v = small(first + i);
    in[i] = r1cs_var(cs, &v);
  }
  poseidon_gadget(cs, out, in, params);
}

/* Two plain instances (inputs 0 and 3), the fold of the two, then the fold
   of that running instance with the second plain instance again. */
static void nova_poseidon_rows(Tally *t, const char *name, const NovaCase *nc) {
  PoseidonParams params;
  R1cs cs;
  NovaInstance u1, u2, run, prev;
  G1 com_t, p, q;
  Fe r, v;
  unsigned j;
  int ok, same;
  poseidon_params(&params, nc->f);
  nova_poseidon(&cs, &params, 0);
  nova_copy(nova_z1, &cs);
  nova_poseidon(&cs, &params, 3);
  nova_copy(nova_z2, &cs);
  nova_zero(nova_e1, cs.used.rows);
  ok = nova_instance(&u1, &nc->key, &cs, nova_z1, nova_e0) &&
       nova_instance(&u2, &nc->key, &cs, nova_z2, nova_e0);
  row(t, name, "nova poseidon plain",
      ok && nova_good(nc, &cs, &u1, nova_z1, nova_e0) &&
          nova_good(nc, &cs, &u2, nova_z2, nova_e0));
  ok = nova_fold(&run, &r, &com_t, nc, &cs, &u1, nova_z1, nova_e1, &u2, nova_z2, cs.used.rows,
                 12345);
  row(t, name, "nova poseidon fold", ok && nova_good(nc, &cs, &run, nova_z1, nova_e1));
  nova_verify_rows(t, name, "nova verify plain", nc, &u1, &u2, &com_t, &run, 12345);
  nova_verify_id_row(t, name, nc, &u1, &u2);
  prev = run;
  memcpy(nova_z3, nova_z1, cs.used.vars * sizeof *nova_z3);
  memcpy(nova_e3, nova_e1, cs.used.rows * sizeof *nova_e3);
  ok = nova_fold(&run, &r, &com_t, nc, &cs, &prev, nova_z1, nova_e1, &u2, nova_z2, cs.used.rows,
                 12346);
  row(t, name, "nova poseidon fold 2", ok && nova_good(nc, &cs, &run, nova_z1, nova_e1));
  nova_direct_mul(&p, &u2.com_w, &r, nc->key.curve);
  nova_direct_add(&q, &prev.com_w, &p, nc->key.curve);
  same = nova_point_is(&q, &run.com_w);
  nova_direct_mul(&p, &com_t, &r, nc->key.curve);
  nova_direct_add(&q, &prev.com_e, &p, nc->key.curve);
  same = same && nova_point_is(&q, &run.com_e);
  fe_add(&v, &prev.u, &r, nc->f);
  same = same && fe_eq(&v, &run.u);
  for (j = 0; j < NOVA_X; j++) {
    fe_mul(&v, &r, &u2.x[j], nc->f);
    fe_add(&v, &prev.x[j], &v, nc->f);
    same = same && fe_eq(&v, &run.x[j]);
  }
  row(t, name, "nova poseidon fold direct", ok && same);
  nova_verify_rows(t, name, "nova verify running", nc, &prev, &u2, &com_t, &run, 12346);
  ok = nova_fold(&run, &r, &com_t, nc, &cs, &prev, nova_z3, nova_e3, &u2, nova_z2, 100, 12346);
  row(t, name, "nova poseidon bad T", ok && nova_fails_at(&cs, nova_z3, nova_e3, 100));
}

#define NOVA_IVARS 65536u
#define NOVA_IROWS 65536u
#define NOVA_ITERMS 524288u

static Fe nova_iz[NOVA_IVARS];
static size_t nova_irow[NOVA_IROWS];
static R1csTerm nova_iterm[NOVA_ITERMS];

/* The storage of the sizing run of P on the real F (the row
   `nova p size h4`): N_P = 2^19 variables and rows, and 3 * 2^20 terms
   (F alone has 2046207 terms, and P with F_t fits in 2^19 terms). */
#define NOVA_H4VARS 524288u
#define NOVA_H4ROWS 524288u
#define NOVA_H4TERMS 3145728u

static Fe nova_h4z[NOVA_H4VARS];
static size_t nova_h4row[NOVA_H4ROWS];
static R1csTerm nova_h4term[NOVA_H4TERMS];

/* The test step F_t (Q-S11-9 (a), the z layout of stepgadget.h): OUT[2] =
   IN[2] + 1 (the count), and OUT[0] and OUT[1] = state[1] and state[2]
   of one Poseidon permutation of (0, IN[0], IN[1]) (the head limbs).
   OUT[3] = IN[3] and OUT[4] = IN[4]. CTX is the PoseidonParams of the
   field of the system. */
static void nova_step_t(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                        const void *ctx) {
  const PoseidonParams *params = (const PoseidonParams *)ctx;
  uint32_t state[POSEIDON_WIDTH];
  uint32_t next[POSEIDON_WIDTH];
  Fe v;
  Fe one;
  fe_from_u64(&v, 0);
  state[0] = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, state[0], 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, 0, 1);
  state[1] = in[0];
  state[2] = in[1];
  poseidon_gadget(cs, next, state, params);
  r1cs_value(&v, cs, in[2]);
  one = small(1);
  fe_add(&v, &v, &one, cs->f);
  out[2] = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, in[2], 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, out[2], 1);
  out[0] = next[1];
  out[1] = next[2];
  out[3] = in[3];
  out[4] = in[4];
}

/* Same sizes as F_t, but the last row and its witness add 2 to the count.
   A key set up for F_t must reject this circuit. */
static void nova_step_changed(R1cs *cs, uint32_t out[STEP_GADGET_Z],
                              const uint32_t in[STEP_GADGET_Z], const void *ctx) {
  Fe one = small(1);
  size_t k;
  nova_step_t(cs, out, in, ctx);
  fe_add(&cs->z[out[2]], &cs->z[out[2]], &one, cs->f);
  for (k = cs->row[cs->used.rows - 1u]; k < cs->used.terms; k++)
    if (cs->term[k].side == R1CS_B && cs->term[k].var == 0u)
      cs->term[k].coeff = small(2);
}

/* One run of step 0 of P (PRIMARY 1, F = F_t) or of S in a new system. */
static int nova_ivc_run(R1cs *cs, Fe x[NOVA_X], Fe z_out[STEP_GADGET_Z], const NovaStepIn *in,
                        const NovaCase *nc, int primary) {
  r1cs_init(cs, nova_base(nc->key.curve), nova_iz, NOVA_IVARS, nova_irow, NOVA_IROWS, nova_iterm,
            NOVA_ITERMS);
  if (primary)
    return nova_primary(cs, x, z_out, in, nova_step_t, &nc->challenge);
  return nova_secondary(cs, x, z_out, in);
}

/* The size of P on the real F (C4d, the row `nova p size h4`): a sizing
   run of step 0 of P (X = 0, as the sizing runs of nova_ivc_setup) with
   F = step_f and z_0 = the inputs of step 0 of h4. IN gives the other
   inputs (U, u and comT of nova_ivc_rows). The row: the run fits the
   storage, and the rows and the variables of P are at or below
   N_P = 2^19. */
static void nova_h4_size_row(Tally *t, const char *name, const NovaCase *nc, const NovaStepIn *in) {
  R1cs cs;
  R1csSize size;
  NovaStepIn h4 = *in;
  StepCase s;
  Fe z_out[STEP_GADGET_Z];
  Fe x[NOVA_X];
  unsigned char genesis[32];
  unsigned char zero4[32];
  unsigned char head[32];
  unsigned char next[32];
  int ok;
  memset(genesis, 0, sizeof genesis);
  memset(zero4, 0, sizeof zero4);
  step_words(genesis, step_genesis, 2u);
  step_hash2(head, genesis, zero4);
  step_case(&s, head, 0u, 0u, next);
  h4.z0 = s.in;
  h4.zi = s.in;
  h4.x[0] = small(0);
  h4.x[1] = small(0);
  r1cs_init(&cs, nova_base(nc->key.curve), nova_h4z, NOVA_H4VARS, nova_h4row, NOVA_H4ROWS, nova_h4term,
            NOVA_H4TERMS);
  ok = nova_primary(&cs, x, z_out, &h4, step_f, &s);
  r1cs_size(&size, &cs);
  row(t, name, "nova p size h4", ok && size.rows <= NOVA_H4ROWS && size.vars <= NOVA_H4VARS);
}

/* Step 0 of P in the field F_p (the run with the curve secp256k1) and of
   S in the field F_n: U = the default instance, u = a plain instance
   (comW = nova_g[1], X = (5, 6)), comT = nova_g[2]. The first run with
   X = 0 must fail (its X ties do not hold). The real run with X = the
   tie values must hold, with X[0] = u.X[1] = 6, the X values in
   variables 1 and 2, and z_1 = F_t(z_0) (P: count 102 + 1) or z_0 (S).
   The size rows: the rows and the variables of the real run are at or
   below N_P = 2^15 (P) or N_S = 2^14 (S). P also gets the row
   `nova p size h4` (the real F, N_P = 2^19). */
static void nova_ivc_rows(Tally *t, const char *name, const NovaCase *nc, int primary) {
  R1cs cs;
  NovaStepIn in;
  NovaInstance big;
  NovaInstance last;
  R1csSize size;
  U256 m;
  Fe z0[STEP_GADGET_Z];
  Fe z_out[STEP_GADGET_Z];
  Fe x[NOVA_X];
  Fe want;
  size_t n;
  size_t k;
  int first;
  int ok;
  step_modulus(&m, nc->f);
  fe_from_u64(&big.com_w.x, 0);
  big.com_w.y = big.com_w.x;
  big.com_e = big.com_w;
  big.u = big.com_w.x;
  big.x[0] = big.com_w.x;
  big.x[1] = big.com_w.x;
  last.com_w = nova_g[1];
  last.com_e = big.com_e;
  last.u = small(1);
  last.x[0] = small(5);
  last.x[1] = small(6);
  for (k = 0; k < STEP_GADGET_Z; k++)
    z0[k] = small(primary ? 100u + k : 0u);
  in.params = &nc->challenge;
  in.m = &m;
  in.d = small(29);
  in.i = small(0);
  in.z0 = z0;
  in.zi = z0;
  in.big = &big;
  in.last = &last;
  in.com_t = nova_g[2];
  in.x[0] = small(0);
  in.x[1] = small(0);
  first = nova_ivc_run(&cs, x, z_out, &in, nc, primary) && !holds(&cs);
  in.x[0] = x[0];
  in.x[1] = x[1];
  ok = nova_ivc_run(&cs, x, z_out, &in, nc, primary);
  r1cs_size(&size, &cs);
  want = small(primary ? 103u : 0u);
  ok = first && ok && holds(&cs) && fe_eq(&x[0], &last.x[1]) && fe_eq(&nova_iz[1], &x[0]) &&
       fe_eq(&nova_iz[2], &x[1]) && fe_eq(&z_out[primary ? 2u : 0u], &want);
  n = primary ? 32768u : 16384u;
  if (primary) {
    row(t, name, "nova p size", size.rows <= n && size.vars <= n);
    row(t, name, "nova p base", ok);
    nova_h4_size_row(t, name, nc, &in);
  } else {
    row(t, name, "nova s size", size.rows <= n && size.vars <= n);
    row(t, name, "nova s base", ok);
  }
}
/* The IVC chain (O162 item 5). P and S are in one chain, thus the chain
   rows are not per field: they run one time, in the nova_rows run with
   f = SECP_FN (the name "n", after nova_ivc_rows). The caps: N_P = 2^15
   generators of P and N_S = 2^14 of S (setup uses the sizing run counts,
   at or below these caps). P uses the storage of nova_ivc_rows. */
#define NOVA_CN_P 32768u
#define NOVA_CN_S 16384u
#define NOVA_CBUCKETS 65536u
static G1 nova_cg_p[NOVA_CN_P];
static U256 nova_ck_p[NOVA_CN_P];
static EcJac nova_cb_p[NOVA_CBUCKETS];
static Fe nova_ct_p[NOVA_IROWS];
static G1 nova_cg_s[NOVA_CN_S];
static U256 nova_ck_s[NOVA_CN_S];
static EcJac nova_cb_s[NOVA_CBUCKETS];
static Fe nova_sz[NOVA_IVARS];
static size_t nova_srow[NOVA_IROWS];
static R1csTerm nova_sterm[NOVA_ITERMS];
static Fe nova_ct_s[NOVA_IROWS];
static Fe nova_rwp[NOVA_IVARS];
static Fe nova_rep[NOVA_IROWS];
static Fe nova_rws[NOVA_IVARS];
static Fe nova_res[NOVA_IROWS];
static Fe nova_lws[NOVA_IVARS];
/* The copy of r_W_p and r_E_p before the last fold (the row
   `nova ivc keeps U`). The fold of the witness is in place. */
static Fe nova_kwp[NOVA_IVARS];
static Fe nova_kep[NOVA_IROWS];
static NovaIvcKey nova_ckey;
static NovaIvcProof nova_cpf;

/* The caller part of one side of the key. M is the field of the X values
   of the folded instances (F_n for P, F_p for S). */
static void nova_ivc_side(NovaIvcSide *sd, G1 *g, size_t g_cap, U256 *k, EcJac *bucket, Fe *z,
                          size_t *rows, R1csTerm *term, Fe *t, const Modulus *m) {
  sd->g = g;
  sd->g_cap = g_cap;
  sd->k = k;
  sd->bucket = bucket;
  sd->buckets = NOVA_CBUCKETS;
  step_modulus(&sd->m, m);
  sd->z = z;
  sd->var_cap = NOVA_IVARS;
  sd->row = rows;
  sd->row_cap = NOVA_IROWS;
  sd->term = term;
  sd->term_cap = NOVA_ITERMS;
  sd->t = t;
}

/* The IVC chain rows. `nova ivc step 1`: setup, prove step 0 with F_t
   (z_0[k] = 100 + k), and verify returns 0 (all 4 checks pass), with
   k = 1 and the count of z_1 = 103. `nova ivc step 2` and `nova ivc
   step 3`: the same for steps 1 and 2 (the counts 104 and 105).
   `nova ivc keeps U` (O154 (1)): the 3-step proof with r_U_p, r_W_p and
   r_E_p from before the last fold; verify returns 2 (the H_n bind of
   r_U_p). `nova ivc z changed` (O154 (3)): the 3-step proof with a
   changed count in z_3; verify returns 2 (the H_p bind of z_k). */
static void nova_ivc_chain_rows(Tally *t, const char *name) {
  NovaIvcKey *key = &nova_ckey;
  NovaIvcProof *pf = &nova_cpf;
  Fe z0[STEP_GADGET_Z];
  NovaInstance keep_u;
  NovaIvcProof bad;
  Fe want;
  size_t terms;
  size_t k;
  int ok;
  nova_ivc_side(&key->p, nova_cg_p, NOVA_CN_P, nova_ck_p, nova_cb_p, nova_iz, nova_irow,
                nova_iterm, nova_ct_p, &SECP_FN);
  nova_ivc_side(&key->s, nova_cg_s, NOVA_CN_S, nova_ck_s, nova_cb_s, nova_sz, nova_srow,
                nova_sterm, nova_ct_s, &SECP_FP);
  for (k = 0; k < STEP_GADGET_Z; k++)
    z0[k] = small(100u + k);
  pf->r_w_p = nova_rwp;
  pf->r_e_p = nova_rep;
  pf->r_w_s = nova_rws;
  pf->r_e_s = nova_res;
  pf->l_w_s = nova_lws;
  nova_ivc_start(pf, z0);
  want = small(103);
  ok = nova_ivc_setup(key, nova_step_t, &key->p.params) &&
       nova_ivc_prove_step(pf, key, nova_step_t, &key->p.params) && nova_ivc_verify(key, pf) == 0 &&
       pf->k == 1u && fe_eq(&pf->zk[2], &want);
  row(t, name, "nova ivc step 1", ok);
  want = small(104);
  ok = ok && nova_ivc_prove_step(pf, key, nova_step_t, &key->p.params) &&
       nova_ivc_verify(key, pf) == 0 && pf->k == 2u && fe_eq(&pf->zk[2], &want);
  row(t, name, "nova ivc step 2", ok);
  keep_u = pf->r_u_p;
  for (k = 0; k < NOVA_IVARS; k++)
    nova_kwp[k] = nova_rwp[k];
  for (k = 0; k < NOVA_IROWS; k++)
    nova_kep[k] = nova_rep[k];
  want = small(105);
  ok = ok && nova_ivc_prove_step(pf, key, nova_step_t, &key->p.params) &&
       nova_ivc_verify(key, pf) == 0 && pf->k == 3u && fe_eq(&pf->zk[2], &want);
  row(t, name, "nova ivc step 3", ok);
  bad = *pf;
  bad.r_u_p = keep_u;
  bad.r_w_p = nova_kwp;
  bad.r_e_p = nova_kep;
  row(t, name, "nova ivc keeps U", ok && nova_ivc_verify(key, &bad) == 2);
  bad = *pf;
  bad.zk[2] = small(106);
  row(t, name, "nova ivc z changed", ok && nova_ivc_verify(key, &bad) == 2);
  /* A zero term preserves every row but changes the setup digest. */
  terms = key->p.cs.used.terms;
  r1cs_term_int(&key->p.cs, R1CS_A, 0, 0);
  row(t, name, "nova ivc key shape changed", ok && nova_ivc_verify(key, pf) == 1);
  key->p.cs.used.terms = terms;
  nova_ivc_start(pf, z0);
  row(t, name, "nova ivc step shape changed",
      ok && !nova_ivc_prove_step(pf, key, nova_step_changed, &key->p.params));
}

static void nova_rows(Tally *t, const char *name, const Modulus *f) {
  NovaCase nc;
  int ok;
  nc.key.curve = GENS_SECP256K1;
  ok = nova_curve(&nc.key.curve, f);
  nc.key.g = nova_g;
  nc.key.n = NOVA_N;
  nc.key.k = nova_k;
  nc.key.bucket = nova_bucket;
  nc.key.buckets = NOVA_BUCKETS;
  nc.f = f;
  nova_gens(nova_g, nc.key.curve, NOVA_N);
  poseidon_params(&nc.challenge, nova_base(nc.key.curve));
  nova_zero(nova_e0, NOVA_N);
  row(t, name, "nova gens",
      ok && nova_on_curve(&nova_g[0], nc.key.curve) &&
          nova_on_curve(&nova_g[NOVA_N - 1], nc.key.curve));
  nova_com_rows(t, name, &nc);
  nova_digest_rows(t, name, &nc);
  nova_hand_rows(t, name, &nc);
  nova_poseidon_rows(t, name, &nc);
  nova_xfold_case_rows(t, name, &nc);
  nova_hash_rows(t, name, &nc);
  nova_ivc_rows(t, name, &nc, f == &SECP_FN);
  if (f == &SECP_FN)
    nova_ivc_chain_rows(t, name);
}

int main(void) {
  Tally t = {0, 0};
  Curve secp = {secp_gen, secp_add, secp_mul};
  Curve secq = {secq_gen, secq_add, secq_mul};
  hand_rows(&t, "p", &SECP_FP);
  gadget_rows(&t, "p", &SECP_FP);
  poseidon_rows(&t, "p", &SECP_FP);
  sha256_rows(&t, "p", &SECP_FP);
  ec7_rows(&t, "p", &SECP_FP, &secp);
  nova_rows(&t, "p", &SECP_FP);
  step_rows(&t);
  hand_rows(&t, "n", &SECP_FN);
  gadget_rows(&t, "n", &SECP_FN);
  poseidon_rows(&t, "n", &SECP_FN);
  ec7_rows(&t, "n", &SECP_FN, &secq);
  nova_rows(&t, "n", &SECP_FN);
  printf("crypto r1cs: %u rows, %u mismatches\n", (unsigned)t.rows, (unsigned)t.mismatches);
  return t.mismatches == 0 ? 0 : 1;
}
