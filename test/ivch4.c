/* NEW (quorum-lang S11 H3c, C4d): the IVC on the real F. One step of h4
   (step 0, the oldest) with F = step_f of test/stepcase.h:
   nova_ivc_setup, nova_ivc_start, nova_ivc_prove_step and
   nova_ivc_verify, with P on N_P = 2^19 generators. The storage is static
   (Q-S11-8 (a)): about 310 MB. The run takes about 40 minutes with TCC,
   thus `make ivc-h4` runs it and `make check` does not. A failed row
   writes `FAIL ivc h4 <name>` to stderr. The last line gives the number
   of rows and the number of mismatches. */
#include <stdio.h>
#include <string.h>

#include "crypto/bn254.h"
#include "crypto/msm.h"
#include "crypto/nova.h"
#include "crypto/novaivc.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/stepgadget.h"
#include "crypto/u256.h"

#include "stepcase.h"

/* P: N_P = 2^19 generators, variables and rows, and 3 * 2^20 terms (the
   row `nova p size h4` of test/ivcr1cs.c: P on the real F has 367831
   variables, 370238 rows and 2133979 terms). S: the caps of the IVC
   chain rows of test/ivcr1cs.c (S does not depend on F). */
#define H4_NP 524288u
#define H4_PVARS 524288u
#define H4_PROWS 524288u
#define H4_PTERMS 3145728u
#define H4_PBUCKETS 262144u
#define H4_NS 16384u
#define H4_SVARS 65536u
#define H4_SROWS 65536u
#define H4_STERMS 524288u
#define H4_SBUCKETS 65536u

typedef struct {
  uint32_t rows;
  uint32_t mismatches;
} Tally;

static G1 h4_g_p[H4_NP];
static U256 h4_k_p[H4_NP];
static EcJac h4_b_p[H4_PBUCKETS];
static Fe h4_z_p[H4_PVARS];
static size_t h4_row_p[H4_PROWS];
static R1csTerm h4_term_p[H4_PTERMS];
static Fe h4_t_p[H4_PROWS];
static G1 h4_g_s[H4_NS];
static U256 h4_k_s[H4_NS];
static EcJac h4_b_s[H4_SBUCKETS];
static Fe h4_z_s[H4_SVARS];
static size_t h4_row_s[H4_SROWS];
static R1csTerm h4_term_s[H4_STERMS];
static Fe h4_t_s[H4_SROWS];
static Fe h4_rwp[H4_PVARS];
static Fe h4_rep[H4_PROWS];
static Fe h4_rws[H4_SVARS];
static Fe h4_res[H4_SROWS];
static Fe h4_lws[H4_SVARS];
static NovaIvcKey h4_key;
static NovaIvcProof h4_pf;

static void row(Tally *t, const char *name, int good) {
  t->rows++;
  if (!good) {
    t->mismatches++;
    fprintf(stderr, "FAIL ivc h4 %s\n", name);
  }
}

/* The caller part of one side of the key (as nova_ivc_side of
   test/ivcr1cs.c, with the caps of the side). M is the field of the X
   values of the folded instances (F_n for P, F_p for S). */
static void h4_side(NovaIvcSide *sd, G1 *g, size_t g_cap, U256 *k, EcJac *bucket, size_t buckets,
                    Fe *z, size_t var_cap, size_t *rows, size_t row_cap, R1csTerm *term,
                    size_t term_cap, Fe *t, const Modulus *m) {
  sd->g = g;
  sd->g_cap = g_cap;
  sd->k = k;
  sd->bucket = bucket;
  sd->buckets = buckets;
  step_modulus(&sd->m, m);
  sd->z = z;
  sd->var_cap = var_cap;
  sd->row = rows;
  sd->row_cap = row_cap;
  sd->term = term;
  sd->term_cap = term_cap;
  sd->t = t;
}

/* The rows. `nova ivc h4 buckets`: the bucket storage of each side holds
   msm_buckets of its generator count. `nova ivc h4 setup`: setup with
   step_f and the StepCase of step 0 of h4. `nova ivc h4 step 1`: prove
   step 0 (z_0 = the inputs of step 0), verify returns 0 (all 4 checks
   pass) and k = 1. `nova ivc h4 z_1`: z_1 holds the native new head, the
   count 1 and the PK (as step_out_is of test/ivcr1cs.c). */
int main(void) {
  Tally t = {0, 0};
  NovaIvcKey *key = &h4_key;
  NovaIvcProof *pf = &h4_pf;
  StepCase s;
  Fe want[STEP_GADGET_Z];
  unsigned char genesis[32];
  unsigned char zero4[32];
  unsigned char head[32];
  unsigned char next[32];
  size_t i;
  int ok;
  int good;
  memset(genesis, 0, sizeof genesis);
  memset(zero4, 0, sizeof zero4);
  step_words(genesis, step_genesis, 2u);
  step_hash2(head, genesis, zero4);
  step_case(&s, head, 0u, 0u, next);
  row(&t, "nova ivc h4 buckets",
      msm_buckets(H4_NP) <= H4_PBUCKETS && msm_buckets(H4_NS) <= H4_SBUCKETS);
  h4_side(&key->p, h4_g_p, H4_NP, h4_k_p, h4_b_p, H4_PBUCKETS, h4_z_p, H4_PVARS, h4_row_p, H4_PROWS,
          h4_term_p, H4_PTERMS, h4_t_p, &SECP_FN);
  h4_side(&key->s, h4_g_s, H4_NS, h4_k_s, h4_b_s, H4_SBUCKETS, h4_z_s, H4_SVARS, h4_row_s, H4_SROWS,
          h4_term_s, H4_STERMS, h4_t_s, &SECP_FP);
  pf->r_w_p = h4_rwp;
  pf->r_e_p = h4_rep;
  pf->r_w_s = h4_rws;
  pf->r_e_s = h4_res;
  pf->l_w_s = h4_lws;
  nova_ivc_start(pf, s.in);
  ok = nova_ivc_setup(key, step_f, &s);
  printf("ivc h4 sizes: n_p %lu n_s %lu\n", (unsigned long)key->p.key.n, (unsigned long)key->s.key.n);
  row(&t, "nova ivc h4 setup", ok);
  ok = ok && nova_ivc_prove_step(pf, key, step_f, &s) && nova_ivc_verify(key, pf) == 0 && pf->k == 1u;
  row(&t, "nova ivc h4 step 1", ok);
  want[0] = step_fe(next + 16, 16u);
  want[1] = step_fe(next, 16u);
  want[2] = small(1u);
  want[3] = s.in[3];
  want[4] = s.in[4];
  good = ok;
  for (i = 0; i < STEP_GADGET_Z; i++) good &= fe_eq(&pf->zk[i], &want[i]);
  row(&t, "nova ivc h4 z_1", good);
  printf("crypto ivc h4: %u rows, %u mismatches\n", (unsigned)t.rows, (unsigned)t.mismatches);
  return t.mismatches == 0 ? 0 : 1;
}
