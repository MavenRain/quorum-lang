/* NEW (quorum-lang S11 H3c, C4d): the IVC on the real F. One step of h4
   (step 0, the oldest) with F = step_f of src/crypto/stepcase.h:
   nova_ivc_setup, nova_ivc_start, nova_ivc_prove_step and
   nova_ivc_verify, with P on N_P = 2^19 generators. The storage is static
   (Q-S11-8 (a)): about 310 MB. The run takes about 72 minutes with TCC
   (measured with other runs in parallel), thus `make ivc-h4` runs it
   and `make check` does not. A failed row writes `FAIL ivc h4 <name>`
   to stderr. The last line gives the number of rows and the number of
   mismatches. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "crypto/bn254.h"
#include "crypto/msm.h"
#include "crypto/nova.h"
#include "crypto/novacomp.h"
#include "crypto/novaivc.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/secq256k1.h"
#include "crypto/stepgadget.h"
#include "crypto/u256.h"

#include "crypto/stepcase.h"

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

/* The compressed proof (H4a C5). The pad of P is a = b = c = 19, thus G
   and K hold 2^19 values, FE holds spartan_work_len (5 x 2^19) and GW
   2^18. S uses the caps of the comp rows of test/ivcr1cs.c (c <= 16). */
#define H4_CP 524288u
#define H4_CS 65536u
#define H4_CSB 16384u
#define H4_CBUF 32768u
static G1 h4_comp_g_p[H4_CP];
static U256 h4_comp_k_p[H4_CP];
static EcJac h4_comp_b_p[H4_PBUCKETS];
static Fe h4_comp_fe_p[H4_CP * 5u];
static G1 h4_comp_gw_p[H4_CP / 2u];
static G1 h4_comp_g_s[H4_CS];
static U256 h4_comp_k_s[H4_CS];
static EcJac h4_comp_b_s[H4_CSB];
static Fe h4_comp_fe_s[H4_CS * 5u];
static G1 h4_comp_gw_s[H4_CS / 2u];
static Fe h4_comp_z[H4_SVARS];
static Fe h4_comp_e[H4_SROWS];
static NovaCompKey h4_comp_key;
static NovaCompProof h4_comp_pf;
static NovaCompProof h4_comp_pf2;
static unsigned char h4_comp_buf[H4_CBUF];
static unsigned char h4_comp_buf2[H4_CBUF];

static void h4_comp_side(NovaCompSide *sd, G1 *g, U256 *k, size_t n, EcJac *bucket, size_t buckets,
                         Fe *fe, G1 *gw) {
  sd->g = g;
  sd->g_cap = n;
  sd->k = k;
  sd->k_cap = n;
  sd->bucket = bucket;
  sd->buckets = buckets;
  sd->fe = fe;
  sd->fe_len = n * 5u;
  sd->gw = gw;
  sd->gw_len = n / 2u;
}

/* Sets the buffers of h4_comp_key, then nova_comp_setup for KEY. */
static int h4_comp_start(const NovaIvcKey *key) {
  h4_comp_side(&h4_comp_key.p, h4_comp_g_p, h4_comp_k_p, H4_CP, h4_comp_b_p, H4_PBUCKETS,
               h4_comp_fe_p, h4_comp_gw_p);
  h4_comp_side(&h4_comp_key.s, h4_comp_g_s, h4_comp_k_s, H4_CS, h4_comp_b_s, H4_CSB, h4_comp_fe_s,
               h4_comp_gw_s);
  h4_comp_key.z = h4_comp_z;
  h4_comp_key.var_cap = H4_SVARS;
  h4_comp_key.e = h4_comp_e;
  h4_comp_key.row_cap = H4_SROWS;
  return nova_comp_setup(&h4_comp_key, key);
}

/* The bytes of the Spartan proof of one side for the pad D (plan item 6):
   sum-check 1 (a x 4 values), v_A, v_B, v_C, v_E, sum-check 2 ((b + 1) x 3
   values), v_W, sum-check 3 (c x 3 values), w, e and a (32 bytes each),
   and the c IPA rounds (L and R, 65 bytes each). */
static size_t h4_side_bytes(const SpartanDims *d) {
  return (size_t)32u * (4u * d->a + 4u + 3u * (d->b + 1u) + 1u + 3u * d->c + 3u) +
         (size_t)130u * d->c;
}

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
   count 1 and the PK (as step_out_is of test/ivcr1cs.c). The compressed
   proof (H4a C5) of the proof of step 1: `nova comp h4 setup`:
   nova_comp_setup holds and the pad of P is a = b = c = 19. `nova comp h4
   prove`: nova_comp_prove holds. `nova comp h4 verify 0`: nova_comp_verify
   returns 0. `nova comp h4 size`: the P side has 8902 bytes, and encode,
   decode and encode give the same nova_comp_size bytes. The `ivc h4 comp`
   lines give the time of each step in seconds and the sizes. */
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
  int cok;
  time_t t0;
  size_t len;
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
  t0 = time(NULL);
  cok = ok && h4_comp_start(key);
  printf("ivc h4 comp setup: %ld s, pad P %u %u %u, pad S %u %u %u\n", (long)(time(NULL) - t0),
         h4_comp_key.p.d.a, h4_comp_key.p.d.b, h4_comp_key.p.d.c, h4_comp_key.s.d.a,
         h4_comp_key.s.d.b, h4_comp_key.s.d.c);
  row(&t, "nova comp h4 setup",
      cok && h4_comp_key.p.d.a == 19u && h4_comp_key.p.d.b == 19u && h4_comp_key.p.d.c == 19u);
  t0 = time(NULL);
  cok = cok && nova_comp_prove(&h4_comp_pf, &h4_comp_key, key, pf);
  printf("ivc h4 comp prove: %ld s\n", (long)(time(NULL) - t0));
  row(&t, "nova comp h4 prove", cok);
  t0 = time(NULL);
  good = cok && nova_comp_verify(&h4_comp_key, key, &h4_comp_pf) == 0;
  printf("ivc h4 comp verify: %ld s\n", (long)(time(NULL) - t0));
  row(&t, "nova comp h4 verify 0", good);
  len = nova_comp_size(&h4_comp_key);
  printf("ivc h4 comp size: %lu bytes (P %lu, S %lu)\n", (unsigned long)len,
         (unsigned long)h4_side_bytes(&h4_comp_key.p.d),
         (unsigned long)h4_side_bytes(&h4_comp_key.s.d));
  good = cok && h4_side_bytes(&h4_comp_key.p.d) == 8902u && len <= H4_CBUF &&
         nova_comp_encode(h4_comp_buf, len, &h4_comp_key, &h4_comp_pf) &&
         nova_comp_decode(&h4_comp_pf2, &h4_comp_key, key, h4_comp_buf, len) &&
         nova_comp_encode(h4_comp_buf2, len, &h4_comp_key, &h4_comp_pf2) &&
         memcmp(h4_comp_buf, h4_comp_buf2, len) == 0;
  row(&t, "nova comp h4 size", good);
  printf("crypto ivc h4: %u rows, %u mismatches\n", (unsigned)t.rows, (unsigned)t.mismatches);
  return t.mismatches == 0 ? 0 : 1;
}
