/* NEW (quorum-lang S11 H3c, C4d): the h4 fixture of the step circuit F,
   from test/ivcr1cs.c: small, the h4 data, StepCase, step_case, step_f
   and the helpers that they call, and step_modulus (the M of a
   NovaIvcSide). test/ivcr1cs.c and test/ivch4.c include it. Each function
   is static, thus each file that includes this header must use each
   function (CLANG_FLAGS has -Wall -Wextra). */
#ifndef LANG_TEST_STEPCASE_H
#define LANG_TEST_STEPCASE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto/bn254.h"
#include "crypto/r1cs.h"
#include "crypto/secp256k1.h"
#include "crypto/sha256.h"
#include "crypto/stepgadget.h"
#include "crypto/u256.h"

static Fe small(uint64_t n) {
  Fe v;
  fe_from_u64(&v, n);
  return v;
}

/* NEW (quorum-lang S11 H3b, O161): the h4 line of
   test/replica/history.txt (the S8 chain fixture; the record order of
   test/replicatool.c parse_chain). PK is x, then y. Each step, the oldest
   first: the body (4 words), R (8 words: x, then y), z (4 words). A word
   is 8 bytes big endian. */
static const uint64_t step_pk[8] = {12497821472401162833ull, 15507384598146669907ull,
                                    6834132724802995776ull, 10000222574484625982ull,
                                    1173050333486418496ull, 4734722359773966692ull,
                                    17534111891838290511ull, 307875280325424553ull};
static const uint64_t step_word[4][16] = {
    {1ull, 1ull, 10ull, 0ull,
     2343347687641151001ull, 615011732042658582ull, 3865476810004566966ull,
     11914428586649733582ull, 12915556322603752808ull, 9561399457263426954ull,
     17742954851220218610ull, 7365230933458378087ull, 4788937510527362129ull,
     16737325580889694508ull, 6464542538254667117ull, 16185013846458767538ull},
    {2ull, 2ull, 20ull, 0ull,
     2017527522702323189ull, 11580570774985015215ull, 4363340732288558447ull,
     1690172092017023383ull, 3912671873706874372ull, 17464866896378878113ull,
     8813895737310075518ull, 18317947955053534112ull, 16541682183807044552ull,
     8531181588818476338ull, 10655443457930798494ull, 9278320044172001680ull},
    {3ull, 3ull, 30ull, 0ull,
     4873820955512674118ull, 8158987396724552477ull, 15019893926309277147ull,
     8227419800731808970ull, 14028461905475441361ull, 8574305021039480870ull,
     6443056524912631238ull, 15978078309966528740ull, 3122099886661746645ull,
     5132730940726145650ull, 3437130952187572450ull, 14411727224674370234ull},
    {4ull, 4ull, 40ull, 0ull,
     1991743116332035185ull, 9072925771727682363ull, 3378520080323091889ull,
     1116509017444999434ull, 338933949063647945ull, 1955529421816616110ull,
     13002856617416922732ull, 1151735958744718383ull, 7789001305003813393ull,
     4753724528895226320ull, 15263891474748950972ull, 1319220416894125305ull}};

/* tagGenesis and tagAppend of replica.lang (then 2 zero words). */
static const uint64_t step_genesis[2] = {8175563235948047719ull, 7308890791633682432ull};
static const uint64_t step_append[2] = {8175563235948047713ull, 8102087254438051840ull};

/* The values of one step: IN, the body bytes, and SIG = R x, R y, z (32
   bytes each, as frost_verify_xy). */
typedef struct {
  Fe in[STEP_GADGET_Z];
  unsigned char body[32];
  unsigned char sig[96];
} StepCase;

static void step_words(unsigned char *out, const uint64_t *w, size_t n) {
  size_t i;
  for (i = 0; i < 8u * n; i++) out[i] = (unsigned char)(w[i / 8u] >> (56u - 8u * (i % 8u)));
}

/* q_hash2 U V of replica.lang: the SHA-256 of the 64 bytes U || V. */
static void step_hash2(unsigned char out[32], const unsigned char u[32], const unsigned char v[32]) {
  unsigned char m[64];
  memcpy(m, u, 32u);
  memcpy(m + 32, v, 32u);
  sha256(m, 64u, out);
}

/* The Fe of the N big endian bytes at B (N at most 32). */
static Fe step_fe(const unsigned char *b, size_t n) {
  unsigned char w[32];
  U256 u;
  Fe v;
  memset(w, 0, sizeof w);
  memcpy(w + 32u - n, b, n);
  u256_from_be(&u, w);
  fe_from_u256(&v, &u, &SECP_FP);
  return v;
}

static void step_modulus(U256 *out, const Modulus *f) {
  Fe m;
  memcpy(m.w, f->w, sizeof m.w);
  fe_to_u256(out, &m);
}

/* New variables for the bits of the 32 bytes at B in the byte-bit order. */
static void step_byte_vars(R1cs *cs, uint32_t v[STEP_GADGET_BITS], const unsigned char *b) {
  Fe bit;
  size_t i;
  for (i = 0; i < STEP_GADGET_BITS; i++) {
    bit = small((b[i / 8u] >> (i % 8u)) & 1u);
    v[i] = r1cs_var(cs, &bit);
  }
}

/* The case of step K (0 = the oldest) of h4 from the head HEAD and the
   count COUNT. NEXT gets the native new head (appendHead). */
static void step_case(StepCase *s, const unsigned char head[32], uint64_t count, size_t k, unsigned char next[32]) {
  unsigned char tag[32];
  unsigned char zero4[32];
  unsigned char a[32];
  unsigned char d[32];
  unsigned char pk[64];
  memset(tag, 0, sizeof tag);
  memset(zero4, 0, sizeof zero4);
  step_words(tag, step_append, 2u);
  step_words(s->body, step_word[k], 4u);
  step_words(s->sig, step_word[k] + 4, 12u);
  step_words(pk, step_pk, 8u);
  step_hash2(a, tag, head);
  step_hash2(d, s->body, zero4);
  step_hash2(next, a, d);
  s->in[0] = step_fe(head + 16, 16u);
  s->in[1] = step_fe(head, 16u);
  s->in[2] = small(count);
  s->in[3] = step_fe(pk, 32u);
  s->in[4] = step_fe(pk + 32, 32u);
}

/* The real F (C4d): a NovaStepFn wrapper on step_gadget. CTX is the
   StepCase of the step: the body bits, R and the z bits come from its
   body and its SIG. */
static void step_f(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                   const void *ctx) {
  const StepCase *s = (const StepCase *)ctx;
  uint32_t body[STEP_GADGET_BITS];
  uint32_t r[2];
  uint32_t z[STEP_GADGET_BITS];
  Fe v;
  step_byte_vars(cs, body, s->body);
  v = step_fe(s->sig, 32u);
  r[0] = r1cs_var(cs, &v);
  v = step_fe(s->sig + 32, 32u);
  r[1] = r1cs_var(cs, &v);
  step_byte_vars(cs, z, s->sig + 64);
  step_gadget(cs, out, in, body, r, z);
}

#endif
