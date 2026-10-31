/* NEW (quorum-lang S11, O161): the gadgets of crypto/stepgadget.h. The
   one internal form of a byte string is the byte-bit order: entry 8 k + b
   is bit b (least significant first) of byte k. A constant bit 1 is
   variable 0 and a constant bit 0 is the variable ZERO of part 1. */
#include "crypto/stepgadget.h"

#include <string.h>

#include "crypto/ec7gadget.h"
#include "crypto/secp256k1.h"
#include "crypto/sha256.h"
#include "crypto/sha256gadget.h"

/* The tagAppend words of replica.lang (then 2 zero words) and the H2
   domain of FROST(secp256k1, SHA-256) (frost.c CTX || "chal"). */
#define STEP_TAG_0 8175563235948047713ull
#define STEP_TAG_1 8102087254438051840ull
#define STEP_DST "FROST-secp256k1-SHA256-v1chal"
#define STEP_DST_LEN 29u

static int bit_of(const U256 *c, size_t i) {
  return (int)((c->limb[i / 64u] >> (i % 64u)) & 1u);
}

static void modulus_u256(U256 *out, const Modulus *f) {
  Fe m;
  memcpy(m.w, f->w, sizeof m.w);
  fe_to_u256(out, &m);
}

/* The 8 big endian bytes of W at P. */
static void put_word(unsigned char *p, uint64_t w) {
  size_t i;
  for (i = 0; i < 8u; i++) p[i] = (unsigned char)(w >> (56u - 8u * i));
}

/* N new boolean variables: the low N bits of the value of X. */
static void value_bits(R1cs *cs, uint32_t *bit, uint32_t x, size_t n) {
  Fe v;
  U256 u;
  size_t i;
  r1cs_value(&v, cs, x);
  fe_to_u256(&u, &v);
  for (i = 0; i < n; i++) {
    fe_from_u64(&v, (u.limb[i / 64u] >> (i % 64u)) & 1u);
    bit[i] = r1cs_bool(cs, &v);
  }
}

/* 1 row: sum 2^i BIT[i] (i below N) = X. */
static void sum_is(R1cs *cs, const uint32_t *bit, size_t n, uint32_t x) {
  Fe w;
  Fe next;
  size_t i;
  fe_from_u64(&w, 1);
  r1cs_row(cs);
  for (i = 0; i < n; i++) {
    r1cs_term(cs, R1CS_A, bit[i], &w);
    fe_add(&next, &w, &w, cs->f);
    w = next;
  }
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, x, 1);
}

/* 1 row: the value of A = the value of B. */
static void equal(R1cs *cs, uint32_t a, uint32_t b) {
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, a, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, b, 1);
}

/* The byte reversal of an N-byte value: from the byte-bit order to the
   integer bits (least significant first), and back. */
static void int_bits(uint32_t *dst, const uint32_t *src, size_t n) {
  size_t i;
  for (i = 0; i < 8u * n; i++) dst[i] = src[8u * (n - 1u - i / 8u) + i % 8u];
}

/* The byte-bit order to the SHA-256 word order (bit j of word i is entry
   32 i + j, big endian words), and back, for N bytes (N a multiple of 4). */
static void word_order(uint32_t *dst, const uint32_t *src, size_t n) {
  size_t i;
  for (i = 0; i < 8u * n; i++) dst[32u * (i / 32u) + 8u * (3u - i / 8u % 4u) + i % 8u] = src[i];
}

/* The constant bits of the N bytes at BYTES in the byte-bit order. */
static void const_bytes(uint32_t *dst, const unsigned char *bytes, size_t n, uint32_t zero) {
  size_t i;
  for (i = 0; i < 8u * n; i++) dst[i] = ((bytes[i / 8u] >> (i % 8u)) & 1u) != 0u ? 0u : zero;
}

/* The constant bits of the SHA-256 state ST in the word order. */
static void const_state(uint32_t dst[SHA256_GADGET_STATE], const uint32_t st[8], uint32_t zero) {
  size_t i;
  for (i = 0; i < SHA256_GADGET_STATE; i++) dst[i] = ((st[i / 32u] >> (i % 32u)) & 1u) != 0u ? 0u : zero;
}

/* OUT = the digest (byte-bit order) of the NB blocks at MSG (byte-bit
   order, with the padding) from the state STATE (word order). */
static void hash_blocks(R1cs *cs, uint32_t out[STEP_GADGET_BITS], const uint32_t state[SHA256_GADGET_STATE],
                        const uint32_t *msg, size_t nb) {
  uint32_t st[SHA256_GADGET_STATE];
  uint32_t next[SHA256_GADGET_STATE];
  uint32_t block[SHA256_GADGET_BLOCK];
  size_t i;
  memcpy(st, state, sizeof st);
  for (i = 0; i < nb; i++) {
    word_order(block, msg + SHA256_GADGET_BLOCK * i, 64u);
    sha256_gadget(cs, next, st, block);
    memcpy(st, next, sizeof st);
  }
  word_order(out, st, 32u);
}

/* OUT = q_hash2 U V of replica.lang = SHA-256(U || V): 2 compressions
   from the initial state INIT. */
static void hash2(R1cs *cs, uint32_t out[STEP_GADGET_BITS], const uint32_t u[STEP_GADGET_BITS],
                  const uint32_t v[STEP_GADGET_BITS], const uint32_t init[SHA256_GADGET_STATE], uint32_t zero) {
  uint32_t msg[2u * SHA256_GADGET_BLOCK];
  unsigned char pad[64];
  memset(pad, 0, sizeof pad);
  pad[0] = 0x80;
  pad[62] = 0x02; /* 512 bits */
  memcpy(msg, u, STEP_GADGET_BITS * sizeof *msg);
  memcpy(msg + STEP_GADGET_BITS, v, STEP_GADGET_BITS * sizeof *msg);
  const_bytes(msg + SHA256_GADGET_BLOCK, pad, 64u, zero);
  hash_blocks(cs, out, init, msg, 2u);
}

/* The 33 bytes enc(P) = (2 + the parity of y) || x from the integer bits
   XI and YI. */
static void enc_point(uint32_t *dst, const uint32_t xi[STEP_GADGET_BITS], const uint32_t yi[STEP_GADGET_BITS],
                      uint32_t zero) {
  size_t i;
  dst[0] = yi[0];
  dst[1] = 0u;
  for (i = 2; i < 8u; i++) dst[i] = zero;
  int_bits(dst + 8, xi, 32u);
}

/* OUT = b_IDX of xmd = SHA-256(B (32 bytes) || IDX || DST || 29): 63
   bytes, so 2 blocks (0x80 at byte 63, the length 504 bits at the end). */
static void xmd_block(R1cs *cs, uint32_t out[STEP_GADGET_BITS], const uint32_t b[STEP_GADGET_BITS],
                      unsigned char idx, const uint32_t init[SHA256_GADGET_STATE], uint32_t zero) {
  uint32_t msg[2u * SHA256_GADGET_BLOCK];
  unsigned char tail[128];
  memset(tail, 0, sizeof tail);
  tail[32] = idx;
  memcpy(tail + 33, STEP_DST, STEP_DST_LEN);
  tail[62] = (unsigned char)STEP_DST_LEN;
  tail[63] = 0x80;
  tail[126] = 0x01; /* 504 bits */
  tail[127] = 0xf8;
  const_bytes(msg, tail, 128u, zero);
  memcpy(msg, b, STEP_GADGET_BITS * sizeof *msg);
  hash_blocks(cs, out, init, msg, 2u);
}

void step_below_gadget(R1cs *cs, const uint32_t bit[STEP_GADGET_BITS], const U256 *c) {
  uint32_t eq[STEP_GADGET_BITS + 1u];
  Fe one;
  Fe b;
  Fe t;
  Fe e;
  Fe next;
  size_t i;
  int coeff;
  fe_from_u64(&one, 1);
  e = one;
  eq[STEP_GADGET_BITS] = 0u;
  for (i = STEP_GADGET_BITS; i > 0u; i--) {
    r1cs_value(&b, cs, bit[i - 1u]);
    t = b;
    if (!bit_of(c, i - 1u)) fe_sub(&t, &one, &b, cs->f);
    fe_mul(&next, &e, &t, cs->f);
    e = next;
    eq[i - 1u] = r1cs_var(cs, &e);
    r1cs_row(cs);
    r1cs_term_int(cs, R1CS_A, eq[i], 1);
    if (bit_of(c, i - 1u)) {
      r1cs_term_int(cs, R1CS_B, bit[i - 1u], 1);
    } else {
      r1cs_term_int(cs, R1CS_B, 0, 1);
      r1cs_term_int(cs, R1CS_B, bit[i - 1u], -1);
    }
    r1cs_term_int(cs, R1CS_C, eq[i - 1u], 1);
  }
  /* The terms of eq_j add to c_(j-1) - c_j: one term for each change of
     the bits of C. */
  r1cs_row(cs);
  for (i = 0; i <= STEP_GADGET_BITS; i++) {
    coeff = (i > 0u ? bit_of(c, i - 1u) : 0) - (i < STEP_GADGET_BITS ? bit_of(c, i) : 0);
    if (coeff != 0) r1cs_term_int(cs, R1CS_A, eq[i], coeff);
  }
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, 0, 1);
}

void step_bits_gadget(R1cs *cs, uint32_t bit[STEP_GADGET_BITS], uint32_t x) {
  U256 m;
  value_bits(cs, bit, x, STEP_GADGET_BITS);
  sum_is(cs, bit, STEP_GADGET_BITS, x);
  modulus_u256(&m, cs->f);
  step_below_gadget(cs, bit, &m);
}

void step_gadget(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                 const uint32_t body[STEP_GADGET_BITS], const uint32_t r[2],
                 const uint32_t z[STEP_GADGET_BITS]) {
  uint32_t zero;
  uint32_t g[2];
  uint32_t pk[2];
  uint32_t cpk[2];
  uint32_t zg[2];
  uint32_t sum[2];
  uint32_t zi[STEP_GADGET_BITS];
  uint32_t head_i[STEP_GADGET_BITS];
  uint32_t head_b[STEP_GADGET_BITS];
  uint32_t pkx[STEP_GADGET_BITS];
  uint32_t pky[STEP_GADGET_BITS];
  uint32_t rx[STEP_GADGET_BITS];
  uint32_t ry[STEP_GADGET_BITS];
  uint32_t count[64];
  uint32_t init[SHA256_GADGET_STATE];
  uint32_t zpad_state[SHA256_GADGET_STATE];
  uint32_t tag[STEP_GADGET_BITS];
  uint32_t zero4[STEP_GADGET_BITS];
  uint32_t a[STEP_GADGET_BITS];
  uint32_t d[STEP_GADGET_BITS];
  uint32_t h[STEP_GADGET_BITS];
  uint32_t h_i[STEP_GADGET_BITS];
  uint32_t msg[3u * SHA256_GADGET_BLOCK];
  uint32_t b0[STEP_GADGET_BITS];
  uint32_t b1[STEP_GADGET_BITS];
  uint32_t b2[STEP_GADGET_BITS];
  uint32_t bx[STEP_GADGET_BITS];
  uint32_t k_b[384];
  uint32_t k_i[384];
  uint32_t st[8];
  unsigned char bytes[192];
  U256 n;
  Fe v;
  G1 gen;
  size_t i;

  /* Part 1: the constants zero (1 row: zero 1 = 0) and G (2 rows). */
  fe_from_u64(&v, 0);
  zero = r1cs_var(cs, &v);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, zero, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  secp_gen(&gen);
  ec7_const_gadget(cs, g, &gen.x, &gen.y);

  /* Part 2: the witness bits, and z < n (frost_verify refuses z >= n). */
  for (i = 0; i < STEP_GADGET_BITS; i++) r1cs_assert_bool(cs, body[i]);
  for (i = 0; i < STEP_GADGET_BITS; i++) r1cs_assert_bool(cs, z[i]);
  int_bits(zi, z, 32u);
  modulus_u256(&n, &SECP_FN);
  step_below_gadget(cs, zi, &n);

  /* Part 3: the old head (2^128 < p, so the bits of each limb are
     canonical), then PK and R (the canonical bits fix enc(PK), enc(R)). */
  value_bits(cs, head_i, in[0], 128u);
  value_bits(cs, head_i + 128, in[1], 128u);
  sum_is(cs, head_i, 128u, in[0]);
  sum_is(cs, head_i + 128, 128u, in[1]);
  int_bits(head_b, head_i, 32u);
  step_bits_gadget(cs, pkx, in[3]);
  step_bits_gadget(cs, pky, in[4]);
  step_bits_gadget(cs, rx, r[0]);
  step_bits_gadget(cs, ry, r[1]);

  /* Part 4: the count: w4a body (bytes 0 to 7) = IN[2] + 1. */
  int_bits(count, body, 8u);
  out[2] = r1cs_pack(cs, count, 64u);
  r1cs_row(cs);
  r1cs_term_int(cs, R1CS_A, in[2], 1);
  r1cs_term_int(cs, R1CS_A, 0, 1);
  r1cs_term_int(cs, R1CS_B, 0, 1);
  r1cs_term_int(cs, R1CS_C, out[2], 1);

  /* Part 5: appendHead head body = q_hash2 (q_hash2 tagAppend head)
     (q_hash2 body zero4). */
  sha256_initial(st);
  const_state(init, st, zero);
  memset(bytes, 0, sizeof bytes);
  const_bytes(zero4, bytes, 32u, zero);
  put_word(bytes, STEP_TAG_0);
  put_word(bytes + 8, STEP_TAG_1);
  const_bytes(tag, bytes, 32u, zero);
  hash2(cs, a, tag, head_b, init, zero);
  hash2(cs, d, body, zero4, init, zero);
  hash2(cs, h, a, d, init, zero);
  int_bits(h_i, h, 32u);
  out[0] = r1cs_pack(cs, h_i, 128u);
  out[1] = r1cs_pack(cs, h_i + 128, 128u);
  out[3] = in[3];
  out[4] = in[4];

  /* Part 6: c = OS2IP(xmd(enc(R) || enc(PK) || h, 48)) mod n (RFC 9380).
     msg_prime = 64 zero bytes || the 98 message bytes || 0x00 0x30 || 0x00
     || DST || 29 (195 bytes, 4 blocks with the padding). Block 0 is
     constant: its state is computed here. Bytes below are msg_prime bytes
     64 to 255. */
  memset(bytes, 0, sizeof bytes);
  sha256_initial(st);
  sha256_compress(st, bytes);
  const_state(zpad_state, st, zero);
  bytes[99] = 0x30;
  memcpy(bytes + 101, STEP_DST, STEP_DST_LEN);
  bytes[130] = (unsigned char)STEP_DST_LEN;
  bytes[131] = 0x80;
  bytes[190] = 0x06; /* 1560 bits */
  bytes[191] = 0x18;
  const_bytes(msg, bytes, 192u, zero);
  enc_point(msg, rx, ry, zero);
  enc_point(msg + 8u * 33u, pkx, pky, zero);
  memcpy(msg + 8u * 66u, h, sizeof h);
  hash_blocks(cs, b0, zpad_state, msg, 3u);
  xmd_block(cs, b1, b0, 1u, init, zero);
  for (i = 0; i < STEP_GADGET_BITS; i++) bx[i] = r1cs_xor(cs, b0[i], b1[i]);
  xmd_block(cs, b2, bx, 2u, init, zero);
  memcpy(k_b, b1, sizeof b1);
  memcpy(k_b + STEP_GADGET_BITS, b2, 128u * sizeof *b2);
  int_bits(k_i, k_b, 48u);

  /* Part 7: z G = R + K PK. K is not reduced mod n: n PK is the identity,
     so K PK = c PK. */
  ec7_curve_gadget(cs, r);
  pk[0] = in[3];
  pk[1] = in[4];
  ec7_mul_bits_gadget(cs, cpk, pk, k_i, 384u);
  ec7_mul_bits_gadget(cs, zg, g, zi, STEP_GADGET_BITS);
  ec7_add_gadget(cs, sum, r, cpk);
  equal(cs, zg[0], sum[0]);
  equal(cs, zg[1], sum[1]);
}
