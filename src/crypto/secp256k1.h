/* Source: intent-lang 79e1898 src/front/secp256k1.h (the p and n comment;
   SECP_P and SECP_N renamed SECP_FP and SECP_FN; secp_recover cut).
   NEW (quorum-lang S7, O93): the group operations, the SEC1 compressed
   points and the scalar bytes of FROST(secp256k1, SHA-256) (RFC 9591
   section 6.5).

   secp256k1 (SEC 2 section 2.4.1): y^2 = x^3 + 7 over Fp, a group of prime
   order n (cofactor 1), on the generic fe_* and ec0_* of crypto/bn254.h.
   G1 (0, 0) is the identity. A scalar is an Fe below n (SECP_FN).

   p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
   n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 */
#ifndef LANG_CRYPTO_SECP256K1_H
#define LANG_CRYPTO_SECP256K1_H

#include "crypto/bn254.h"

extern const Modulus SECP_FP;
extern const Modulus SECP_FN;

/* OUT = the generator G (SEC 2 section 2.4.1). */
void secp_gen(G1 *out);
/* 1 when P is the identity or a point of y^2 = x^3 + 7. */
int secp_on_curve(const G1 *p);
/* OUT = A + B. */
void secp_add(G1 *out, const G1 *a, const G1 *b);
/* OUT = K P for each word K (n P is the identity). */
void secp_mul(G1 *out, const G1 *p, const U256 *k);
/* OUT = -A (the identity for the identity). */
void secp_neg(G1 *out, const G1 *a);
/* 1 when A and B are the same point. */
int secp_eq(const G1 *a, const G1 *b);
/* OUT = the SEC1 compressed bytes of P (SEC 1 section 2.3.3): 02 for an
   even y, 03 for an odd y, then x as 32 big endian bytes. Returns 1, or 0
   with OUT not written when P is the identity or off the curve (RFC 9591
   section 6.5 SerializeElement). */
int secp_encode(unsigned char out[33], const G1 *p);
/* OUT = the point of the SEC1 compressed bytes IN (RFC 9591 section 6.5
   DeserializeElement). Returns 1, or 0 with OUT not written when the
   prefix is not 02 or 03, x is p or more, or x^3 + 7 is not a square. */
int secp_decode(G1 *out, const unsigned char in[33]);
/* OUT = the scalar of the 32 big endian bytes IN (RFC 9591 section 6.5
   DeserializeScalar). Returns 1, or 0 with OUT not written when the value
   is n or more. */
int scalar_decode(Fe *out, const unsigned char in[32]);
/* OUT = the 32 big endian bytes of K (RFC 9591 section 6.5
   SerializeScalar). */
void scalar_encode(unsigned char out[32], const Fe *k);
/* NEW (quorum-lang S8, O105, R-C2): OUT = the point of the 64 bytes IN: x,
   then y, 32 big endian bytes each. Returns 1, or 0 with OUT not written
   when a coordinate is p or more or the point is not on the curve. (0, 0)
   gives the identity. */
int secp_from_xy(G1 *out, const unsigned char in[64]);
/* OUT = x, then y of P, 32 big endian bytes each ((0, 0) for the
   identity). */
void secp_to_xy(unsigned char out[64], const G1 *p);
#endif
