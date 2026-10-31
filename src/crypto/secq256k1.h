/* NEW (quorum-lang S11 H2, O156): the secq256k1 curve of the IVC cycle, and
   a square root in any prime field.

   secq256k1: y^2 = x^3 + 7 over F_n, with n the order of secp256k1 (SECQ_FB
   = SECP_FN). Its group has the prime order p of the secp256k1 base field
   (SECQ_FS = SECP_FP), so the two curves make a cycle. The operations use
   the generic fe_* and ec0_* of crypto/bn254.h. G1 (0, 0) is the identity.

   The generator (O156) is the point with the least x (x = 1) and the even
   y. No published secq256k1 generator is used:
   x = 1
   y = 0x0c7c97045a2074634909abdf82c9bd0248916189041f2af0c1b800d1ffc278c0 */
#ifndef LANG_CRYPTO_SECQ256K1_H
#define LANG_CRYPTO_SECQ256K1_H

#include "crypto/secp256k1.h"

/* The base field and the scalar field of secq256k1. */
#define SECQ_FB SECP_FN
#define SECQ_FS SECP_FP

/* OUT = a square root of A in F, by Tonelli-Shanks (F is an odd prime).
   Returns 1, or 0 when A is not a square (OUT does not change). The root
   is the one that the algorithm finds; a caller that needs a parity sets
   it. OUT can be A. */
int fe_sqrt(Fe *out, const Fe *a, const Modulus *f);

/* OUT = the generator G (O156). */
void secq_gen(G1 *out);
/* 1 when P is on the curve; (0, 0) is. */
int secq_on_curve(const G1 *p);
/* Each operation takes points on the curve. OUT can be A or B. */
void secq_add(G1 *out, const G1 *a, const G1 *b);
void secq_double(G1 *out, const G1 *a);
/* K times P over all 256 bits of K (ec0_mul). */
void secq_mul(G1 *out, const G1 *p, const U256 *k);
void secq_neg(G1 *out, const G1 *a);
int secq_eq(const G1 *a, const G1 *b);

#endif
