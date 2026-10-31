/* NEW (quorum-lang S11 H3a P4, O159): R1CS gadgets of the points of
   y^2 = x^3 + 7 over the field of the system: secp256k1 over F_p in the
   primary circuit and secq256k1 over F_n in the secondary circuit (O144).
   A point is 2 variables (x, y) in affine form.

   The rule of the edge cases (O159): the identity has no form in these
   gadgets. Each input point must be a point of the curve that is not the
   identity, and no gadget makes the identity. The add is not complete:
   it proves that x2 - x1 is not 0 (1 row), so a system with A = B or
   A = -B has no witness (the free lambda of A = B is closed). The double
   needs a point of the curve: then y is not 0, because the group order is
   an odd prime. A scalar K with K P the identity (K = 0, K = n) has no
   witness. One exception (O160): the flag A_ID of ec7_add_id_gadget says
   that A is the identity, because the folded commitment E of the Nova
   fold is the identity after the base step. */
#ifndef LANG_CRYPTO_EC7GADGET_H
#define LANG_CRYPTO_EC7GADGET_H

#include <stddef.h>

#include "crypto/r1cs.h"

/* The scalar bits of ec7_mul_gadget: 2 limbs of 128 bits. */
#define EC7_GADGET_BITS 256u

/* Asserts that P = (P[0], P[1]) is on y^2 = x^3 + 7: 3 rows, 2 new
   variables, 10 terms. */
void ec7_curve_gadget(R1cs *cs, const uint32_t p[2]);
/* OUT = A + B for 2 points with different x: 4 rows ((x2 - x1) inv = 1,
   lambda, x3, y3), 4 new variables (inv, lambda, x3, y3), 19 terms. */
void ec7_add_gadget(R1cs *cs, uint32_t out[2], const uint32_t a[2], const uint32_t b[2]);
/* OUT = 2 A for a point A of the curve: 4 rows (x x, lambda, x3, y3), 4
   new variables (x x, lambda, x3, y3), 15 terms. OUT can be A. */
void ec7_double_gadget(R1cs *cs, uint32_t out[2], const uint32_t a[2]);
/* OUT = K P for K = K[0] + 2^128 K[1], where each limb must be below
   2^128. P must be a point of the curve (the gadget asserts it). The
   rows: the curve check of P (3), the 256 scalar bits (bit i of limb j
   is bit 128 j + i of K), 1 linear row for each limb, 2 rows for the
   constant offset point Q, and then for each bit i (least significant
   first) ACC + 2^i P (4), 2 selects and the next double (4, not after
   bit 255). ACC starts at Q, so it is never the identity. The last add
   (4) gives ACC + (-Q) (1 row for -Q). 2824 rows, 2821 new variables,
   12315 terms. */
void ec7_mul_gadget(R1cs *cs, uint32_t out[2], const uint32_t p[2], const uint32_t k[2]);
/* OUT = K P for K = sum 2^i BIT[i] (i < N, N at least 1): the scalar as N
   bits, least significant first (O160). The fold challenge r of Nova is
   128 bits of a Poseidon output; a hash output can also be the scalar.
   Each BIT[i] must be a boolean variable: the caller asserts it (with
   r1cs_bool, or the output bits of sha256_gadget). P must be a point of
   the curve (the gadget asserts it). The rows: the curve check of P (3),
   Q (2), the loop (10 for each bit, 6 for the last bit), -Q (1) and the
   last add (4). 10 N + 6 rows, 10 N + 5 new variables, 44 N + 23 terms. */
void ec7_mul_bits_gadget(R1cs *cs, uint32_t out[2], const uint32_t p[2], const uint32_t *bit,
                         size_t n);
/* OUT = A + B when A_ID is 0, and OUT = B when A_ID is 1 (O160). A_ID = 1
   says that A is the identity; the gadget then does not use the
   coordinates of A. A_ID must be 0 or 1 (the gadget asserts it). B must
   be a point of the curve that is not the identity. When A_ID is 0, A
   must be a point of the curve with a different x. When A_ID is 1, the
   add uses Q (the offset point of the mul) in place of A, and the select
   ignores that sum. 11 rows (A_ID boolean, Q (2), 2 selects, the add (4),
   2 selects), 10 new variables, 48 terms. */
void ec7_add_id_gadget(R1cs *cs, uint32_t out[2], const uint32_t a[2], uint32_t a_id,
                       const uint32_t b[2]);

/* NEW (quorum-lang S11 H3b, O161): OUT = the constant point (X, Y), for
   the generator in crypto/stepgadget.h. 2 rows (each V 1 = C), 2 new
   variables, 6 terms. The caller gives a point on the curve. */
void ec7_const_gadget(R1cs *cs, uint32_t out[2], const Fe *x, const Fe *y);
#endif
