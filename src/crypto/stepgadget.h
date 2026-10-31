/* NEW (quorum-lang S11, O161): the step circuit F of the replica chain
   over F_p of secp256k1 (the primary circuit, O144). F proves one good
   step of replica.lang stepOf: the body count is the old count + 1, the
   new head is appendHead of the old head and the body, and (R, z) is a
   FROST(secp256k1, SHA-256) signature of the new head for PK
   (frost_verify_xy). A bad step has no witness. Each gadget reads its
   input values with r1cs_value, so the sizing run (all capacities 0)
   gives the same rows. */
#ifndef LANG_CRYPTO_STEPGADGET_H
#define LANG_CRYPTO_STEPGADGET_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/r1cs.h"
#include "crypto/u256.h"

/* The state z of F: head limb 0, head limb 1, count, PK x, PK y. The head
   H (32 bytes) is OS2IP(H) = limb 0 + 2^128 limb 1. */
#define STEP_GADGET_Z 5u
/* The bits of a field element or of a 32-byte value. */
#define STEP_GADGET_BITS 256u

/* Asserts sum 2^i BIT[i] < C (the caller asserts each bit boolean): 256
   rows eq_i = eq_(i+1) t_i (t_i = BIT[i] when bit i of C is 1, else 1 -
   BIT[i]; eq_256 = 1), then 1 row: the sum over the 1 bits of C of
   eq_(i+1) - eq_i is 1. 257 rows, 256 new variables. */
void step_below_gadget(R1cs *cs, const uint32_t bit[STEP_GADGET_BITS], const U256 *c);

/* BIT = the 256 canonical bits of X (least significant first): 256
   r1cs_bool, 1 row sum 2^i BIT[i] = X, then step_below_gadget with the
   modulus of the field. 514 rows, 512 new variables. */
void step_bits_gadget(R1cs *cs, uint32_t bit[STEP_GADGET_BITS], uint32_t x);

/* F: OUT = the state after the step from IN with the body BODY and the
   signature (R, Z). BODY and Z are the bits of the 32 body bytes and of
   the 32 z bytes: entry 8 k + b is bit b (least significant first) of
   byte k. R = (x, y). F asserts each bit of BODY and Z boolean. OUT[0] and
   OUT[1] are the limbs of the new head and OUT[2] is the new count (new
   variables); OUT[3] = IN[3] and OUT[4] = IN[4]. The parts (O161): 1 the
   constants, 2 the witness bits and z < n, 3 the input bits, 4 the count,
   5 the head link (6 compressions), 6 the challenge (xmd, 7
   compressions), 7 z G = R + c PK. */
void step_gadget(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                 const uint32_t body[STEP_GADGET_BITS], const uint32_t r[2],
                 const uint32_t z[STEP_GADGET_BITS]);
#endif
