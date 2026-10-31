/* NEW (quorum-lang S11 H3a P3): the SHA-256 compression of sha256.c
   (FIPS 180-4 section 6.2.2) as rows of a rank-1 constraint system
   (r1cs.h), on boolean bit variables. All the sums are less than 2^35, so
   the rows hold in F_p and in F_n.

   A word is 32 bit variables, bit 0 first (the least significant bit). A
   rotation or a shift only moves bits, so it adds no rows. The xor of 3
   words takes 2 rows for each bit (r1cs_xor 2 times). Where a right shift
   gives the constant 0, it takes 1 row. Ch (e, f, g) is r1cs_select (e, f,
   g): 1 row for each bit. Maj (a, b, c) is c where a and b are different
   and a where they are equal: r1cs_xor and r1cs_select, 2 rows for each
   bit. A sum mod 2^32 of m terms (the words and a constant that is not 0)
   is less than 2^(32 + c), where c is the number of bits of m - 1. The
   sum gets 32 + c new boolean bits (32 + c rows) and 1 linear row: the
   packed input bits and the constant equal the packed new bits. A round
   makes the new e and the new a directly with 2 sums, so T1 and T2 get no
   variables.

   Count: each of the 48 schedule words takes 61 (sigma 0) + 54 (sigma 1)
   + 35 (a sum of 4 words) = 150 rows. Each of the 64 rounds takes 64
   (Sigma 1) + 32 (Ch) + 64 (Sigma 0) + 64 (Maj) + 36 + 36 (the 2 sums) =
   296 rows. Each of the 8 final sums takes 34 rows. Thus 7200 + 18944 +
   272 = 26416 rows and 26232 new variables (O146 gives about 27k). With
   the 768 boolean input bits (1 row each) and the constant, the system of
   test/ivcr1cs.c (the row `sha256 sizes`) has 27001 variables, 27184 rows
   and 156584 terms. */
#ifndef LANG_CRYPTO_SHA256GADGET_H
#define LANG_CRYPTO_SHA256GADGET_H

#include <stdint.h>

#include "crypto/r1cs.h"

enum { SHA256_GADGET_STATE = 256, SHA256_GADGET_BLOCK = 512 };

/* OUT = the bits of sha256_compress of the block BLOCK into the state
   STATE. Bit j of word i is entry 32 i + j of each array (bit 0 is the
   least significant bit). The 16 block words are the big-endian words of
   the 64 block bytes. STATE and BLOCK must be boolean variables of CS. OUT
   gets new boolean variables. */
void sha256_gadget(R1cs *cs, uint32_t out[SHA256_GADGET_STATE],
                   const uint32_t state[SHA256_GADGET_STATE],
                   const uint32_t block[SHA256_GADGET_BLOCK]);

#endif
