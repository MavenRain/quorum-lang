/* NEW (quorum-lang S11 H2): the commitment generators of the IVC on
   secp256k1 and secq256k1, by try and increment from SHA-256.

   For the index i and the counter c = 0, 1, 2, ...:
   msg = "quorum-lang/ivc/gens/v1" || 0x00 || curve name || 0x00 ||
         be32(i) || be32(c)
   x = SHA-256(msg) as a big-endian number. The generator is the first
   (x, y) with x below the base field modulus q and x^3 + 7 a square in
   F_q; y is the even root. The curve names are "secp256k1" and
   "secq256k1". The steps follow gens of quorum-lang-work/s11-h2-vectors.py. */
#ifndef LANG_CRYPTO_GENS_H
#define LANG_CRYPTO_GENS_H

#include <stdint.h>

#include "crypto/bn254.h"

typedef enum {
  GENS_SECP256K1,
  GENS_SECQ256K1
} GensCurve;

/* OUT = the generator INDEX of CURVE. */
void gens_point(G1 *out, GensCurve curve, uint32_t index);

#endif
