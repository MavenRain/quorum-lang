/* NEW (quorum-lang S11 H2, O155): the Poseidon permutation of the IVC
   transcript and commitments.

   The parameters (O155): width 3 (rate 2, capacity 1), alpha 5, R_F 8 full
   rounds (4 before and 4 after the partial rounds), R_P 57 partial rounds
   with the S-box on element 0 only. Each round adds the round constants,
   applies the S-box x^5, and multiplies by the MDS matrix.

   The round constants and the MDS matrix come from the Grain LFSR of the
   Poseidon reference (generate_params_poseidon.sage): the seed has the
   field type 1, the S-box 0, the bit length of the modulus, the width, R_F
   and R_P. The MDS matrix is the Cauchy matrix of the first sample; the
   script quorum-lang-work/s11-h2-vectors.py checks this sample (the
   characteristic polynomials of M to M^6 are irreducible) for SECP_FP,
   SECP_FN and BN254_FR. With BN254_FR the permutation is the one of
   circomlib poseidon for 2 inputs. */
#ifndef LANG_CRYPTO_POSEIDON_H
#define LANG_CRYPTO_POSEIDON_H

#include "crypto/bn254.h"

#define POSEIDON_WIDTH 3u
#define POSEIDON_RF 8u
#define POSEIDON_RP 57u
#define POSEIDON_ROUNDS (POSEIDON_RF + POSEIDON_RP)
#define POSEIDON_CONSTANTS (POSEIDON_ROUNDS * POSEIDON_WIDTH)

/* The parameter set for one field. */
typedef struct {
  Modulus f;
  Fe rc[POSEIDON_CONSTANTS];
  Fe mds[POSEIDON_WIDTH][POSEIDON_WIDTH];
} PoseidonParams;

/* OUT = the Grain parameter set for the prime field F. */
void poseidon_params(PoseidonParams *out, const Modulus *f);
/* STATE = the permutation of STATE (each element below the modulus). */
void poseidon_perm(Fe state[POSEIDON_WIDTH], const PoseidonParams *p);

#endif
