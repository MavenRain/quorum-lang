/* New C (S6 H2b): a Pedersen distributed key generation over BN254 G1,
   after the FROST paper (Komlo and Goldberg, 2020), Figure 1, without a
   trusted dealer.

   Each dealer i of n deals a polynomial f_i of degree t - 1 over Fr, with
   the coefficients a_{i,k} = thr_nonce(seed_i, k). The dealer publishes the
   Feldman commitments C_{i,k} = a_{i,k} G and a Schnorr proof of knowledge
   of a_{i,0}, and sends f_i(j) to the member j. QUAL is the set of the
   dealers with a valid proof and a valid share for each member: a
   complaint against one share removes the dealer for all members, so QUAL
   is the same at each member. The member j keeps sk_j = the sum over QUAL
   of f_i(j). The public key is PK = the sum over QUAL of C_{i,0}, and
   PK_j = sk_j G. The output is a ThrShare, so thr_partial and thr_open
   take DKG shares.

   Dealer and member indices are 1 to n. A QUAL is a bit set: bit i is the
   dealer i (as the seen set of thr_open). SHARES is the n by n table of the
   sent shares: SHARES[(i - 1) n + (j - 1)] = f_i(j). */
#ifndef LANG_CRYPTO_DKG_H
#define LANG_CRYPTO_DKG_H

#include <stdint.h>

#include "crypto/bn254.h"
#include "crypto/threshold.h"
#include "crypto/u256.h"

/* The domain tag of the proof challenge: the ASCII bytes of "dkg" as a
   word. */
extern const U256 DKG_TAG;

/* The public part of a dealing for the threshold t: C[k] = a_k G for k < t
   (the other points are 0), and the proof R = w G, z = w + c a_0 mod r. */
typedef struct {
  G1 c[THR_N_MAX];
  G1 r;
  U256 z;
} DkgDealing;

typedef enum {
  DKG_OK,
  DKG_BAD_SHARE, /* a share fails its Feldman check: the dealer is not in QUAL */
  DKG_BAD_PROOF, /* a proof fails or a point is off the curve: the dealer is not in QUAL */
  DKG_BAD_INDEX, /* an index is 0 or above n, or t or n is out of range */
  DKG_TOO_FEW    /* QUAL is empty */
} DkgResult;

/* The challenge c: the chain of thr_hash from DKG_TAG over CTX, I, C0.x,
   C0.y, R.x, R.y (6 hashes), not reduced. */
void dkg_challenge(U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r);
/* The dealing of the dealer I for T of N and CTX, with SHARES[j - 1] =
   f_i(j) for j = 1 to N. SEED is fresh secret 256-bit entropy for each
   dealing. DKG_BAD_INDEX when N is above THR_N_MAX, T is 0 or above N, or
   I is 0 or above N (before any write), else DKG_OK. */
DkgResult dkg_deal(DkgDealing *out, U256 *shares, const U256 *seed, uint32_t i, uint32_t t, uint32_t n, const U256 *ctx);
/* 1 when R and C[k] for k < T are on the curve and z G = R + c C[0], with
   c = dkg_challenge for the dealer I. T must be 1 to THR_N_MAX. */
int dkg_check_proof(const DkgDealing *d, uint32_t i, uint32_t t, const U256 *ctx);
/* The sum over k < T of J^k C[k], by Horner. T must be 1 to THR_N_MAX. */
void dkg_eval(G1 *out, const DkgDealing *d, uint32_t t, uint32_t j);
/* 1 when S G = dkg_eval(D, T, J): the Feldman check of the share of the
   member J. */
int dkg_check_share(const DkgDealing *d, uint32_t t, uint32_t j, const U256 *s);
/* QUAL for the N dealings and the share table. In order: DKG_BAD_INDEX
   when N is above THR_N_MAX or T is 0 or above N (before any write),
   DKG_TOO_FEW when QUAL is empty, DKG_BAD_PROOF when a dealer fails its
   proof, DKG_BAD_SHARE when a dealer fails a share check, else DKG_OK.
   *QUAL gets the set for each result but DKG_BAD_INDEX. */
DkgResult dkg_qual(uint32_t *qual, const DkgDealing *dealings, const U256 *shares, uint32_t t, uint32_t n, const U256 *ctx);
/* The share of the member J: x = J, s = the sum over QUAL of f_i(J) mod r,
   key = s G. In order: DKG_BAD_INDEX when N is above THR_N_MAX or J is 0
   or above N, DKG_TOO_FEW when QUAL has no dealer of 1 to N (before any
   write), else DKG_OK. */
DkgResult dkg_share(ThrShare *out, uint32_t qual, const U256 *shares, uint32_t j, uint32_t n);
/* PK_J from the commitments only (the KEYS of thr_open): the sum over QUAL
   of dkg_eval(D_i, T, J). In order: DKG_BAD_INDEX when N is above
   THR_N_MAX, T is 0 or above N, or J is 0 or above N, DKG_TOO_FEW when
   QUAL has no dealer of 1 to N (before any write), else DKG_OK. */
DkgResult dkg_key(G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t t, uint32_t j, uint32_t n);
/* PK: the sum over QUAL of C_{i,0} for the dealers 1 to N. */
void dkg_public(G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t n);

#endif
