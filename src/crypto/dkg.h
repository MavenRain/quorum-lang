/* New C (S6 H2b): a Pedersen distributed key generation, after the FROST
   paper (Komlo and Goldberg, 2020), Figure 1, without a trusted dealer.
   S7 H3b (O96): one DKG for two curves. A DkgCurve gives the group
   operations, the scalar modulus r and the generator G: DKG_BN254 (BN254
   G1, the S6 DKG) and DKG_SECP256K1 (the keys of FROST). Each dkg_*
   function takes the curve first.
   Each dealer i of n deals a polynomial f_i of degree t - 1 mod r, with
   the coefficients a_{i,k} = the nonce of the curve for (seed_i, k). The
   dealer publishes the Feldman commitments C_{i,k} = a_{i,k} G and a
   Schnorr proof of knowledge of a_{i,0}, and sends f_i(j) to the member j.
   QUAL is the set of the dealers with a valid proof and a valid share for
   each member: a complaint against one share removes the dealer for all
   members, so QUAL is the same at each member. The member j keeps sk_j =
   the sum over QUAL of f_i(j). The public key is PK = the sum over QUAL of
   C_{i,0}, and PK_j = sk_j G. The output is a ThrShare: with DKG_BN254,
   thr_partial and thr_open take DKG shares; with DKG_SECP256K1, s is the
   FROST secret share and key is its verification share.
   Dealer and member indices are 1 to n. A QUAL is a bit set: bit i is the
   dealer i (as the seen set of thr_open). SHARES is the n by n table of the
   sent shares: SHARES[(i - 1) n + (j - 1)] = f_i(j). */
#ifndef LANG_CRYPTO_DKG_H
#define LANG_CRYPTO_DKG_H

#include <stdint.h>

#include "crypto/bn254.h"
#include "crypto/threshold.h"
#include "crypto/u256.h"

/* The domain tag of the DKG_BN254 proof challenge: the ASCII bytes of
   "dkg" as a word. */
extern const U256 DKG_TAG;

/* A curve y^2 = x^3 + b of prime order r, with (0, 0) the identity. */
typedef struct {
  /* The scalar modulus r. */
  const Modulus *order;
  void (*gen)(G1 *out);
  int (*on_curve)(const G1 *p);
  void (*add)(G1 *out, const G1 *a, const G1 *b);
  void (*mul)(G1 *out, const G1 *p, const U256 *k);
  int (*eq)(const G1 *a, const G1 *b);
  /* OUT = X mod r. OUT can be X. */
  void (*reduce)(U256 *out, const U256 *x);
  /* The private coefficient a_K of SEED, below r. */
  void (*nonce)(U256 *out, const U256 *seed, uint64_t k);
  /* The proof challenge c of the dealer I over CTX, C0 and R. Returns 1,
     or 0 with C = 0 when C0 or R has no encoding. */
  int (*challenge)(U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r);
} DkgCurve;

/* BN254 G1 (S6): g1_*, elg_generator, scalar_reduce, thr_nonce, and the
   challenge = the chain of thr_hash from DKG_TAG over CTX, I, C0.x, C0.y,
   R.x, R.y (6 hashes), not reduced. */
extern const DkgCurve DKG_BN254;

/* secp256k1 (O96): secp_*, the nonce = xmd_to_scalar(SEED || K, "dkg
   nonce") with SEED 32 and K 8 big endian bytes, and the challenge =
   xmd_to_scalar(I || enc(C0) || enc(R)) with I 32 big endian bytes, enc
   the SEC1 compressed form and DST = the 32 big endian bytes of CTX ||
   "dkg". The challenge is 0 when C0 or R is the identity. */
extern const DkgCurve DKG_SECP256K1;

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
  DKG_TOO_FEW,    /* QUAL is empty, or (reshare) Q is below the old t or QUAL' is not Q */
  DKG_BAD_RESHARE /* a reshare dealer fails C'_{i,0} = lambda_{i,Q} PK_i: the dealer is not in QUAL' */
} DkgResult;

/* The challenge of CURVE for the dealer I (see DkgCurve). */
int dkg_challenge(const DkgCurve *curve, U256 *c, const U256 *ctx, uint32_t i, const G1 *c0, const G1 *r);

/* The dealing of the dealer I for T of N and CTX, with SHARES[j - 1] =
   f_i(j) for j = 1 to N. SEED is fresh secret 256-bit entropy for each
   dealing. DKG_BAD_INDEX when N is above THR_N_MAX, T is 0 or above N, or
   I is 0 or above N (before any write), else DKG_OK. */
DkgResult dkg_deal(const DkgCurve *curve, DkgDealing *out, U256 *shares, const U256 *seed, uint32_t i, uint32_t t,
                   uint32_t n, const U256 *ctx);

/* 1 when R and C[k] for k < T are on the curve, the challenge c of the
   dealer I exists and z G = R + c C[0]. T must be 1 to THR_N_MAX. */
int dkg_check_proof(const DkgCurve *curve, const DkgDealing *d, uint32_t i, uint32_t t, const U256 *ctx);

/* The sum over k < T of J^k C[k], by Horner. T must be 1 to THR_N_MAX. */
void dkg_eval(const DkgCurve *curve, G1 *out, const DkgDealing *d, uint32_t t, uint32_t j);

/* 1 when S G = dkg_eval(D, T, J): the Feldman check of the share of the
   member J. */
int dkg_check_share(const DkgCurve *curve, const DkgDealing *d, uint32_t t, uint32_t j, const U256 *s);

/* QUAL for the N dealings and the share table. In order: DKG_BAD_INDEX
   when N is above THR_N_MAX or T is 0 or above N (before any write),
   DKG_TOO_FEW when QUAL is empty, DKG_BAD_PROOF when a dealer fails its
   proof, DKG_BAD_SHARE when a dealer fails a share check, else DKG_OK.
   *QUAL gets the set for each result but DKG_BAD_INDEX. */
DkgResult dkg_qual(const DkgCurve *curve, uint32_t *qual, const DkgDealing *dealings, const U256 *shares, uint32_t t,
                   uint32_t n, const U256 *ctx);

/* The share of the member J: x = J, s = the sum over QUAL of f_i(J) mod r,
   key = s G. In order: DKG_BAD_INDEX when N is above THR_N_MAX or J is 0
   or above N, DKG_TOO_FEW when QUAL has no dealer of 1 to N (before any
   write), else DKG_OK. */
DkgResult dkg_share(const DkgCurve *curve, ThrShare *out, uint32_t qual, const U256 *shares, uint32_t j, uint32_t n);

/* PK_J from the commitments only (the KEYS of thr_open): the sum over QUAL
   of dkg_eval(D_i, T, J). In order: DKG_BAD_INDEX when N is above
   THR_N_MAX, T is 0 or above N, or J is 0 or above N, DKG_TOO_FEW when
   QUAL has no dealer of 1 to N (before any write), else DKG_OK. */
DkgResult dkg_key(const DkgCurve *curve, G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t t, uint32_t j,
                  uint32_t n);

/* PK: the sum over QUAL of C_{i,0} for the dealers 1 to N. */
void dkg_public(const DkgCurve *curve, G1 *out, uint32_t qual, const DkgDealing *dealings, uint32_t n);

/* The reshare (O97, S7 H4a): the old members Q (COUNT indices 1 to
   THR_N_MAX in rising order) deal the old key again to a new committee of
   T of N. A reshare dealer is its old index i, and bit i of QUAL' is the
   dealer i. DEALINGS[k], SHARES[k N + j - 1] = g_{Q[k]}(j) and KEYS[k] are
   for the dealer Q[k]. The new PK = the sum of C'_{i,0} = the old PK when
   QUAL' = Q. Second source: cairn-lang 6748510 src/front/dkg.h:79, :87. */

/* The reshare dealing of the old member OLD of Q for T of N and CTX:
   dkg_deal with I = OLD.x and a_0 = lambda_{I,Q} OLD.s mod r (lambda over
   Q at 0, the frost_lagrange rule). OLD.s is reduced mod r. DKG_BAD_INDEX when N is above
   THR_N_MAX, T is 0 or above N, Q is not valid or OLD.x is not in Q
   (before any write), else DKG_OK. */
DkgResult dkg_reshare_deal(const DkgCurve *curve, DkgDealing *out, U256 *shares, const U256 *seed, const ThrShare *old,
                           const uint32_t *quorum, uint32_t count, uint32_t t, uint32_t n, const U256 *ctx);

/* QUAL' for the reshare dealings, with KEYS[k] = PK_{Q[k]} of the old
   committee (dkg_key) and the old threshold OLD_T. In order: DKG_BAD_INDEX
   when N is above THR_N_MAX, T is 0 or above N, OLD_T is 0 or Q is not
   valid (before any write), DKG_TOO_FEW when COUNT is below OLD_T or QUAL'
   is empty, DKG_BAD_PROOF when a dealer fails its proof, DKG_BAD_RESHARE
   when C'_{i,0} is not lambda_{i,Q} PK_i, DKG_BAD_SHARE when a dealer fails
   a share check, else DKG_OK. *QUAL gets the set for each result but
   DKG_BAD_INDEX. */
DkgResult dkg_reshare_qual(const DkgCurve *curve, uint32_t *qual, const DkgDealing *dealings, const U256 *shares,
                           const G1 *keys, const uint32_t *quorum, uint32_t count, uint32_t old_t, uint32_t t,
                           uint32_t n, const U256 *ctx);

/* The new share of the member J: x = J, s = the sum over Q of g_i(J) mod
   r, key = s G. Each received word is reduced mod r, as in dkg_share.
   In order: DKG_BAD_INDEX when N is above THR_N_MAX, J is 0
   or above N, or Q is not valid, DKG_TOO_FEW when QUAL is not the set of Q
   (lambda is over Q; before any write), else DKG_OK. */
DkgResult dkg_reshare_share(const DkgCurve *curve, ThrShare *out, uint32_t qual, const U256 *shares,
                            const uint32_t *quorum, uint32_t count, uint32_t j, uint32_t n);

/* PK'_J from the commitments only: the sum over Q of dkg_eval(D_i, T, J).
   The results are as dkg_reshare_share, with DKG_BAD_INDEX also when T is
   0 or above N. */
DkgResult dkg_reshare_key(const DkgCurve *curve, G1 *out, uint32_t qual, const DkgDealing *dealings,
                          const uint32_t *quorum, uint32_t count, uint32_t t, uint32_t j, uint32_t n);

#endif
