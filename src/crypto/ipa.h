#ifndef LANG_CRYPTO_IPA_H
/* NEW (quorum-lang S11 H4a C2): the inner product argument (IPA) of the
   compressed Nova proof, without zero knowledge (O151), and the helpers of
   the multilinear extension (MLE) and of the transcript.

   The key (Q-S11-11 (a)): G[i] = the generator i of the curve (gens_point)
   for i below 2^c, thus the first n points are the points of nova_gens(n),
   and a Nova commitment Com(V) of length n <= 2^c is the IPA commitment of
   V with 0 values after V. Q = the generator 2^c.

   The variables of an MLE over 2^c values: R[0] is the top bit of the
   index j and R[c - 1] is the low bit. eq(R, j) is the product of
   R[i] j_i + (1 - R[i]) (1 - j_i), with j_i the bit c - 1 - i of j.

   The transcript (Q-S11-13 (a)): the Poseidon sponge of nova_hash over the
   field F of the side (the scalar field of the curve). The state starts at
   (DOMAIN, 0, 0). The inputs come in pairs: for each pair, state[1] adds
   the first input and state[2] adds the second, then the permutation
   follows. A point gives 4 inputs: x and y, each as 2 limbs of 128 bits
   (the low limb first). A challenge first adds the open input of a pair to
   state[1] (if there is one), then applies the permutation. The challenge
   is state[1], or the 128 low bits of state[1].

   The IPA for C = Com(A), B = the eq table of RHO and V = <A, B>: the
   transcript adds C and V and gives h; Q' = h Q and P_0 = C + V Q'. Round
   i (c rounds, the current length 2m): L = <A_lo, G_hi> + <A_lo, B_hi> Q'
   and R = <A_hi, G_lo> + <A_hi, B_lo> Q'; the transcript adds L and R and
   gives x (128 bits, not 0); A' = A_lo + x^-1 A_hi, B' = B_lo + x B_hi,
   G' = G_lo + x G_hi and P' = P + x L + x^-1 R. The proof is the c pairs
   (L, R) and the last value a of A. The verifier computes G_final = the
   sum of s_j G_j (s_j = the product of the x_i with j_i = 1), b_final =
   the product of ((1 - RHO[i]) + x_i RHO[i]), and checks with one MSM that
   P_c = a G_final + a b_final Q'. */
#define LANG_CRYPTO_IPA_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/bn254.h"
#include "crypto/gens.h"
#include "crypto/nova.h"
#include "crypto/poseidon.h"
#include "crypto/u256.h"

/* The largest round count c (2^24 values). */
#define IPA_C_MAX 24u
/* The DOMAIN value of the transcript of the compressed proof: the ASCII
   bytes "qlcomp1" as a big-endian number. */
#define IPA_TS_DOMAIN 0x716c636f6d7031ull

/* The IPA key: the 2^c points G, the point Q, F (the scalar field of the
   curve) and the work space of the MSM. K holds 2^c scalars. BUCKET holds
   BUCKETS points, at least msm_buckets(2^c). */
typedef struct {
  GensCurve curve;
  const Modulus *f;
  unsigned c;
  G1 *g;
  G1 q;
  U256 *k;
  EcJac *bucket;
  size_t buckets;
} IpaKey;

/* The transcript state. PEND is the open input of a pair when HAS is 1. */
typedef struct {
  const PoseidonParams *params;
  Fe state[POSEIDON_WIDTH];
  Fe pend;
  int has;
} IpaTranscript;

/* The IPA proof: C rounds of (L, R) and the last value A. */
typedef struct {
  unsigned c;
  G1 l[IPA_C_MAX];
  G1 r[IPA_C_MAX];
  Fe a;
} IpaProof;

/* OUT = the IPA key of 2^C points on the curve of NOVA. G[i] = NOVA->g[i]
   for i below NOVA->n, else gens_point i; Q = gens_point 2^C. G holds 2^C
   points (G can be NOVA->g). Returns 1, or 0 when C is more than IPA_C_MAX
   or BUCKETS is less than msm_buckets(2^C). */
int ipa_key(IpaKey *out, const NovaKey *nova, unsigned c, G1 *g, U256 *k, EcJac *bucket,
            size_t buckets);
/* OUT = the sum of V[i] G[i] for i below LEN (the identity for LEN 0).
   Returns 1, or 0 when LEN is more than 2^c or the MSM fails. */
int ipa_com(G1 *out, const IpaKey *key, const Fe *v, size_t len);

/* OUT[j] = eq(R, j) for j below 2^C. Returns 1, or 0 when C is more than
   IPA_C_MAX (OUT does not change then). */
int ipa_eq(Fe *out, const Fe *r, unsigned c, const Modulus *f);
/* OUT = the product of A[i] B[i] + (1 - A[i]) (1 - B[i]) for i below C. */
void ipa_eq_at(Fe *out, const Fe *a, const Fe *b, unsigned c, const Modulus *f);
/* OUT = the MLE of V at R: the sum of V[j] eq(R, j) for j below LEN (the
   values from LEN to 2^C are 0). W holds 2^C values of work space. Returns
   1, or 0 when C is more than IPA_C_MAX or LEN is more than 2^C. */
int ipa_mle(Fe *out, const Fe *v, size_t len, const Fe *r, unsigned c, Fe *w, const Modulus *f);

/* OUT = IPA_TS_DOMAIN in F. */
void ipa_ts_domain(Fe *out);
/* TS = the start state (DOMAIN, 0, 0) of the sponge of PARAMS. */
void ipa_ts_start(IpaTranscript *ts, const PoseidonParams *params, const Fe *domain);
/* TS adds X (below the modulus of the params). */
void ipa_ts_fe(IpaTranscript *ts, const Fe *x);
/* TS adds the point P as 4 inputs (the identity is (0, 0)). */
void ipa_ts_point(IpaTranscript *ts, const G1 *p);
/* OUT = the next challenge: state[1]. */
void ipa_ts_challenge(IpaTranscript *ts, Fe *out);
/* OUT = the next challenge: the 128 low bits of state[1]. */
void ipa_ts_challenge128(IpaTranscript *ts, Fe *out);

/* OUT = the IPA proof that COM = Com(A) opens to V at RHO (V = the MLE of
   A at RHO). A holds 2^c values and changes. B holds 2^c values of work
   space (the eq table of RHO). GW holds 2^(c - 1) points of work space (no
   point for c = 0). TS must be in the state of the verifier. Returns 1, or
   0 when a challenge x is 0 or an MSM fails. */
int ipa_prove(IpaProof *out, const IpaKey *key, IpaTranscript *ts, const G1 *com, Fe *a, Fe *b,
              const Fe *rho, const Fe *v, G1 *gw);
/* Checks the IPA proof PF of COM, RHO and V. W holds 2^c values of work
   space. Returns 0 when the proof holds, else the number of the failed
   check: 1 the round count is not c, 2 a challenge x is 0, 3 an MSM fails,
   4 the last equation does not hold. This check does not read whether L
   and R are on the curve (the decode of the proof does). */
int ipa_verify(const IpaKey *key, IpaTranscript *ts, const G1 *com, const Fe *rho, const Fe *v,
               const IpaProof *pf, Fe *w);

#endif
