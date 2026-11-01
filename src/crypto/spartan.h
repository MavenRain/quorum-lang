#ifndef LANG_CRYPTO_SPARTAN_H
/* NEW (quorum-lang S11 H4a C3): Spartan for relaxed R1CS with the IPA
   opening of ipa.h, without zero knowledge (O151).

   The relation of the system CS over F, with z = (u, X_0, X_1, W) as in
   nova.h and the error vector E: (A_k z) (B_k z) = u (C_k z) + E_k for each
   row k. The pad: 2^a >= the row count; 2^b >= the W length and 2^b >=
   NOVA_W; c = max(a, b), the round count of the IPA.

   The column map (plan item 3): W takes the columns 0 .. 2^b - 1, and
   (u, X_0, X_1) take the columns from 2^b, thus 2^(b + 1) columns. The
   variable y_0 of a column is its top bit, and Z~(y) = (1 - y_0) W~(y')
   + y_0 P~(y') with P = (u, X_0, X_1, 0, ..). The shape does not change.

   A round message of a sum-check is the coefficients of the round
   polynomial g (g = s_0 + s_1 X + s_2 X^2 + ..). The verifier checks g(0)
   + g(1) = the claim, and the next claim is g(r).

   The transcript (plan item 5): the instance (comW, comE, u, X), then tau
   (a values). Sum-check 1 (a rounds, degree 3): 0 = the sum over x of
   eq(tau, x) (Az(x) Bz(x) - u Cz(x) - E(x)). Then v_A, v_B, v_C and v_E
   (the values at r_x) and r_A, r_B, r_C. Sum-check 2 (b + 1 rounds, degree
   2): r_A v_A + r_B v_B + r_C v_C = the sum over y of M(r_x, y) Z(y), with
   M = r_A A + r_B B + r_C C. Then v_W = W~(r_y') (r_y = (y_0, r_y')) and
   g. Sum-check 3 (c rounds, degree 2): v_W + g v_E = the sum over j of
   (eq(r_y', j) W_j + g eq(r_x, j) E_j) (each table is 0 after its length).
   Then w = W~(rho), e = E~(rho) and d. The IPA of comW + d comE, W + d E,
   rho and w + d e. Each challenge is a full field value (ipa_ts_challenge);
   the IPA makes its own challenges. */
#define LANG_CRYPTO_SPARTAN_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/ipa.h"
#include "crypto/nova.h"
#include "crypto/r1cs.h"

/* The pad of a system: 2^A rows, 2^B W columns, C = max(A, B). */
typedef struct {
  unsigned a;
  unsigned b;
  unsigned c;
} SpartanDims;

/* The work space of the caller: FE holds FE_LEN values (at least
   spartan_work_len) and GW holds GW_LEN points (at least 2^(c - 1), no
   point for c = 0). */
typedef struct {
  Fe *fe;
  size_t fe_len;
  G1 *gw;
  size_t gw_len;
} SpartanWork;

/* The Spartan proof: the dims, the 3 sum-checks, the values at the ends of
   the sum-checks and the IPA proof. */
typedef struct {
  SpartanDims d;
  Fe sc1[IPA_C_MAX][4];
  Fe va;
  Fe vb;
  Fe vc;
  Fe ve;
  Fe sc2[IPA_C_MAX + 1u][3];
  Fe vw;
  Fe sc3[IPA_C_MAX][3];
  Fe w;
  Fe e;
  IpaProof ipa;
} SpartanProof;

/* OUT = the pad of CS (cs->used.rows rows, cs->used.vars variables).
   Returns 1, or 0 when CS has less than NOVA_W variables or a pad is more
   than IPA_C_MAX. */
int spartan_dims(SpartanDims *out, const R1cs *cs);
/* The value count of the work space for the pad D. */
size_t spartan_work_len(const SpartanDims *d);

/* OUT = the Spartan proof for the instance U with Z (cs->used.vars values,
   Z[0] = u) and E (cs->used.rows values). The proof does not check the
   relation: for a false relation the verify fails. KEY must have c = the c
   of the pad of CS and the field of CS. TS must be in the state of the
   verifier. Returns 1, or 0 when the system is full, the pad or the key or
   the work space is not correct, a term has a variable that is not in the
   system, or the IPA fails. */
int spartan_prove(SpartanProof *out, const IpaKey *key, IpaTranscript *ts, const R1cs *cs,
                  const NovaInstance *u, const Fe *z, const Fe *e, const SpartanWork *wk);
/* Checks the proof PF for the instance U and the shape CS (this check
   does not read cs->z). Returns 0 when the proof holds, else the number of
   the failed check: 1 the shape (the system is full, the pad, the key, the
   work space, or a term variable is not in the system), 2 a round of
   sum-check 1, 3 the last check of sum-check 1, 4 a round of sum-check 2,
   5 the last check of sum-check 2, 6 a round of sum-check 3, 7 the last
   check of sum-check 3, 8 the IPA. */
int spartan_verify(const IpaKey *key, IpaTranscript *ts, const R1cs *cs, const NovaInstance *u,
                   const SpartanProof *pf, const SpartanWork *wk);

#endif
