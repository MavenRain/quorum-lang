/* NEW (quorum-lang S10 H2, O137 to O139, Q14 (a), Q-S10-4 (b)): the BGW
   protocol of the MPC tally route (docs/PLAN.md section 5). The guest
   calls it through the host imports q_mpc_check to q_mpc_open (S10 H3,
   the byte forms at the end): the guest keeps the MPC tally and its law;
   this file is a host model of the protocol under it (the S8 model: the
   host does the field and group work).

   A sharing is a degree-1 Shamir sharing over Fr to the members x = 1 to
   n, with Feldman commitments in the DkgDealing form: T = BGW_T = 2, C[0]
   = a_0 G, C[1] = a_1 G, the other points and the dealer proof are 0. Each
   member checks its share with dkg_check_share. The add and the public
   affine map are local.

   The multiply (BGW): the member i forms the product share p_i = a_i b_i
   and gives D_i = a_i B_i = p_i G with a Chaum-Pedersen proof (thr_partial)
   that log_G A_i = log_B_i D_i. A_i and B_i are the Feldman points of the
   two input sharings at i. Then the member i reshares p_i by a degree-1
   dealing with C[0] = D_i. The member j checks each proof and each
   sub-share s_ij. Its new share is the sum over i of lambda_i s_ij, with
   lambda_i = thr_lagrange over all n members (degree 2 needs 3 points).
   The open checks each output share against the commitments, then takes
   the Lagrange sum at 0.

   Honest majority: n >= 2 t' + 1 for t' corrupt members, thus n = 3 for
   t' = 1. This host model checks arithmetic and transcript consistency;
   it does not provide private MPC. The Feldman constant commitment
   C[0] = a_0 G reveals a bit by comparison with infinity and G, and the
   host transcript contains every member's shares. The proofs do not
   hide those values. A private deployment needs hiding commitments and
   compatible proofs, separate member execution, and private authenticated
   channels. See docs/PLAN.md section 5 for the S10 security scope. */
#ifndef LANG_CRYPTO_BGW_H
#define LANG_CRYPTO_BGW_H

#include <stdint.h>

#include "crypto/dkg.h"
#include "crypto/threshold.h"
#include "crypto/u256.h"

/* The coefficients of a degree-1 sharing (the T of dkg_eval). */
#define BGW_T 2u
/* The members that a multiply needs: 2 BGW_T - 1 (a degree-2 product). */
#define BGW_N_MIN 3u

typedef enum {
  BGW_OK,
  BGW_BAD_INDEX, /* n, k or a member index is out of range, or an index repeats */
  BGW_BAD_SHARE, /* a Feldman share check fails */
  BGW_BAD_PROOF  /* a product proof fails, or the reshare does not commit to D_i */
} BgwResult;

/* The product step of a member: PROOF.d = D_i with its proof, and RESHARE
   the degree-1 dealing of p_i. */
typedef struct {
  ThrPart proof;
  DkgDealing reshare;
} BgwProduct;

/* The dealing of A0 + A1 x (each mod r), with SHARES[j - 1] = A0 + A1 j for
   j = 1 to N. BGW_BAD_INDEX when N is below BGW_T or above THR_N_MAX (before
   any write), else BGW_OK. The coefficients are inputs, so that a fixture
   can give a fixed dealing. A live dealer takes them from fresh secret
   entropy. */
BgwResult bgw_deal(DkgDealing *out, U256 *shares, const U256 *a0, const U256 *a1, uint32_t n);
/* 1 when S is the share of the member J of D (dkg_check_share, T = BGW_T). */
int bgw_check(const DkgDealing *d, uint32_t j, const U256 *s);
/* The local add: OUT = the sum of the COUNT shares S mod r. */
void bgw_sum(U256 *out, const U256 *s, uint32_t count);
/* The commitments of the sum: C[k] = the point sum of DS[m].C[k]. */
void bgw_sum_commit(DkgDealing *out, const DkgDealing *ds, uint32_t count);
/* The public affine map: OUT = W S + K mod r. */
void bgw_affine(U256 *out, const U256 *s, const U256 *w, const U256 *k);
/* Its commitments: C[0] = W D.C[0] + K G, C[1] = W D.C[1]. OUT is not D. */
void bgw_affine_commit(DkgDealing *out, const DkgDealing *d, const U256 *w, const U256 *k);
/* The product step of the member I for the input sharings DA and DB, with
   its shares SA and SB and the reshare coefficient RHO: *OUT, and
   SUBSHARES[j - 1] = s_ij for j = 1 to N. BGW_BAD_INDEX when N is below
   BGW_N_MIN or above THR_N_MAX, or I is 0 or above N (before any write),
   else BGW_OK. */
BgwResult bgw_product(BgwProduct *out, U256 *subshares, const DkgDealing *da, const DkgDealing *db, uint32_t i,
                      const U256 *sa, const U256 *sb, const U256 *rho, uint32_t n);
/* The check of the product of the member I. In order: BGW_BAD_INDEX for N
   or I as in bgw_product, or a proof index other than I; BGW_BAD_PROOF when
   a point is off the curve, the proof fails, or RESHARE.C[0] is not
   PROOF.d; else BGW_OK. */
BgwResult bgw_product_check(const BgwProduct *prod, const DkgDealing *da, const DkgDealing *db, uint32_t i, uint32_t n);
/* The degree reduction at the member J, with PRODS[i - 1] and SUBSHARES[i -
   1] = s_ij from the member i, for i = 1 to N. *OUT gets 0 first. In order:
   BGW_BAD_INDEX for N or J as in bgw_product, the bgw_product_check of each
   product, BGW_BAD_SHARE when a sub-share fails its check, else *OUT = the
   sum of lambda_i s_ij and BGW_OK. */
BgwResult bgw_reduce(U256 *out, const BgwProduct *prods, const U256 *subshares, const DkgDealing *da,
                     const DkgDealing *db, uint32_t j, uint32_t n);
/* The commitments of the reduced sharing: C[k] = the sum over i of lambda_i
   PRODS[i - 1].reshare.C[k]. BGW_BAD_INDEX for N as in bgw_product. */
BgwResult bgw_reduce_commit(DkgDealing *out, const BgwProduct *prods, uint32_t n);
/* The open of D from the K output shares SS of the members XS. *OUT gets 0
   first. In order: BGW_BAD_INDEX when N is below BGW_T or above THR_N_MAX,
   K is below BGW_T or above N, or an index is 0, above N or repeated;
   BGW_BAD_SHARE when a share fails its check; else *OUT = the Lagrange sum
   at 0 and BGW_OK. */
BgwResult bgw_open(U256 *out, const DkgDealing *d, const uint32_t *xs, const U256 *ss, uint32_t k, uint32_t n);

/* The byte forms of the host imports (S10 H3; langc eval and the Wasm
   host call them). Each word is 8 bytes big endian. A U256 is 4 words
   (word 0 the most significant), a point 8 words (x, then y). A dealing is
   16 words: C[0], then C[1] (the other points, R and z are 0). A share
   list is 16 words: the share of the member j in the words 4 j - 4 to
   4 j - 1, for j = 1 to BGW_SLOTS. A Prods cell is 53 words: the part of
   the member i (29 words, the thr_verify_be form: x, d, a, b, z; d = D_i,
   the reshare C[0]), the reshare C[1] (8 words), then the sub-shares s_ij
   as a share list. PRODS holds the lists of the members 1 to BGW_N_MIN,
   BGW_LIST_BYTES apart, with HAVE[i - 1] cells in the list of the member
   i. */
#define BGW_SLOTS 4u
#define BGW_CELL_BYTES 424u
#define BGW_LIST_BYTES (8u * BGW_CELL_BYTES)

/* The code of bgw_check for the shares S of the members 1 to N of D. In
   order: BGW_BAD_INDEX when N is below BGW_T or above BGW_SLOTS;
   BGW_BAD_SHARE when a point of D does not decode or a share fails; else
   BGW_OK. */
BgwResult bgw_check_be(const unsigned char *d, const unsigned char *s, uint64_t n);
/* OUT = the dealing of bgw_sum_commit over A and B; 0 when a point does
   not decode. */
void bgw_add_be(unsigned char *out, const unsigned char *a, const unsigned char *b);
/* OUT = the dealing of bgw_affine_commit (D, W, K); 0 when a point does
   not decode. */
void bgw_affine_be(unsigned char *out, const unsigned char *d, const unsigned char *w, const unsigned char *k);
/* The degree reduction of the step M (the cell M of each list) at the
   members j = 1 to BGW_N_MIN, for the input dealings DA and DB. OUT is a
   share list: the new share of j in its slot, the code in word 12 (the
   first that is not BGW_OK), the words 13 to 15 zero; all shares 0 on a
   code. In order: BGW_BAD_INDEX when a list has more than 8 cells or no
   cell M; BGW_BAD_PROOF when a point does not decode; then the codes of
   bgw_reduce. */
void bgw_mul_be(unsigned char *out, const unsigned char *prods, const uint32_t *have, uint64_t m,
                const unsigned char *da, const unsigned char *db);
/* OUT = the dealing of bgw_reduce_commit for the step M; 0 when a list
   has more than 8 cells or no cell M, or a point does not decode. */
void bgw_mulc_be(unsigned char *out, const unsigned char *prods, const uint32_t *have, uint64_t m);
/* The open of D from the shares S of the members 1 to N (K = N). OUT is 8
   words: the value in the words 0 to 3 (0 on a code), the code in word 4,
   the words 5 to 7 zero. In order: BGW_BAD_INDEX when N is below BGW_T or
   above BGW_SLOTS; BGW_BAD_SHARE when a point of D does not decode; then
   the codes of bgw_open. */
void bgw_open_be(unsigned char *out, const unsigned char *d, const unsigned char *s, uint64_t n);

#endif
