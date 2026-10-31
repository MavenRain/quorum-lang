/* NEW (quorum-lang S11 H3c C3): the in-circuit NIFS verifier of Nova
   (O162 items 3, 4 and 7) on the rows of a rank-1 constraint system
   (crypto/r1cs.h).

   The circuit is over the base field of the commitment curve of the
   instances (crypto/nova.h: nova_base). Thus the points of an instance are
   native variables (x, y), but the X values of an instance are in the
   other field of the cycle: the field of the instances, with the modulus
   M. An X value is NOVA_LIMBS variables of NOVA_LIMB_BITS bits each (the
   low limb first). The caller asserts the range of the input limbs. The
   caller gives all the storage, so this module allocates no memory. */
#ifndef LANG_CRYPTO_NOVAGADGET_H
#define LANG_CRYPTO_NOVAGADGET_H

#include "crypto/nova.h"
#include "crypto/stepgadget.h"

#define NOVA_LIMBS 4u
#define NOVA_LIMB_BITS 64u
#define NOVA_Q_BITS 129u
#define NOVA_CARRY_BITS 72u

/* An instance (comW, comE, u, X) as variables. W_ID and E_ID are 1 when
   comW or comE is the identity (the coordinates are then not used). */
typedef struct {
  uint32_t com_w[2];
  uint32_t w_id;
  uint32_t com_e[2];
  uint32_t e_id;
  uint32_t u;
  uint32_t x[NOVA_X][NOVA_LIMBS];
} NovaVars;

/* The native witness of the X fold: X1 + R X2 = Q M + REM as integers,
   with REM below M. X1 and X2 must be below M, and R below 2^NOVA_R_BITS.
   Then Q is below 2^NOVA_Q_BITS. */
void nova_xfold_witness(U256 *q, U256 *rem, const U256 *x1, const U256 *x2, const U256 *r,
                        const U256 *m);

/* The rows of the X fold with the witness Q and REM: OUT (new limb
   variables) = REM. R is 2 limb variables of NOVA_LIMB_BITS bits. The
   rows: the 256 bits of REM (256 r1cs_bool rows, 4 pack rows),
   REM below M (step_below_gadget, 257 rows), the NOVA_Q_BITS bits of Q
   (129 rows, 2 pack rows), the 8 products r_i x2_j, then 6 limb rows. Each
   limb row k says that the sum of the column k terms (X1, the products,
   minus Q M, minus REM, the carry in) is 2^64 times the carry out. A carry
   is c = cb - 2^71, with cb as NOVA_CARRY_BITS bits (73 rows for each of 5
   carries). 1027 rows. All the values are below 2^140, thus each limb row
   holds as integers, and the rows give X1 + R X2 = Q M + REM with
   REM < M. */
void nova_xfold_qr_gadget(R1cs *cs, uint32_t out[NOVA_LIMBS], const uint32_t x1[NOVA_LIMBS],
                          const uint32_t x2[NOVA_LIMBS], const uint32_t r[2], const U256 *m,
                          const U256 *q, const U256 *rem);

/* The X fold X' = X1 + R X2 mod M: nova_xfold_witness on the values of
   the variables, then nova_xfold_qr_gadget. */
void nova_xfold_gadget(R1cs *cs, uint32_t out[NOVA_LIMBS], const uint32_t x1[NOVA_LIMBS],
                       const uint32_t x2[NOVA_LIMBS], const uint32_t r[2], const U256 *m);

/* The cut of X: BIT gets the canonical bits of X (step_bits_gadget, 514
   rows), and the return value is a new variable for the NOVA_CUT_BITS low
   bits (1 row). 515 rows. */
uint32_t nova_cut_gadget(R1cs *cs, uint32_t bit[STEP_GADGET_BITS], uint32_t x);

/* The cut hash of nova_hash on variables. The return value is the
   variable of the cut (nova_cut_gadget on state[1] after the last
   permutation). D, I, the Z_LEN variables of Z0 and of ZI, the x and y of
   U->com_w and of U->com_e, and U->u go in as one input each. Each X value
   of U goes in as 2 inputs of 128 bits: limb 0 + 2^64 limb 1, then
   limb 2 + 2^64 limb 3. U->w_id and U->e_id are not used (nova.c keeps
   the identity as (0, 0)). The input count 11 + 2 Z_LEN is odd, thus the
   last permutation adds 0 as the last input. The rows: 1 zero row,
   6 + Z_LEN poseidon_gadget calls, 9 + 2 Z_LEN sum rows and the cut (515
   rows). */
uint32_t nova_hash_gadget(R1cs *cs, uint32_t d, uint32_t i, const uint32_t *z0,
                          const uint32_t *zi, size_t z_len, const NovaVars *u,
                          const PoseidonParams *params);

/* The NIFS verifier: OUT = the fold of the running instance U1 with the
   plain instance U2 and COM_T, as nova_challenge and nova_fold_instance
   do it natively. PARAMS is over the field of the system. D is the
   parameter digest and H1 the cut hash of U1. The rows: 1 zero row, the
   sponge (5 poseidon_gadget calls and 8 sum rows), the canonical bits of
   h (514 rows), the 2 limbs of r (2 rows), u' = u1 + r (1 row), comW' and
   comE' (ec7_mul_bits_gadget on NOVA_R_BITS bits and ec7_add_id_gadget,
   1297 rows each), the id flag of COM_T (5 rows), 4 selects, 1 product
   row, and the 2 X folds (nova_xfold_gadget). COM_T = (0, 0) is the
   identity (nova.c keeps the identity as (0, 0)). The challenge uses
   COM_T as it is. When COM_T is the identity, comE' = comE of U1,
   OUT->e_id = U1->e_id, and the mul for comE' uses comW of U2 in place
   of COM_T (the select ignores that product). Else comE' is not the
   identity and OUT->e_id is 0. comW' is not the identity: OUT->w_id is
   the zero variable. U2->w_id, U2->com_e, U2->e_id and U2->u are not
   used (u2 is 1). */
void nova_verify_gadget(R1cs *cs, NovaVars *out, uint32_t d, uint32_t h1, const NovaVars *u1,
                        const NovaVars *u2, const uint32_t com_t[2], const PoseidonParams *params,
                        const U256 *m);

#endif
