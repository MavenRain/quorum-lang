/* NEW (quorum-lang S11 H3c C2, O162 items 2 and 3): the native parts of
   Nova on the secp256k1 cycle. The commitments, the relaxed R1CS check, the
   parameter digest D, the cross term T, the Poseidon challenge r and the
   fold (NIFS) of a running instance with a plain instance.

   A system over F_p commits on secq256k1 (its scalars are in F_p, its
   points are over F_n). A system over F_n commits on secp256k1 (its scalars
   are in F_n, its points are over F_p). The witness vector is
   z = (u, X, W): z[0] = u, the NOVA_X public values X are the variables 1
   and 2, and W is the rest. E has one value for each row. An instance
   (comW, comE, u, X) is satisfied when each row k holds as
   (A_k z) (B_k z) = u (C_k z) + E_k, comW = Com(W) and comE = Com(E). A
   plain instance has u = 1, E = 0 and comE = the identity (0, 0).

   The module reads the rows and the terms of an R1cs (crypto/r1cs.h)
   directly; the r1cs API does not change. The caller gives all the
   storage, so this module allocates no memory. */
#ifndef LANG_CRYPTO_NOVA_H
#define LANG_CRYPTO_NOVA_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/bn254.h"
#include "crypto/gens.h"
#include "crypto/poseidon.h"
#include "crypto/r1cs.h"
#include "crypto/u256.h"

/* The count of the public values X. */
#define NOVA_X 2u
/* The first variable of W in z. */
#define NOVA_W (1u + NOVA_X)
/* D keeps this many low bits of its SHA-256 digest. */
#define NOVA_CUT_BITS 250u
/* The challenge r has this many bits. */
#define NOVA_R_BITS 128u

/* The commitment key: the first N generators G of one curve and the work
   space of the MSM. K holds N scalars. BUCKET holds BUCKETS points, at
   least msm_buckets(N). */
typedef struct {
  GensCurve curve;
  const G1 *g;
  size_t n;
  U256 *k;
  EcJac *bucket;
  size_t buckets;
} NovaKey;

/* An instance: comW, comE, u and the X values. */
typedef struct {
  G1 com_w;
  G1 com_e;
  Fe u;
  Fe x[NOVA_X];
} NovaInstance;

/* OUT = the curve of the commitments of a system over F: secq256k1 for
   F_p, secp256k1 for F_n. Returns 1, or 0 when F is neither field (OUT
   does not change then). */
int nova_curve(GensCurve *out, const Modulus *f);
/* The base field of CURVE: the field of the MSM, of the points and of the
   challenge sponge. */
const Modulus *nova_base(GensCurve curve);
/* OUT[i] = the generator i of CURVE (gens_point) for i below N. */
void nova_gens(G1 *out, GensCurve curve, size_t n);
/* OUT = A + B on CURVE. A and B can be the identity (0, 0). */
void nova_add(G1 *out, const G1 *a, const G1 *b, GensCurve curve);
/* OUT = K P on CURVE. P can be the identity (0, 0). */
void nova_mul(G1 *out, const G1 *p, const Fe *k, GensCurve curve);
/* OUT = Com(V) = the sum of V[i] G[i] for i below LEN (the identity for
   LEN 0). Returns 1, or 0 when LEN is more than the generator count or the
   bucket space is too small (OUT does not change then). */
int nova_com(G1 *out, const NovaKey *key, const Fe *v, size_t len);

/* OUT = D: the NOVA_CUT_BITS low bits of SHA-256 over this byte string:
   the tag "quorum-lang/ivc/params/v1" and a 0x00 byte, the tag
   "quorum-lang/ivc/gens/v1" and a 0x00 byte, be32(N_P), be32(N_S), then
   for P and then for S: be32 of the variable count, the row count and the
   term count, then each term as be32(row), 1 byte for the side (A 0, B 1,
   C 2), be32(var) and the coefficient as 32 big-endian bytes. D is below
   2^250 < n < p, thus D is the same element of F_p and F_n. Returns 1, or
   0 when P or S is full. */
int nova_digest(Fe *out, const R1cs *p, uint32_t n_p, const R1cs *s, uint32_t n_s);

/* A, B and C = A_K z, B_K z and C_K z of row K for the vector Z. Returns
   1, or 0 when a term of the row has a variable that is not in the system
   (that term adds nothing). The system must not be full. */
int nova_row(Fe *a, Fe *b, Fe *c, const R1cs *cs, const Fe *z, size_t k);
/* The relaxed check. Z has cs->used.vars values (Z[0] = u) and E has
   cs->used.rows values. Returns 1 when the system is not full and each row
   k holds as (A_k z) (B_k z) = u (C_k z) + E[k]. Otherwise returns 0 and
   sets *FAILED to the first row that does not hold, or to the row count
   when the system is full. A term with a variable that is not in the
   system fails its row. This check does not read the commitments. */
int nova_check(const R1cs *cs, const Fe *z, const Fe *e, size_t *failed);
/* OUT = the instance of the witness (Z, E): comW = Com(W) with W the
   values of Z from NOVA_W, comE = Com(E), u = Z[0] and X = Z[1], Z[2].
   Returns 1, or 0 when the system is full, has less than NOVA_W variables,
   or a commitment fails (nova_com). */
int nova_instance(NovaInstance *out, const NovaKey *key, const R1cs *cs, const Fe *z,
                  const Fe *e);
/* T[k] = a1 b2 + a2 b1 - u1 c2 - u2 c1 for each row k, with (a1, b1, c1)
   of Z1, (a2, b2, c2) of Z2, u1 = Z1[0] and u2 = Z2[0]. Returns 1, or 0
   when the system is full (T does not change then). */
int nova_cross(Fe *t, const R1cs *cs, const Fe *z1, const Fe *z2);
/* R = the challenge: a Poseidon sponge over the field of PARAMS (the base
   field of the curve of the instances). The state starts at (0, 0, 0).
   Each of the 5 permutations first adds 2 inputs to state[1] and state[2].
   The 10 inputs are D, H1 (the cut hash of the running instance), the x
   and y of COM_W2, X2[0] and X2[1] each as 2 limbs of 128 bits (the low
   limb first), and the x and y of COM_T. R = the NOVA_R_BITS low bits of
   state[1] after the last permutation. */
void nova_challenge(Fe *r, const PoseidonParams *params, const Fe *d, const Fe *h1,
                    const G1 *com_w2, const Fe x2[NOVA_X], const G1 *com_t);
/* H = the cut hash of the running instance U (O162 item 3). The sponge is
   the sponge of nova_challenge over the field of PARAMS: the state starts
   at (0, 0, 0), and each permutation first adds 2 inputs to state[1] and
   state[2]. The inputs are D, I, the Z_LEN values of Z0, the Z_LEN values
   of ZI, the x and y of comW, the x and y of comE, u, and X[0] and X[1]
   each as 2 limbs of 128 bits (the low limb first). The input count
   11 + 2 Z_LEN is odd, thus the last permutation adds 0 as the last input
   (O162 does not state this; it is a choice of this module). H = the
   NOVA_CUT_BITS low bits of state[1] after the last permutation. H_p has
   Z_LEN 5 (21 inputs, 11 permutations), and H_n has Z_LEN 1 (13 inputs,
   7 permutations). Returns 1, or 0 when u is not below the modulus of
   PARAMS (H does not change then). */
int nova_hash(Fe *h, const PoseidonParams *params, const Fe *d, const Fe *i, const Fe *z0,
              const Fe *zi, size_t z_len, const NovaInstance *u);
/* OUT = the fold of the running U1 with the plain U2 (E2 = 0, thus this
   does not read comE of U2): comW' = comW1 + R comW2,
   comE' = comE1 + R COM_T, u' = u1 + R u2 and X'_j = X1_j + R X2_j in F
   (the field of the system). CURVE is the curve of the commitments. OUT
   can be U1. */
void nova_fold_instance(NovaInstance *out, const NovaInstance *u1, const NovaInstance *u2,
                        const G1 *com_t, const Fe *r, const Modulus *f, GensCurve curve);
/* The fold of the witness in F: Z[i] = Z1[i] + R Z2[i] for i below VARS
   (this gives u', X' and W') and E[k] = E1[k] + R T[k] for k below ROWS.
   Z can be Z1 and E can be E1. */
void nova_fold_witness(Fe *z, Fe *e, const Fe *z1, const Fe *e1, const Fe *z2, const Fe *t,
                       const Fe *r, size_t vars, size_t rows, const Modulus *f);

#endif
