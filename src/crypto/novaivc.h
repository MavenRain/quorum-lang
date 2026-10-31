/* The augmented circuits of Nova on the cycle (O162 item 4). P is over
   F_p and folds S instances (secp256k1 points, X in F_n). S is over F_n
   and folds P instances (secq256k1 points, X in F_p). One call adds the
   circuit of step i to a new system (r1cs_init, then no variable before
   the call). The X variables are variables 1 and 2 (O162 item 2): their
   values come from IN->x. At the end, 1 row for each ties it to its value
   in the circuit, and the call gives these values in OUT_X. Thus a build
   is 2 runs (O162 item 5 (2)): a run with IN->x = 0 gives OUT_X, then
   the real run with IN->x = OUT_X holds. */
#ifndef LANG_CRYPTO_NOVAIVC_H
#define LANG_CRYPTO_NOVAIVC_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/bn254.h"
#include "crypto/nova.h"
#include "crypto/novagadget.h"
#include "crypto/poseidon.h"
#include "crypto/r1cs.h"
#include "crypto/stepgadget.h"
#include "crypto/u256.h"

/* The z length of S (the Nova TrivialCircuit). */
#define NOVA_S_Z 1u

/* A step circuit F: OUT = F(IN) on variables. CTX is the witness of the
   step (for example the body, R and the z bits of step_gadget). */
typedef void (*NovaStepFn)(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z],
                           const void *ctx);

/* The inputs of one step i of P or of S. PARAMS is over the field of the
   system, and M is the modulus of the X values of the folded instances
   (n in P, p in S). Z0 and ZI hold STEP_GADGET_Z values in P and
   NOVA_S_Z values in S. BIG is the running instance U and LAST is the
   last plain instance u of the other circuit. At i = 0, BIG is the
   default instance (both points (0, 0), u = 0, X = 0), and LAST and
   COM_T are any points on the curve: the base case does not use the
   fold. */
typedef struct {
  const PoseidonParams *params;
  const U256 *m;
  Fe d;
  Fe i;
  const Fe *z0;
  const Fe *zi;
  const NovaInstance *big;
  const NovaInstance *last;
  G1 com_t;
  Fe x[NOVA_X];
} NovaStepIn;

/* P, step i (O162 item 4): h_in = the cut H_p(D, i, z_0, z_i, U) (Z_LEN
   STEP_GADGET_Z), the NIFS fold of U with u and comT (h1 = h_in), and
   z_(i+1) = F(i = 0 ? z_0 : z_i). At i = 0, U' = the default instance;
   else U' = the fold and u.X[0] = h_in (on the limbs). h_out = the cut
   H_p(D, i + 1, z_0, z_(i+1), U'). X = (u.X[1], h_out). Each id flag of
   U and u is 1 exactly when its point is (0, 0) (5 rows each), and each
   X limb of U and u is range checked to 64 bits (65 rows each). Z_OUT
   gets z_(i+1). Returns 1, or 0 when the system is full or u of an
   instance is not below the modulus of the system. */
int nova_primary(R1cs *cs, Fe out_x[NOVA_X], Fe z_out[STEP_GADGET_Z], const NovaStepIn *in,
                 NovaStepFn step, const void *ctx);

/* S, step i: as nova_primary with H_n (Z_LEN NOVA_S_Z) and the trivial
   step z_(i+1) = (i = 0 ? z_0 : z_i). At i = 0, U' = u as a relaxed
   instance (u = 1, comE = (0, 0), the Nova base case of the secondary
   circuit). */
int nova_secondary(R1cs *cs, Fe out_x[NOVA_X], Fe z_out[NOVA_S_Z], const NovaStepIn *in);

/* One circuit of the IVC (P or S) and its work space. The caller sets G
   (G_CAP generators: setup writes them), K (G_CAP scalars), BUCKET
   (BUCKETS points, at least msm_buckets(G_CAP)), M (the modulus of the X
   values of the folded instances: n for P, p for S), and the storage of
   the system: Z (VAR_CAP values), ROW (ROW_CAP), TERM (TERM_CAP) and T
   (ROW_CAP values). nova_ivc_setup sets KEY, F, PARAMS and CS. CS is the
   shape: setup and each prove step build the circuit in CS (the rows and
   the terms do not depend on the witness), thus Z holds the witness of
   the last build. T is the work space of the cross term and of the zero
   E of verify. */
typedef struct {
  G1 *g;
  size_t g_cap;
  U256 *k;
  EcJac *bucket;
  size_t buckets;
  U256 m;
  Fe *z;
  size_t var_cap;
  size_t *row;
  size_t row_cap;
  R1csTerm *term;
  size_t term_cap;
  Fe *t;
  NovaKey key;
  const Modulus *f;
  PoseidonParams params;
  R1cs cs;
} NovaIvcSide;

/* The IVC key (O162 item 5): D, P (over F_p, the commitments on
   secq256k1, N_P generators) and S (over F_n, the commitments on
   secp256k1, N_S generators). */
typedef struct {
  Fe d;
  NovaIvcSide p;
  NovaIvcSide s;
} NovaIvcKey;

/* The IVC proof after K steps (O162 item 5): z_0, z_k, the running P
   instance r_U_p with its witness R_W_P (the full vector z, z[0] = u) and
   R_E_P (E), the running S instance r_U_s with R_W_S and R_E_S, and the
   last S instance l_u_s with L_W_S. The caller gives the storage of the
   vectors: R_W_P and R_E_P hold the VAR_CAP and the ROW_CAP of P; R_W_S,
   R_E_S and L_W_S hold the caps of S. The z of S is always z0_s = (0)
   (the trivial step), thus the proof does not keep it. */
typedef struct {
  size_t k;
  Fe z0[STEP_GADGET_Z];
  Fe zk[STEP_GADGET_Z];
  NovaInstance r_u_p;
  Fe *r_w_p;
  Fe *r_e_p;
  NovaInstance r_u_s;
  Fe *r_w_s;
  Fe *r_e_s;
  NovaInstance l_u_s;
  Fe *l_w_s;
} NovaIvcProof;

/* Setup: the generators, the sizing runs and D. The sizing runs are step
   0 of P (with STEP and CTX) and of S, with X = 0, z_0 = 0, U = the
   default instance, and u and comT = the generators 1 and 2 of the other
   curve. N_P and N_S = the generator counts that the sizing runs need
   (the larger of the W length and the row count). Setup writes the first
   N_P and N_S generators, and D = nova_digest(P, N_P, S, N_S). Returns 1,
   or 0 when a G_CAP is below 3 or below its need, or a run fails. */
int nova_ivc_setup(NovaIvcKey *key, NovaStepFn step, const void *ctx);

/* The proof before step 0: k = 0, z_k = z_0 = Z0, and the 3 instances =
   the default instance. The caller sets the vector storage of PF. */
void nova_ivc_start(NovaIvcProof *pf, const Fe z0[STEP_GADGET_Z]);

/* Prove step i = k (O162 item 5 steps (1) to (4)). (1) i at least 1: the
   native NIFS of (r_U_s; r_W_s, r_E_s) with (l_u_s; l_w_s) over F_n (the
   challenge over F_p with h1 = H_p(D, i, z_0, z_i, r_U_s)) gives comT_s
   and U_s'. (2) The build of P (2 runs) with r_U_s, l_u_s and comT_s
   (i = 0: the default instance, and the generators 1 and 2 of S) gives
   l_u_p, l_w_p and z_(i+1). (3) i = 0: r_U_p = l_u_p (E = 0) and r_U_s =
   the default instance (W = 0, E = 0). i at least 1: the native NIFS of
   (r_U_p; r_W_p, r_E_p) with (l_u_p; l_w_p) over F_p (the challenge over
   F_n with h1 = H_n(D, i, z0_s, zi_s, r_U_p)) gives comT_p and the new
   r_U_p, and r_U_s = U_s'. (4) The build of S with r_U_p before the fold
   of (3), l_u_p and comT_p (i = 0: the default instance and the
   generator 2 of P) gives l_u_s and l_w_s. Then z_k = z_(i+1) and
   k = i + 1. The rebuilt shapes must match the setup digest D. Returns 1,
   or 0 when a part fails or the shapes change (PF is then not a valid
   proof). */
int nova_ivc_prove_step(NovaIvcProof *pf, NovaIvcKey *key, NovaStepFn step, const void *ctx);

/* Verify (O162 item 5), the checks in this order. (1) k at least 1 and
   the shapes match the setup digest D. (2) l_u_s.X[0] =
   H_p(D, k, z_0, z_k, r_U_s) and l_u_s.X[1] =
   H_n(D, k, z0_s, z0_s, r_U_p) (the cut hashes; Poseidon only). (3) The
   rows: r_U_p relaxed in P with (r_W_p, r_E_p), r_U_s relaxed in S with
   (r_W_s, r_E_s), and l_u_s plain in S (u = 1, E = 0) with l_w_s; each
   witness vector also has z[0] = u and (z[1], z[2]) = X of its instance.
   (4) The 5 commitments: Com_P(r_W_p), Com_P(r_E_p), Com_S(r_W_s),
   Com_S(r_E_s) and Com_S(l_w_s) (W = the values from NOVA_W) equal the
   points of the instances. Returns 0 when all checks pass, else the
   number of the first check that fails. KEY must be the key of the prove
   steps (its CS holds the shapes). */
int nova_ivc_verify(const NovaIvcKey *key, const NovaIvcProof *pf);

#endif
