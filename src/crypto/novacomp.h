#ifndef LANG_CRYPTO_NOVACOMP_H
/* NEW (quorum-lang S11 H4a C4): the compressed proof of a Nova IVC proof
   (NovaIvcProof of novaivc.h), without zero knowledge (O151).

   The last fold (Q-S11-10 (a)): T = the cross term of r_U_s and l_u_s,
   comT_s = Com(T), r = the 128-bit challenge of the secondary transcript
   after the head, and f_U_s = the fold of r_U_s with l_u_s. Then Spartan
   (spartan.h) on r_U_p with the primary transcript and on f_U_s with the
   secondary transcript.

   The transcripts (plan item 5): each side has a sponge of its params with
   the start state (NOVA_COMP_DOMAIN, 0, 0). The head goes in first: D, k,
   z_0, z_k, r_U_p, r_U_s, l_u_s (comW, comE, u, X) and comT_s. A point goes
   in as 4 limbs of 128 bits (ipa_ts_point). A field value V goes in as the
   point (V, 0), thus a value of the other field is safe. Then the
   secondary transcript gives r. Spartan then adds its instance.

   The bytes (Q-S11-14 (a)): a field value is 32 bytes little-endian. A
   point is 65 bytes: 0x04, then x and y as 32 bytes big-endian each
   (SEC1). The identity is 65 zero bytes. The order: k (8 bytes
   little-endian), z_0, z_k, r_U_p, r_U_s, l_u_s, comT_s, then each side
   (the primary side first): sum-check 1 (a x 4 values), v_A, v_B, v_C,
   v_E, sum-check 2 ((b + 1) x 3 values), v_W, sum-check 3 (c x 3 values),
   w, e, the IPA rounds (c x (L, R)) and a. The pad (a, b, c) of each side
   comes from its shape, thus the bytes do not hold it. */
#define LANG_CRYPTO_NOVACOMP_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/ipa.h"
#include "crypto/nova.h"
#include "crypto/novaivc.h"
#include "crypto/spartan.h"

/* The domain value of the transcripts ("qlcomp2"; IPA_TS_DOMAIN is
   "qlcomp1"). */
#define NOVA_COMP_DOMAIN 0x716c636f6d7032ull

/* The work space of one side. The caller sets the buffers and the caps: G
   (G_CAP points) and K (K_CAP values) for the IPA key and its MSM, the
   buckets of the MSM, FE (FE_LEN values) and GW (GW_LEN points) for
   Spartan. nova_comp_setup sets D (the pad) and IPA (the IPA key). */
typedef struct {
  G1 *g;
  size_t g_cap;
  U256 *k;
  size_t k_cap;
  EcJac *bucket;
  size_t buckets;
  Fe *fe;
  size_t fe_len;
  G1 *gw;
  size_t gw_len;
  SpartanDims d;
  IpaKey ipa;
} NovaCompSide;

/* The key of the compressed proof: one side for each side of the IVC key,
   and Z (VAR_CAP values) and E (ROW_CAP values) for the folded witness of
   the secondary side. */
typedef struct {
  NovaCompSide p;
  NovaCompSide s;
  Fe *z;
  size_t var_cap;
  Fe *e;
  size_t row_cap;
} NovaCompKey;

/* The compressed proof: the head and one Spartan proof for each side. */
typedef struct {
  size_t k;
  Fe z0[STEP_GADGET_Z];
  Fe zk[STEP_GADGET_Z];
  NovaInstance r_u_p;
  NovaInstance r_u_s;
  NovaInstance l_u_s;
  G1 com_t_s;
  SpartanProof p;
  SpartanProof s;
} NovaCompProof;

/* Sets the pad and the IPA key of each side of CK for the shapes of KEY.
   Returns 1, or 0 when a pad is not correct (spartan_dims), a buffer is
   too small (G and K need 2^c, FE needs spartan_work_len, GW needs
   2^(c - 1), Z needs the variable count and E the row count of the
   secondary system), or ipa_key fails. */
int nova_comp_setup(NovaCompKey *ck, const NovaIvcKey *key);
/* OUT = the compressed proof of PF. This does not check PF (for a false PF
   the verify fails). This writes key->s.t (the cross term), CK->z and
   CK->e. Returns 1, or 0 when k is 0, a buffer of CK is too small, the
   cross term or a commitment fails, or a Spartan proof fails. */
int nova_comp_prove(NovaCompProof *out, const NovaCompKey *ck, const NovaIvcKey *key,
                    const NovaIvcProof *pf);
/* Checks PF. Returns 0 when PF holds, else the number of the first failed
   check: 1 k is 0 or the shapes do not give D, 2 a bind of l_u_s.X (H_p or
   H_n, as nova_ivc_verify), 3 u of l_u_s is not 1 or comE of l_u_s is not
   the identity, 10 + n the check n of spartan_verify on the primary side,
   20 + n the check n of spartan_verify on the secondary side. */
int nova_comp_verify(const NovaCompKey *ck, const NovaIvcKey *key, const NovaCompProof *pf);
/* The byte count of a compressed proof for the pads of CK. */
size_t nova_comp_size(const NovaCompKey *ck);
/* OUT (LEN bytes) = the bytes of PF. Returns 1, or 0 when LEN is not
   nova_comp_size or a pad of PF is not the pad of CK. */
int nova_comp_encode(unsigned char *out, size_t len, const NovaCompKey *ck,
                     const NovaCompProof *pf);
/* OUT = the proof of the LEN bytes IN. Returns 1, or 0 when LEN is not
   nova_comp_size, k does not fit in size_t, a value is not below the
   modulus of its field, a coordinate is not below the modulus of the base
   field, a point is not on its curve, or the first byte of a point is not
   0x04 (65 zero bytes give the identity). */
int nova_comp_decode(NovaCompProof *out, const NovaCompKey *ck, const NovaIvcKey *key,
                     const unsigned char *in, size_t len);

#endif
