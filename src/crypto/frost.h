/* NEW (quorum-lang S7, O94). FROST(secp256k1, SHA-256) (RFC 9591): the
   nonces, commitments, binding factors, group commitment, challenge,
   Lagrange values, signature shares, aggregate and verification of
   sections 4 and 5 and App. B, with the context string
   "FROST-secp256k1-SHA256-v1" (section 6.5).

   H1, H2 and H3 are xmd_to_scalar (crypto/xmd.h) with the DST ctx || "rho",
   ctx || "chal" and ctx || "nonce". H4 = SHA-256(ctx || "msg" || m) and
   H5 = SHA-256(ctx || "com" || m). An identifier is 1 to THR_N_MAX. A
   commitment list is sorted by identifier, with each identifier one time
   (section 4.3). frost_aggregate does not check MIN_PARTICIPANTS: the
   coordinator does that (O94). */
#ifndef LANG_CRYPTO_FROST_H
#define LANG_CRYPTO_FROST_H
#include <stddef.h>
#include <stdint.h>

#include "crypto/secp256k1.h"
#include "crypto/threshold.h"
#include "crypto/xmd.h"

/* The longest message: the H2 input enc(R) || enc(PK) || MSG has 66 + MSG
   bytes, and xmd_expand takes XMD_MSG_MAX bytes. */
#define FROST_MSG_MAX (XMD_MSG_MAX - 66u)
/* The bytes of a signature: enc(R) || SerializeScalar(z) (section 5.3). */
#define FROST_SIG_BYTES 65u

typedef enum {
  FROST_OK,
  /* frost_verify_share: z G is not D + rho E + (c lambda) PK_i. */
  FROST_BAD_SHARE,
  /* An identifier is 0, above THR_N_MAX, repeated, not sorted or not in
     the list, or the list is empty or longer than THR_N_MAX. */
  FROST_BAD_INDEX,
  /* A point does not decode or is the identity. */
  FROST_BAD_POINT,
  /* frost_verify: z is n or more, or z G is not R + c PK. */
  FROST_BAD_SIG,
  /* MSG is longer than FROST_MSG_MAX. */
  FROST_BAD_MSG
} FrostResult;

/* One entry of a commitment list (section 4.3): the identifier and the
   hiding and binding nonce commitments D and E. */
typedef struct {
  uint32_t id;
  G1 hiding;
  G1 binding;
} FrostCommit;

/* The secret nonces d and e of one signer (section 5.1). */
typedef struct {
  Fe hiding;
  Fe binding;
} FrostNonce;

/* OUT = nonce_generate(SECRET) with the 32 random bytes RANDOM (section
   4.1): H3(RANDOM || SerializeScalar(SECRET)). */
void frost_nonce(Fe *out, const unsigned char random[32], const Fe *secret);
/* Round one (section 5.1): NONCE = the nonces of SECRET from HIDING_RANDOM
   and BINDING_RANDOM, COMMIT = (ID, d G, e G). FROST_BAD_INDEX when ID is 0
   or above THR_N_MAX, with NONCE and COMMIT not written. */
FrostResult frost_commit(FrostNonce *nonce, FrostCommit *commit, uint32_t id, const Fe *secret,
                         const unsigned char hiding_random[32], const unsigned char binding_random[32]);
/* RHO[k] = the binding factor of LIST[k] (section 4.4): H1(rho_input) with
   rho_input = enc(PK) || H4(MSG) || H5(the encoded LIST) ||
   SerializeScalar(identifier). FROST_BAD_INDEX, FROST_BAD_POINT (PK or a
   commitment is the identity or off the curve) or FROST_BAD_MSG, with RHO
   not written. */
FrostResult frost_binding_factors(Fe rho[], const G1 *pk, const FrostCommit *list, size_t count,
                                  const unsigned char *msg, size_t msg_len);
/* OUT = R = the sum over LIST of D + RHO[k] E (section 4.5). */
void frost_group_commitment(G1 *out, const FrostCommit *list, const Fe rho[], size_t count);
/* OUT = c = H2(enc(R) || enc(PK) || MSG) (section 4.6). FROST_BAD_POINT
   when R or PK is the identity or off the curve, or FROST_BAD_MSG, with
   OUT not written. */
FrostResult frost_challenge(Fe *out, const G1 *r, const G1 *pk, const unsigned char *msg, size_t msg_len);
/* OUT = derive_interpolating_value(IDS, ID) (section 4.2): the product over
   the other x_j of IDS of x_j / (x_j - ID). FROST_BAD_INDEX, with OUT not
   written, when IDS is not a sorted list of 1 to THR_N_MAX identifiers
   (each one time) or ID is not in IDS. */
FrostResult frost_lagrange(Fe *out, uint32_t id, const uint32_t ids[], size_t count);
/* Round two (section 5.2): Z = d + e rho + lambda SECRET c for the signer
   ID with the secret share SECRET and the nonces NONCE. FROST_BAD_POINT
   also when the LIST entry of ID is not the commitment of NONCE. Z is not
   written on a refusal. */
FrostResult frost_sign(Fe *z, uint32_t id, const Fe *secret, const FrostNonce *nonce, const G1 *pk,
                       const FrostCommit *list, size_t count, const unsigned char *msg, size_t msg_len);
/* Section 5.4: FROST_OK when Z G = D + rho E + (c lambda) PK_ID for the
   LIST entry of ID, else FROST_BAD_SHARE or a refusal code of the steps.
   FROST_BAD_POINT when PK_ID is the identity or off the curve. */
FrostResult frost_verify_share(uint32_t id, const G1 *pk_id, const Fe *z, const G1 *pk, const FrostCommit *list,
                               size_t count, const unsigned char *msg, size_t msg_len);
/* Section 5.3: SIG = enc(R) || SerializeScalar(z), with z the sum of Z[0]
   to Z[COUNT - 1] (the shares in LIST order). It does not check
   MIN_PARTICIPANTS. SIG is not written on a refusal. */
FrostResult frost_aggregate(unsigned char sig[FROST_SIG_BYTES], const Fe z[], const G1 *pk,
                            const FrostCommit *list, size_t count, const unsigned char *msg, size_t msg_len);
/* App. B with cofactor 1: FROST_OK when SIG = enc(R) || z is a signature
   of MSG for PK: z G = R + c PK with c = H2(enc(R) || enc(PK) || MSG).
   FROST_BAD_POINT when R does not decode or PK is the identity or off the curve,
   FROST_BAD_SIG when z is n or more or the two points are not equal, or
   FROST_BAD_MSG. */
FrostResult frost_verify(const unsigned char sig[FROST_SIG_BYTES], const G1 *pk, const unsigned char *msg,
                         size_t msg_len);
#endif
