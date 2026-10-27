/* NEW (quorum-lang S7, O92). expand_message_xmd with H = SHA-256 (RFC
   9380 section 5.3.1) and hash_to_field with one element of L = 48 bytes
   (RFC 9380 section 5.2, RFC 9591 section 6.5): the FROST(secp256k1,
   SHA-256) hashes H1, H2 and H3. */
#ifndef LANG_CRYPTO_XMD_H
#define LANG_CRYPTO_XMD_H
#include <stddef.h>

#include "crypto/bn254.h"

/* The longest MSG that xmd_expand takes (O91). */
#define XMD_MSG_MAX 1024u
/* The longest DST (RFC 9380 section 5.3.1; no long-DST hash, section 5.3.3). */
#define XMD_DST_MAX 255u
/* The longest output: 255 blocks of 32 bytes. */
#define XMD_LEN_MAX (255u * 32u)

/* OUT = expand_message_xmd(MSG, DST, LEN) with H = SHA-256. Returns 1, or 0
   with OUT not written when LEN is 0 or more than XMD_LEN_MAX, DST_LEN is 0
   (RFC 9380 section 3.1: a tag has a nonzero length) or more than
   XMD_DST_MAX, or MSG_LEN is more than XMD_MSG_MAX. */
int xmd_expand(unsigned char *out, size_t len, const unsigned char *msg, size_t msg_len,
               const unsigned char *dst, size_t dst_len);
/* OUT = hash_to_field(MSG, 1) over the field N with L = 48: the 48 bytes of
   xmd_expand(MSG, DST, 48) as a big endian integer, mod N. Exact for each N
   above 256. Returns 1, or 0 when xmd_expand refuses the input. */
int xmd_to_scalar(Fe *out, const unsigned char *msg, size_t msg_len, const unsigned char *dst,
                  size_t dst_len, const Modulus *n);
#endif
