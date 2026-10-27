/* NEW (quorum-lang S7, O92): RFC 9380 section 5.3.1 with H = SHA-256
   (b_in_bytes 32, s_in_bytes 64) and section 5.2 hash_to_field with count 1
   and L = 48. sha256 is one-shot, so each hash input is built in a fixed
   buffer (O91). */
#include "crypto/xmd.h"

#include "crypto/sha256.h"

enum { XMD_B = 32, XMD_S = 64, XMD_L = 48 };

/* msg_prime = Z_pad || MSG || I2OSP(LEN, 2) || I2OSP(0, 1) || DST_prime, the
   largest hash input. */
#define XMD_PRIME_MAX (XMD_S + XMD_MSG_MAX + 3u + XMD_DST_MAX + 1u)

/* BUF[AT..] = DST_prime = DST || I2OSP(DST_LEN, 1). Returns the new end. */
static size_t put_dst(unsigned char *buf, size_t at, const unsigned char *dst, size_t dst_len) {
  for (size_t i = 0; i < dst_len; i++)
    buf[at + i] = dst[i];
  buf[at + dst_len] = (unsigned char)dst_len;
  return at + dst_len + 1u;
}

int xmd_expand(unsigned char *out, size_t len, const unsigned char *msg, size_t msg_len,
               const unsigned char *dst, size_t dst_len) {
  unsigned char prime[XMD_PRIME_MAX];
  unsigned char b0[XMD_B];
  unsigned char bi[XMD_B];
  size_t ell = (len + XMD_B - 1u) / XMD_B;
  size_t at;
  if (len == 0 || len > XMD_LEN_MAX || dst_len == 0 || dst_len > XMD_DST_MAX || msg_len > XMD_MSG_MAX)
    return 0;
  /* Steps 3 to 7: b_0 = H(msg_prime). */
  for (at = 0; at < XMD_S; at++)
    prime[at] = 0;
  for (size_t i = 0; i < msg_len; i++)
    prime[at + i] = msg[i];
  at += msg_len;
  prime[at] = (unsigned char)(len >> 8);
  prime[at + 1u] = (unsigned char)len;
  prime[at + 2u] = 0;
  sha256(prime, put_dst(prime, at + 3u, dst, dst_len), b0);
  /* Steps 8 to 12: b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) ||
     DST_prime), with b_(0) taken as 32 zero bytes for i = 1, so that b_1 =
     H(b_0 || I2OSP(1, 1) || DST_prime). OUT gets the first LEN bytes of
     b_1 || ... || b_ell. */
  for (size_t j = 0; j < XMD_B; j++)
    bi[j] = 0;
  for (size_t i = 1; i <= ell; i++) {
    for (size_t j = 0; j < XMD_B; j++)
      prime[j] = (unsigned char)(b0[j] ^ bi[j]);
    prime[XMD_B] = (unsigned char)i;
    sha256(prime, put_dst(prime, XMD_B + 1u, dst, dst_len), bi);
    for (size_t j = 0; j < XMD_B && (i - 1u) * XMD_B + j < len; j++)
      out[(i - 1u) * XMD_B + j] = bi[j];
  }
  return 1;
}

int xmd_to_scalar(Fe *out, const unsigned char *msg, size_t msg_len, const unsigned char *dst,
                  size_t dst_len, const Modulus *n) {
  unsigned char bytes[XMD_L];
  Fe radix;
  Fe digit;
  Fe acc;
  Fe shifted;
  if (!xmd_expand(bytes, XMD_L, msg, msg_len, dst, dst_len))
    return 0;
  /* OS2IP(bytes) mod N, the most significant byte first: acc = acc 256 +
     byte. 256 and each byte are below N, so fe_mul and fe_add are exact. */
  fe_from_u64(&radix, 256u);
  fe_from_u64(&acc, 0);
  for (size_t i = 0; i < XMD_L; i++) {
    fe_from_u64(&digit, bytes[i]);
    fe_mul(&shifted, &acc, &radix, n);
    fe_add(&acc, &shifted, &digit, n);
  }
  *out = acc;
  return 1;
}
