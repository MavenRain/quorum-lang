/* NEW (quorum-lang S7, O99): host FROST regressions. H2a: the SHA-256 rows
   (src/crypto/sha256.c) and the expand_message_xmd rows (src/crypto/xmd.c).
   H2b: the secp256k1 rows (src/crypto/secp256k1.c) and the xmd_to_scalar
   row. H3a: the FROST(secp256k1, SHA-256) rows (src/crypto/frost.c).
   H3b: the secp256k1 DKG rows (src/crypto/dkg.c, O96). H4a: the reshare
   rows (O97). H4b: `frosttool rep`, the representation map (O98).
   Each row has its source and a second source in a comment. */
#include <stdio.h>
#include <string.h>

#include "crypto/dkg.h"
#include "crypto/frost.h"
#include "crypto/secp256k1.h"
#include "crypto/sha256.h"
#include "crypto/xmd.h"

/* The DST of RFC 9380 App. K.1. */
#define K1_DST "QUUX-V01-CS02-with-expander-SHA256-128"

/* FIPS 180-2 B.3: 1,000,000 repetitions of "a". Also the input of the
   refusal rows. */
static unsigned char million[1000000];

/* 1 when the SIZE bytes at GOT are the 2 SIZE lowercase hex digits WANT. */
static int bytes_row(const char *name, const unsigned char *got, size_t size, const char *want) {
  static const char digits[] = "0123456789abcdef";
  int same = strlen(want) == 2u * size;
  for (size_t i = 0; same && i < size; i++)
    same = want[2u * i] == digits[got[i] >> 4] && want[2u * i + 1u] == digits[got[i] & 15u];
  if (same)
    return 1;
  fprintf(stderr, "FAIL frost %s: ", name);
  for (size_t i = 0; i < size; i++)
    fprintf(stderr, "%02x", got[i]);
  fputc('\n', stderr);
  return 0;
}

/* 1 when sha256 of the SIZE bytes at DATA is WANT. */
static int sha_row(const char *name, const unsigned char *data, size_t size, const char *want) {
  unsigned char digest[32];
  sha256(data, size, digest);
  return bytes_row(name, digest, 32u, want);
}

/* 1 when xmd_expand(MSG, K1_DST, LEN) is WANT (LEN at most 128). */
static int xmd_row(const char *name, const unsigned char *msg, size_t msg_len, size_t len, const char *want) {
  unsigned char out[128];
  if (len <= sizeof out && xmd_expand(out, len, msg, msg_len, (const unsigned char *)K1_DST, strlen(K1_DST)))
    return bytes_row(name, out, len, want);
  fprintf(stderr, "FAIL frost %s: refused\n", name);
  return 0;
}

/* 1 when xmd_expand refuses the input (O92). */
static int refuse_row(const char *name, size_t len, size_t msg_len, size_t dst_len) {
  static unsigned char out[XMD_LEN_MAX + 1u];
  if (!xmd_expand(out, len, million, msg_len, million, dst_len))
    return 1;
  fprintf(stderr, "FAIL frost %s: not refused\n", name);
  return 0;
}

/* BUF = PREFIX then COUNT copies of FILL. Returns the length. */
static size_t repeat_msg(unsigned char *buf, const char *prefix, char fill, size_t count) {
  size_t n = strlen(prefix);
  memcpy(buf, prefix, n);
  memset(buf + n, fill, count);
  return n + count;
}

/* 1 when the 32 big endian bytes of X are WANT. */
static int fe_row(const char *name, const Fe *x, const char *want) {
  unsigned char out[32];
  scalar_encode(out, x);
  return bytes_row(name, out, 32u, want);
}

/* 1 when P is the point (WANT_X, WANT_Y). */
static int point_row(const char *name, const G1 *p, const char *want_x, const char *want_y) {
  int x_ok = fe_row(name, &p->x, want_x);
  return fe_row(name, &p->y, want_y) & x_ok;
}

/* 1 when GOOD is not 0. */
static int true_row(const char *name, int good) {
  if (good)
    return 1;
  fprintf(stderr, "FAIL frost %s\n", name);
  return 0;
}

/* The value of the lowercase hex digit C. */
static unsigned nibble(char c) {
  return c <= '9' ? (unsigned)(c - '0') : (unsigned)(c - 'a' + 10);
}

/* OUT = the SIZE bytes of the 2 SIZE lowercase hex digits HEX. Returns OUT. */
static unsigned char *from_hex(unsigned char *out, size_t size, const char *hex) {
  for (size_t i = 0; i < size; i++)
    out[i] = (unsigned char)((nibble(hex[2u * i]) << 4) | nibble(hex[2u * i + 1u]));
  return out;
}

/* The secp256k1 rows (O93, O95). Source: SEC 2 section 2.4.1 (p, n, G,
   cofactor 1). Second source: W/s7-secp-check.py (Python big integers: 2G,
   (n - 1) G, the SEC1 bytes, the parity lift, the non-square x 5; it also
   checks the intent-lang 79e1898 limb constants against SEC 2). */
static int secp_rows(void) {
  /* SEC 2 section 2.4.1: n and n - 1, low limb first. */
  static const U256 n_word = {{0xbfd25e8cd0364141ull, 0xbaaedce6af48a03bull, 0xfffffffffffffffeull, 0xffffffffffffffffull}};
  static const U256 n1_word = {{0xbfd25e8cd0364140ull, 0xbaaedce6af48a03bull, 0xfffffffffffffffeull, 0xffffffffffffffffull}};
  unsigned char pt[33];
  unsigned char sc[32];
  U256 two;
  G1 zero;
  G1 g;
  G1 g2;
  G1 neg;
  G1 q;
  Fe k;
  int ok;
  memset(&zero, 0, sizeof zero);
  u256_from_u64(&two, 2);
  secp_gen(&g);
  ok = true_row("secp G on the curve", secp_on_curve(&g));
  ok &= point_row("secp G", &g, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  secp_mul(&g2, &g, &two);
  ok &= point_row("secp 2G", &g2, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                  "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
  secp_add(&q, &g, &g);
  ok &= true_row("secp G + G is 2G on the curve", secp_eq(&q, &g2) && secp_on_curve(&g2));
  secp_mul(&q, &g, &n_word);
  ok &= true_row("secp n G is the identity", secp_eq(&q, &zero));
  secp_neg(&neg, &g);
  ok &= point_row("secp -G", &neg, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                  "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777");
  secp_mul(&q, &g, &n1_word);
  ok &= true_row("secp (n - 1) G is -G", secp_eq(&q, &neg));
  secp_add(&q, &g, &neg);
  ok &= true_row("secp G + -G is the identity", secp_eq(&q, &zero));
  /* SEC 1 section 2.3.3 and 2.3.4 (compressed), RFC 9591 section 6.5
     SerializeElement and DeserializeElement. SEC 2 section 2.4.1 gives
     the compressed G. */
  ok &= true_row("secp enc G", secp_encode(pt, &g)) &&
        bytes_row("secp enc G", pt, 33u, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  ok &= true_row("secp dec enc G is G", secp_decode(&q, pt) && secp_eq(&q, &g));
  ok &= true_row("secp enc 2G", secp_encode(pt, &g2)) &&
        bytes_row("secp enc 2G", pt, 33u, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
  ok &= true_row("secp dec enc 2G is 2G", secp_decode(&q, pt) && secp_eq(&q, &g2));
  ok &= true_row("secp dec 03 x(G) is -G",
                 secp_decode(&q, from_hex(pt, 33u, "03" "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")) && secp_eq(&q, &neg));
  /* Refusals: RFC 9591 section 6.5 (DeserializeElement: prefix, x range,
     x on the curve; SerializeElement of the identity; DeserializeScalar of
     n). */
  ok &= true_row("secp refuse prefix 04", !secp_decode(&q, from_hex(pt, 33u, "04" "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")));
  ok &= true_row("secp refuse x = p", !secp_decode(&q, from_hex(pt, 33u, "02" "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")));
  ok &= true_row("secp refuse a non-square x", !secp_decode(&q, from_hex(pt, 33u, "02" "0000000000000000000000000000000000000000000000000000000000000005")));
  ok &= true_row("secp refuse enc of the identity", !secp_encode(pt, &zero));
  ok &= true_row("scalar refuse n", !scalar_decode(&k, from_hex(sc, 32u, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")));
  ok &= true_row("scalar dec n - 1", scalar_decode(&k, from_hex(sc, 32u, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"))) &&
        fe_row("scalar enc n - 1", &k, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
  /* xmd_to_scalar (src/crypto/xmd.c). Source: RFC 9380 section 5.2
     (hash_to_field, L = 48: the 48 bytes as a big endian integer, mod n)
     and RFC 9591 section 6.5 (H1, H2, H3), here with the K.1 DST and
     "abc". Second source: W/s7-secp-check.py. The external check is the
     RFC 9591 App. E.5 rows (H3a). */
  ok &= true_row("xmd_to_scalar abc", xmd_to_scalar(&k, (const unsigned char *)"abc", 3u,
                                                    (const unsigned char *)K1_DST, strlen(K1_DST),
                                                    &SECP_FN)) &&
        fe_row("xmd_to_scalar abc", &k, "26a475d37f1a1585e49e28e02de9fb234184bc3a1da5ccdb3f992a7c6dbcb4a2");
  return ok;
}

/* OUT = K G. */
static void gen_mul(G1 *out, const Fe *k) {
  U256 w;
  G1 g;
  secp_gen(&g);
  fe_to_u256(&w, k);
  secp_mul(out, &g, &w);
}

/* 1 when the SEC1 compressed bytes of P are the 33 bytes WANT. */
static int enc_row(const char *name, const G1 *p, const char *want) {
  unsigned char out[33];
  return true_row(name, secp_encode(out, p)) && bytes_row(name, out, 33u, want);
}

/* 1 when GOT is WANT. */
static int code_row(const char *name, FrostResult got, FrostResult want) {
  if (got == want)
    return 1;
  fprintf(stderr, "FAIL frost %s: code %d, want %d\n", name, (int)got, (int)want);
  return 0;
}

/* The FROST rows (O94, O95). Source: RFC 9591 App. E.5 FROST(secp256k1,
   SHA-256), copy W/vectors/rfc9591-e5.txt: MAX_PARTICIPANTS 3,
   MIN_PARTICIPANTS 2, signers 1 and 3, message "test". Second source:
   W/s7-frost-check.py (Python big integers and hashlib from the E.5
   inputs, 22 of 22 equal; it also checks the two binding factor inputs). */
static int frost_rows(void) {
  static const unsigned char msg[4] = {'t', 'e', 's', 't'};
  static const unsigned char other[4] = {'t', 'e', 's', 'u'};
  static const uint32_t ids_zero[2] = {0, 3u};
  static const uint32_t ids_high[2] = {1u, THR_N_MAX + 1u};
  static const uint32_t ids_twice[2] = {1u, 1u};
  static const uint32_t ids_down[2] = {3u, 1u};
  static const uint32_t ids_e5[2] = {1u, 3u};
  unsigned char sc[32];
  unsigned char hr[32];
  unsigned char br[32];
  unsigned char sig[FROST_SIG_BYTES];
  unsigned char e5_sig[FROST_SIG_BYTES];
  unsigned char bad_sig[FROST_SIG_BYTES];
  Fe sk;
  Fe a1;
  Fe x;
  Fe t;
  Fe one;
  Fe lam;
  Fe z_bad;
  Fe share[3];
  Fe rho[2];
  Fe rho_bad[2];
  Fe z[2];
  G1 pk;
  G1 pk1;
  G1 pk3;
  FrostNonce nonce[2];
  FrostNonce spare_nonce;
  FrostCommit list[2];
  FrostCommit bad[2];
  FrostCommit spare;
  int ok;
  /* E.5 group input parameters. The shares are f(i) = sk + a1 i (App. C,
     the trusted dealer with one coefficient). */
  ok = true_row("e5 group_secret_key", scalar_decode(&sk, from_hex(sc, 32u, "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114")));
  ok &= true_row("e5 coefficient", scalar_decode(&a1, from_hex(sc, 32u, "fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579")));
  gen_mul(&pk, &sk);
  ok &= enc_row("e5 group_public_key", &pk, "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
  for (uint32_t i = 0; i < 3u; i++) {
    fe_from_u64(&x, i + 1u);
    fe_mul(&t, &a1, &x, &SECP_FN);
    fe_add(&share[i], &sk, &t, &SECP_FN);
  }
  ok &= fe_row("e5 P1 participant_share", &share[0], "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c");
  ok &= fe_row("e5 P2 participant_share", &share[1], "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984");
  ok &= fe_row("e5 P3 participant_share", &share[2], "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc");
  /* E.5 signer round one outputs (RFC 9591 sections 4.1 and 5.1). */
  ok &= code_row("e5 P1 commit",
                 frost_commit(&nonce[0], &list[0], 1u, &share[0], from_hex(hr, 32u, "7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2"),
                              from_hex(br, 32u, "47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5")),
                 FROST_OK);
  ok &= code_row("e5 P3 commit",
                 frost_commit(&nonce[1], &list[1], 3u, &share[2], from_hex(hr, 32u, "e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544"),
                              from_hex(br, 32u, "7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9")),
                 FROST_OK);
  ok &= fe_row("e5 P1 hiding_nonce", &nonce[0].hiding, "841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0");
  ok &= fe_row("e5 P1 binding_nonce", &nonce[0].binding, "8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80");
  ok &= enc_row("e5 P1 hiding_nonce_commitment", &list[0].hiding, "03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904");
  ok &= enc_row("e5 P1 binding_nonce_commitment", &list[0].binding, "02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e");
  ok &= fe_row("e5 P3 hiding_nonce", &nonce[1].hiding, "2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2");
  ok &= fe_row("e5 P3 binding_nonce", &nonce[1].binding, "7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98");
  ok &= enc_row("e5 P3 hiding_nonce_commitment", &list[1].hiding, "03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6");
  ok &= enc_row("e5 P3 binding_nonce_commitment", &list[1].binding, "02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135");
  /* E.5 binding factors (section 4.4). */
  ok &= code_row("e5 binding factors", frost_binding_factors(rho, &pk, list, 2u, msg, sizeof msg), FROST_OK);
  ok &= fe_row("e5 P1 binding_factor", &rho[0], "3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6");
  ok &= fe_row("e5 P3 binding_factor", &rho[1], "93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7");
  /* E.5 signer round two outputs (sections 4.2, 4.5, 4.6 and 5.2). */
  ok &= code_row("e5 P1 sign", frost_sign(&z[0], 1u, &share[0], &nonce[0], &pk, list, 2u, msg, sizeof msg), FROST_OK);
  ok &= code_row("e5 P3 sign", frost_sign(&z[1], 3u, &share[2], &nonce[1], &pk, list, 2u, msg, sizeof msg), FROST_OK);
  ok &= fe_row("e5 P1 sig_share", &z[0], "c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197");
  ok &= fe_row("e5 P3 sig_share", &z[1], "0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d");
  /* E.5 sig (section 5.3: enc(R) || z). */
  ok &= code_row("e5 aggregate", frost_aggregate(sig, z, &pk, list, 2u, msg, sizeof msg), FROST_OK);
  ok &= bytes_row("e5 sig", sig, sizeof sig, "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324");
  /* App. B (cofactor 1) on the E.5 sig bytes, and section 5.4 on each E.5
     share with PK_i = s_i G. */
  from_hex(e5_sig, sizeof e5_sig, "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324");
  ok &= code_row("e5 verify sig", frost_verify(e5_sig, &pk, msg, sizeof msg), FROST_OK);
  gen_mul(&pk1, &share[0]);
  gen_mul(&pk3, &share[2]);
  ok &= code_row("e5 verify P1 sig_share", frost_verify_share(1u, &pk1, &z[0], &pk, list, 2u, msg, sizeof msg),
                 FROST_OK);
  ok &= code_row("e5 verify P3 sig_share", frost_verify_share(3u, &pk3, &z[1], &pk, list, 2u, msg, sizeof msg),
                 FROST_OK);
  /* Refusals (O94). An identifier is a nonzero scalar (RFC 9591 section
     5); O94 also refuses one above THR_N_MAX. The list is sorted, with
     each identifier one time (section 4.3). Section 4.2 refuses an
     identifier that is not in the list. */
  ok &= code_row("refuse commit id 0", frost_commit(&spare_nonce, &spare, 0, &share[0], hr, br), FROST_BAD_INDEX);
  ok &= code_row("refuse commit id 9", frost_commit(&spare_nonce, &spare, THR_N_MAX + 1u, &share[0], hr, br),
                 FROST_BAD_INDEX);
  ok &= code_row("refuse lagrange id 0", frost_lagrange(&lam, 3u, ids_zero, 2u), FROST_BAD_INDEX);
  ok &= code_row("refuse lagrange id 9", frost_lagrange(&lam, 1u, ids_high, 2u), FROST_BAD_INDEX);
  ok &= code_row("refuse lagrange repeated", frost_lagrange(&lam, 1u, ids_twice, 2u), FROST_BAD_INDEX);
  ok &= code_row("refuse lagrange not sorted", frost_lagrange(&lam, 1u, ids_down, 2u), FROST_BAD_INDEX);
  ok &= code_row("refuse lagrange not in list", frost_lagrange(&lam, 2u, ids_e5, 2u), FROST_BAD_INDEX);
  bad[0] = list[0];
  bad[1] = list[0];
  ok &= code_row("refuse list repeated", frost_binding_factors(rho_bad, &pk, bad, 2u, msg, sizeof msg),
                 FROST_BAD_INDEX);
  bad[0] = list[1];
  bad[1] = list[0];
  ok &= code_row("refuse list not sorted", frost_binding_factors(rho_bad, &pk, bad, 2u, msg, sizeof msg),
                 FROST_BAD_INDEX);
  /* Section 5.2: the list entry of the signer is not the commitment of its
     nonces. */
  ok &= code_row("refuse sign other nonce",
                 frost_sign(&z_bad, 1u, &share[0], &nonce[1], &pk, list, 2u, msg, sizeof msg), FROST_BAD_POINT);
  /* Section 5.4: a changed signature share. */
  fe_from_u64(&one, 1u);
  fe_add(&z_bad, &z[0], &one, &SECP_FN);
  ok &= code_row("refuse changed sig_share",
                 frost_verify_share(1u, &pk1, &z_bad, &pk, list, 2u, msg, sizeof msg), FROST_BAD_SHARE);
  /* App. B: a changed signature byte (z, then the SEC1 prefix), another
     message, z = n (section 6.5 DeserializeScalar), a message above
     FROST_MSG_MAX. */
  memcpy(bad_sig, e5_sig, sizeof bad_sig);
  bad_sig[64] ^= 1u;
  ok &= code_row("refuse changed sig z byte", frost_verify(bad_sig, &pk, msg, sizeof msg), FROST_BAD_SIG);
  memcpy(bad_sig, e5_sig, sizeof bad_sig);
  bad_sig[0] = 4u;
  ok &= code_row("refuse sig prefix 04", frost_verify(bad_sig, &pk, msg, sizeof msg), FROST_BAD_POINT);
  ok &= code_row("refuse other message", frost_verify(e5_sig, &pk, other, sizeof other), FROST_BAD_SIG);
  memcpy(bad_sig, e5_sig, sizeof bad_sig);
  from_hex(bad_sig + 33u, 32u, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  ok &= code_row("refuse sig z = n", frost_verify(bad_sig, &pk, msg, sizeof msg), FROST_BAD_SIG);
  ok &= code_row("refuse long message", frost_verify(e5_sig, &pk, million, FROST_MSG_MAX + 1u), FROST_BAD_MSG);
  /* O94: frost_aggregate does not check MIN_PARTICIPANTS. Signer 1 alone
     (below t = 2) gives a signature that does not verify. */
  ok &= code_row("below t sign", frost_sign(&z_bad, 1u, &share[0], &nonce[0], &pk, list, 1u, msg, sizeof msg),
                 FROST_OK);
  ok &= code_row("below t aggregate", frost_aggregate(bad_sig, &z_bad, &pk, list, 1u, msg, sizeof msg), FROST_OK);
  ok &= code_row("below t verify", frost_verify(bad_sig, &pk, msg, sizeof msg), FROST_BAD_SIG);
  return ok;
}

/* The invalid point (1, 0) has order 2 under the unchecked formulas.
   For MSG = 00 the challenge is even, so (R = G, z = 1) used to verify
   under that point. Refuse it at every FROST point input. */
static int invalid_point_rows(void) {
  static const unsigned char msg[1] = {0};
  unsigned char sig[FROST_SIG_BYTES];
  unsigned char encoded[33];
  unsigned char untouched[33];
  G1 g;
  G1 bad;
  G1 zero;
  Fe one;
  Fe rho;
  Fe challenge;
  FrostCommit list;
  int ok = 1;
  memset(&bad, 0, sizeof bad);
  memset(&zero, 0, sizeof zero);
  fe_from_u64(&bad.x, 1u);
  fe_from_u64(&one, 1u);
  secp_gen(&g);
  list.id = 1u;
  list.hiding = g;
  list.binding = g;
  memset(encoded, 0xa5, sizeof encoded);
  memcpy(untouched, encoded, sizeof encoded);
  ok &= true_row("off-curve encode refused", !secp_encode(encoded, &bad));
  ok &= true_row("off-curve encode keeps output", memcmp(encoded, untouched, sizeof encoded) == 0);
  ok &= true_row("invalid-key sig R", secp_encode(sig, &g));
  scalar_encode(sig + 33u, &one);
  ok &= code_row("off-curve key forgery", frost_verify(sig, &bad, msg, sizeof msg), FROST_BAD_POINT);
  ok &= code_row("off-curve group key", frost_binding_factors(&rho, &bad, &list, 1u, msg, sizeof msg),
                 FROST_BAD_POINT);
  ok &= code_row("off-curve challenge R", frost_challenge(&challenge, &bad, &g, msg, sizeof msg),
                 FROST_BAD_POINT);
  ok &= code_row("off-curve verification share",
                 frost_verify_share(1u, &bad, &one, &g, &list, 1u, msg, sizeof msg), FROST_BAD_POINT);
  ok &= code_row("identity verification share",
                 frost_verify_share(1u, &zero, &one, &g, &list, 1u, msg, sizeof msg), FROST_BAD_POINT);
  list.hiding = bad;
  ok &= code_row("off-curve hiding commitment", frost_binding_factors(&rho, &g, &list, 1u, msg, sizeof msg),
                 FROST_BAD_POINT);
  list.hiding = g;
  list.binding = bad;
  ok &= code_row("off-curve binding commitment", frost_binding_factors(&rho, &g, &list, 1u, msg, sizeof msg),
                 FROST_BAD_POINT);
  return ok;
}

/* Add 1 mod n to the word X (plus_one of test/tallytool.c, mod n). */
static void plus_one(U256 *x) {
  Fe a;
  Fe one;
  Fe sum;
  fe_from_u256(&a, x, &SECP_FN);
  fe_from_u64(&one, 1u);
  fe_add(&sum, &a, &one, &SECP_FN);
  fe_to_u256(x, &sum);
}

/* 1 when GOT is WANT (a DkgResult or a QUAL bit set). */
static int int_row(const char *name, int got, int want) {
  if (got == want)
    return 1;
  fprintf(stderr, "FAIL frost %s: code %d, want %d\n", name, got, want);
  return 0;
}

/* A scalar word 1 + r passes the Feldman check just like 1. The reshare
   must reduce that word when receiving a share and when dealing an old
   share, as dkg_share already does. Exercise both supported orders. */
static int reshare_scalar_rows(const DkgCurve *curve) {
  static const uint32_t quorum[1] = {1u};
  DkgDealing dealing;
  DkgDealing again;
  ThrShare old;
  ThrShare fresh;
  U256 table[1];
  U256 again_table[1];
  U256 modulus;
  U256 alias;
  U256 seed;
  U256 ctx;
  Fe order;
  uint32_t qual = 0;
  int ok = 1;
  memcpy(order.w, curve->order->w, sizeof order.w);
  fe_to_u256(&modulus, &order);
  u256_from_u64(&old.s, 1u);
  u256_add(&alias, &old.s, &modulus);
  old.x = 1u;
  curve->gen(&old.key);
  u256_from_u64(&seed, 42u);
  u256_from_u64(&ctx, 7u);
  ok &= int_row("scalar alias deal",
                dkg_reshare_deal(curve, &dealing, table, &seed, &old, quorum, 1u, 1u, 1u, &ctx), DKG_OK);
  table[0] = alias;
  ok &= int_row("scalar alias qualifies",
                dkg_reshare_qual(curve, &qual, &dealing, table, &old.key, quorum, 1u, 1u, 1u, 1u, &ctx), DKG_OK);
  ok &= int_row("scalar alias share", dkg_reshare_share(curve, &fresh, qual, table, quorum, 1u, 1u, 1u), DKG_OK);
  ok &= true_row("scalar alias secret", memcmp(&fresh.s, &old.s, sizeof old.s) == 0);
  ok &= true_row("scalar alias public key", curve->eq(&fresh.key, &old.key));
  old.s = alias;
  ok &= int_row("old scalar alias deal",
                dkg_reshare_deal(curve, &again, again_table, &seed, &old, quorum, 1u, 1u, 1u, &ctx), DKG_OK);
  ok &= true_row("old scalar alias constant", curve->eq(&again.c[0], &dealing.c[0]));
  ok &= true_row("old scalar alias share", memcmp(again_table, &fresh.s, sizeof fresh.s) == 0);
  return ok;
}

/* The FROST signature (RFC 9591 sections 5.1 to 5.3) of MSG by the COUNT
   DKG members IDS, checked under PK (App. B). *STEPS = 1 when each step
   before the check gives FROST_OK. */
static FrostResult sign_by(int *steps, const ThrShare share[], const G1 *pk, const uint32_t ids[], size_t count) {
  static const unsigned char msg[] = "quorum-lang DKG key";
  unsigned char hiding[32];
  unsigned char binding[32];
  unsigned char sig[FROST_SIG_BYTES] = {0};
  FrostNonce nonce[THR_N_MAX];
  FrostCommit list[THR_N_MAX];
  Fe secret[THR_N_MAX];
  Fe z[THR_N_MAX];
  size_t k;
  int ok = 1;
  for (k = 0; k < count; k++) {
    memset(hiding, (int)ids[k], sizeof hiding);
    memset(binding, (int)(ids[k] + 16u), sizeof binding);
    ok &= fe_from_u256(&secret[k], &share[ids[k] - 1u].s, &SECP_FN);
    ok &= frost_commit(&nonce[k], &list[k], ids[k], &secret[k], hiding, binding) == FROST_OK;
  }
  for (k = 0; k < count; k++)
    ok &= frost_sign(&z[k], ids[k], &secret[k], &nonce[k], pk, list, count, msg, sizeof msg - 1u) == FROST_OK;
  ok &= frost_aggregate(sig, z, pk, list, count, msg, sizeof msg - 1u) == FROST_OK;
  *steps = ok;
  return frost_verify(sig, pk, msg, sizeof msg - 1u);
}

/* 1 when the DKG members IDS sign with FROST and the signature verifies
   under PK (WANT 1) or does not verify (WANT 0). */
static int sign_row(const char *name, const ThrShare share[], const G1 *pk, const uint32_t ids[], size_t count,
                    int want) {
  int steps = 0;
  FrostResult res = sign_by(&steps, share, pk, ids, count);
  return true_row(name, steps && (res == FROST_OK) == want);
}

#define DKG_T 2u
#define DKG_N 3u

/* The signer and quorum lists of the DKG and reshare rows. */
static const uint32_t IDS_1[1] = {1u};
static const uint32_t IDS_12[2] = {1u, 2u};
static const uint32_t IDS_13[2] = {1u, 3u};
static const uint32_t IDS_23[2] = {2u, 3u};
static const uint32_t IDS_123[3] = {1u, 2u, 3u};
static const uint32_t IDS_234[3] = {2u, 3u, 4u};

#define RS_Q 2u
#define RS_T 3u
#define RS_N 4u

/* The secp256k1 reshare rows (O97). The old committee is the good DKG of
   dkg_rows: t 2 of n 3, the dealings OLD, the shares SHARE, the key PK and
   SECRET = the sum of the a_{i,0}. Q = {1, 3} deals the key again to the
   new t 3 of n 4 under the context 8, the dealer i with the seed 200 + i.
   Source: O97. No RFC gives a reshare vector: the rows C'_{1,0}, z'_1 and
   sk'_1 have the second source W/s7-dkg-check.py (W/s7-dkg-values.txt). */
static int reshare_rows(const DkgDealing old[], const ThrShare share[], const G1 *pk, const Fe *secret) {
  const DkgCurve *curve = &DKG_SECP256K1;
  DkgDealing dealings[RS_Q];
  U256 table[RS_Q * RS_N];
  G1 keys[RS_Q];
  ThrShare fresh[RS_N];
  U256 ctx;
  U256 seed;
  Fe lam;
  Fe s;
  Fe tmp;
  Fe acc;
  G1 sum;
  G1 key;
  uint32_t qual = 0;
  uint32_t k;
  int ok = 1;
  u256_from_u64(&ctx, 8u);
  for (k = 0; k < RS_Q; k++) {
    ok &= int_row("reshare old key", dkg_key(curve, &keys[k], 14u, old, DKG_T, IDS_13[k], DKG_N), DKG_OK);
    u256_from_u64(&seed, 200u + IDS_13[k]);
    ok &= int_row("reshare deal",
                  dkg_reshare_deal(curve, &dealings[k], &table[k * RS_N], &seed, &share[IDS_13[k] - 1u], IDS_13, RS_Q,
                                   RS_T, RS_N, &ctx),
                  DKG_OK);
  }
  ok &= int_row("reshare good",
                dkg_reshare_qual(curve, &qual, dealings, table, keys, IDS_13, RS_Q, DKG_T, RS_T, RS_N, &ctx), DKG_OK);
  ok &= int_row("reshare good QUAL'", (int)qual, 10);
  ok &= enc_row("reshare C'_{1,0}", &dealings[0].c[0], "0225ab8a28919cf93f023ab38179382fc6d530533d1be07ab89ac0e955f7d7fca3");
  fe_from_u256(&tmp, &dealings[0].z, &SECP_FN);
  ok &= fe_row("reshare z'_1", &tmp, "838ad4c3493806cdaddfb00e5def34948a043998ac256fec406b8676f7e4c066");
  /* (1) The new PK = the sum of C'_{i,0} = the old PK. */
  curve->add(&sum, &dealings[0].c[0], &dealings[1].c[0]);
  ok &= true_row("reshare new PK = old PK", secp_eq(&sum, pk));
  for (k = 1u; k <= RS_N; k++) {
    ok &= int_row("reshare share", dkg_reshare_share(curve, &fresh[k - 1u], qual, table, IDS_13, RS_Q, k, RS_N),
                  DKG_OK);
    ok &= int_row("reshare key", dkg_reshare_key(curve, &key, qual, dealings, IDS_13, RS_Q, RS_T, k, RS_N), DKG_OK);
    ok &= true_row("reshare PK'_j = sk'_j G", secp_eq(&key, &fresh[k - 1u].key));
  }
  fe_from_u256(&tmp, &fresh[0].s, &SECP_FN);
  ok &= fe_row("reshare sk'_1", &tmp, "5496d394d17480cb37628115ef342c072e489fb63698ae8efdd1ba00fd0f8559");
  /* (2) The old {1, 2} and (3) the new {2, 3, 4} sign under PK. (5) The
     new {1, 2} is below t' = 3: the signature does not verify. */
  ok &= sign_row("reshare old FROST {1, 2}", share, pk, IDS_12, 2u, 1);
  ok &= sign_row("reshare new FROST {2, 3, 4}", fresh, pk, IDS_234, 3u, 1);
  ok &= sign_row("reshare new FROST {1, 2} fails", fresh, pk, IDS_12, 2u, 0);
  /* (4) The Lagrange sum of the new shares {1, 2, 3} = the old secret. */
  fe_from_u64(&acc, 0u);
  for (k = 0; k < 3u; k++) {
    ok &= int_row("reshare lagrange", frost_lagrange(&lam, IDS_123[k], IDS_123, 3u), FROST_OK);
    fe_from_u256(&s, &fresh[IDS_123[k] - 1u].s, &SECP_FN);
    fe_mul(&tmp, &lam, &s, &SECP_FN);
    fe_add(&s, &acc, &tmp, &SECP_FN);
    acc = s;
  }
  ok &= true_row("reshare Lagrange {1, 2, 3} = secret", fe_eq(&acc, secret));
  /* (6) The dealer 1 deals g_1(0) = s_1 (the quorum {1}: lambda = 1):
     DKG_BAD_RESHARE, QUAL' = {3}, and no new share. */
  u256_from_u64(&seed, 201u);
  ok &= int_row("reshare no lambda deal",
                dkg_reshare_deal(curve, &dealings[0], table, &seed, &share[0], IDS_1, 1u, RS_T, RS_N, &ctx), DKG_OK);
  ok &= int_row("reshare no lambda",
                dkg_reshare_qual(curve, &qual, dealings, table, keys, IDS_13, RS_Q, DKG_T, RS_T, RS_N, &ctx),
                DKG_BAD_RESHARE);
  ok &= int_row("reshare no lambda QUAL'", (int)qual, 8);
  ok &= int_row("reshare no lambda share", dkg_reshare_share(curve, &fresh[0], qual, table, IDS_13, RS_Q, 1u, RS_N),
                DKG_TOO_FEW);
  /* Q = {1} is below the old t 2, and the old member 2 is not in Q. */
  ok &= int_row("reshare Q below t",
                dkg_reshare_qual(curve, &qual, dealings, table, keys, IDS_1, 1u, DKG_T, RS_T, RS_N, &ctx), DKG_TOO_FEW);
  ok &= int_row("reshare dealer not in Q",
                dkg_reshare_deal(curve, &dealings[0], table, &seed, &share[1], IDS_13, RS_Q, RS_T, RS_N, &ctx),
                DKG_BAD_INDEX);
  return ok;
}

/* The secp256k1 DKG rows (O96): the S6 five DKG fixtures of test/tallytool.c
   on DKG_SECP256K1, and the DKG key signs with FROST. Source: O96. No RFC
   gives a DKG vector: the rows PK, C_{1,0}, z_1 and sk_1 have the second
   source W/s7-dkg-check.py (W/s7-dkg-values.txt). */
static int dkg_rows(void) {
  const DkgCurve *curve = &DKG_SECP256K1;
  DkgDealing dealings[DKG_N];
  DkgDealing bad[DKG_N];
  U256 table[DKG_N * DKG_N];
  U256 forged[DKG_N * DKG_N];
  ThrShare share[DKG_N];
  ThrShare other;
  U256 ctx;
  U256 seed;
  U256 w;
  Fe a0;
  Fe sum;
  Fe tmp;
  G1 pk;
  G1 key;
  G1 want;
  uint32_t qual = 0;
  uint32_t i;
  int ok = 1;
  /* (1) The good dealing: t 2 of n 3 under the context 7, the dealer i with
     the seed 100 + i (as tallytool deal_good). QUAL = {1, 2, 3}, PK = (the
     sum of a_{i,0}) G, PK_j = sk_j G. */
  u256_from_u64(&ctx, 7u);
  fe_from_u64(&sum, 0u);
  for (i = 1u; i <= DKG_N; i++) {
    u256_from_u64(&seed, 100u + i);
    ok &= int_row("dkg secp deal",
                  dkg_deal(curve, &dealings[i - 1u], &table[(i - 1u) * DKG_N], &seed, i, DKG_T, DKG_N, &ctx), DKG_OK);
    ok &= true_row("dkg secp proof", dkg_check_proof(curve, &dealings[i - 1u], i, DKG_T, &ctx));
    curve->nonce(&w, &seed, 0u);
    fe_from_u256(&a0, &w, &SECP_FN);
    fe_add(&tmp, &sum, &a0, &SECP_FN);
    sum = tmp;
  }
  ok &= int_row("dkg secp good", dkg_qual(curve, &qual, dealings, table, DKG_T, DKG_N, &ctx), DKG_OK);
  ok &= int_row("dkg secp good QUAL", (int)qual, 14);
  dkg_public(curve, &pk, qual, dealings, DKG_N);
  gen_mul(&want, &sum);
  ok &= true_row("dkg secp PK = (sum a_{i,0}) G", secp_eq(&pk, &want));
  ok &= enc_row("dkg secp PK", &pk, "03ad712e69b0b88251d7354c215fe55d535ed7b78121c146408ac7ed72b2ff9a3e");
  ok &= enc_row("dkg secp C_{1,0}", &dealings[0].c[0], "03a6b84ddd28cf2b7a6f2d66c78db190812d42bbecf4a2024c1de1508f3183b8f8");
  fe_from_u256(&tmp, &dealings[0].z, &SECP_FN);
  ok &= fe_row("dkg secp z_1", &tmp, "f74ac4d1f888edcfe902040d1a085a4092f25ff28d6c08da36e0868b18824a5e");
  for (i = 1u; i <= DKG_N; i++) {
    ok &= int_row("dkg secp share", dkg_share(curve, &share[i - 1u], qual, table, i, DKG_N), DKG_OK);
    ok &= int_row("dkg secp key", dkg_key(curve, &key, qual, dealings, DKG_T, i, DKG_N), DKG_OK);
    ok &= true_row("dkg secp PK_j = sk_j G", secp_eq(&key, &share[i - 1u].key));
  }
  fe_from_u256(&tmp, &share[0].s, &SECP_FN);
  ok &= fe_row("dkg secp sk_1", &tmp, "62ba331e4506cbe1b545c7753c7a7abdc34804fe787bfb52a68c850990cd4cb9");
  /* The DKG key signs: FROST by {1, 2} and by {2, 3} verifies under PK. */
  ok &= sign_row("dkg secp FROST {1, 2}", share, &pk, IDS_12, 2u, 1);
  ok &= sign_row("dkg secp FROST {2, 3}", share, &pk, IDS_23, 2u, 1);
  ok &= reshare_rows(dealings, share, &pk, &sum);
  /* (2) The dealer 2 sends f_2(3) + 1 to the member 3: QUAL = {1, 3}. */
  memcpy(forged, table, sizeof forged);
  plus_one(&forged[DKG_N + 2u]);
  ok &= int_row("dkg secp bad share", dkg_qual(curve, &qual, dealings, forged, DKG_T, DKG_N, &ctx), DKG_BAD_SHARE);
  ok &= int_row("dkg secp bad share QUAL", (int)qual, 10);
  /* (3) The dealer 1 with z + 1: QUAL = {2, 3}. */
  memcpy(bad, dealings, sizeof bad);
  plus_one(&bad[0].z);
  ok &= int_row("dkg secp bad proof", dkg_qual(curve, &qual, bad, table, DKG_T, DKG_N, &ctx), DKG_BAD_PROOF);
  ok &= int_row("dkg secp bad proof QUAL", (int)qual, 12);
  /* (4) The member 0 and the member n + 1. */
  ok &= int_row("dkg secp member 0", dkg_share(curve, &other, 14u, table, 0u, DKG_N), DKG_BAD_INDEX);
  ok &= int_row("dkg secp member n + 1", dkg_share(curve, &other, 14u, table, DKG_N + 1u, DKG_N), DKG_BAD_INDEX);
  /* (5) Each dealing is bad: QUAL is empty. */
  plus_one(&bad[1].z);
  plus_one(&bad[2].z);
  ok &= int_row("dkg secp too few", dkg_qual(curve, &qual, bad, table, DKG_T, DKG_N, &ctx), DKG_TOO_FEW);
  ok &= int_row("dkg secp too few QUAL", (int)qual, 0);
  return ok;
}

/* The rep lines of one key (O98): for each set S of the members 1 to N, the
   members of S sign with FROST under PK, and the line `denote NAME B1 ... BN
   => V` has Bi = 1 when i is in S, V = 1 when the signature verifies. The
   empty set has no signer: V = 0. 1 when each step before the check gives
   FROST_OK. */
static int rep_lines(const char *name, const ThrShare share[], const G1 *pk, uint32_t n) {
  uint32_t ids[THR_N_MAX];
  uint32_t set;
  uint32_t k;
  int ok = 1;
  for (set = 0; set < (1u << n); set++) {
    size_t count = 0;
    int steps = 1;
    int v = 0;
    for (k = 1u; k <= n; k++)
      if (set & (1u << (k - 1u))) ids[count++] = k;
    if (count > 0) v = sign_by(&steps, share, pk, ids, count) == FROST_OK;
    ok &= steps;
    printf("denote %s", name);
    for (k = 0; k < n; k++)
      printf(" %u", (unsigned)((set >> k) & 1u));
    printf(" => %d\n", v);
  }
  return ok;
}

/* `frosttool rep` (O98): the representation map of `Authorized`. The good DKG
   of dkg_rows (t 2 of n 3, the context 7, the seeds 100 + i) gives the lines
   of denAuth3. The reshare of reshare_rows (Q = {1, 3} to t' 3 of n' 4, the
   context 8, the seeds 200 + i) gives the lines of denAuth4 under the same
   PK. test/gate.sh gives each line to `langc eval`. */
static int rep_mode(void) {
  const DkgCurve *curve = &DKG_SECP256K1;
  DkgDealing dealings[DKG_N];
  DkgDealing redeal[RS_Q];
  U256 table[DKG_N * DKG_N];
  U256 retable[RS_Q * RS_N];
  ThrShare share[DKG_N];
  ThrShare fresh[RS_N];
  G1 keys[RS_Q];
  U256 ctx;
  U256 seed;
  G1 pk;
  uint32_t qual = 0;
  uint32_t requal = 0;
  uint32_t k;
  int ok = 1;
  u256_from_u64(&ctx, 7u);
  for (k = 1u; k <= DKG_N; k++) {
    u256_from_u64(&seed, 100u + k);
    ok &= dkg_deal(curve, &dealings[k - 1u], &table[(k - 1u) * DKG_N], &seed, k, DKG_T, DKG_N, &ctx) == DKG_OK;
  }
  ok &= dkg_qual(curve, &qual, dealings, table, DKG_T, DKG_N, &ctx) == DKG_OK;
  dkg_public(curve, &pk, qual, dealings, DKG_N);
  for (k = 1u; k <= DKG_N; k++)
    ok &= dkg_share(curve, &share[k - 1u], qual, table, k, DKG_N) == DKG_OK;
  ok &= rep_lines("denAuth3", share, &pk, DKG_N);
  u256_from_u64(&ctx, 8u);
  for (k = 0; k < RS_Q; k++) {
    ok &= dkg_key(curve, &keys[k], qual, dealings, DKG_T, IDS_13[k], DKG_N) == DKG_OK;
    u256_from_u64(&seed, 200u + IDS_13[k]);
    ok &= dkg_reshare_deal(curve, &redeal[k], &retable[k * RS_N], &seed, &share[IDS_13[k] - 1u], IDS_13, RS_Q, RS_T,
                           RS_N, &ctx) == DKG_OK;
  }
  ok &= dkg_reshare_qual(curve, &requal, redeal, retable, keys, IDS_13, RS_Q, DKG_T, RS_T, RS_N, &ctx) == DKG_OK;
  for (k = 1u; k <= RS_N; k++)
    ok &= dkg_reshare_share(curve, &fresh[k - 1u], requal, retable, IDS_13, RS_Q, k, RS_N) == DKG_OK;
  ok &= rep_lines("denAuth4", fresh, &pk, RS_N);
  if (!ok) fputs("frosttool rep: a DKG, reshare or FROST step failed\n", stderr);
  return ok;
}

int main(int argc, char **argv) {
  unsigned char msg[517];
  size_t size;
  int ok;
  if (argc == 2 && strcmp(argv[1], "rep") == 0) return rep_mode() ? 0 : 1;
  if (argc != 1) {
    fputs("usage: frosttool [rep]\n", stderr);
    return 2;
  }
  memset(million, 'a', sizeof million);
  /* FIPS 180-2 App. B.1 to B.3 (FIPS 180-4 points to the same values in
     the NIST CSRC example file SHA256.pdf) and the CAVP
     SHA256ShortMsg.rsp row Len = 0. Second source: cairn-lang 6748510
     test/shatool.c:36 to :43, and `shasum -a 256` on the host
     (W/S7-PROGRESS.md session 2). */
  ok = sha_row("sha256 empty", (const unsigned char *)"", 0,
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  ok &= sha_row("sha256 abc", (const unsigned char *)"abc", 3u,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ok &= sha_row("sha256 448-bit message", (const unsigned char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56u,
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  ok &= sha_row("sha256 one million a", million, sizeof million,
                 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  /* RFC 9380 App. K.1, expand_message_xmd(SHA-256), DST K1_DST: the 5
     msgs at len_in_bytes 0x20 and 0x80. Copy: W/vectors/rfc9380-k1.txt.
     Second source: W/s7-xmd-check.py (Python hashlib, from the section
     5.3.1 steps), 10 of 10 equal. */
  size = 0;
  ok &= xmd_row("xmd empty 0x20", msg, size, 32u,
                "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
  size = repeat_msg(msg, "abc", 0, 0);
  ok &= xmd_row("xmd abc 0x20", msg, size, 32u,
                "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615");
  size = repeat_msg(msg, "abcdef0123456789", 0, 0);
  ok &= xmd_row("xmd abcdef0123456789 0x20", msg, size, 32u,
                "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1");
  size = repeat_msg(msg, "q128_", 'q', 128u);
  ok &= xmd_row("xmd q128 0x20", msg, size, 32u,
                "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9");
  size = repeat_msg(msg, "a512_", 'a', 512u);
  ok &= xmd_row("xmd a512 0x20", msg, size, 32u,
                "4623227bcc01293b8c130bf771da8c298dede7383243dc0993d2d94823958c4c");
  size = 0;
  ok &= xmd_row("xmd empty 0x80", msg, size, 128u,
                "af84c27ccfd45d41914fdff5df25293e221afc53d8ad2ac06d5e3e29485dadbe"
                "e0d121587713a3e0dd4d5e69e93eb7cd4f5df4cd103e188cf60cb02edc3edf18"
                "eda8576c412b18ffb658e3dd6ec849469b979d444cf7b26911a08e63cf31f9dc"
                "c541708d3491184472c2c29bb749d4286b004ceb5ee6b9a7fa5b646c993f0ced");
  size = repeat_msg(msg, "abc", 0, 0);
  ok &= xmd_row("xmd abc 0x80", msg, size, 128u,
                "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a"
                "647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635"
                "bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00"
                "058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40");
  size = repeat_msg(msg, "abcdef0123456789", 0, 0);
  ok &= xmd_row("xmd abcdef0123456789 0x80", msg, size, 128u,
                "ef904a29bffc4cf9ee82832451c946ac3c8f8058ae97d8d629831a74c6572bd9"
                "ebd0df635cd1f208e2038e760c4994984ce73f0d55ea9f22af83ba4734569d4b"
                "c95e18350f740c07eef653cbb9f87910d833751825f0ebefa1abe5420bb52be1"
                "4cf489b37fe1a72f7de2d10be453b2c9d9eb20c7e3f6edc5a60629178d9478df");
  size = repeat_msg(msg, "q128_", 'q', 128u);
  ok &= xmd_row("xmd q128 0x80", msg, size, 128u,
                "80be107d0884f0d881bb460322f0443d38bd222db8bd0b0a5312a6fedb49c1bb"
                "d88fd75d8b9a09486c60123dfa1d73c1cc3169761b17476d3c6b7cbbd727acd0"
                "e2c942f4dd96ae3da5de368d26b32286e32de7e5a8cb2949f866a0b80c58116b"
                "29fa7fabb3ea7d520ee603e0c25bcaf0b9a5e92ec6a1fe4e0391d1cdbce8c68a");
  size = repeat_msg(msg, "a512_", 'a', 512u);
  ok &= xmd_row("xmd a512 0x80", msg, size, 128u,
                "546aff5444b5b79aa6148bd81728704c32decb73a3ba76e9e75885cad9def1d0"
                "6d6792f8a7d12794e90efed817d96920d728896a4510864370c207f99bd4a608"
                "ea121700ef01ed879745ee3e4ceef777eda6d9e5e38b90c86ea6fb0b36504ba4"
                "a45d22e86f6db5dd43d98a294bebb9125d5b794e9d2a81181066eb954966a487");
  /* O92 refusals: LEN 0, LEN above 255 x 32, DST_LEN 0 and 256, MSG_LEN
     above XMD_MSG_MAX. Source: RFC 9380 sections 3.1 and 5.3.1 step 2,
     and O91. */
  ok &= refuse_row("xmd refuse len 0", 0, 3u, 8u);
  ok &= refuse_row("xmd refuse len 8161", XMD_LEN_MAX + 1u, 3u, 8u);
  ok &= refuse_row("xmd refuse dst 0", 32u, 3u, 0);
  ok &= refuse_row("xmd refuse dst 256", 32u, 3u, XMD_DST_MAX + 1u);
  ok &= refuse_row("xmd refuse msg 1025", 32u, XMD_MSG_MAX + 1u, 8u);
  ok &= secp_rows();
  ok &= frost_rows();
  ok &= invalid_point_rows();
  ok &= reshare_scalar_rows(&DKG_BN254);
  ok &= reshare_scalar_rows(&DKG_SECP256K1);
  ok &= dkg_rows();
  if (ok) puts("frost regressions: passed");
  return ok ? 0 : 1;
}
