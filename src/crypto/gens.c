/* NEW (quorum-lang S11 H2): the try-and-increment generators. */
#include "crypto/gens.h"

#include <string.h>

#include "crypto/secq256k1.h"
#include "crypto/sha256.h"

static const char GENS_TAG[] = "quorum-lang/ivc/gens/v1";

/* The name and the base field of CURVE. */
static const char *curve_name(GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return "secp256k1";
  case GENS_SECQ256K1:
    return "secq256k1";
  }
  return "";
}

static const Modulus *curve_field(GensCurve curve) {
  switch (curve) {
  case GENS_SECP256K1:
    return &SECP_FP;
  case GENS_SECQ256K1:
    return &SECQ_FB;
  }
  return &SECP_FP;
}

static uint32_t put_be32(unsigned char *out, uint32_t v) {
  out[0] = (unsigned char)(v >> 24);
  out[1] = (unsigned char)(v >> 16);
  out[2] = (unsigned char)(v >> 8);
  out[3] = (unsigned char)v;
  return 4u;
}

/* The point with x = X and the even y on y^2 = x^3 + 7 over F. Returns 1,
   or 0 when x^3 + 7 is not a square. */
static int even_lift(G1 *out, const Fe *x, const Modulus *f) {
  Fe rhs;
  Fe y;
  Fe seven;
  U256 w;
  fe_from_u64(&seven, 7);
  fe_mul(&rhs, x, x, f);
  fe_mul(&rhs, &rhs, x, f);
  fe_add(&rhs, &rhs, &seven, f);
  if (!fe_sqrt(&y, &rhs, f))
    return 0;
  fe_to_u256(&w, &y);
  if ((w.limb[0] & 1u) != 0u)
    fe_neg(&y, &y, f);
  out->x = *x;
  out->y = y;
  return 1;
}

void gens_point(G1 *out, GensCurve curve, uint32_t index) {
  const char *name = curve_name(curve);
  const Modulus *f = curve_field(curve);
  size_t tag_size = sizeof GENS_TAG - 1u;
  size_t name_size = strlen(name);
  unsigned char msg[sizeof GENS_TAG + 16u + 8u];
  unsigned char digest[32];
  size_t size = 0;
  size_t at;
  uint32_t c = 0;
  U256 x;
  Fe fx;
  int found = 0;
  memcpy(msg, GENS_TAG, tag_size);
  size = tag_size;
  msg[size++] = 0u;
  memcpy(msg + size, name, name_size);
  size += name_size;
  msg[size++] = 0u;
  size += put_be32(msg + size, index);
  at = size;
  size += 4u;
  while (!found) {
    (void)put_be32(msg + at, c);
    sha256(msg, size, digest);
    u256_from_be(&x, digest);
    found = fe_from_u256(&fx, &x, f) && even_lift(out, &fx, f);
    c++;
  }
}
