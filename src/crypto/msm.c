/* NEW (quorum-lang S11 H2, O157): see crypto/msm.h. */
#include <string.h>

#include "crypto/msm.h"

unsigned msm_window(size_t n) {
  unsigned lg = 0;
  size_t x;
  for (x = n; x > 1u; x >>= 1)
    lg++;
  if (lg <= 3u)
    return 1u;
  if (lg - 3u > MSM_WINDOW_MAX)
    return MSM_WINDOW_MAX;
  return lg - 3u;
}

size_t msm_buckets(size_t n) {
  return ((size_t)1 << msm_window(n)) - 1u;
}

/* The C bits of K from bit LO up, as a number. A bit above 255 is 0. */
static unsigned digit(const U256 *k, unsigned lo, unsigned c) {
  unsigned d = 0;
  unsigned i;
  for (i = c; i > 0; i--) {
    unsigned bit = lo + i - 1u;
    d <<= 1;
    if (bit < 256u)
      d |= (unsigned)((k->limb[bit / 64u] >> (bit % 64u)) & 1u);
  }
  return d;
}

int msm(G1 *out, const G1 *p, const U256 *k, size_t n, EcJac *buckets, size_t count,
        const Modulus *f) {
  unsigned c = msm_window(n);
  size_t used = msm_buckets(n);
  unsigned w;
  unsigned i;
  size_t j;
  size_t d;
  EcJac acc;
  EcJac run;
  EcJac sum;
  if (count < used)
    return 0;
  memset(&acc, 0, sizeof acc);
  for (w = (256u + c - 1u) / c; w > 0; w--) {
    for (i = 0; i < c; i++)
      ec0_jac_double(&acc, &acc, f);
    memset(buckets, 0, used * sizeof *buckets);
    for (j = 0; j < n; j++) {
      unsigned dj = digit(&k[j], (w - 1u) * c, c);
      if (dj != 0)
        ec0_jac_add_affine(&buckets[dj - 1u], &buckets[dj - 1u], &p[j], f);
    }
    memset(&run, 0, sizeof run);
    memset(&sum, 0, sizeof sum);
    /* Bucket sum: RUN is the sum of buckets D and up, SUM adds each RUN. */
    for (d = used; d > 0; d--) {
      ec0_jac_add(&run, &run, &buckets[d - 1u], f);
      ec0_jac_add(&sum, &sum, &run, f);
    }
    ec0_jac_add(&acc, &acc, &sum, f);
  }
  ec0_jac_affine(out, &acc, f);
  return 1;
}
