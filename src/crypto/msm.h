/* NEW (quorum-lang S11 H2, O157): the multi-scalar multiplication of the
   IVC commitments. The sum of k_i P_i over N points, by the bucket method of
   Pippenger in Jacobian form (EcJac of crypto/bn254.h), on any curve
   y^2 = x^3 + b over any field F (a = 0).

   Each scalar has 256 bits, cut into windows of c bits from the top. In
   each window, point i goes into the bucket of its digit d (1 to 2^c - 1).
   The running sum of the buckets from the top bucket down, added up, gives
   the sum of d times bucket d. The result of a window goes into the total,
   which doubles c times before the next window. The caller gives the
   2^c - 1 buckets (msm_buckets), so this module allocates no memory. */
#ifndef LANG_CRYPTO_MSM_H
#define LANG_CRYPTO_MSM_H

#include <stddef.h>

#include "crypto/bn254.h"
#include "crypto/u256.h"

#define MSM_WINDOW_MAX 16u

/* The window width c for N points: floor(log2 N) minus 3, from 1 to
   MSM_WINDOW_MAX. The cost is about (256 / c) (N + 2^(c + 1)) additions;
   this c is near the least cost from N = 2^4 to N = 2^19. */
unsigned msm_window(size_t n);
/* The number of buckets for N points: 2^c - 1. */
size_t msm_buckets(size_t n);
/* OUT = the sum of K[i] P[i] for i below N over F, with all 256 bits of
   each K[i] (no reduction). Each P[i] is on the curve or (0, 0). BUCKETS
   holds COUNT points of work space. Returns 1, or 0 when COUNT is less than
   msm_buckets(N) (OUT does not change then). */
int msm(G1 *out, const G1 *p, const U256 *k, size_t n, EcJac *buckets, size_t count,
        const Modulus *f);

#endif
