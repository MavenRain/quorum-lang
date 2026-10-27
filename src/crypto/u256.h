/* Source: intent-lang 79e1898 src/front/u256.h, without word_text and the WORD_ enum. */
/* 256-bit words for the core types U256 and Addr (kit slice K2).

   limb[0] holds the low 64 bits. An Addr uses the low 160 bits. The helpers
   use no __int128 (tcc has none) and no shift by 64 or more. */
#ifndef LANG_CRYPTO_U256_H
#define LANG_CRYPTO_U256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint64_t limb[4];
} U256;

/* Each operation returns 1, or 0 for a trap. OUT can be A or B. */
int u256_add(U256 *out, const U256 *a, const U256 *b); /* traps on an overflow */
int u256_sub(U256 *out, const U256 *a, const U256 *b); /* stops at 0, no trap */
int u256_mul(U256 *out, const U256 *a, const U256 *b); /* traps on an overflow */
int u256_div(U256 *out, const U256 *a, const U256 *b); /* floors, traps on 0 */
int u256_min(U256 *out, const U256 *a, const U256 *b); /* no trap */
/* -1, 0 or 1. */
int u256_cmp(const U256 *a, const U256 *b);
void u256_from_u64(U256 *out, uint64_t n);
/* X = X * MUL + ADD. Returns 0 on an overflow. */
int u256_scale_add(U256 *x, uint32_t mul, uint32_t add);

#endif
