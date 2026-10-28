/* A shim for TinyCC and the wasm2c output (O104, S8 probe P1). TCC has no
   __builtin_add_overflow, and the range checks of the wasm2c output use it.
   The Makefile includes this file (with -include) ONLY in the compile of
   build/replica.c. Do not include it in other files: the macOS SDK headers
   refuse the __has_builtin change. */
#ifndef QUORUM_W2C_TCC_H
#define QUORUM_W2C_TCC_H

#include <stdint.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include "wasm-rt.h"

static inline int w2c_tcc_add_overflow(uint64_t a, uint64_t b, uint64_t *r) {
  *r = a + b;
  return *r < a;
}

#define __builtin_add_overflow(a, b, r) w2c_tcc_add_overflow((a), (b), (r))
#undef __has_builtin
#define __has_builtin(x) 1

#endif
