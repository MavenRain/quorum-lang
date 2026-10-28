/* Host imports are deterministic stubs so these tests isolate whether
   the compiler preserves deferred traps at the import boundary. */
#include <stdio.h>
#include "hostflags.h"
#include "wasm-rt-exceptions.h"
#include "wasm-rt-impl.h"

struct w2c_q { int unused; };

u64 w2c_q_q_hash2(struct w2c_q *q, u64 out, u64 a, u64 b) {
  (void)q; (void)out; (void)a; (void)b;
  return 0;
}
u64 w2c_q_q_frost_verify(struct w2c_q *q, u64 pk, u64 sig, u64 msg) {
  (void)q; (void)pk; (void)sig; (void)msg;
  return 0;
}
u64 w2c_q_q_ballot_verify(struct w2c_q *q, u64 proof, u64 pk, u64 ct, u64 ctx, u64 j) {
  (void)q; (void)proof; (void)pk; (void)ct; (void)ctx; (void)j;
  return 0;
}
u64 w2c_q_q_tally_add(struct w2c_q *q, u64 out, u64 a, u64 b, u64 k) {
  (void)q; (void)out; (void)a; (void)b; (void)k;
  return 0;
}
u64 w2c_q_q_partial_verify(struct w2c_q *q, u64 part, u64 key, u64 ct) {
  (void)q; (void)part; (void)key; (void)ct;
  return 0;
}
u64 w2c_q_q_combine(struct w2c_q *q, u64 out, u64 parts, u64 k, u64 keys, u64 t, u64 n, u64 ct, u64 bits) {
  (void)q; (void)out; (void)parts; (void)k; (void)keys; (void)t; (void)n; (void)ct; (void)bits;
  return 0;
}

typedef u64 (*EntryFn)(w2c_hostflags *, u64);

static int check(w2c_hostflags *inst, EntryFn fn, u64 arg, int trap) {
  wasm_rt_trap_t code = wasm_rt_impl_try();
  if (code != WASM_RT_TRAP_NONE)
    return trap && code == WASM_RT_TRAP_UNREACHABLE;
  return fn(inst, arg) == 0 && !trap;
}

int main(void) {
  static EntryFn const entries[] = {w2c_hostflags_hashFlag, w2c_hostflags_frostFlag,
      w2c_hostflags_ballotFlag, w2c_hostflags_tallyFlag, w2c_hostflags_partialFlag,
      w2c_hostflags_partsFlag, w2c_hostflags_keysFlag, w2c_hostflags_scalarFlag};
  w2c_hostflags inst;
  struct w2c_q q = {0};
  unsigned i;
  int ok = 1;
  wasm_rt_init();
  wasm2c_hostflags_instantiate(&inst, &q);
  for (i = 0; i < sizeof entries / sizeof entries[0]; i++) {
    if (!check(&inst, entries[i], 0, 0) || !check(&inst, entries[i], UINT64_MAX, 1)) {
      fprintf(stderr, "FAIL host flags: entry %u\n", i);
      ok = 0;
    }
  }
  ok &= check(&inst, w2c_hostflags_unusedKey, UINT64_MAX, 0);
  wasm2c_hostflags_free(&inst);
  wasm_rt_free();
  if (ok) puts("host flag regressions: passed");
  return ok ? 0 : 1;
}
