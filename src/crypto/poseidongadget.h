/* NEW (quorum-lang S11 H3a P2): the Poseidon permutation of poseidon.c as
   rows of a rank-1 constraint system (r1cs.h), over the field of the
   system (F_p or F_n).

   Between two rounds, each state element is a linear combination of at
   most POSEIDON_WIDTH variables and a constant. An S-box puts this linear
   combination directly in its rows: x x = s, s s = q, q x = y (3 rows and
   3 new variables). Thus the linear layers of the full rounds add no rows.
   In a partial round, the two elements that skip the S-box each get a new
   variable (1 row each). Without these rows, each partial round adds one
   variable to each linear combination, and the number of terms grows with
   the square of the number of partial rounds. After the last round, 1 row
   for each element gives the output variables.

   Count: 81 S-boxes (24 full, 57 partial) of 3 rows, 2 rows for each of
   the 57 partial rounds, and 3 output rows: 243 + 114 + 3 = 360 rows and
   360 new variables. With the 3 input variables and the constant, the
   system has 364 variables and 2139 terms (test/ivcr1cs.c, the row
   `poseidon sizes`). A new variable for each element after each linear
   layer gives 438 rows. */
#ifndef LANG_CRYPTO_POSEIDONGADGET_H
#define LANG_CRYPTO_POSEIDONGADGET_H

#include <stdint.h>

#include "crypto/poseidon.h"
#include "crypto/r1cs.h"

/* OUT[i] = element i of poseidon_perm of the state IN (variables of CS).
   P must be the parameters for the field of CS. */
void poseidon_gadget(R1cs *cs, uint32_t out[POSEIDON_WIDTH],
                     const uint32_t in[POSEIDON_WIDTH], const PoseidonParams *p);

#endif
