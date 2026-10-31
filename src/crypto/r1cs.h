/* NEW (quorum-lang S11 H3a, Q-S11-8 (a)): a rank-1 constraint system over
   one prime field F (the caller gives F_p or F_n of the secp256k1 cycle) and
   the small gadgets of the IVC step circuit.

   The witness is the vector z. Variable 0 is the constant 1. Each row has
   three sparse linear combinations A, B and C of the variables, and holds
   when (A z) (B z) = (C z) in F. A row is a run of terms; each term gives
   its side (A, B or C), one variable and one coefficient.

   The caller gives all the storage (the witness, the row starts and the
   terms), so this module allocates no memory. The system counts each
   variable, row and term, and keeps only those that fit. A run with no
   storage (all capacities 0) thus gives the sizes (r1cs_size) for the real
   run. Values that do not fit read as 0 in such a run. A system with an
   item that did not fit is full, and r1cs_check rejects it. */
#ifndef LANG_CRYPTO_R1CS_H
#define LANG_CRYPTO_R1CS_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/bn254.h"

typedef enum { R1CS_A, R1CS_B, R1CS_C } R1csSide;

typedef struct {
  uint32_t var;
  R1csSide side;
  Fe coeff;
} R1csTerm;

typedef struct {
  size_t vars;  /* with variable 0 */
  size_t rows;
  size_t terms;
} R1csSize;

typedef struct {
  const Modulus *f;
  Fe *z;
  size_t *row;  /* the first term of each row */
  R1csTerm *term;
  R1csSize cap;
  R1csSize used;
} R1cs;

/* Starts an empty system over F with the storage of the caller. Variable 0
   gets the value 1. Any capacity can be 0 (a sizing run). */
void r1cs_init(R1cs *cs, const Modulus *f, Fe *z, size_t var_cap, size_t *row,
               size_t row_cap, R1csTerm *term, size_t term_cap);
/* The counts of the variables, rows and terms so far. */
void r1cs_size(R1csSize *out, const R1cs *cs);
/* 1 when a variable, a row or a term did not fit. */
int r1cs_full(const R1cs *cs);

/* A new variable with the value V. Returns its index. */
uint32_t r1cs_var(R1cs *cs, const Fe *v);
/* OUT = the value of variable VAR (0 when it is not stored). */
void r1cs_value(Fe *out, const R1cs *cs, uint32_t var);
/* Starts a new row. The terms that follow go into this row. */
void r1cs_row(R1cs *cs);
/* Adds C times VAR to one side of the current row. */
void r1cs_term(R1cs *cs, R1csSide side, uint32_t var, const Fe *c);
/* As r1cs_term, with a small signed coefficient. */
void r1cs_term_int(R1cs *cs, R1csSide side, uint32_t var, int32_t c);

/* Returns 1 when the system is not full, z_0 = 1, and each row holds.
   Otherwise returns 0 and sets *FAILED to the first row that does not
   hold, or to the row count when the system is full or z_0 is not 1.
   A term with a variable that is not in the system fails its row. */
int r1cs_check(const R1cs *cs, size_t *failed);

/* The gadgets. Each one makes its output variable from the values of its
   inputs, and adds the rows that make the output the only good value. */

/* B in {0, 1}: one row B * B = B. */
void r1cs_assert_bool(R1cs *cs, uint32_t b);
/* A new boolean variable with the value V (0 or 1): r1cs_var and
   r1cs_assert_bool. */
uint32_t r1cs_bool(R1cs *cs, const Fe *v);
/* OUT = X Y: one row. */
uint32_t r1cs_mul(R1cs *cs, uint32_t x, uint32_t y);
/* OUT = B ? X : Y for a boolean B: one row B (X - Y) = OUT - Y. */
uint32_t r1cs_select(R1cs *cs, uint32_t b, uint32_t x, uint32_t y);
/* OUT = A xor B for booleans A and B: one row (2 A) B = A + B - OUT. */
uint32_t r1cs_xor(R1cs *cs, uint32_t a, uint32_t b);
/* OUT = the sum of 2^i BIT[i] for i below N (N at most 255): one row
   (sum 2^i BIT[i]) * 1 = OUT. The bits must be boolean variables. */
uint32_t r1cs_pack(R1cs *cs, const uint32_t *bit, size_t n);

#endif
