/* The type checker, the refusals R1-R4 and the eval command. SHARED by the
   tcc kits. */
#ifndef LANG_FRONT_CHECK_H
#define LANG_FRONT_CHECK_H

#include "front/core.h"

#define ENTRY_PARAMS_MAX 16u

/* The kind of an entry parameter. An INPUT parameter (O109 (i)) has a list
   family type (check.c input_family). The host writes its blocks in memory
   and gives the address. */
typedef enum {
  ENTRY_PARAM_NAT,
  ENTRY_PARAM_FLAG,
  ENTRY_PARAM_INPUT
} EntryParam;

/* An entry: a program definition of type Nat, Flag, or a function of Nat,
   Flag and input arguments to a Nat or Flag result. */
typedef struct {
  uint32_t param_count;
  EntryParam param_kind[ENTRY_PARAMS_MAX];
  uint32_t param_family[ENTRY_PARAMS_MAX]; /* INPUT: the family */
  int result_flag;
} Entry;

/* Checks the domain declarations, then the program, into M. Returns 1, or 0
   after a diagnostic. */
int check_program(Arena *arena, const DeclList *decls, Machine *m, Diag *diag);
/* Returns 1 when TYPE is the type of an entry. */
int entry_of(Machine *m, const Value *type, Entry *out);
/* Evaluates the definition NAME on ARGS and prints the result. Returns 0, 1
   after a diagnostic, or 2 after an EVAL_ARGS diagnostic. */
int eval_command(Machine *m, const char *name, char *const *args, int arg_count, FILE *out, FILE *err);

#endif
