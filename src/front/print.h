/* The canonical printer. SHARED by the tcc kits. `langc fmt` uses it. */
#ifndef LANG_FRONT_PRINT_H
#define LANG_FRONT_PRINT_H

#include "front/parser.h"

typedef struct {
  const char *text; /* NUL-terminated */
  size_t len;
} Printed;

/* Prints DECLS and the comments in TOKS in canonical form (docs/GRAMMAR.md).
   Returns 1, or 0 after an OOM diagnostic. */
int print_source(Arena *arena, const TokenList *toks, const DeclList *decls, Printed *out, Diag *diag);

#endif
