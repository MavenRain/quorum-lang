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
/* Prints the type of the global NAME of DECLS in canonical form (O119):
   the type of a definition or a postulate, the telescope of a family or
   a record, or the type of a constructor. OUT->text is NULL when DECLS
   has no global NAME. Returns 1, or 0 after an OOM diagnostic. */
int print_global_type(Arena *arena, const DeclList *decls, const char *name, Printed *out, Diag *diag);

#endif
