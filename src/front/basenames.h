/* The PLAN sec 3 names for `langc explain` and `langc list-base` (O119,
   O120). SHARED by the tcc kits. */
#ifndef LANG_FRONT_BASENAMES_H
#define LANG_FRONT_BASENAMES_H

#include <stddef.h>

/* A design name of a PLAN sec 3 table. KIND is the kind that starts the
   kind cell. SLICE is the slice tags of the slice cell, as "S5, S8". */
typedef struct {
  const char *name;
  const char *kind;
  const char *slice;
} BaseName;

extern const BaseName BASE_NAMES[];
extern const size_t BASE_NAME_COUNT;

/* The row of NAME, or NULL. */
const BaseName *base_name_find(const char *name);

#endif
