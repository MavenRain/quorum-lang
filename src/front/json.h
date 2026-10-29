/* The `langc check --json` printer. SHARED by the tcc kits. */
#ifndef LANG_FRONT_JSON_H
#define LANG_FRONT_JSON_H

#include <stdio.h>

#include "front/base.h"

/* The counts of the summary line. */
typedef struct {
  size_t parsed; /* program declarations parsed before the first parse failure */
  size_t typed;  /* program declarations checked before the first failure */
  size_t laws;   /* program laws parsed (S4 O64) */
  size_t discharged; /* laws among the typed declarations */
} Counts;

/* Writes DIAG as one JSON object on one line. The keys are code, span,
   expected, found, fix, retry and message, in this order. */
void json_diag(const Diag *diag, FILE *out);
/* Writes the summary object on one line. */
void json_summary(const Counts *counts, FILE *out);
/* Writes TEXT as one JSON string. */
void json_string(const char *text, FILE *out);
/* Writes LEN bytes as one JSON string, including embedded NUL bytes. */
void json_string_n(const char *text, size_t len, FILE *out);

#endif
